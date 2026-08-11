import { Worker } from 'node:worker_threads';
import { createLayeredPii } from '../dist/index.js';

const ENTITY_NAMES = new Set([
  'address',
  'bank-account',
  'credit-card',
  'custom',
  'date-of-birth',
  'email',
  'ip-address',
  'name',
  'passport',
  'phone',
  'ssn',
  'token',
  'uuid',
  'medical-id',
]);
const MAX_REQUEST_BYTES = 1_100_000;
const MAX_INPUT_LENGTH = 1_000_000;
const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_PROCESSOR_ID_LENGTH = 128;
const MAX_PATTERN_NAME_LENGTH = 128;
const MAX_PATTERN_SOURCE_LENGTH = 4_096;
const MAX_PATTERNS = 24;
const VALID_FLAGS = /^[dgimsuvy]*$/;
const PLACEHOLDER_PATTERN = /\[[A-Z-]+_\d+\]/g;
const FAILURE_PLACEHOLDER = '[REDACTION_FAILED]';
const PATTERN_VALIDATION_TIMEOUT_MS = 300;

class BadRequest extends Error {}
class PayloadTooLarge extends Error {}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function byteLength(value) {
  return new TextEncoder().encode(value).byteLength;
}

function send(res, status, payload) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json(payload);
}

function checkRequestSize(raw) {
  if (byteLength(raw) > MAX_REQUEST_BYTES) throw new PayloadTooLarge('Request body is too large.');
}

async function bodyOf(req) {
  try {
    if (req.body !== undefined) {
      if (typeof req.body === 'string') {
        checkRequestSize(req.body);
        return JSON.parse(req.body);
      }
      const serialized = JSON.stringify(req.body);
      if (typeof serialized !== 'string') throw new Error('body is not serializable');
      checkRequestSize(serialized);
      return req.body;
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      const bytes = Buffer.from(chunk);
      size += bytes.byteLength;
      if (size > MAX_REQUEST_BYTES) throw new PayloadTooLarge('Request body is too large.');
      chunks.push(bytes);
    }
    const raw = Buffer.concat(chunks).toString('utf8');
    return raw ? JSON.parse(raw) : {};
  } catch (error) {
    if (error instanceof PayloadTooLarge) throw error;
    throw new BadRequest('Request body must be valid JSON.');
  }
}

function parsePattern(pattern, index) {
  if (!isRecord(pattern)) throw new BadRequest(`Pattern ${index + 1} must be an object.`);
  const configuredName = typeof pattern.name === 'string' && pattern.name.trim() ? pattern.name : pattern.type;
  const name = typeof configuredName === 'string' ? configuredName.trim() : '';
  const source = typeof pattern.regex === 'string' ? pattern.regex : '';
  const flags = pattern.flags === undefined ? 'g' : pattern.flags;
  if (!name) throw new BadRequest(`Pattern ${index + 1} needs a name.`);
  if (name.length > MAX_PATTERN_NAME_LENGTH) throw new PayloadTooLarge(`Pattern ${index + 1} name is too large.`);
  if (!source) throw new BadRequest(`Pattern ${index + 1} needs a regular expression.`);
  if (source.length > MAX_PATTERN_SOURCE_LENGTH) throw new PayloadTooLarge(`Pattern ${index + 1} regular expression is too large.`);
  if (typeof flags !== 'string' || !VALID_FLAGS.test(flags)) throw new BadRequest(`Pattern ${index + 1} has invalid flags.`);

  let regex;
  try {
    regex = new RegExp(source, flags);
  } catch (error) {
    if (error instanceof BadRequest) throw error;
    throw new BadRequest(`Pattern ${index + 1} has an invalid regular expression.`);
  }

  const result = pattern.type !== undefined && pattern.name === undefined
    ? { type: name, regex }
    : { name, regex };
  if (pattern.entity !== undefined) {
    if (typeof pattern.entity !== 'string' || !ENTITY_NAMES.has(pattern.entity)) {
      throw new BadRequest(`Pattern ${index + 1} has an unsupported entity.`);
    }
    result.entity = pattern.entity;
  }
  if (pattern.priority !== undefined) {
    if (typeof pattern.priority !== 'number' || !Number.isFinite(pattern.priority) || pattern.priority < 0) {
      throw new BadRequest(`Pattern ${index + 1} priority must be a non-negative number.`);
    }
    result.priority = pattern.priority;
  }
  return result;
}

function effectiveFlags(regex) {
  const flags = regex.flags.replaceAll('y', '');
  return flags.includes('g') ? flags : `${flags}g`;
}

function validatePatterns(text, patterns) {
  if (patterns.length === 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('../dist/custom-pattern-worker.js', import.meta.url));
    let settled = false;
    let timer;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.removeAllListeners();
      void worker.terminate().then(
        () => error ? reject(error) : resolve(),
        () => error ? reject(error) : resolve(),
      );
    };
    timer = setTimeout(() => finish(new BadRequest('Custom pattern validation timed out.')), PATTERN_VALIDATION_TIMEOUT_MS);
    worker.once('error', () => finish(new BadRequest('Custom pattern validation failed.')));
    worker.once('exit', () => finish(new BadRequest('Custom pattern validation failed.')));
    worker.once('online', () => {
      try {
        worker.postMessage({ texts: [text], patterns: patterns.map(({ regex }) => ({ source: regex.source, flags: effectiveFlags(regex) })) });
      } catch {
        finish(new BadRequest('Custom pattern validation failed.'));
      }
    });
    worker.once('message', (message) => {
      if (message?.ok === true || message?.reason === 'too-many-matches') return finish();
      if (message?.reason === 'zero-width') return finish(new BadRequest('Custom patterns must match a non-empty value.'));
      finish(new BadRequest('Custom pattern validation failed.'));
    });
  });
}

async function normalizeConfig(config, text) {
  if (!isRecord(config)) throw new BadRequest('Configuration must be an object.');
  let serialized;
  try {
    serialized = JSON.stringify(config);
  } catch {
    throw new BadRequest('Configuration must be a JSON object.');
  }
  if (typeof serialized !== 'string' || byteLength(serialized) > MAX_CONFIG_BYTES) {
    throw new PayloadTooLarge('Configuration is too large.');
  }

  const normalized = {};
  if (config.id !== undefined) {
    if (typeof config.id !== 'string' || config.id.trim() === '') throw new BadRequest('Processor id must be a non-empty string.');
    if (config.id.trim().length > MAX_PROCESSOR_ID_LENGTH) throw new PayloadTooLarge('Processor id is too large.');
    normalized.id = config.id.trim();
  }

  const layers = config.layers === undefined ? ['deterministic'] : config.layers;
  if (!Array.isArray(layers) || layers.length !== 1 || layers[0] !== 'deterministic') {
    throw new BadRequest('Alpha 1 supports only the deterministic layer.');
  }
  normalized.layers = ['deterministic'];

  if (config.entities !== undefined) {
    if (!Array.isArray(config.entities) || config.entities.some((entity) => !ENTITY_NAMES.has(entity))) {
      throw new BadRequest('Entity filters contain an unsupported entity.');
    }
    normalized.entities = config.entities;
  }

  const patterns = [
    ...(Array.isArray(config.patterns) ? config.patterns : []),
    ...(Array.isArray(config.customPatterns) ? config.customPatterns : []),
  ];
  if (config.patterns !== undefined && !Array.isArray(config.patterns)) throw new BadRequest('Patterns must be an array.');
  if (config.customPatterns !== undefined && !Array.isArray(config.customPatterns)) throw new BadRequest('Custom patterns must be an array.');
  if (patterns.length > MAX_PATTERNS) throw new BadRequest(`A maximum of ${MAX_PATTERNS} custom patterns is supported.`);
  normalized.patterns = patterns.map(parsePattern);
  await validatePatterns(text, normalized.patterns);
  return normalized;
}

function newPlaceholderCount(input, output) {
  const before = new Map();
  for (const placeholder of input.match(PLACEHOLDER_PATTERN) ?? []) {
    before.set(placeholder, (before.get(placeholder) ?? 0) + 1);
  }
  let count = 0;
  for (const placeholder of output.match(PLACEHOLDER_PATTERN) ?? []) {
    const remaining = before.get(placeholder) ?? 0;
    if (remaining > 0) before.set(placeholder, remaining - 1);
    else count += 1;
  }
  return count;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');

  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST') return send(res, 405, { error: 'Use POST.' });

  try {
    const body = await bodyOf(req);
    if (!isRecord(body) || typeof body.text !== 'string') throw new BadRequest('Input text must be a string.');
    if (body.text.length > MAX_INPUT_LENGTH) throw new PayloadTooLarge('Input text is too large.');

    const config = await normalizeConfig(body.config ?? {}, body.text);
    const startedAt = performance.now();
    const pii = createLayeredPii(config);
    const output = await pii.redactText(body.text, { layers: config.layers });
    if (output === FAILURE_PLACEHOLDER && output !== body.text) return send(res, 500, { error: 'Redaction failed. Try a smaller input or simpler pattern.' });
    const redactionCount = newPlaceholderCount(body.text, output);

    return send(res, 200, {
      output,
      redactionCount,
      durationMs: Math.round((performance.now() - startedAt) * 10) / 10,
      config: {
        id: pii.id,
        layers: config.layers,
        entityCount: config.entities?.length ?? ENTITY_NAMES.size,
        patternCount: config.patterns.length,
      },
    });
  } catch (error) {
    if (error instanceof BadRequest) return send(res, 400, { error: error.message });
    if (error instanceof PayloadTooLarge) return send(res, 413, { error: error.message });
    return send(res, 500, { error: 'Redaction failed. Try a smaller input or simpler pattern.' });
  }
}
