import { Worker } from 'node:worker_threads';
import { LruCache, createLocalAdapter, createPresidioAdapter } from './analyzer.js';
import type { Analyzer, AnalyzerSpan, PresidioAdapterConfig } from './analyzer.js';
import type {
  CoreMessageV4,
  MastraDBMessage,
  MastraMessagePart,
} from '@mastra/core/agent/message-list';
import type {
  ProcessInputArgs,
  ProcessInputResult,
  ProcessLLMRequestArgs,
  ProcessLLMRequestResult,
  ProcessOutputResultArgs,
  Processor,
  ProcessorMessageResult,
} from '@mastra/core/processors';

/** Stable entity names emitted by Alpha 1 placeholders. */
export type PiiEntity =
  | 'address'
  | 'bank-account'
  | 'credit-card'
  | 'custom'
  | 'date-of-birth'
  | 'email'
  | 'ip-address'
  | 'name'
  | 'passport'
  | 'phone'
  | 'ssn'
  | 'token'
  | 'uuid'
  | 'medical-id'
  | 'aadhaar'
  | 'pan'
  | 'upi'
  | 'ifsc'
  | 'voter-id'
  | 'driving-license'
  | 'vehicle';

/** Alpha 1 exposes one deterministic local layer. */
export type PiiLayer = 'deterministic' | 'ner' | 'model';

/** Options for a single redaction call. */
export interface RedactTextOptions {
  readonly layers?: readonly PiiLayer[];
}

type PiiPatternFields = {
  readonly regex: RegExp;
  readonly entity?: PiiEntity;
  readonly priority?: number;
};
export type PiiPattern = PiiPatternFields &
  ({ readonly name: string; readonly type?: never } | { readonly type: string; readonly name?: never });

export interface LayeredPiiConfig {
  readonly id?: string;
  readonly entities?: readonly PiiEntity[];
  /** Custom patterns are part of the deterministic layer. */
  readonly patterns?: readonly PiiPattern[];
  /** Alias for integrations that call these custom patterns. */
  readonly customPatterns?: readonly PiiPattern[];
  readonly layers?: readonly PiiLayer[];
  /** Engine. Default: the local deterministic adapter. Mutually exclusive with `presidio`. */
  readonly analyzer?: Analyzer;
  /** Remote Presidio container shorthand (createPresidioAdapter). Mutually exclusive with `analyzer`. */
  readonly presidio?: PresidioAdapterConfig;
  /** On analyzer failure: 'local' falls back to the deterministic engine (default), 'strict' fails closed. */
  readonly fallback?: 'local' | 'strict';
  /** Per-text redaction cache, keyed by text (0 disables; default 256). */
  readonly cacheSize?: number;
  /** Placeholder style: 'type' emits [ENTITY_n] (default), 'uniform' emits a fixed token. */
  readonly anonymize?: { readonly format?: 'type' | 'uniform'; readonly uniformToken?: string };
}

export type PiiProcessor = Processor<string> & Required<Pick<Processor<string>, 'processInput' | 'processLLMRequest' | 'processOutputResult'>>;

export interface LayeredPii {
  readonly id: string;
  readonly warmup: () => Promise<void>;
  readonly redactText: (text: string, options?: RedactTextOptions) => Promise<string>;
  readonly processor: PiiProcessor;
}

const FAILURE_PLACEHOLDER = '[REDACTION_FAILED]';

export { createLocalAdapter, createPresidioAdapter, INDIAN_DEFAULTS } from './analyzer.js';
export type { Analyzer, AnalyzerSpan, PresidioAdapterConfig, PresidioPatternRecognizer } from './analyzer.js';
const DEFAULT_ID = 'mastra-pii';
const MAX_TEXT_LENGTH = 1_000_000;
const CUSTOM_PATTERN_TIMEOUT_BASE_MS = 250;
const CUSTOM_PATTERN_TIMEOUT_MS_PER_KB = 1;
const CUSTOM_PATTERN_CHUNK_SIZE = 256;
const MAX_JSON_DEPTH = 32;
const MAX_JSON_NODES = 10_000;
const SUPPORTED_LAYERS = new Set<PiiLayer>(['deterministic']);
const ENTITY_NAMES = new Set<PiiEntity>([
  'address', 'bank-account', 'credit-card', 'custom', 'date-of-birth', 'email',
  'ip-address', 'name', 'passport', 'phone', 'ssn', 'token', 'uuid', 'medical-id',
  'aadhaar', 'pan', 'upi', 'ifsc', 'voter-id', 'driving-license', 'vehicle',
]);

type JsonCloneState = { readonly active: WeakSet<object>; nodes: number };
type RuntimePattern = {
  readonly source: string;
  readonly flags: string;
  readonly entity: PiiEntity;
  readonly priority: number;
  readonly order: number;
};
type SpanCandidate = {
  readonly start: number;
  readonly end: number;
  readonly entity: PiiEntity;
  readonly priority: number;
  readonly order: number;
};
type RedactMany = (texts: readonly string[]) => Promise<string[]>;

function fail(message: string): never {
  // Deliberately never include caller configuration, matches, or text in a public error.
  throw new TypeError(message);
}

function validateLayers(layers: unknown): void {
  if (!Array.isArray(layers) || layers.length === 0) fail('PII layers must be a non-empty array');
  for (const layer of layers) {
    if (layer === 'ner' || layer === 'model') fail(`PII layer '${layer}' is not available in Alpha 1`);
    if (typeof layer !== 'string' || !SUPPORTED_LAYERS.has(layer as PiiLayer)) fail('PII layers contain an unsupported layer');
  }
}

function validatePatterns(patterns: readonly PiiPattern[] | undefined): void {
  if (patterns === undefined) return;
  if (!Array.isArray(patterns)) fail('PII patterns must be an array');
  for (const pattern of patterns) {
    if (pattern === null || typeof pattern !== 'object' || Array.isArray(pattern)) fail('PII pattern must be an object');
    const patternName = 'name' in pattern ? pattern.name : 'type' in pattern ? pattern.type : undefined;
    if (typeof patternName !== 'string' || patternName.trim() === '') fail('PII pattern name must be non-empty');
    if (!(pattern.regex instanceof RegExp)) fail('PII pattern regex must be a RegExp');
    const probe = new RegExp(pattern.regex.source, pattern.regex.flags.replaceAll('g', '').replaceAll('y', ''));
    if (probe.test('')) fail('PII pattern regex must match a non-empty value');
    if (pattern.entity !== undefined && !ENTITY_NAMES.has(pattern.entity)) fail('PII pattern entity is unsupported');
    if (pattern.priority !== undefined && (!Number.isFinite(pattern.priority) || pattern.priority < 0)) {
      fail('PII pattern priority must be a non-negative finite number');
    }
  }
}

function validateConfig(config: LayeredPiiConfig): void {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) fail('PII configuration must be an object');
  if (config.id !== undefined && (typeof config.id !== 'string' || config.id.trim() === '')) fail('PII configuration id must be a non-empty string');
  const untypedConfig = config as Record<string, unknown>;
  if (untypedConfig.ner !== undefined || untypedConfig.model !== undefined) fail('PII NER and model layers are not available in Alpha 1');
  if (config.layers !== undefined) validateLayers(config.layers);
  if (config.entities !== undefined) {
    if (!Array.isArray(config.entities)) fail('PII entities must be an array');
    for (const entity of config.entities) if (!ENTITY_NAMES.has(entity)) fail('PII entities contain an unsupported entity');
  }
  validatePatterns(config.patterns);
  validatePatterns(config.customPatterns);
  if (config.analyzer !== undefined && config.presidio !== undefined) fail('PII configuration must not set both analyzer and presidio');
  if (config.analyzer !== undefined && (config.analyzer === null || typeof config.analyzer !== 'object' || typeof config.analyzer.analyze !== 'function')) fail('PII analyzer must implement analyze(text)');
  if (config.presidio !== undefined && (config.presidio === null || typeof config.presidio !== 'object' || Array.isArray(config.presidio))) fail('PII presidio configuration must be an object');
  if (config.fallback !== undefined && config.fallback !== 'local' && config.fallback !== 'strict') fail('PII fallback must be "local" or "strict"');
  if (config.cacheSize !== undefined && (!Number.isInteger(config.cacheSize) || config.cacheSize < 0)) fail('PII cacheSize must be a non-negative integer');
  if (config.anonymize !== undefined) {
    if (config.anonymize === null || typeof config.anonymize !== 'object' || Array.isArray(config.anonymize)) fail('PII anonymize configuration must be an object');
    if (config.anonymize.format !== undefined && config.anonymize.format !== 'type' && config.anonymize.format !== 'uniform') fail('PII anonymize format must be "type" or "uniform"');
    if (config.anonymize.uniformToken !== undefined && (typeof config.anonymize.uniformToken !== 'string' || config.anonymize.uniformToken.trim() === '')) fail('PII anonymize uniformToken must be a non-empty string');
  }
}

function globalFlags(regex: RegExp): string {
  const flags = regex.flags.replaceAll('y', '');
  return flags.includes('g') ? flags : `${flags}g`;
}

function normalizedEntity(type: string, configured?: PiiEntity): PiiEntity {
  if (configured) return configured;
  const value = type.toLowerCase().replace(/[\s_]+/g, '-');
  const tokens = new Set(value.split('-').filter(Boolean));
  const has = (...terms: string[]): boolean => terms.some((term) => tokens.has(term));
  if (has('aadhaar', 'aadhar', 'uidai')) return 'aadhaar';
  if (value === 'pan' || has('pan')) return 'pan';
  if (has('upi')) return 'upi';
  if (has('ifsc')) return 'ifsc';
  if (has('voter', 'epic')) return 'voter-id';
  if (has('driver', 'license', 'dl')) return 'driving-license';
  if (has('vehicle', 'registration')) return 'vehicle';
  if (has('person')) return 'name';
  if (has('location')) return 'address';
  if ((tokens.has('api') && tokens.has('key')) || (tokens.has('access') && tokens.has('key')) || (tokens.has('service') && tokens.has('account')) || has('password', 'secret', 'token')) return 'token';
  if (value === 'email' || has('email')) return 'email';
  if (has('phone', 'mobile')) return 'phone';
  if (has('credit', 'card', 'cvv', 'expiry')) return 'credit-card';
  if (value === 'ssn' || has('ssn', 'social-security')) return 'ssn';
  if (value === 'ip' || value === 'ipv4' || value === 'ipv6' || value === 'ip-address') return 'ip-address';
  if (has('address')) return 'address';
  if (has('passport')) return 'passport';
  if (has('name')) return 'name';
  if (has('birth', 'dob', 'date', 'time')) return 'date-of-birth';
  if (has('uuid')) return 'uuid';
  if (has('iban', 'bank', 'account')) return 'bank-account';
  if (has('medical', 'health', 'nhs')) return 'medical-id';
  return 'custom';
}

function builtInSpans(detections: readonly AnalyzerSpan[]): SpanCandidate[] {
  return detections.map((detection, order) => ({
    start: detection.start,
    end: detection.end,
    entity: normalizedEntity(detection.type),
    priority: 0,
    order,
  }));
}

/** One worker call per chunk of texts; the worker tags every span with its text index. */
async function customPatternSpans(texts: readonly string[], patterns: readonly RuntimePattern[]): Promise<SpanCandidate[][]> {
  if (patterns.length === 0 || texts.length === 0) return texts.map(() => []);
  const totalChars = texts.reduce((sum, text) => sum + text.length, 0);
  const timeoutMs = CUSTOM_PATTERN_TIMEOUT_BASE_MS + Math.floor(totalChars / 1024) * CUSTOM_PATTERN_TIMEOUT_MS_PER_KB;
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./custom-pattern-worker.js', import.meta.url));
    let settled = false;
    let timer: NodeJS.Timeout;
    const finish = (error?: Error, value?: SpanCandidate[][]): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.removeAllListeners();
      void worker.terminate().then(
        () => error ? reject(error) : resolve(value ?? []),
        () => reject(error ?? new Error('custom pattern worker failed')),
      );
    };
    timer = setTimeout(() => finish(new Error('custom pattern timeout')), timeoutMs);
    worker.once('error', () => finish(new Error('custom pattern worker failed')));
    worker.once('exit', () => finish(new Error('custom pattern worker failed')));
    worker.once('online', () => {
      try {
        worker.postMessage({ texts, patterns: patterns.map(({ source, flags }) => ({ source, flags })) });
      } catch {
        finish(new Error('custom pattern worker failed'));
      }
    });
    worker.once('message', (message: unknown) => {
      if (!message || typeof message !== 'object' || Array.isArray(message)) return finish(new Error('custom pattern worker failed'));
      const response = message as { ok?: unknown; spans?: unknown };
      if (response.ok !== true || !Array.isArray(response.spans) || response.spans.length > MAX_JSON_NODES) {
        return finish(new Error('custom pattern worker failed'));
      }
      try {
        const perText: SpanCandidate[][] = Array.from({ length: texts.length }, () => []);
        for (const raw of response.spans) {
          if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('invalid worker span');
          const span = raw as { textIndex?: unknown; patternIndex?: unknown; start?: unknown; end?: unknown };
          if (!Number.isInteger(span.textIndex) || !Number.isInteger(span.patternIndex) || !Number.isInteger(span.start) || !Number.isInteger(span.end)) {
            throw new Error('invalid worker span');
          }
          const textIndex = span.textIndex as number;
          const pattern = patterns[span.patternIndex as number];
          if (!pattern || textIndex < 0 || textIndex >= texts.length) throw new Error('invalid worker span');
          perText[textIndex]!.push({
            start: span.start as number,
            end: span.end as number,
            entity: pattern.entity,
            priority: pattern.priority,
            order: pattern.order,
          });
        }
        finish(undefined, perText);
      } catch {
        finish(new Error('custom pattern worker failed'));
      }
    });
  });
}

function safeSpans(textLength: number, detections: readonly SpanCandidate[], entities?: readonly PiiEntity[]): SpanCandidate[] {
  const allowed = entities ? new Set(entities) : undefined;
  const candidates = detections.filter((span) => {
    if (!Number.isInteger(span.start) || !Number.isInteger(span.end) || span.start < 0 || span.end <= span.start || span.end > textLength) {
      throw new Error('invalid detector span');
    }
    return !allowed || allowed.has(span.entity);
  });
  candidates.sort((a, b) => a.start - b.start || a.end - b.end || b.priority - a.priority || a.order - b.order || a.entity.localeCompare(b.entity));
  const selected: SpanCandidate[] = [];
  for (let index = 0; index < candidates.length;) {
    const first = candidates[index];
    if (!first) break;
    const group = [first];
    let groupEnd = first.end;
    index += 1;
    while (index < candidates.length) {
      const candidate = candidates[index];
      if (!candidate || candidate.start >= groupEnd) break;
      group.push(candidate);
      groupEnd = Math.max(groupEnd, candidate.end);
      index += 1;
    }
    group.sort((a, b) =>
      b.priority - a.priority ||
      (b.end - b.start) - (a.end - a.start) ||
      a.start - b.start ||
      a.order - b.order ||
      a.entity.localeCompare(b.entity) ||
      a.end - b.end,
    );
    const winner = group[0];
    if (winner) selected.push({ ...winner, start: first.start, end: groupEnd });
  }
  return selected.sort((a, b) => a.start - b.start || a.end - b.end || a.order - b.order);
}

function applyPlaceholders(text: string, spans: readonly SpanCandidate[], format: 'type' | 'uniform' = 'type', uniformToken = '[REDACTED]'): string {
  const counts = new Map<PiiEntity, number>();
  const placeholders = spans.map((span) => {
    if (format === 'uniform') return uniformToken;
    const number = (counts.get(span.entity) ?? 0) + 1;
    counts.set(span.entity, number);
    return `[${span.entity.toUpperCase()}_${number}]`;
  });
  let output = text;
  for (let index = spans.length - 1; index >= 0; index -= 1) {
    const span = spans[index];
    const placeholder = placeholders[index];
    if (span && placeholder) output = `${output.slice(0, span.start)}${placeholder}${output.slice(span.end)}`;
  }
  return output;
}

function failedMastraMessage(): MastraDBMessage {
  return {
    id: 'redacted-message', role: 'user', createdAt: new Date(0),
    content: { format: 2, parts: [{ type: 'text', text: FAILURE_PLACEHOLDER } as MastraMessagePart], content: FAILURE_PLACEHOLDER },
  };
}

function failedCoreMessage(): CoreMessageV4 {
  return { role: 'system', content: FAILURE_PLACEHOLDER };
}

function failedPromptMessage(): ProcessLLMRequestArgs['prompt'][number] {
  return { role: 'system', content: FAILURE_PLACEHOLDER };
}

/** Fail-closed marker at part granularity: the part is replaced, the rest of the message survives. */
function failedPart(): MastraMessagePart {
  return { type: 'text', text: FAILURE_PLACEHOLDER } as MastraMessagePart;
}

async function failClosed<T>(work: () => Promise<T>, fallback: () => T): Promise<T> {
  try {
    return await work();
  } catch {
    return fallback();
  }
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Redacts one string through the batched engine. */
async function redactOne(redactMany: RedactMany, text: string): Promise<string> {
  return (await redactMany([text]))[0] ?? FAILURE_PLACEHOLDER;
}

/**
 * Validated clone walk over bounded JSON: strings are handed to `visit`, object
 * keys are preserved verbatim (they are schema identifiers; renaming them would
 * corrupt fixed-schema payloads).
 */
function walkJson(value: unknown, depth: number, state: JsonCloneState, visit: (text: string) => unknown): unknown {
  if (depth > MAX_JSON_DEPTH || ++state.nodes > MAX_JSON_NODES) throw new Error('payload limit exceeded');
  if (typeof value === 'string') return visit(value);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object') throw new Error('unsupported payload');
  if (state.active.has(value)) throw new Error('cyclic payload');
  state.active.add(value);
  try {
    if (Array.isArray(value)) {
      const clone: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) throw new Error('sparse payload');
        clone.push(walkJson(value[index], depth + 1, state, visit));
      }
      return clone;
    }
    if (!plainRecord(value) || Object.getOwnPropertySymbols(value).length !== 0) throw new Error('unsupported payload');
    const clone = Object.create(Object.getPrototypeOf(value)) as Record<string, unknown>;
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) throw new Error('unsupported payload');
      Object.defineProperty(clone, key, {
        ...descriptor,
        value: walkJson(descriptor.value, depth + 1, state, visit),
      });
    }
    return clone;
  } finally {
    state.active.delete(value);
  }
}

function collectJsonStrings(value: unknown): string[] {
  const state: JsonCloneState & { strings: string[] } = { active: new WeakSet(), nodes: 0, strings: [] };
  walkJson(value, 0, state, (text) => {
    state.strings.push(text);
    return text;
  });
  return state.strings;
}

/**
 * Collects every string in the payload, redacts the deduplicated set in one
 * batched pass, then rebuilds the clone in the same traversal order.
 */
function redactPayload(value: unknown, redactMany: RedactMany): Promise<unknown> {
  const strings = collectJsonStrings(value);
  return redactMany(strings).then((redacted) => {
    let index = 0;
    return walkJson(value, 0, { active: new WeakSet(), nodes: 0 }, () => redacted[index++]!);
  });
}

async function cloneJsonFields(
  source: Record<string, unknown>,
  clone: Record<string, unknown>,
  fields: readonly string[],
  redactMany: RedactMany,
): Promise<Record<string, unknown>> {
  for (const field of fields) {
    if (source[field] !== undefined) clone[field] = await redactPayload(source[field], redactMany);
  }
  return clone;
}

function cloneProviderOptions(
  source: Record<string, unknown>,
  clone: Record<string, unknown>,
  redactMany: RedactMany,
): Promise<Record<string, unknown>> {
  return cloneJsonFields(source, clone, ['providerOptions', 'providerMetadata', 'experimental_providerMetadata'], redactMany);
}

function cloneMedia(value: unknown): Uint8Array | ArrayBuffer {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (value instanceof ArrayBuffer) return value.slice(0);
  throw new Error('unsupported media');
}

/**
 * Structural identifiers (tool call ids, tool names, approval ids) are
 * provider- or framework-generated, not user content, so they are copied
 * verbatim after a shape and size check. Running PII detection over them would
 * redact provider-generated UUIDs and fail the whole message closed.
 */
function validateStructuralIdentifier(value: unknown): void {
  if (typeof value !== 'string' || value.length > MAX_TEXT_LENGTH) throw new Error('invalid structural identifier');
}

function validateToolIdentifiers(value: Record<string, unknown>): void {
  validateStructuralIdentifier(value.toolCallId);
  validateStructuralIdentifier(value.toolName);
}

async function cloneApproval(value: unknown, redactMany: RedactMany): Promise<unknown> {
  if (!plainRecord(value)) throw new Error('invalid approval');
  validateStructuralIdentifier(value.id);
  if (value.reason !== undefined && typeof value.reason !== 'string') throw new Error('invalid approval reason');
  return { ...value, ...(value.reason === undefined ? {} : { reason: await redactOne(redactMany, value.reason) }) };
}

async function cloneToolFields(part: Record<string, unknown>, redactMany: RedactMany): Promise<Record<string, unknown>> {
  const clone = { ...part };
  for (const field of ['args', 'input', 'result', 'output', 'rawInput'] as const) {
    if (part[field] !== undefined) clone[field] = await redactPayload(part[field], redactMany);
  }
  for (const field of ['errorText', 'title'] as const) {
    if (part[field] !== undefined) {
      if (typeof part[field] !== 'string') throw new Error('invalid tool text');
      clone[field] = await redactOne(redactMany, part[field]);
    }
  }
  if (part.approval !== undefined) clone.approval = await cloneApproval(part.approval, redactMany);
  return cloneProviderOptions(part, clone, redactMany);
}

async function cloneToolInvocation(value: unknown, redactMany: RedactMany): Promise<unknown> {
  if (!plainRecord(value)) throw new Error('invalid tool invocation');
  validateToolIdentifiers(value);
  return cloneToolFields(value, redactMany);
}

async function clonePart(part: MastraMessagePart, redactMany: RedactMany): Promise<MastraMessagePart> {
  if (!plainRecord(part) || typeof part.type !== 'string') throw new Error('invalid message part');
  if (part.type === 'text') {
    if (typeof part.text !== 'string') throw new Error('invalid text part');
    return await cloneProviderOptions(part, { ...part, text: await redactOne(redactMany, part.text) }, redactMany) as MastraMessagePart;
  }
  if (part.type === 'reasoning') {
    if (typeof part.reasoning !== 'string' || !Array.isArray(part.details)) throw new Error('invalid reasoning part');
    const details = await Promise.all(part.details.map(async (detail) => {
      if (!plainRecord(detail) || typeof detail.type !== 'string') throw new Error('invalid reasoning detail');
      if (detail.type === 'text') {
        if (typeof detail.text !== 'string') throw new Error('invalid reasoning detail text');
        return { ...detail, text: await redactOne(redactMany, detail.text) };
      }
      if (detail.type === 'redacted' && typeof detail.data === 'string') return { ...detail };
      throw new Error('invalid reasoning detail');
    }));
    return await cloneProviderOptions(part, { ...part, reasoning: await redactOne(redactMany, part.reasoning), details }, redactMany) as MastraMessagePart;
  }
  if (part.type === 'tool-invocation') {
    const clone = await cloneToolFields(part, redactMany);
    clone.toolInvocation = await cloneToolInvocation(part.toolInvocation, redactMany);
    return clone as MastraMessagePart;
  }
  const mediaPart = part as Record<string, unknown>;
  if (mediaPart.type === 'file' || mediaPart.type === 'image') {
    const field = mediaPart.type === 'file' ? 'data' : 'image';
    if (!(field in mediaPart)) throw new Error('invalid media part');
    let clonedMedia: Uint8Array | ArrayBuffer;
    try {
      clonedMedia = cloneMedia(mediaPart[field]);
    } catch {
      // Unsupported media (string, base64, URL/data-URL): fail closed at part
      // granularity so unrelated parts of the message survive.
      return failedPart();
    }
    return await cloneProviderOptions(mediaPart, {
      ...mediaPart,
      [field]: clonedMedia,
      ...(typeof mediaPart.filename === 'string' ? { filename: await redactOne(redactMany, mediaPart.filename) } : {}),
    }, redactMany) as MastraMessagePart;
  }
  if (part.type === 'source-document') {
    if (typeof part.sourceId !== 'string' || typeof part.mediaType !== 'string' || typeof part.title !== 'string') throw new Error('invalid source document');
    if (part.filename !== undefined && typeof part.filename !== 'string') throw new Error('invalid source filename');
    return await cloneProviderOptions(part, {
      ...part,
      sourceId: await redactOne(redactMany, part.sourceId),
      title: await redactOne(redactMany, part.title),
      ...(part.filename === undefined ? {} : { filename: await redactOne(redactMany, part.filename) }),
    }, redactMany) as MastraMessagePart;
  }
  if (part.type === 'source') {
    if (!plainRecord(part.source) || part.source.sourceType !== 'url' || typeof part.source.id !== 'string' || typeof part.source.url !== 'string') {
      throw new Error('invalid source');
    }
    if (part.source.title !== undefined && typeof part.source.title !== 'string') throw new Error('invalid source title');
    const source = await cloneProviderOptions(part.source, {
      ...part.source,
      id: await redactOne(redactMany, part.source.id),
      url: await redactOne(redactMany, part.source.url),
      ...(part.source.title === undefined ? {} : { title: await redactOne(redactMany, part.source.title) }),
    }, redactMany);
    return await cloneProviderOptions(part, { ...part, source }, redactMany) as MastraMessagePart;
  }
  if (part.type.startsWith('data-')) {
    if (!('data' in part)) throw new Error('invalid data part');
    return await cloneProviderOptions(part, { ...part, data: await redactPayload(part.data, redactMany) }, redactMany) as MastraMessagePart;
  }
  return await cloneToolFields(part, redactMany) as MastraMessagePart;
}

async function redactMastraMessage(message: MastraDBMessage, redactMany: RedactMany): Promise<MastraDBMessage> {
  if (!plainRecord(message) || !plainRecord(message.content) || !Array.isArray(message.content.parts)) throw new Error('invalid message');
  const content = message.content;
  if (content.content !== undefined && typeof content.content !== 'string') throw new Error('invalid message content');
  if (content.reasoning !== undefined && typeof content.reasoning !== 'string') throw new Error('invalid message reasoning');
  if (content.toolInvocations !== undefined && !Array.isArray(content.toolInvocations)) throw new Error('invalid tool invocations');
  const clonedContent = await cloneJsonFields(content, {
    ...content,
    parts: await Promise.all(content.parts.map((part) => clonePart(part, redactMany))),
    ...(content.content === undefined ? {} : { content: await redactOne(redactMany, content.content) }),
    ...(content.reasoning === undefined ? {} : { reasoning: await redactOne(redactMany, content.reasoning) }),
    ...(content.toolInvocations === undefined ? {} : { toolInvocations: await Promise.all(content.toolInvocations.map((item) => cloneToolInvocation(item, redactMany))) }),
  }, ['metadata', 'annotations'], redactMany);
  if (content.experimental_attachments !== undefined) {
    // UI attachments carry all-string fields; url and name may embed user data
    // (filenames, signed URLs) and are redacted as text instead of failing the message.
    if (!Array.isArray(content.experimental_attachments)) throw new Error('invalid attachments');
    clonedContent.experimental_attachments = await Promise.all(content.experimental_attachments.map(async (attachment) => {
      if (!plainRecord(attachment) || typeof attachment.url !== 'string') throw new Error('invalid attachment');
      return {
        ...attachment,
        url: await redactOne(redactMany, attachment.url),
        ...(attachment.name === undefined ? {} : { name: await redactOne(redactMany, attachment.name) }),
      };
    }));
  }
  await cloneProviderOptions(content, clonedContent, redactMany);
  return await cloneProviderOptions(message, { ...message, content: clonedContent }, redactMany) as MastraDBMessage;
}

async function redactMessages(messages: unknown, redactMany: RedactMany): Promise<MastraDBMessage[]> {
  if (!Array.isArray(messages)) return [failedMastraMessage()];
  return Promise.all(messages.map((message) => failClosed(() => redactMastraMessage(message as MastraDBMessage, redactMany), failedMastraMessage)));
}

async function cloneCorePart(part: unknown, redactMany: RedactMany): Promise<unknown> {
  if (!plainRecord(part) || typeof part.type !== 'string') throw new Error('invalid core message part');
  if (part.type === 'text' || part.type === 'reasoning') {
    if (typeof part.text !== 'string') throw new Error('invalid core text part');
    return cloneProviderOptions(part, { ...part, text: await redactOne(redactMany, part.text) }, redactMany);
  }
  if (part.type === 'tool-call') {
    if (!('args' in part)) throw new Error('invalid core tool call');
    validateToolIdentifiers(part);
    return cloneProviderOptions(part, { ...part, args: await redactPayload(part.args, redactMany) }, redactMany);
  }
  if (part.type === 'tool-result') {
    if (!('result' in part)) throw new Error('invalid core tool result');
    validateToolIdentifiers(part);
    const clone: Record<string, unknown> = { ...part, result: await redactPayload(part.result, redactMany) };
    if (part.experimental_content !== undefined) {
      if (!Array.isArray(part.experimental_content)) throw new Error('invalid core tool content');
      clone.experimental_content = await Promise.all(part.experimental_content.map(async (item) => {
        if (!plainRecord(item) || typeof item.type !== 'string') throw new Error('invalid core tool content');
        if (item.type === 'text' && typeof item.text === 'string') {
          return cloneProviderOptions(item, { ...item, text: await redactOne(redactMany, item.text) }, redactMany);
        }
        if (item.type === 'image' && 'data' in item) {
          try {
            return cloneProviderOptions(item, { ...item, data: cloneMedia(item.data) }, redactMany);
          } catch {
            return { type: 'text', text: FAILURE_PLACEHOLDER };
          }
        }
        throw new Error('invalid core tool content');
      }));
    }
    return cloneProviderOptions(part, clone, redactMany);
  }
  if (part.type === 'image' || part.type === 'file') {
    const field = part.type === 'image' ? 'image' : 'data';
    if (!(field in part)) throw new Error('invalid core media');
    let clonedMedia: Uint8Array | ArrayBuffer;
    try {
      clonedMedia = cloneMedia(part[field]);
    } catch {
      return { type: 'text', text: FAILURE_PLACEHOLDER };
    }
    return cloneProviderOptions(part, {
      ...part,
      [field]: clonedMedia,
      ...(typeof part.filename === 'string' ? { filename: await redactOne(redactMany, part.filename) } : {}),
    }, redactMany);
  }
  if (part.type === 'redacted-reasoning' && typeof part.data === 'string') {
    return cloneProviderOptions(part, { ...part }, redactMany);
  }
  throw new Error('unsupported core message part');
}

async function redactCoreMessage(message: CoreMessageV4, redactMany: RedactMany): Promise<CoreMessageV4> {
  if (!plainRecord(message) || typeof message.role !== 'string') throw new Error('invalid core message');
  if (typeof message.content === 'string') {
    return await cloneProviderOptions(message, { ...message, content: await redactOne(redactMany, message.content) }, redactMany) as CoreMessageV4;
  }
  if (!Array.isArray(message.content)) throw new Error('invalid core message content');
  return await cloneProviderOptions(message, {
    ...message,
    content: await Promise.all(message.content.map((part) => cloneCorePart(part, redactMany))),
  }, redactMany) as CoreMessageV4;
}

async function redactCoreMessages(messages: unknown, redactMany: RedactMany): Promise<CoreMessageV4[]> {
  if (!Array.isArray(messages)) return [failedCoreMessage()];
  return Promise.all(messages.map((message) => failClosed(() => redactCoreMessage(message as CoreMessageV4, redactMany), failedCoreMessage)));
}

async function clonePromptOutput(output: unknown, redactMany: RedactMany): Promise<unknown> {
  if (!plainRecord(output) || typeof output.type !== 'string') throw new Error('invalid tool output');
  if ((output.type === 'text' || output.type === 'error-text') && typeof output.value === 'string') return { ...output, value: await redactOne(redactMany, output.value) };
  if (output.type === 'json' || output.type === 'error-json') return { ...output, value: await redactPayload(output.value, redactMany) };
  if (output.type === 'content' && Array.isArray(output.value)) {
    return {
      ...output,
      value: await Promise.all(output.value.map(async (item) => {
        if (!plainRecord(item) || typeof item.type !== 'string') throw new Error('invalid tool output content');
        if (item.type === 'text' && typeof item.text === 'string') {
          return cloneProviderOptions(item, { ...item, text: await redactOne(redactMany, item.text) }, redactMany);
        }
        if (item.type === 'media' && 'data' in item && typeof item.mediaType === 'string') {
          try {
            return cloneProviderOptions(item, { ...item, data: cloneMedia(item.data) }, redactMany);
          } catch {
            return { type: 'text', text: FAILURE_PLACEHOLDER };
          }
        }
        throw new Error('invalid tool output content');
      })),
    };
  }
  throw new Error('invalid tool output');
}

async function clonePromptPart(part: unknown, redactMany: RedactMany): Promise<unknown> {
  if (!plainRecord(part) || typeof part.type !== 'string') throw new Error('invalid prompt part');
  if (part.type === 'text' || part.type === 'reasoning') {
    if (typeof part.text !== 'string') throw new Error('invalid prompt text');
    return cloneProviderOptions(part, { ...part, text: await redactOne(redactMany, part.text) }, redactMany);
  }
  if (part.type === 'tool-call') {
    if (!('input' in part)) throw new Error('invalid prompt tool call');
    validateToolIdentifiers(part);
    return cloneProviderOptions(part, { ...part, input: await redactPayload(part.input, redactMany) }, redactMany);
  }
  if (part.type === 'tool-result') {
    validateToolIdentifiers(part);
    return cloneProviderOptions(part, { ...part, output: await clonePromptOutput(part.output, redactMany) }, redactMany);
  }
  if (part.type === 'file') {
    if (!('data' in part) || typeof part.mediaType !== 'string') throw new Error('invalid prompt file');
    if (part.filename !== undefined && typeof part.filename !== 'string') throw new Error('invalid prompt filename');
    let clonedData: Uint8Array | ArrayBuffer;
    try {
      clonedData = cloneMedia(part.data);
    } catch {
      return { type: 'text', text: FAILURE_PLACEHOLDER };
    }
    return cloneProviderOptions(part, {
      ...part,
      data: clonedData,
      ...(part.filename === undefined ? {} : { filename: await redactOne(redactMany, part.filename) }),
    }, redactMany);
  }
  throw new Error('unsupported prompt part');
}

async function redactPromptMessage(message: ProcessLLMRequestArgs['prompt'][number], redactMany: RedactMany): Promise<ProcessLLMRequestArgs['prompt'][number]> {
  if (!plainRecord(message) || typeof message.role !== 'string') throw new Error('invalid prompt message');
  if (message.role === 'system') {
    if (typeof message.content !== 'string') throw new Error('invalid prompt system message');
    return await cloneProviderOptions(message, { ...message, content: await redactOne(redactMany, message.content) }, redactMany) as ProcessLLMRequestArgs['prompt'][number];
  }
  if (!Array.isArray(message.content)) throw new Error('invalid prompt content');
  return await cloneProviderOptions(message, {
    ...message,
    content: await Promise.all(message.content.map((part) => clonePromptPart(part, redactMany))),
  }, redactMany) as ProcessLLMRequestArgs['prompt'][number];
}

async function redactPrompt(prompt: unknown, redactMany: RedactMany): Promise<ProcessLLMRequestArgs['prompt']> {
  if (!Array.isArray(prompt)) return [failedPromptMessage()];
  return Promise.all(prompt.map((message) => failClosed(() => redactPromptMessage(message as ProcessLLMRequestArgs['prompt'][number], redactMany), failedPromptMessage)));
}

export function createLayeredPii(config: LayeredPiiConfig = {}): LayeredPii {
  validateConfig(config);
  const id = config.id?.trim() || DEFAULT_ID;
  const patterns = [...(config.patterns ?? []), ...(config.customPatterns ?? [])];
  const runtimePatterns: RuntimePattern[] = patterns.map((pattern, order) => ({
    source: pattern.regex.source,
    flags: globalFlags(pattern.regex),
    entity: pattern.entity ?? 'custom',
    // Custom patterns default above every built-in detection so an explicit
    // lower priority is required for a built-in to win an overlap.
    priority: pattern.priority ?? pattern.regex.source.length + 1000,
    order,
  }));
  let customPatternQueue: Promise<void> = Promise.resolve();
  const queuedCustomPatternSpans = (texts: string[]): Promise<SpanCandidate[][]> => {
    const results: SpanCandidate[][] = [];
    let chain: Promise<unknown> = Promise.resolve();
    for (let offset = 0; offset < texts.length; offset += CUSTOM_PATTERN_CHUNK_SIZE) {
      const chunk = texts.slice(offset, offset + CUSTOM_PATTERN_CHUNK_SIZE);
      chain = chain.then(() => customPatternSpans(chunk, runtimePatterns)).then((spans) => {
        results.push(...spans);
      });
    }
    const queued = customPatternQueue.then(() => chain);
    customPatternQueue = queued.then(() => undefined, () => undefined);
    return queued.then(() => results);
  };

  const localAdapter = createLocalAdapter();
  const analyzer: Analyzer = config.presidio !== undefined ? createPresidioAdapter(config.presidio) : (config.analyzer ?? localAdapter);
  const fallbackAnalyzer: Analyzer | undefined = config.fallback === 'strict' || analyzer === localAdapter ? undefined : localAdapter;
  const cache = config.cacheSize === 0 ? undefined : new LruCache<string, string>(config.cacheSize ?? 256);
  const anonymizeFormat: 'type' | 'uniform' = config.anonymize?.format ?? 'type';
  const uniformToken = config.anonymize?.uniformToken ?? '[REDACTED]';

  const redactMany: RedactMany = async (texts: readonly string[]): Promise<string[]> => {
    if (texts.length === 0) return [];
    const unique = [...new Set(texts)];
    const outcome = new Map<string, string>();
    const pending: string[] = [];
    for (const text of unique) {
      if (text.length > MAX_TEXT_LENGTH) {
        outcome.set(text, FAILURE_PLACEHOLDER);
        continue;
      }
      const cached = cache?.get(text);
      if (cached !== undefined) {
        outcome.set(text, cached);
        continue;
      }
      pending.push(text);
    }
    try {
      if (pending.length > 0) {
        const [analyzed, custom] = await Promise.all([
          Promise.all(pending.map(async (text) => {
            try {
              return builtInSpans(await analyzer.analyze(text));
            } catch (error) {
              if (fallbackAnalyzer) return builtInSpans(await fallbackAnalyzer.analyze(text));
              throw error;
            }
          })),
          queuedCustomPatternSpans(pending),
        ]);
        for (let index = 0; index < pending.length; index += 1) {
          const text = pending[index]!;
          const redacted = applyPlaceholders(
            text,
            safeSpans(text.length, [...analyzed[index]!, ...custom[index]!], config.entities),
            anonymizeFormat,
            uniformToken,
          );
          outcome.set(text, redacted);
          cache?.set(text, redacted);
        }
      }
    } catch {
      for (const text of pending) outcome.set(text, FAILURE_PLACEHOLDER);
    }
    return texts.map((text) => outcome.get(text) ?? FAILURE_PLACEHOLDER);
  };

  const redactText = async (text: string, options?: RedactTextOptions): Promise<string> => {
    if (options !== undefined) {
      if (options === null || typeof options !== 'object' || Array.isArray(options)) return FAILURE_PLACEHOLDER;
      if (options.layers !== undefined) {
        try {
          validateLayers(options.layers);
        } catch (error) {
          if (error instanceof TypeError && (error.message === "PII layer 'ner' is not available in Alpha 1" || error.message === "PII layer 'model' is not available in Alpha 1")) throw error;
          throw new TypeError('PII layer configuration is invalid');
        }
      }
    }
    if (typeof text !== 'string') return FAILURE_PLACEHOLDER;
    return (await redactMany([text]))[0] ?? FAILURE_PLACEHOLDER;
  };

  let warmupPromise: Promise<void> | undefined;
  const warmup = (): Promise<void> => (warmupPromise ??= analyzer.warmup?.() ?? Promise.resolve());

  const processInput = (args: ProcessInputArgs): Promise<ProcessInputResult> => failClosed(async () => {
    if (!args || typeof args !== 'object') throw new Error('invalid processor input');
    return {
      messages: await redactMessages(args.messages, redactMany),
      systemMessages: await redactCoreMessages(args.systemMessages, redactMany),
    };
  }, () => ({ messages: [failedMastraMessage()], systemMessages: [failedCoreMessage()] }));

  const processLLMRequest = (args: ProcessLLMRequestArgs): Promise<ProcessLLMRequestResult> => failClosed(async () => {
    if (!args || typeof args !== 'object') throw new Error('invalid LLM request');
    return { prompt: await redactPrompt(args.prompt, redactMany) };
  }, () => ({ prompt: [failedPromptMessage()] }));

  const processOutputResult = (args: ProcessOutputResultArgs): ProcessorMessageResult => failClosed(async () => {
    if (!args || typeof args !== 'object') throw new Error('invalid processor output');
    return redactMessages(args.messages, redactMany);
  }, () => [failedMastraMessage()]);

  const processor: PiiProcessor = {
    id,
    name: 'Mastra PII redaction',
    description: 'Adapter-based PII redaction for the agent loop (Presidio remote or local deterministic)',
    processInput,
    processLLMRequest,
    processOutputResult,
  };

  return { id, warmup, redactText, processor };
}
