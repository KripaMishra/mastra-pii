import { Worker } from 'node:worker_threads';
import { LiteOpenRedaction } from '@openredaction/core/lite';
import type { PIIDetection } from '@openredaction/core/lite';
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
  Processor,
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
  | 'medical-id';

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
}

export type PiiProcessor = Processor<string> & Required<Pick<Processor<string>, 'processInput' | 'processLLMRequest'>>;

export interface LayeredPii {
  readonly id: string;
  readonly warmup: () => Promise<void>;
  readonly redactText: (text: string, options?: RedactTextOptions) => Promise<string>;
  readonly processor: PiiProcessor;
}

const FAILURE_PLACEHOLDER = '[REDACTION_FAILED]';
const DEFAULT_ID = 'mastra-pii';
const CUSTOM_PATTERN_TIMEOUT_MS = 250;
const MAX_JSON_DEPTH = 32;
const MAX_JSON_NODES = 10_000;
const SUPPORTED_LAYERS = new Set<PiiLayer>(['deterministic']);
const ENTITY_NAMES = new Set<PiiEntity>([
  'address', 'bank-account', 'credit-card', 'custom', 'date-of-birth', 'email',
  'ip-address', 'name', 'passport', 'phone', 'ssn', 'token', 'uuid', 'medical-id',
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
}

function globalFlags(regex: RegExp): string {
  const flags = regex.flags.replaceAll('y', '');
  return flags.includes('g') ? flags : `${flags}g`;
}

function normalizedEntity(type: string, configured?: PiiEntity): PiiEntity {
  if (configured) return configured;
  const value = type.toLowerCase().replace(/[_\s]+/g, '-');
  const tokens = new Set(value.split('-').filter(Boolean));
  const has = (...terms: string[]): boolean => terms.some((term) => tokens.has(term));
  if ((tokens.has('api') && tokens.has('key')) || (tokens.has('access') && tokens.has('key')) || (tokens.has('service') && tokens.has('account')) || has('password', 'secret', 'token')) return 'token';
  if (value === 'email' || has('email')) return 'email';
  if (has('phone', 'mobile')) return 'phone';
  if (has('credit', 'card')) return 'credit-card';
  if (value === 'ssn' || has('ssn', 'social-security')) return 'ssn';
  if (value === 'ip' || value === 'ipv4' || value === 'ipv6' || value === 'ip-address') return 'ip-address';
  if (has('address')) return 'address';
  if (has('passport')) return 'passport';
  if (has('name')) return 'name';
  if (has('birth', 'dob')) return 'date-of-birth';
  if (has('uuid')) return 'uuid';
  if (has('iban', 'bank', 'account')) return 'bank-account';
  if (has('medical', 'health', 'nhs')) return 'medical-id';
  return 'custom';
}

function builtInSpans(detections: readonly PIIDetection[]): SpanCandidate[] {
  return detections.map((detection, order) => ({
    start: detection.position[0],
    end: detection.position[1],
    entity: normalizedEntity(detection.type),
    priority: 0,
    order,
  }));
}

async function customPatternSpans(text: string, patterns: readonly RuntimePattern[]): Promise<SpanCandidate[]> {
  if (patterns.length === 0) return [];
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./custom-pattern-worker.js', import.meta.url));
    let settled = false;
    let timer: NodeJS.Timeout;
    const finish = (error?: Error, value?: SpanCandidate[]): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.removeAllListeners();
      void worker.terminate().then(
        () => error ? reject(error) : resolve(value ?? []),
        () => reject(error ?? new Error('custom pattern worker failed')),
      );
    };
    timer = setTimeout(() => finish(new Error('custom pattern timeout')), CUSTOM_PATTERN_TIMEOUT_MS);
    worker.once('error', () => finish(new Error('custom pattern worker failed')));
    worker.once('exit', () => finish(new Error('custom pattern worker failed')));
    worker.once('online', () => {
      try {
        worker.postMessage({ text, patterns: patterns.map(({ source, flags }) => ({ source, flags })) });
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
        const spans = response.spans.map((raw): SpanCandidate => {
          if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('invalid worker span');
          const span = raw as { patternIndex?: unknown; start?: unknown; end?: unknown };
          if (!Number.isInteger(span.patternIndex) || !Number.isInteger(span.start) || !Number.isInteger(span.end)) throw new Error('invalid worker span');
          const pattern = patterns[span.patternIndex as number];
          if (!pattern) throw new Error('invalid worker span');
          return {
            start: span.start as number,
            end: span.end as number,
            entity: pattern.entity,
            priority: pattern.priority,
            order: pattern.order,
          };
        });
        finish(undefined, spans);
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

function applyPlaceholders(text: string, spans: readonly SpanCandidate[]): string {
  const counts = new Map<PiiEntity, number>();
  const placeholders = spans.map((span) => {
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

async function redactJson(value: unknown, redact: (text: string) => Promise<string>, state: JsonCloneState, depth = 0): Promise<unknown> {
  if (depth > MAX_JSON_DEPTH || ++state.nodes > MAX_JSON_NODES) throw new Error('payload limit exceeded');
  if (typeof value === 'string') return redact(value);
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
        clone.push(await redactJson(value[index], redact, state, depth + 1));
      }
      return clone;
    }
    if (!plainRecord(value) || Object.getOwnPropertySymbols(value).length !== 0) throw new Error('unsupported payload');
    const clone = Object.create(Object.getPrototypeOf(value)) as Record<string, unknown>;
    const clonedKeys = new Set<string>();
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) throw new Error('unsupported payload');
      const clonedKey = await redact(key);
      if (clonedKeys.has(clonedKey)) throw new Error('payload key collision');
      clonedKeys.add(clonedKey);
      Object.defineProperty(clone, clonedKey, {
        ...descriptor,
        value: await redactJson(descriptor.value, redact, state, depth + 1),
      });
    }
    return clone;
  } finally {
    state.active.delete(value);
  }
}

function redactPayload(value: unknown, redact: (text: string) => Promise<string>): Promise<unknown> {
  return redactJson(value, redact, { active: new WeakSet(), nodes: 0 });
}

async function cloneJsonFields(
  source: Record<string, unknown>,
  clone: Record<string, unknown>,
  fields: readonly string[],
  redact: (text: string) => Promise<string>,
): Promise<Record<string, unknown>> {
  for (const field of fields) {
    if (source[field] !== undefined) clone[field] = await redactPayload(source[field], redact);
  }
  return clone;
}

function cloneProviderOptions(
  source: Record<string, unknown>,
  clone: Record<string, unknown>,
  redact: (text: string) => Promise<string>,
): Promise<Record<string, unknown>> {
  return cloneJsonFields(source, clone, ['providerOptions', 'providerMetadata', 'experimental_providerMetadata'], redact);
}

function cloneMedia(value: unknown): Uint8Array | ArrayBuffer {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (value instanceof ArrayBuffer) return value.slice(0);
  throw new Error('unsupported media');
}

async function validateStructuralIdentifier(value: unknown, redact: (text: string) => Promise<string>): Promise<void> {
  if (typeof value !== 'string') throw new Error('invalid structural identifier');
  const redacted = await redact(value);
  if (redacted === FAILURE_PLACEHOLDER || redacted !== value) throw new Error('unsafe structural identifier');
}

async function validateToolIdentifiers(value: Record<string, unknown>, redact: (text: string) => Promise<string>): Promise<void> {
  await validateStructuralIdentifier(value.toolCallId, redact);
  await validateStructuralIdentifier(value.toolName, redact);
}

async function cloneApproval(value: unknown, redact: (text: string) => Promise<string>): Promise<unknown> {
  if (!plainRecord(value)) throw new Error('invalid approval');
  await validateStructuralIdentifier(value.id, redact);
  if (value.reason !== undefined && typeof value.reason !== 'string') throw new Error('invalid approval reason');
  return { ...value, ...(value.reason === undefined ? {} : { reason: await redact(value.reason) }) };
}

async function cloneToolFields(part: Record<string, unknown>, redact: (text: string) => Promise<string>): Promise<Record<string, unknown>> {
  const clone = { ...part };
  for (const field of ['args', 'input', 'result', 'output', 'rawInput'] as const) {
    if (part[field] !== undefined) clone[field] = await redactPayload(part[field], redact);
  }
  for (const field of ['errorText', 'title'] as const) {
    if (part[field] !== undefined) {
      if (typeof part[field] !== 'string') throw new Error('invalid tool text');
      clone[field] = await redact(part[field]);
    }
  }
  if (part.approval !== undefined) clone.approval = await cloneApproval(part.approval, redact);
  return cloneProviderOptions(part, clone, redact);
}

async function cloneToolInvocation(value: unknown, redact: (text: string) => Promise<string>): Promise<unknown> {
  if (!plainRecord(value)) throw new Error('invalid tool invocation');
  await validateToolIdentifiers(value, redact);
  return cloneToolFields(value, redact);
}

async function clonePart(part: MastraMessagePart, redact: (text: string) => Promise<string>): Promise<MastraMessagePart> {
  if (!plainRecord(part) || typeof part.type !== 'string') throw new Error('invalid message part');
  if (part.type === 'text') {
    if (typeof part.text !== 'string') throw new Error('invalid text part');
    return await cloneProviderOptions(part, { ...part, text: await redact(part.text) }, redact) as MastraMessagePart;
  }
  if (part.type === 'reasoning') {
    if (typeof part.reasoning !== 'string' || !Array.isArray(part.details)) throw new Error('invalid reasoning part');
    const details = await Promise.all(part.details.map(async (detail) => {
      if (!plainRecord(detail) || typeof detail.type !== 'string') throw new Error('invalid reasoning detail');
      if (detail.type === 'text') {
        if (typeof detail.text !== 'string') throw new Error('invalid reasoning detail text');
        return { ...detail, text: await redact(detail.text) };
      }
      if (detail.type === 'redacted' && typeof detail.data === 'string') return { ...detail };
      throw new Error('invalid reasoning detail');
    }));
    return await cloneProviderOptions(part, { ...part, reasoning: await redact(part.reasoning), details }, redact) as MastraMessagePart;
  }
  if (part.type === 'tool-invocation') {
    const clone = await cloneToolFields(part, redact);
    clone.toolInvocation = await cloneToolInvocation(part.toolInvocation, redact);
    return clone as MastraMessagePart;
  }
  const mediaPart = part as Record<string, unknown>;
  if (mediaPart.type === 'file' || mediaPart.type === 'image') {
    const field = mediaPart.type === 'file' ? 'data' : 'image';
    if (!(field in mediaPart)) throw new Error('invalid media part');
    return await cloneProviderOptions(mediaPart, {
      ...mediaPart,
      [field]: cloneMedia(mediaPart[field]),
      ...(typeof mediaPart.filename === 'string' ? { filename: await redact(mediaPart.filename) } : {}),
    }, redact) as MastraMessagePart;
  }
  if (part.type === 'source-document') {
    if (typeof part.sourceId !== 'string' || typeof part.mediaType !== 'string' || typeof part.title !== 'string') throw new Error('invalid source document');
    if (part.filename !== undefined && typeof part.filename !== 'string') throw new Error('invalid source filename');
    return await cloneProviderOptions(part, {
      ...part,
      sourceId: await redact(part.sourceId),
      title: await redact(part.title),
      ...(part.filename === undefined ? {} : { filename: await redact(part.filename) }),
    }, redact) as MastraMessagePart;
  }
  if (part.type === 'source') {
    if (!plainRecord(part.source) || part.source.sourceType !== 'url' || typeof part.source.id !== 'string' || typeof part.source.url !== 'string') {
      throw new Error('invalid source');
    }
    if (part.source.title !== undefined && typeof part.source.title !== 'string') throw new Error('invalid source title');
    const source = await cloneProviderOptions(part.source, {
      ...part.source,
      id: await redact(part.source.id),
      url: await redact(part.source.url),
      ...(part.source.title === undefined ? {} : { title: await redact(part.source.title) }),
    }, redact);
    return await cloneProviderOptions(part, { ...part, source }, redact) as MastraMessagePart;
  }
  if (part.type.startsWith('data-')) {
    if (!('data' in part)) throw new Error('invalid data part');
    return await cloneProviderOptions(part, { ...part, data: await redactPayload(part.data, redact) }, redact) as MastraMessagePart;
  }
  return await cloneToolFields(part, redact) as MastraMessagePart;
}

async function redactMastraMessage(message: MastraDBMessage, redact: (text: string) => Promise<string>): Promise<MastraDBMessage> {
  if (!plainRecord(message) || !plainRecord(message.content) || !Array.isArray(message.content.parts)) throw new Error('invalid message');
  const content = message.content;
  if (content.content !== undefined && typeof content.content !== 'string') throw new Error('invalid message content');
  if (content.reasoning !== undefined && typeof content.reasoning !== 'string') throw new Error('invalid message reasoning');
  if (content.toolInvocations !== undefined && !Array.isArray(content.toolInvocations)) throw new Error('invalid tool invocations');
  if (content.experimental_attachments !== undefined) {
    if (!Array.isArray(content.experimental_attachments) || content.experimental_attachments.length !== 0) throw new Error('unsupported media');
  }
  const clonedContent = await cloneJsonFields(content, {
    ...content,
    parts: await Promise.all(content.parts.map((part) => clonePart(part, redact))),
    ...(content.content === undefined ? {} : { content: await redact(content.content) }),
    ...(content.reasoning === undefined ? {} : { reasoning: await redact(content.reasoning) }),
    ...(content.toolInvocations === undefined ? {} : { toolInvocations: await Promise.all(content.toolInvocations.map((item) => cloneToolInvocation(item, redact))) }),
  }, ['metadata', 'annotations'], redact);
  await cloneProviderOptions(content, clonedContent, redact);
  return await cloneProviderOptions(message, { ...message, content: clonedContent }, redact) as MastraDBMessage;
}

async function redactMessages(messages: unknown, redact: (text: string) => Promise<string>): Promise<MastraDBMessage[]> {
  if (!Array.isArray(messages)) return [failedMastraMessage()];
  return Promise.all(messages.map((message) => failClosed(() => redactMastraMessage(message as MastraDBMessage, redact), failedMastraMessage)));
}

async function cloneCorePart(part: unknown, redact: (text: string) => Promise<string>): Promise<unknown> {
  if (!plainRecord(part) || typeof part.type !== 'string') throw new Error('invalid core message part');
  if (part.type === 'text' || part.type === 'reasoning') {
    if (typeof part.text !== 'string') throw new Error('invalid core text part');
    return cloneProviderOptions(part, { ...part, text: await redact(part.text) }, redact);
  }
  if (part.type === 'tool-call') {
    if (!('args' in part)) throw new Error('invalid core tool call');
    await validateToolIdentifiers(part, redact);
    return cloneProviderOptions(part, { ...part, args: await redactPayload(part.args, redact) }, redact);
  }
  if (part.type === 'tool-result') {
    if (!('result' in part)) throw new Error('invalid core tool result');
    await validateToolIdentifiers(part, redact);
    const clone: Record<string, unknown> = { ...part, result: await redactPayload(part.result, redact) };
    if (part.experimental_content !== undefined) {
      if (!Array.isArray(part.experimental_content)) throw new Error('invalid core tool content');
      clone.experimental_content = await Promise.all(part.experimental_content.map(async (item) => {
        if (!plainRecord(item) || typeof item.type !== 'string') throw new Error('invalid core tool content');
        if (item.type === 'text' && typeof item.text === 'string') {
          return cloneProviderOptions(item, { ...item, text: await redact(item.text) }, redact);
        }
        if (item.type === 'image' && 'data' in item) {
          return cloneProviderOptions(item, { ...item, data: cloneMedia(item.data) }, redact);
        }
        throw new Error('invalid core tool content');
      }));
    }
    return cloneProviderOptions(part, clone, redact);
  }
  if (part.type === 'image' || part.type === 'file') {
    const field = part.type === 'image' ? 'image' : 'data';
    if (!(field in part)) throw new Error('invalid core media');
    return cloneProviderOptions(part, {
      ...part,
      [field]: cloneMedia(part[field]),
      ...(typeof part.filename === 'string' ? { filename: await redact(part.filename) } : {}),
    }, redact);
  }
  if (part.type === 'redacted-reasoning' && typeof part.data === 'string') {
    return cloneProviderOptions(part, { ...part }, redact);
  }
  throw new Error('unsupported core message part');
}

async function redactCoreMessage(message: CoreMessageV4, redact: (text: string) => Promise<string>): Promise<CoreMessageV4> {
  if (!plainRecord(message) || typeof message.role !== 'string') throw new Error('invalid core message');
  if (typeof message.content === 'string') {
    return await cloneProviderOptions(message, { ...message, content: await redact(message.content) }, redact) as CoreMessageV4;
  }
  if (!Array.isArray(message.content)) throw new Error('invalid core message content');
  return await cloneProviderOptions(message, {
    ...message,
    content: await Promise.all(message.content.map((part) => cloneCorePart(part, redact))),
  }, redact) as CoreMessageV4;
}

async function redactCoreMessages(messages: unknown, redact: (text: string) => Promise<string>): Promise<CoreMessageV4[]> {
  if (!Array.isArray(messages)) return [failedCoreMessage()];
  return Promise.all(messages.map((message) => failClosed(() => redactCoreMessage(message as CoreMessageV4, redact), failedCoreMessage)));
}

async function clonePromptOutput(output: unknown, redact: (text: string) => Promise<string>): Promise<unknown> {
  if (!plainRecord(output) || typeof output.type !== 'string') throw new Error('invalid tool output');
  if ((output.type === 'text' || output.type === 'error-text') && typeof output.value === 'string') return { ...output, value: await redact(output.value) };
  if (output.type === 'json' || output.type === 'error-json') return { ...output, value: await redactPayload(output.value, redact) };
  if (output.type === 'content' && Array.isArray(output.value)) {
    return {
      ...output,
      value: await Promise.all(output.value.map(async (item) => {
        if (!plainRecord(item) || typeof item.type !== 'string') throw new Error('invalid tool output content');
        if (item.type === 'text' && typeof item.text === 'string') {
          return cloneProviderOptions(item, { ...item, text: await redact(item.text) }, redact);
        }
        if (item.type === 'media' && 'data' in item && typeof item.mediaType === 'string') {
          return cloneProviderOptions(item, { ...item, data: cloneMedia(item.data) }, redact);
        }
        throw new Error('invalid tool output content');
      })),
    };
  }
  throw new Error('invalid tool output');
}

async function clonePromptPart(part: unknown, redact: (text: string) => Promise<string>): Promise<unknown> {
  if (!plainRecord(part) || typeof part.type !== 'string') throw new Error('invalid prompt part');
  if (part.type === 'text' || part.type === 'reasoning') {
    if (typeof part.text !== 'string') throw new Error('invalid prompt text');
    return cloneProviderOptions(part, { ...part, text: await redact(part.text) }, redact);
  }
  if (part.type === 'tool-call') {
    if (!('input' in part)) throw new Error('invalid prompt tool call');
    await validateToolIdentifiers(part, redact);
    return cloneProviderOptions(part, { ...part, input: await redactPayload(part.input, redact) }, redact);
  }
  if (part.type === 'tool-result') {
    await validateToolIdentifiers(part, redact);
    return cloneProviderOptions(part, { ...part, output: await clonePromptOutput(part.output, redact) }, redact);
  }
  if (part.type === 'file') {
    if (!('data' in part) || typeof part.mediaType !== 'string') throw new Error('invalid prompt file');
    if (part.filename !== undefined && typeof part.filename !== 'string') throw new Error('invalid prompt filename');
    return cloneProviderOptions(part, {
      ...part,
      data: cloneMedia(part.data),
      ...(part.filename === undefined ? {} : { filename: await redact(part.filename) }),
    }, redact);
  }
  throw new Error('unsupported prompt part');
}

async function redactPromptMessage(message: ProcessLLMRequestArgs['prompt'][number], redact: (text: string) => Promise<string>): Promise<ProcessLLMRequestArgs['prompt'][number]> {
  if (!plainRecord(message) || typeof message.role !== 'string') throw new Error('invalid prompt message');
  if (message.role === 'system') {
    if (typeof message.content !== 'string') throw new Error('invalid prompt system message');
    return await cloneProviderOptions(message, { ...message, content: await redact(message.content) }, redact) as ProcessLLMRequestArgs['prompt'][number];
  }
  if (!Array.isArray(message.content)) throw new Error('invalid prompt content');
  return await cloneProviderOptions(message, {
    ...message,
    content: await Promise.all(message.content.map((part) => clonePromptPart(part, redact))),
  }, redact) as ProcessLLMRequestArgs['prompt'][number];
}

async function redactPrompt(prompt: unknown, redact: (text: string) => Promise<string>): Promise<ProcessLLMRequestArgs['prompt']> {
  if (!Array.isArray(prompt)) return [failedPromptMessage()];
  return Promise.all(prompt.map((message) => failClosed(() => redactPromptMessage(message as ProcessLLMRequestArgs['prompt'][number], redact), failedPromptMessage)));
}

export function createLayeredPii(config: LayeredPiiConfig = {}): LayeredPii {
  validateConfig(config);
  const id = config.id?.trim() || DEFAULT_ID;
  const patterns = [...(config.patterns ?? []), ...(config.customPatterns ?? [])];
  const runtimePatterns: RuntimePattern[] = patterns.map((pattern, order) => ({
    source: pattern.regex.source,
    flags: globalFlags(pattern.regex),
    entity: pattern.entity ?? 'custom',
    priority: pattern.priority ?? 0,
    order,
  }));
  let customPatternQueue: Promise<void> = Promise.resolve();
  const queuedCustomPatternSpans = (text: string): Promise<SpanCandidate[]> => {
    const job = customPatternQueue.then(() => customPatternSpans(text, runtimePatterns));
    customPatternQueue = job.then(() => undefined, () => undefined);
    return job;
  };

  const detectorOptions = {
    includeNames: false,
    includeAddresses: false,
    includePhones: true,
    includeEmails: true,
    deterministic: true,
    redactionMode: 'placeholder' as const,
    enableContextAnalysis: false,
    enableFalsePositiveFilter: false,
    enableMultiPass: false,
    enableCache: false,
    debug: false,
    enableAuditLog: false,
    enableMetrics: false,
    maxInputSize: 1_000_000,
    regexTimeout: 100,
  };
  let detector: LiteOpenRedaction;
  let uuidDetector: LiteOpenRedaction;
  try {
    detector = new LiteOpenRedaction(detectorOptions);
    uuidDetector = new LiteOpenRedaction({ ...detectorOptions, patterns: ['DEVICE_UUID'] });
  } catch {
    fail('PII detector initialization failed');
  }

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
    try {
      const [builtIn, uuid, custom] = await Promise.all([
        detector.detect(text),
        uuidDetector.detect(text),
        queuedCustomPatternSpans(text),
      ]);
      const builtIns = builtInSpans([...builtIn.detections, ...uuid.detections]);
      return applyPlaceholders(text, safeSpans(text.length, [...builtIns, ...custom], config.entities));
    } catch {
      return FAILURE_PLACEHOLDER;
    }
  };

  let warmupPromise: Promise<void> | undefined;
  const warmup = (): Promise<void> => (warmupPromise ??= Promise.resolve());

  const processInput = (args: ProcessInputArgs): Promise<ProcessInputResult> => failClosed(async () => {
    if (!args || typeof args !== 'object') throw new Error('invalid processor input');
    return {
      messages: await redactMessages(args.messages, redactText),
      systemMessages: await redactCoreMessages(args.systemMessages, redactText),
    };
  }, () => ({ messages: [failedMastraMessage()], systemMessages: [failedCoreMessage()] }));

  const processLLMRequest = (args: ProcessLLMRequestArgs): Promise<ProcessLLMRequestResult> => failClosed(async () => {
    if (!args || typeof args !== 'object') throw new Error('invalid LLM request');
    return { prompt: await redactPrompt(args.prompt, redactText) };
  }, () => ({ prompt: [failedPromptMessage()] }));

  const processor: PiiProcessor = {
    id,
    name: 'Mastra PII redaction',
    description: 'Local deterministic Alpha 1 PII redaction',
    processInput,
    processLLMRequest,
  };

  return { id, warmup, redactText, processor };
}
