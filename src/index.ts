import { LiteOpenRedaction } from '@openredaction/core/lite';
import type { PIIPattern, PIIDetection } from '@openredaction/core/lite';
import type {
  CoreMessageV4,
  MastraDBMessage,
  MastraMessagePart,
} from '@mastra/core/agent/message-list';
import type {
  ProcessInputArgs,
  Processor,
  ProcessInputResult,
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

export interface LayeredPii {
  readonly id: string;
  readonly warmup: () => Promise<void>;
  readonly redactText: (text: string, options?: RedactTextOptions) => Promise<string>;
  readonly processor: Processor<string>;
}

const FAILURE_PLACEHOLDER = '[REDACTION_FAILED]';
const DEFAULT_ID = 'mastra-pii';
const SUPPORTED_LAYERS = new Set<PiiLayer>(['deterministic']);
const ENTITY_NAMES = new Set<PiiEntity>([
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

function fail(message: string): never {
  // Deliberately never include caller configuration or text in a public error.
  throw new TypeError(message);
}

function validateLayers(layers: unknown): void {
  if (!Array.isArray(layers) || layers.length === 0) fail('PII layers must be a non-empty array');
  for (const layer of layers) {
    if (layer === 'ner' || layer === 'model') fail(`PII layer '${layer}' is not available in Alpha 1`);
    if (typeof layer !== 'string' || !SUPPORTED_LAYERS.has(layer as PiiLayer)) {
      fail('PII layers contain an unsupported layer');
    }
  }
}

function validateConfig(config: LayeredPiiConfig): void {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    fail('PII configuration must be an object');
  }
  if (config.id !== undefined && (typeof config.id !== 'string' || config.id.trim() === '')) {
    fail('PII configuration id must be a non-empty string');
  }
  const untypedConfig = config as Record<string, unknown>;
  if (untypedConfig.ner !== undefined || untypedConfig.model !== undefined) {
    fail('PII NER and model layers are not available in Alpha 1');
  }
  if (config.layers !== undefined) validateLayers(config.layers);
  if (config.entities !== undefined) {
    if (!Array.isArray(config.entities)) fail('PII entities must be an array');
    for (const entity of config.entities) {
      if (!ENTITY_NAMES.has(entity)) fail('PII entities contain an unsupported entity');
    }
  }
  validatePatterns(config.patterns);
  validatePatterns(config.customPatterns);
}

function validatePatterns(patterns: readonly PiiPattern[] | undefined): void {
  if (patterns === undefined) return;
  if (!Array.isArray(patterns)) fail('PII patterns must be an array');
  for (const pattern of patterns) {
    if (pattern === null || typeof pattern !== 'object' || Array.isArray(pattern)) fail('PII pattern must be an object');
    const patternName = 'name' in pattern ? pattern.name : 'type' in pattern ? pattern.type : undefined;
    if (typeof patternName !== 'string' || patternName.trim() === '') fail('PII pattern name must be non-empty');
    if (!(pattern.regex instanceof RegExp)) fail('PII pattern regex must be a RegExp');
    const probe = new RegExp(pattern.regex.source, pattern.regex.flags.replace('g', '').replace('y', ''));
    if (probe.test('')) fail('PII pattern regex must match a non-empty value');
    if (pattern.entity !== undefined && !ENTITY_NAMES.has(pattern.entity)) fail('PII pattern entity is unsupported');
    if (pattern.priority !== undefined && (!Number.isFinite(pattern.priority) || pattern.priority < 0)) {
      fail('PII pattern priority must be a non-negative finite number');
    }
  }
}

function cloneRegex(regex: RegExp): RegExp {
  const flags = regex.flags.replace('y', '').includes('g') ? regex.flags.replace('y', '') : `${regex.flags.replace('y', '')}g`;
  return new RegExp(regex.source, flags);
}

function normalizedEntity(type: string, configured?: PiiEntity): PiiEntity {
  if (configured) return configured;
  const value = type.toLowerCase().replace(/[_\s]+/g, '-');
  const tokens = new Set(value.split('-').filter(Boolean));
  const has = (...terms: string[]): boolean => terms.some((term) => tokens.has(term));
  // Credential names can also contain "account" (for example service account).
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

type SafeSpan = {
  readonly start: number;
  readonly end: number;
  readonly entity: PiiEntity;
  readonly order: number;
};

function safeSpans(textLength: number, detections: readonly PIIDetection[], customEntities: ReadonlyMap<string, PiiEntity>, entities?: readonly PiiEntity[]): SafeSpan[] {
  const allowed = entities ? new Set(entities) : undefined;
  const candidates: SafeSpan[] = [];
  for (const [order, detection] of detections.entries()) {
    const start = detection.position[0];
    const end = detection.position[1];
    const entity = normalizedEntity(detection.type, customEntities.get(detection.type));
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start || end > textLength) {
      throw new Error('invalid detector span');
    }
    if (allowed && !allowed.has(entity)) continue;
    candidates.push({ start, end, entity, order });
  }

  candidates.sort((a, b) => a.start - b.start || a.end - b.end || a.order - b.order || a.entity.localeCompare(b.entity));
  const selected: SafeSpan[] = [];
  for (let index = 0; index < candidates.length;) {
    const first = candidates[index];
    if (!first) break;
    const group: SafeSpan[] = [first];
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

function applyPlaceholders(text: string, spans: readonly SafeSpan[]): string {
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
    if (!span || !placeholder) continue;
    output = `${output.slice(0, span.start)}${placeholder}${output.slice(span.end)}`;
  }
  return output;
}

function failedMastraMessage(): MastraDBMessage {
  return {
    id: 'redacted-message',
    role: 'user',
    createdAt: new Date(0),
    content: { format: 2, parts: [{ type: 'text', text: FAILURE_PLACEHOLDER } as MastraMessagePart], content: FAILURE_PLACEHOLDER },
  };
}

function failedCoreMessage(): CoreMessageV4 {
  return { role: 'system', content: FAILURE_PLACEHOLDER };
}

async function clonePart(part: MastraMessagePart, redact: (text: string) => Promise<string>): Promise<MastraMessagePart> {
  if (!part || typeof part !== 'object' || Array.isArray(part) || typeof part.type !== 'string') throw new Error('invalid message part');
  if (part.type === 'text') {
    if (typeof part.text !== 'string') throw new Error('invalid text part');
    return { ...part, text: await redact(part.text) } as MastraMessagePart;
  }
  if (part.type === 'reasoning') {
    const reasoningPart = part as MastraMessagePart & { reasoning?: unknown; details?: unknown };
    if (typeof reasoningPart.reasoning !== 'string' || !Array.isArray(reasoningPart.details)) throw new Error('invalid reasoning part');
    const details = await Promise.all(reasoningPart.details.map(async (detail) => {
      if (!detail || typeof detail !== 'object' || Array.isArray(detail) || typeof detail.type !== 'string') {
        throw new Error('invalid reasoning detail');
      }
      if (detail.type === 'text') {
        if (typeof detail.text !== 'string') throw new Error('invalid reasoning detail text');
        return { ...detail, text: await redact(detail.text) };
      }
      if (detail.type === 'redacted' && typeof detail.data === 'string') return { ...detail };
      throw new Error('invalid reasoning detail');
    }));
    return { ...part, reasoning: await redact(reasoningPart.reasoning), details } as MastraMessagePart;
  }
  return { ...part } as MastraMessagePart;
}

async function redactMastraMessage(message: MastraDBMessage, redact: (text: string) => Promise<string>): Promise<MastraDBMessage> {
  if (!message || typeof message !== 'object' || Array.isArray(message) || !message.content || typeof message.content !== 'object' || Array.isArray(message.content)) {
    return failedMastraMessage();
  }
  const content = message.content;
  if (!Array.isArray(content.parts)) return failedMastraMessage();
  if (content.content !== undefined && typeof content.content !== 'string') return failedMastraMessage();
  if (content.reasoning !== undefined && typeof content.reasoning !== 'string') return failedMastraMessage();
  return {
    ...message,
    content: {
      ...content,
      parts: await Promise.all(content.parts.map((part) => clonePart(part, redact))),
      ...(content.content === undefined ? {} : { content: await redact(content.content) }),
      ...(content.reasoning === undefined ? {} : { reasoning: await redact(content.reasoning) }),
    },
  };
}

async function redactMessages(messages: unknown, redact: (text: string) => Promise<string>): Promise<MastraDBMessage[]> {
  if (!Array.isArray(messages)) return [failedMastraMessage()];
  return Promise.all(messages.map(async (message) => {
    try {
      return await redactMastraMessage(message as MastraDBMessage, redact);
    } catch {
      return failedMastraMessage();
    }
  }));
}

async function redactCoreMessage(message: CoreMessageV4, redact: (text: string) => Promise<string>): Promise<CoreMessageV4> {
  if (!message || typeof message !== 'object' || Array.isArray(message) || typeof message.role !== 'string') return failedCoreMessage();
  if (typeof message.content === 'string') return { ...message, content: await redact(message.content) } as CoreMessageV4;
  if (!Array.isArray(message.content)) return failedCoreMessage();
  const content = await Promise.all(message.content.map(async (part) => {
    if (typeof part === 'string') return redact(part);
    if (!part || typeof part !== 'object' || Array.isArray(part) || typeof part.type !== 'string') throw new Error('invalid core message part');
    if (part.type === 'text' && 'text' in part) {
      if (typeof part.text !== 'string') throw new Error('invalid core text part');
      return { ...part, text: await redact(part.text) };
    }
    if (part.type === 'reasoning' && 'text' in part) {
      if (typeof part.text !== 'string') throw new Error('invalid core reasoning part');
      return { ...part, text: await redact(part.text) };
    }
    return { ...part };
  }));
  return { ...message, content } as CoreMessageV4;
}

async function redactCoreMessages(messages: unknown, redact: (text: string) => Promise<string>): Promise<CoreMessageV4[]> {
  if (!Array.isArray(messages)) return [failedCoreMessage()];
  return Promise.all(messages.map(async (message) => {
    try {
      return await redactCoreMessage(message as CoreMessageV4, redact);
    } catch {
      return failedCoreMessage();
    }
  }));
}

export function createLayeredPii(config: LayeredPiiConfig = {}): LayeredPii {
  validateConfig(config);
  const id = config.id?.trim() || DEFAULT_ID;
  const patterns = [...(config.patterns ?? []), ...(config.customPatterns ?? [])];
  const customEntities = new Map<string, PiiEntity>();
  const customPatterns: PIIPattern[] = patterns.map((pattern, index) => {
    const patternName = 'name' in pattern ? pattern.name : pattern.type;
    const type = `CUSTOM_${index}_${patternName.trim().toUpperCase().replace(/[^A-Z0-9]+/g, '_')}`;
    customEntities.set(type, pattern.entity ?? 'custom');
    return {
      type,
      regex: cloneRegex(pattern.regex),
      priority: pattern.priority ?? pattern.regex.source.length + 1000,
      placeholder: '[REDACTED]',
      severity: 'high',
    };
  });

  let detector: LiteOpenRedaction;
  let customDetectors: LiteOpenRedaction[];
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
  try {
    detector = new LiteOpenRedaction(detectorOptions);
    // The dependency pre-merges overlapping patterns. Run each caller pattern
    // separately so safeSpans can perform the final transitive union.
    const uuidDetector = new LiteOpenRedaction({ ...detectorOptions, patterns: ['DEVICE_UUID'] });
    customDetectors = [uuidDetector, ...customPatterns.map((pattern) => new LiteOpenRedaction({
      ...detectorOptions,
      patterns: ['__mastra_custom_only__'],
      customPatterns: [pattern],
    }))];
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
          if (error instanceof TypeError && (error.message === "PII layer 'ner' is not available in Alpha 1" || error.message === "PII layer 'model' is not available in Alpha 1")) {
            throw error;
          }
          throw new TypeError('PII layer configuration is invalid');
        }
      }
    }
    if (typeof text !== 'string') return FAILURE_PLACEHOLDER;
    try {
      const results = await Promise.all([
        detector.detect(text),
        ...customDetectors.map((customDetector) => customDetector.detect(text)),
      ]);
      const spans = safeSpans(
        text.length,
        results.flatMap((result) => result.detections),
        customEntities,
        config.entities,
      );
      return applyPlaceholders(text, spans);
    } catch {
      return FAILURE_PLACEHOLDER;
    }
  };

  let warmupPromise: Promise<void> | undefined;
  const warmup = (): Promise<void> => {
    warmupPromise ??= Promise.resolve();
    return warmupPromise;
  };

  const processor: Processor<string> = {
    id,
    name: 'Mastra PII redaction',
    description: 'Local deterministic Alpha 1 PII redaction',
    async processInput(args: ProcessInputArgs): Promise<ProcessInputResult> {
      try {
        if (!args || typeof args !== 'object') return { messages: [failedMastraMessage()], systemMessages: [failedCoreMessage()] };
        const messages = await redactMessages(args.messages, redactText);
        const systemMessages = await redactCoreMessages(args.systemMessages, redactText);
        return { messages, systemMessages };
      } catch {
        return { messages: [failedMastraMessage()], systemMessages: [failedCoreMessage()] };
      }
    },
  };

  return { id, warmup, redactText, processor };
}
