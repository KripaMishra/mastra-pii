/**
 * Analyzer layer: Presidio-style typed span detection with pluggable adapters.
 *
 * - RemotePresidioAdapter: talks to a deployed presidio-analyzer container
 *   (POST /analyze) with configurable Indian ad_hoc recognizers, a curated
 *   entity allowlist, client-side checksum/boundary post-filters and a
 *   type-aware span dedupe. Behavior validated on the v1/v3 corpora
 *   (docs/evaluation/benchmark-results.md § Presidio P0 spike).
 * - LocalFallbackAdapter: the in-house 17-recognizer regex engine (2 ms,
 *   zero deps) — the outage/offline mode and the default analyzer.
 */

export interface AnalyzerSpan {
  readonly type: string;
  readonly start: number;
  readonly end: number;
  readonly score: number;
}

export interface Analyzer {
  readonly id: string;
  analyze(text: string): Promise<AnalyzerSpan[]>;
  warmup?(): Promise<void>;
}

/** One Presidio ad_hoc PatternRecognizer (pure regex; checksums run client-side). */
export interface PresidioPatternRecognizer {
  readonly name: string;
  readonly supported_language: string;
  readonly supported_entity: string;
  readonly patterns: ReadonlyArray<{ readonly name: string; readonly regex: string; readonly score: number }>;
  readonly context?: readonly string[];
}

export interface PresidioAdapterConfig {
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly timeoutMs?: number; // default 3000
  readonly retries?: number; // default 1
  readonly recognizers?: readonly PresidioPatternRecognizer[]; // default INDIAN_DEFAULTS
  readonly scoreThreshold?: number; // default 0.35 (Presidio default)
  readonly validate?: { readonly verhoeff?: boolean; readonly luhn?: boolean }; // defaults: verhoeff true, luhn false
}

// ---------------------------------------------------------------------------
// checksums
// ---------------------------------------------------------------------------

const VERHOEFF_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VERHOEFF_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];

/** Verhoeff checksum — the correct `(i+1)%8` P-table variant (i%8 wrongly accepts 999999999999). */
function verhoeff(num: string): boolean {
  let c = 0;
  const digits = num.split('').reverse().map(Number);
  for (let i = 0; i < digits.length; i += 1) c = VERHOEFF_D[c]![VERHOEFF_P[(i + 1) % 8]![digits[i]!]!]!;
  return c === 0;
}

function luhn(num: string): boolean {
  const digits = num.replace(/\D/g, '').split('').reverse().map(Number);
  let sum = 0;
  for (let i = 0; i < digits.length; i += 1) {
    const d = digits[i]!;
    sum += i % 2 ? (d * 2 > 9 ? d * 2 - 9 : d * 2) : d;
  }
  return sum % 10 === 0;
}

// ---------------------------------------------------------------------------
// RECOGNIZERS — single source for both engines (benchmarked set, port of RECS)
//
// The presidio shape (INDIAN_DEFAULTS) needs JSON-serializable regex strings,
// scores and context; the local engine needs RegExp literals, priorities and
// optional checksums. Both derive from this one table — never duplicated.
// Case-sensitivity is preserved per engine (local adds /i for UPI/SECRET/
// EXPIRY/CVV); aligning the engines is tracked in the recognizer tickets.
// ---------------------------------------------------------------------------

type RecognizerSpec = {
  readonly type: string;
  readonly regex: string;
  readonly score: number;
  readonly priority: number;
  readonly caseInsensitive?: boolean;
  readonly context?: readonly string[];
  readonly validate?: (value: string) => boolean;
};

const RECOGNIZERS: readonly RecognizerSpec[] = [
  { type: 'IFSC', regex: '\\b[A-Z]{4}0[A-Z0-9]{6}\\b', score: 0.6, priority: 80, context: ['ifsc', 'bank', 'branch'] },
  { type: 'AADHAAR', regex: '\\b[1-9]\\d{3}[ ]?\\d{4}[ ]?\\d{4}\\b', score: 0.6, priority: 90, context: ['aadhaar', 'aadhar', 'uidai', 'adhaar'], validate: (v) => verhoeff(v.replace(/ /g, '')) },
  { type: 'PAN', regex: '\\b[A-Z]{5}\\d{4}[A-Z]\\b', score: 0.6, priority: 90, context: ['pan', 'permanent account number'] },
  { type: 'VOTER_ID', regex: '\\b[A-Z]{3,4}\\d{7}\\b', score: 0.55, priority: 80, context: ['voter', 'epic'] },
  { type: 'UPI', regex: '\\b[\\w.-]{2,}@(?:ok[a-z]+|ybl|paytm|apl|axl|ibl|upi|icici|sbi|hdfc|kotak|yesbank|federal|jio|payzapp|amazonpay|phonepe|cred|freecharge|mobikwik|yono)\\b', score: 0.6, priority: 80, caseInsensitive: true, context: ['upi', 'handle', 'pay'] },
  { type: 'CARD', regex: '\\b\\d{4}[ -]?\\d{4}[ -]?\\d{4}[ -]?\\d{4}\\b', score: 0.6, priority: 70, context: ['card', 'credit', 'debit'] },
  { type: 'PHONE', regex: '(?:\\+91[ -]?|0)?[6-9]\\d{4}[ -]\\d{5}\\b|(?:\\+91[ -]?|0)?[6-9]\\d{9}\\b', score: 0.6, priority: 70, context: ['phone', 'mobile', 'call', 'reach'] },
  { type: 'EMAIL', regex: '\\b[\\w.+-]+@[\\w-]+\\.[\\w.]+\\b', score: 0.6, priority: 70, context: ['email', 'mail'] },
  { type: 'IP', regex: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', score: 0.6, priority: 70, context: ['ip', 'address'] },
  { type: 'BANK_ACC', regex: '\\b\\d{9,18}\\b', score: 0.4, priority: 40, context: ['account', 'acc', 'bank'] },
  { type: 'DOB', regex: '\\b\\d{1,2}[/-]\\d{1,2}[/-]\\d{2,4}\\b', score: 0.4, priority: 40, context: ['dob', 'birth', 'born'] },
  { type: 'VEHICLE', regex: '\\b[A-Z]{2}[ ]?\\d{1,2}[ ]?[A-Z]{1,2}[ ]?\\d{4}\\b', score: 0.5, priority: 60, context: ['vehicle', 'registration', 'reg', 'car'] },
  { type: 'DL', regex: '\\b[A-Z]{2}[-/]?\\d{2}[-/]?\\d{4,11}\\b', score: 0.5, priority: 60, context: ['driving', 'license', 'dl'] },
  { type: 'PASSPORT', regex: '\\b[A-Z][1-9]\\d{6}\\b', score: 0.5, priority: 60, context: ['passport'] },
  { type: 'EXPIRY', regex: '(?:exp|expiry|valid (?:thru|through))[^\\d]{0,8}(\\d{2}/\\d{2})', score: 0.5, priority: 60, caseInsensitive: true, context: ['expiry', 'exp', 'valid'] },
  { type: 'CVV', regex: '(?:cvv|security code)[^\\d]{0,8}(\\d{3})', score: 0.5, priority: 60, caseInsensitive: true, context: ['cvv', 'security code'] },
  { type: 'SECRET', regex: '(?:password|secret|pin)[^\\w]{0,6}([\\w!@#$%^&*]{4,})|\\bsk-[A-Za-z0-9_-]{20,}\\b', score: 0.55, priority: 60, caseInsensitive: true, context: ['password', 'secret', 'pin'] },
];

/** Presidio ad_hoc shape: JSON-serializable strings for the container. */
export const INDIAN_DEFAULTS: readonly PresidioPatternRecognizer[] = RECOGNIZERS.map((recognizer) => ({
  name: recognizer.type,
  supported_language: 'en',
  supported_entity: recognizer.type,
  patterns: [{ name: recognizer.type.toLowerCase(), regex: recognizer.regex, score: recognizer.score }],
  ...(recognizer.context === undefined ? {} : { context: recognizer.context }),
}));

/** Curated entity allowlist: spaCy NER types we trust + Indian ad_hoc types. */
const ENTITY_ALLOWLIST = [
  'PERSON', 'PHONE_NUMBER', 'EMAIL_ADDRESS', 'DATE_TIME', 'CREDIT_CARD', 'IP_ADDRESS',
  'IFSC', 'AADHAAR', 'PAN', 'VOTER_ID', 'UPI', 'CARD', 'PHONE', 'EMAIL', 'IP',
  'BANK_ACC', 'DOB', 'VEHICLE', 'DL', 'PASSPORT', 'EXPIRY', 'CVV', 'SECRET',
];

/**
 * Type-aware span dedupe: structurally-strong Indian IDs beat generic defaults
 * on overlap (UPI must not lose to PHONE_NUMBER on score alone; the BANK_ACC
 * \d{9,18} firehose must NOT outrank phones). Within a tier, higher score wins.
 */
const SPECIFIC_TYPES = new Set(['IFSC', 'AADHAAR', 'PAN', 'VOTER_ID', 'UPI', 'DL', 'PASSPORT', 'EXPIRY', 'CVV', 'SECRET']);

function dedupe(spans: readonly AnalyzerSpan[]): AnalyzerSpan[] {
  const out: AnalyzerSpan[] = [];
  const ranked = [...spans].sort((a, b) =>
    (Number(SPECIFIC_TYPES.has(b.type)) - Number(SPECIFIC_TYPES.has(a.type))) || (b.score - a.score));
  for (const span of ranked) {
    if (!out.some((o) => o.start < span.end && span.start < o.end)) out.push(span);
  }
  return out.sort((a, b) => a.start - b.start);
}

/**
 * Client-side post-filters (adapter-level, language invariants — validated on
 * the corpora, not corpus tuning):
 * - AADHAAR: Verhoeff checksum + alnum boundary guard (v3 trap SN-482910485920-ACER)
 * - CARD: Luhn lenient by default (AI-generated test cards fail real checksums)
 * - PERSON: spaCy scores everything 0.85 on Hinglish chat (names AND "bhai");
 *   no threshold separates them — shape filter: capital-initial multi-token names
 * - LOCATION: dropped (0 true hits on the corpus; hallucinates the literal word "IFSC")
 * - DATE_TIME: date-shaped only (kills spaCy tagging "42", "122001" as dates)
 * - PHONE_NUMBER: score >= 0.75 (kills the US recognizer's 0.40 base-score noise)
 */
function postFilter(spans: readonly AnalyzerSpan[], text: string, validate: { verhoeff: boolean; luhn: boolean }): AnalyzerSpan[] {
  return spans.filter((s) => {
    if (s.type === 'AADHAAR') {
      if (validate.verhoeff) {
        const v = text.slice(s.start, s.end).replace(/\s/g, '');
        if (!verhoeff(v)) return false;
      }
      const before = text[s.start - 1];
      const after = text[s.end];
      if (before && /[A-Za-z0-9_.\-/]/.test(before)) return false;
      if (after && /[A-Za-z0-9_.\-/]/.test(after)) return false;
    }
    if ((s.type === 'CARD' || s.type === 'CREDIT_CARD') && validate.luhn) {
      if (text.slice(s.start, s.end).length < 16 || !luhn(text.slice(s.start, s.end))) return false;
    }
    if (s.type === 'PERSON') {
      if (!/^[A-Z][A-Za-z]+( [A-Z][A-Za-z]+)+$/.test(text.slice(s.start, s.end))) return false;
    }
    if (s.type === 'LOCATION') return false;
    if (s.type === 'DATE_TIME') {
      if (!/^\d{1,2}[/-]\d{1,2}[/-]\d{2,4}$/.test(text.slice(s.start, s.end))) return false;
    }
    if (s.type === 'PHONE_NUMBER' && s.score < 0.75) return false;
    return true;
  });
}

// ---------------------------------------------------------------------------
// RemotePresidioAdapter
// ---------------------------------------------------------------------------

export function createPresidioAdapter(config: PresidioAdapterConfig): Analyzer {
  if (config === null || typeof config !== 'object') throw new TypeError('Presidio adapter configuration must be an object');
  if (typeof config.url !== 'string' || config.url.trim() === '') throw new TypeError('Presidio adapter url must be a non-empty string');
  const url = config.url.replace(/\/+$/, '');
  const timeoutMs = config.timeoutMs ?? 3000;
  const retries = config.retries ?? 1;
  const scoreThreshold = config.scoreThreshold ?? 0.35;
  const recognizers = config.recognizers ?? INDIAN_DEFAULTS;
  const validate = { verhoeff: config.validate?.verhoeff ?? true, luhn: config.validate?.luhn ?? false };

  let warmupDone = false;
  return {
    id: 'presidio-remote',
    async warmup(): Promise<void> {
      if (warmupDone) return;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(`${url}/health`, { ...(config.headers ? { headers: config.headers } : {}), signal: controller.signal });
        if (!response.ok) throw new Error(`presidio health ${response.status}`);
      } finally {
        clearTimeout(timer);
      }
      warmupDone = true;
    },
    async analyze(text: string): Promise<AnalyzerSpan[]> {
      const body = { text, language: 'en', score_threshold: scoreThreshold, entities: ENTITY_ALLOWLIST, ad_hoc_recognizers: recognizers };
      let lastError: unknown;
      for (let attempt = 0; attempt <= retries; attempt += 1) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
          const response = await fetch(`${url}/analyze`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...config.headers },
            body: JSON.stringify(body),
            signal: controller.signal,
          });
          if (!response.ok) throw new Error(`presidio analyze ${response.status}`);
          const payload = (await response.json()) as ReadonlyArray<{ entity_type?: unknown; start?: unknown; end?: unknown; score?: unknown }>;
          const spans: AnalyzerSpan[] = [];
          for (const item of payload) {
            const start = item.start;
            const end = item.end;
            if (typeof item.entity_type !== 'string' || typeof start !== 'number' || typeof end !== 'number') continue;
            if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start || end > text.length) continue;
            spans.push({ type: item.entity_type, start, end, score: typeof item.score === 'number' ? item.score : 0 });
          }
          return dedupe(postFilter(spans, text, validate));
        } catch (error) {
          lastError = error;
          if (attempt < retries) continue;
        } finally {
          clearTimeout(timer);
        }
      }
      throw lastError instanceof Error ? lastError : new Error('presidio analyze failed');
    },
  };
}

// ---------------------------------------------------------------------------
// LocalFallbackAdapter — the in-house deterministic engine (benchmarked 69.2% v1)
// ---------------------------------------------------------------------------

type LocalRecognizer = { readonly type: string; readonly priority: number; readonly re: RegExp; readonly validate?: (value: string) => boolean };

/** Local engine shape derived from the same RECOGNIZERS table. */
const LOCAL_RECS: readonly LocalRecognizer[] = RECOGNIZERS.map((recognizer) => ({
  type: recognizer.type,
  priority: recognizer.priority,
  re: new RegExp(recognizer.regex, recognizer.caseInsensitive ? 'gi' : 'g'),
  ...(recognizer.validate === undefined ? {} : { validate: recognizer.validate }),
}));

export function createLocalAdapter(): Analyzer {
  return {
    id: 'local-deterministic',
    async analyze(text: string): Promise<AnalyzerSpan[]> {
      const spans: AnalyzerSpan[] = [];
      for (const rec of LOCAL_RECS) {
        rec.re.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = rec.re.exec(text)) !== null) {
          const value = match[1] ?? match[0];
          if (rec.validate && !rec.validate(value)) continue;
          const start = match[1] ? match.index + match[0].indexOf(match[1]) : match.index;
          spans.push({ type: rec.type, start, end: start + value.length, score: rec.priority / 100 });
        }
      }
      spans.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
      const merged: AnalyzerSpan[] = [];
      for (const span of spans) {
        const previous = merged[merged.length - 1];
        if (previous && span.start < previous.end) {
          if (span.end > previous.end) merged.push(span);
          continue;
        }
        merged.push(span);
      }
      return merged;
    },
  };
}

// ---------------------------------------------------------------------------
// minimal LRU cache (text-hash keyed; agent loops re-send the same texts)
// ---------------------------------------------------------------------------

export class LruCache<K, V> {
  readonly #limit: number;
  readonly #map = new Map<K, V>();

  constructor(limit: number) {
    this.#limit = limit;
  }

  get(key: K): V | undefined {
    const value = this.#map.get(key);
    if (value === undefined) return undefined;
    this.#map.delete(key);
    this.#map.set(key, value);
    return value;
  }

  set(key: K, value: V): void {
    this.#map.delete(key);
    this.#map.set(key, value);
    if (this.#map.size > this.#limit) {
      const oldest = this.#map.keys().next().value;
      if (oldest !== undefined) this.#map.delete(oldest);
    }
  }

  get size(): number {
    return this.#map.size;
  }
}
