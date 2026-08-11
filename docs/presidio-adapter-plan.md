# Presidio Adapter Architecture — Implementation Plan

Status: **P0 ✅ + P1 ✅** (2026-08-11). The adapter-based engine is shipped in the
package (`src/analyzer.ts` + `src/index.ts`, v0.2.0-alpha.2, `@openredaction/core` deleted).
P2 (canonicalization, GSTIN/VID/SWIFT recognizers, agent tool) remains open work.
P0 numbers: presidio_indian v1 = 84.6% typed recall / 2 FP / p95 16 ms (gate: ≥60% / ≤5 / <300 ms).
Full tables + adapter-design findings: `docs/evaluation/benchmark-results.md` (§ Presidio P0 spike).
Corpus context: v1 (`docs/evaluation/indian_pii_testsuite.json`, 39 spans) and v3
(`test_2.json`, 29 spans + 20 FP traps) — numbers referenced below from
`docs/evaluation/benchmark-results.md` and `bench-v3.mjs`.

## 0. Critical verdict (decides everything)

The architecture below is low-risk plumbing around **one unmeasured number**:
Presidio's typed recall on Indian/Hinglish chat. No packaged NER has proven
itself on this data (Piiranha: 1/10 names on v3; bert-base-NER: 0/6 on v1).
Therefore the plan is gated: **spike first (P0), build the package only if the
gate passes.** If Presidio loses to the in-house engine, it remains an optional
adapter and the local engine stays default — a config switch, not a rewrite.

Gate: typed recall ≥ 60% on v1, FP ≤ 5, p95 analyze latency < 300 ms.

## 1. Architecture

```
┌─ Mastra agent loop ─────────────────────────────────────────────┐
│  Processor (processInput → processLLMRequest → processLLMResponse) │
└───────────────┬─────────────────────────────────────────────────┘
                │  Span[] (typed, 0-indexed, [start,end))
┌───────────────▼─────────────────────────────────────────────────┐
│  Analyzer interface                     Anonymizer (TS-side)    │
│  ┌──────────────────────┐  fallback    · span → "[TYPE]"        │
│  │ RemotePresidioAdapter │◄────────────  · shared by both adapters│
│  │  POST /analyze        │  on error   └────────────────────────┘
│  │  + ad_hoc_recognizers │  (or strict)  · LRU cache (text-hash)
│  │  + client post-filter │              · Verhoeff/Luhn validation
│  └──────────────────────┘
│  ┌──────────────────────┐
│  │ LocalFallbackAdapter │  (in-house regex + Verhoeff, 2 ms, 0 deps)
│  └──────────────────────┘
└──────────────────────────────────────────────────────────────────┘
```

Decisions (grill-me rounds 1–2, user-confirmed):
- **Pivot**: package consumes a *deployed* Presidio container over HTTP; container
  deployment is part of the project ("deploy later"). Reverses the earlier
  no-Python-sidecar constraint; logged as a requirements evolution for the article.
- **Analyze-only**: one HTTP call per message; anonymization is TS-side.
- **Placeholders**: type-tagged `[PHONE]` (configurable; `[REDACTED]` option kept).
- **Outage**: default = LocalFallbackAdapter + logged metric; `strict: true` blocks.
- **Package**: evolve `@kripamishra/mastra-pii` → 0.2.0-alpha; delete `@openredaction/core`.
- **Recognizers**: configurable (project-portable), shipping Indian defaults.

## 2. API sketch (target)

```ts
export interface AnalyzerSpan { type: string; start: number; end: number; score: number; }

export interface Analyzer {
  readonly id: string;
  analyze(text: string): Promise<AnalyzerSpan[]>;
}

export interface PresidioAdapterConfig {
  url: string;                              // e.g. https://pii.example.com
  headers?: Record<string, string>;         // auth gateway tokens etc.
  timeoutMs?: number;                       // default 3000
  retries?: number;                         // default 1 (idempotent GET-like)
  recognizers?: PresidioPatternRecognizer[];// default = INDIAN_DEFAULTS
  scoreThreshold?: number;                  // default 0.35 (Presidio default)
  validate?: { verhoeff?: boolean; luhn?: boolean };  // default both true
}

export interface MastraPiiOptions {
  analyzer: Analyzer;                       // RemotePresidioAdapter | LocalFallbackAdapter
  fallback?: 'local' | 'strict';            // default 'local'
  cacheSize?: number;                       // default 256 (0 = off)
  anonymize?: { format: 'type' | 'uniform'; uniformToken?: string };
}

export function createPiiProcessor(opts: MastraPiiOptions): LayeredPii; // existing API shape
export const INDIAN_DEFAULTS: PresidioPatternRecognizer[];             // port of RECS (17 recognizers)
export function createPresidioAdapter(cfg: PresidioAdapterConfig): RemotePresidioAdapter;
export function createLocalAdapter(): LocalFallbackAdapter;
```

`LayeredPii` contract preserved: `{ id, warmup, redactText, processor }`.
- `warmup()` = health-check `GET /` (or `/healthz`) for remote; no-op for local.
- `redactText()` = analyze → anonymize → replace; same fail-closed
  `[REDACTION_FAILED]` path as today.

### Presidio /analyze payload (adapter-generated)

```jsonc
POST {url}/analyze
{
  "text": "<message>",
  "language": "en",
  "score_threshold": 0.35,
  "ad_hoc_recognizers": [
    {
      "name": "AADHAAR",
      "supported_language": "en",
      "patterns": [{ "name": "aadhaar", "regex": "\\b[1-9]\\d{3}[ ]?\\d{4}[ ]?\\d{4}\\b", "score": 0.6 }],
      "context": ["aadhaar", "uidai", "aadhar"]
    }
    // ... port of RECS: PAN, VOTER_ID, IFSC, UPI, CARD, PHONE, EMAIL, IP,
    // BANK_ACC, DOB, VEHICLE, DL, PASSPORT, EXPIRY, CVV, SECRET, GSTIN, JWT
  ]
}
```

Response spans are post-filtered client-side:
- **Verhoeff**: drop AADHAAR spans whose 12-digit core fails the checksum
  (correct `(i+1)%8` P-table variant).
- **Luhn**: drop CREDIT_CARD spans failing Luhn (unless `validate.luhn: false`).
- **Boundary guard**: drop AADHAAR spans embedded in alnum runs
  (`SN-482910485920-ACER` v3 trap).

### Configurable recognizers (per your call)

`recognizers` replaces the default set entirely when provided (explicit opt-in,
no merge ambiguity). Ships with `INDIAN_DEFAULTS` so a bare URL works on Indian
data; other projects pass their own sets (EU/US/corporate). Validators
(Verhoeff/Luhn) are keyed to entity types and stay client-side regardless.

## 3. Phases

### P0 — Spike: Presidio on the corpora (gate) ✅ DONE
1. `deploy/` folder: docker-compose.yml (presidio-analyzer image, port 3000) + README.
   Notes: image moved to ghcr.io/data-privacy-stack (mcr path is gone); stock gunicorn
   entrypoint hung on this host (worker forked but never accepted connections) — compose
   bypasses with werkzeug for local benchmarking; health route is `/health` (not /healthz).
2. `docs/evaluation/bench-presidio.mjs`: reuse `bench.mjs` harness; engines =
   remote Presidio (default recognizers) + remote Presidio (INDIAN_DEFAULTS
   via ad_hoc) — the delta isolates NER contribution vs regex contribution.
3. Port RECS → `INDIAN_DEFAULTS` JSON; add client Verhoeff/Luhn/boundary filters.
4. Run v1 + v3; write tables to `benchmark-results.md`.
5. **Gate**: typed recall ≥ 60% v1, FP ≤ 5, p95 < 300 ms. Pass → P1.
   Fail → Presidio = optional adapter only; local engine remains default;
   document the number in the vault (still a valid article beat).

### P1 — Package build ✅ DONE
6. `src/analyzer.ts`: Analyzer interface, RemotePresidioAdapter (allowlist +
   ad_hoc recognizers + post-filters + type-aware dedupe + retries/timeout),
   LocalFallbackAdapter (RECS + Verhoeff), LruCache, INDIAN_DEFAULTS.
   `src/index.ts`: engine wiring, extended PiiEntity taxonomy (aadhaar/pan/upi/
   ifsc/voter-id/driving-license/vehicle), config surface (analyzer XOR
   presidio, fallback, cacheSize, anonymize format), 3 hooks (processInput /
   processLLMRequest / processOutputResult — processLLMResponse is a void
   side-effect hook in Mastra 1.57, so output redaction lives in
   processOutputResult). `@openredaction/core` deleted.
7. Tests: 64 passing (unit: anonymizer formats, Verhoeff/Luhn/boundary filters,
   type-aware dedupe, LRU; adapter: hand-rolled node:http mock server — success,
   shape filters, outage → fallback, strict → fail-closed, warmup health-check;
   existing fail-closed suite re-targeted from openredaction's US/EU taxonomy to
   the Indian domain and stays green).
8. README rewritten (usage, deployment, corpus numbers, limitations);
   `verify:package` allowlist extended for dist/analyzer.js; live smoke test
   against the running container passed (local + remote + uniform + strict).
9. Not published — publish step is separate (0.2.0-alpha.2 is the next version).

### P2 — Hardening (only if gate passed and time allows)
10. Retries with jitter, per-hook enable/disable, tool-result hook opt-in,
    `redactPII` Mastra tool (agent-callable), observability counters
    (analyze_ms p50/p95, fallback_count, cache_hit_rate).

## 4. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Presidio NER weak on Hinglish names | High | P0 gate; ad_hoc regexes cover IDs regardless; verdict may relegate Presidio to optional |
| Latency in agent loop (up to 3 hooks/turn) | Med | 1 call/message (analyze-only), LRU cache, timeout 3s, async where safe |
| ad_hoc recognizers are pure regex | Med | Client-side Verhoeff/Luhn post-filters |
| No auth on stock Presidio container | Med | `headers` config for gateway tokens; deployment README shows auth proxy |
| PII in logs/traces (correlation_id) | Low | Never log text payloads; redact spans only |
| Presidio API drift across image versions | Low | Pin image tag in deploy/; adapter tests pin against mocked contract |

## 5. Test matrix

| Area | Cases |
|---|---|
| Anonymizer | type-tagged, uniform, multi-span, overlap ordering, [REDACTION_FAILED] path |
| Filters | valid/invalid Verhoeff, valid/invalid Luhn, embedded-serial rejection |
| Adapter (mock HTTP) | 200 spans, 500, timeout, retry-then-fallback, strict-throw, auth header |
| Loop integration | processInput/LLMRequest/Response each redact; cache hit skips HTTP |
| Regression | v1 + v3 corpora via harness (numbers in benchmark-results.md) |

## 6. Success criteria

- P0 gate numbers published in `benchmark-results.md`.
- `npm run check` green; fail-closed suite unchanged-green.
- A live demo: Mastra agent with the processor configured against a deployed
  Presidio URL; corpus message in, no raw PII in LLM request or response.
