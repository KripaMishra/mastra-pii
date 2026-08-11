# @kripamishra/mastra-pii

Adapter-based PII redaction for Mastra agent loops. Ships two analyzers behind
one interface: a **remote Presidio adapter** (deployed container, spaCy NER +
configurable Indian ad_hoc recognizers) and a **local deterministic adapter**
(zero-dependency regex/checksum engine) that doubles as the outage fallback.
Node `>=22.13.0`, Mastra `>=1.57.0 <2`.

## Setup

```sh
npm install @kripamishra/mastra-pii @mastra/core
# optional: deploy the Presidio analyzer (see deploy/README.md)
docker compose -f deploy/docker-compose.yml up -d
```

## Usage

```ts
import { Agent } from '@mastra/core/agent';
import { createLayeredPii } from '@kripamishra/mastra-pii';

// Local deterministic engine (default — no network, ~2 ms)
const pii = createLayeredPii({
  patterns: [
    { name: 'account-code', regex: /ACCT-[0-9]{6}/g, entity: 'bank-account' },
  ],
});

// Or: remote Presidio container (spaCy NER + Indian recognizers).
// The URL is an explicit config value — read it from your own env wiring:
const pii = createLayeredPii({
  presidio: {
    url: process.env.PRESIDIO_URL ?? 'http://localhost:3000',
    headers: { authorization: 'Bearer …' },
  },
  fallback: 'local',          // default: degrade to the deterministic engine on outage
  // fallback: 'strict',      // fail closed with [REDACTION_FAILED] instead
  cacheSize: 256,             // per-text LRU; 0 disables
  anonymize: { format: 'type' }, // 'type' → [PAN_1], 'uniform' → [REDACTED]
});

await pii.warmup(); // health-checks the remote service (no-op for local)
const safe = await pii.redactText('Aadhaar 7316 7253 5875, PAN ABCDE1234F');
// "Aadhaar [AADHAAR_1], PAN [PAN_1]"

const agent = new Agent({ inputProcessors: [pii.processor] });
```

The processor sanitizes the initial Mastra input (`processInput`), the final
model prompt before every LLM call including tool continuations
(`processLLMRequest`), and the assistant output message (`processOutputResult`).
It copies caller-owned values, redacts known tool
arguments/results/errors/raw input/approval/title fields recursively, and fails
the containing message closed for malformed or unsupported structured data.
Provider-generated structural identifiers (tool call ids, tool names, approval
ids) are copied verbatim — they are not user content, and detecting PII in them
would redact provider UUIDs and break every Gemini/Vertex tool call. Provider
options are recursively sanitized as bounded JSON; object keys are preserved
verbatim so fixed-schema tool payloads are never renamed. Only in-memory
`Uint8Array` and `ArrayBuffer` media is copied as opaque binary data; string,
base64, URL/data-URL, and textual tool-output media replace that part with the
fail-closed marker while the rest of the message survives. UI attachment URLs
and names are redacted as text.

## Entities

Structured detections normalize to stable placeholders for `email`, `phone`,
`credit-card`, `bank-account`, `ip-address`, `passport`, `address`, `name`,
`date-of-birth`, `token`, `uuid`, `medical-id`, plus Indian identifiers
`aadhaar`, `pan`, `upi`, `ifsc`, `voter-id`, `driving-license`, `vehicle`
(expiry/CVV collapse into `credit-card`; secrets into `token`). Unknown custom
patterns use `custom`. `entities` can restrict the emitted entity set.

**Indian recognizers** ship as `INDIAN_DEFAULTS` (Aadhaar+Verhoeff, PAN, UPI,
IFSC, voter ID, card, phone, email, IP, bank account, DOB, vehicle, DL,
passport, expiry, CVV, secrets). The Presidio adapter sends them as
`ad_hoc_recognizers` with each `/analyze` call and applies client-side
post-filters: Verhoeff checksum + boundary guards on Aadhaar, a
capital-initial multi-token shape filter on spaCy `PERSON` (Hinglish chat
hallucinations score identically to real names — no threshold separates them),
date-shape filtering on `DATE_TIME`, and score flooring on `PHONE_NUMBER`.
Pass a custom `recognizers` array in the Presidio config to swap the set for
another project's domain (EU/US/corporate).

Custom patterns have a `name` (or dependency-compatible `type`), `RegExp`,
optional `entity`, and optional non-negative `priority`. They are part of the
`deterministic` layer. Strings are deduplicated per payload and custom patterns
run against them in terminable local workers (one worker per batch of up to 256
strings, serialized); timeout or worker failure returns `[REDACTION_FAILED]`.
Custom patterns default to a priority above every built-in detection
(`regex.source.length + 1000`), so a built-in detection needs an explicitly
lower-priority pattern to win an overlap; among ties the longer match and
declaration order decide, while the full transitive overlap union is redacted.
`layers` accepts `deterministic`; requesting `ner` or `model` is rejected. The
same layer option is accepted by `redactText(text, options?)`.

## Guarantees and limitations

- The local adapter is a pure regex/checksum engine (~2 ms, no network).
  Benchmark: 69.2% typed recall / 2 FP on the Indian chat corpus v1.
- The Presidio adapter adds spaCy NER (6/6 names on the corpus). Benchmark:
  84.6% typed recall / 2 FP / p95 16 ms on v1. Obfuscated formats (leet speak,
  spaced PANs, `[at]` emails) defeat every engine — a canonicalization pass is
  planned work.
- Fail-closed by default: analyzer outage degrades to the local engine, or to
  `[REDACTION_FAILED]` under `fallback: 'strict'`. Public output contains only
  redacted text or the generic marker; detector values and raw matches stay
  private. This is not a claim of perfect PII recall.
- Media contents are not inspected. Only cloned `Uint8Array`/`ArrayBuffer`
  payloads are preserved; string/base64, URL/data-URL, and textual tool-result
  media are replaced by `[REDACTION_FAILED]` at part granularity, and the rest
  of the containing message survives.
- No Transformers.js NER, Mastra `PIIDetector` model layer, reversible
  restoration, audit logs, telemetry, or structured document redaction.
  `ner` and `model` layers are rejected explicitly.
- Custom-regex execution is time-bounded with worker termination: 250 ms base
  plus 1 ms per KB of batched input. Regexes should still be reviewed by
  callers; no detector can guarantee detection of every arbitrary identifier
  or name.

## Test UI

The Vercel-ready test console lives in `test-ui/`. It calls the Node function at
`/api/redact`, which builds the package and exposes `id`, `layers`, `entities`,
and bounded custom regex patterns as tunable controls. The API function uses
the **`PRESIDIO_URL` environment variable** to enable the remote engine: when
set, every request runs through the Presidio container (with the local engine
as the outage fallback) and the UI shows `presidio (remote)` in the ENGINE
summary; when unset, it runs the local deterministic engine. Set it in your
deployment environment (Vercel dashboard → project → Environment Variables, or
your container runtime); client-supplied `presidio` config in the request body
is rejected.

```sh
npx vercel dev
```

Deploy the repository root to Vercel. `vercel.json` runs `npm run build`, serves
`test-ui/`, and keeps the package worker available to the Node 22 function.

## Query samples

With the test console running (`npx vercel dev`), the API is
`POST /api/redact` with `{ text, config? }`. Try these:

```sh
# 1. Baseline: Indian identifiers redacted by the local engine
curl -s -X POST http://localhost:3001/api/redact \
  -H 'content-type: application/json' \
  -d '{"text":"Aadhaar 7316 7253 5875, PAN ABCDE1234F, UPI 9999999999@ybl, call 98765 43210"}'
# → {"output":"Aadhaar [AADHAAR_1], PAN [PAN_1], UPI [UPI_1], call [PHONE_1]", ...}

# 2. Hinglish chat line (spaCy name detection when PRESIDIO_URL is set)
curl -s -X POST http://localhost:3001/api/redact \
  -H 'content-type: application/json' \
  -d '{"text":"bhai new joiner ka Aadhar verify kar lo -> 4829 1048 5920. Name is Kripa Shankar Mishra"}'
# → local:    no redaction (4829 1048 5920 fails Verhoeff; no name detection without NER)
# → presidio: "bhai new joiner ka Aadhar verify kar lo -> 4829 1048 5920. Name is Kripa [NAME_1]"
#   (spaCy tags "Shankar Mishra"; the shape filter keeps "bhai" unredacted)

# 3. Entity filtering: only tokens are replaced
curl -s -X POST http://localhost:3001/api/redact \
  -H 'content-type: application/json' \
  -d '{"text":"sk-51H8abc12345678901234567890 and phone 98765 43210","config":{"entities":["token"]}}'
# → "sk-51H8abc12345678901234567890 and phone 98765 43210" is redacted to [TOKEN_1]; the phone stays

# 4. Custom patterns
curl -s -X POST http://localhost:3001/api/redact \
  -H 'content-type: application/json' \
  -d '{"text":"ACCT-123456 is mine","config":{"patterns":[{"name":"account-code","regex":"ACCT-[0-9]{6}","entity":"bank-account"}]}}'
# → "[BANK-ACCOUNT_1] is mine"

# 5. Fail-closed behavior: catastrophic regex on triggering input is rejected with 400
curl -s -X POST http://localhost:3001/api/redact \
  -H 'content-type: application/json' \
  -d '{"text":"aaaaab","config":{"patterns":[{"name":"bad","regex":"(a+)+$"}]}}'
# → 400 (custom pattern validation timeout)

# 6. Engine check: the response config reports which engine ran
curl -s -X POST http://localhost:3001/api/redact \
  -H 'content-type: application/json' \
  -d '{"text":"PAN ABCDE1234F"}'
# → "config":{"engine":"local"}   (or "presidio" when PRESIDIO_URL is set)
```

The full corpus benchmark messages live in `docs/evaluation/indian_pii_testsuite.json`
(v1) and `test_2.json` (v3) — feed any of those inputs to sample 1 for a spot
check against the published numbers.

## Development

```sh
npm run check
npm run verify:package
npm audit --omit=dev
```

The package is MIT licensed. Version `0.2.0-alpha.2`. Research, benchmark
harnesses, corpora, and the adapter plan live in `docs/`; the deployment recipe
is in `deploy/`.
