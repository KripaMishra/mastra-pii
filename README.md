# @kripamishra/mastra-pii

Deterministic, local PII redaction for Mastra. Alpha 1 is a foundation release
for Node `>=22.13.0` and Mastra `>=1.57.0 <2`.

## Alpha 1

```sh
npm install @kripamishra/mastra-pii @mastra/core
```

```ts
import { Agent } from '@mastra/core/agent';
import { createLayeredPii } from '@kripamishra/mastra-pii';

const pii = createLayeredPii({
  layers: ['deterministic'],
  patterns: [
    { name: 'account-code', regex: /ACCT-[0-9]{6}/g, entity: 'bank-account' },
  ],
});

await pii.warmup(); // idempotent; currently a no-op
const safe = await pii.redactText('Email alpha@example.test', {
  layers: ['deterministic'],
});
// "Email [EMAIL_1]"

const agent = new Agent({ inputProcessors: [pii.processor] });
```

`redactText()` is asynchronous because the detector API is asynchronous. It
performs no network or model calls. The returned processor sanitizes both the
initial Mastra input and the final model prompt before every LLM call, including
tool continuations. It copies caller-owned values, redacts known tool
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

### Entities

Structured detections are normalized to stable placeholders for `email`,
`phone`, `ssn`, `credit-card`, `bank-account`, `ip-address`, `passport`,
`address`, `name`, `date-of-birth`, `token`, `uuid`, and `medical-id`. Unknown custom
patterns use `custom`. `entities` can restrict the emitted entity set. Alpha 1
keeps free-form name and address heuristics disabled by default; configure a
pattern when those fields must be covered.

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

- Alpha 1 uses `@openredaction/core/lite` only, with cache, debug, audit,
  metrics, context, multipass, and NER disabled/avoided.
- Detector values, maps, raw matches, and dependency result objects are kept
  private. Public output contains only redacted text or a generic
  `[REDACTION_FAILED]` fail-closed marker.
- Invalid input and detector failures fail closed locally; this is not a claim
  of perfect PII recall.
- Alpha 1 does not inspect media contents. It preserves only cloned
  `Uint8Array`/`ArrayBuffer` payloads; string/base64, URL/data-URL, and textual
  tool-result media are replaced by a `[REDACTION_FAILED]` marker at part
  granularity, and the rest of the containing message survives.
- Alpha 1 does not implement Transformers.js NER, a Mastra `PIIDetector` model
  layer, reversible restoration, audit logs, telemetry, or structured document
  redaction. `ner` and `model` layers are rejected explicitly.
- Custom-regex execution is time-bounded with worker termination: 250 ms base
  plus 1 ms per KB of batched input. Regexes should still be reviewed by
  callers; no detector can guarantee detection of every arbitrary identifier
  or name.

## Test UI

The Vercel-ready test console lives in `test-ui/`. It calls the Node function at
`/api/redact`, which builds the package and exposes `id`, `layers`, `entities`,
and bounded custom regex patterns as tunable controls.

```sh
npx vercel dev
```

Deploy the repository root to Vercel. `vercel.json` runs `npm run build`, serves
`test-ui/`, and keeps the package worker available to the Node 22 function.

## Development

```sh
npm run check
npm run verify:package
npm audit --omit=dev
```

The package is MIT licensed. Alpha 1 is prepared for version `0.1.0-alpha.1`
only; it is not published by this repository change.
