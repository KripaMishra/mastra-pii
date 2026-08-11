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
Provider options are recursively sanitized as bounded JSON. Only in-memory
`Uint8Array` and `ArrayBuffer` media is copied as opaque binary data; string,
base64, URL/data-URL, and textual tool-output media are rejected fail closed.

### Entities

Structured detections are normalized to stable placeholders for `email`,
`phone`, `ssn`, `credit-card`, `bank-account`, `ip-address`, `passport`,
`address`, `name`, `date-of-birth`, `token`, `uuid`, and `medical-id`. Unknown custom
patterns use `custom`. `entities` can restrict the emitted entity set. Alpha 1
keeps free-form name and address heuristics disabled by default; configure a
pattern when those fields must be covered.

Custom patterns have a `name` (or dependency-compatible `type`), `RegExp`,
optional `entity`, and optional non-negative `priority`. They are part of the
`deterministic` layer. Each pattern runs against the original text in a
terminable local worker; timeout or worker failure returns
`[REDACTION_FAILED]`. Higher priority wins an overlap, followed by match length
and declaration order, while the full transitive overlap union is redacted.
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
  `Uint8Array`/`ArrayBuffer` payloads and rejects string/base64, URL/data-URL,
  and textual tool-result media by failing the containing message closed.
- Alpha 1 does not implement Transformers.js NER, a Mastra `PIIDetector` model
  layer, reversible restoration, audit logs, telemetry, or structured document
  redaction. `ner` and `model` layers are rejected explicitly.
- Custom-regex execution is time-bounded with worker termination. Regexes
  should still be reviewed by callers; no detector can guarantee detection of
  every arbitrary identifier or name.

## Development

```sh
npm run check
npm run verify:package
npm audit --omit=dev
```

The package is MIT licensed. Alpha 1 is prepared for version `0.1.0-alpha.1`
only; it is not published by this repository change.
