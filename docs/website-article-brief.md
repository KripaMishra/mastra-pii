# Website Article Brief — mastra-pii

Audience: developers who use Mastra (or TypeScript agent frameworks) and handle
Indian PII. Written for an agent that will draft the article from this brief.

---

## Core positioning (the message to land)

**mastra-pii is an adapter, not a detector.** It owns the interface; the
deployment owns the intelligence. The adapter's KPI is **compatibility + ease
of use**. Accuracy is a property of the deployed analyzer — not part of this
package's story and not covered by the article.

Value props, in priority order:

1. **Compatibility** — drop-in Mastra processors (input + LLM-request + output
   hooks) plus a standalone `redactText()`; zero integration code.
2. **Flexibility** — one interface over whatever Presidio deployment you run:
   spaCy by default; model layer and custom recognizers are deployment-side
   options. Swap deployments without changing app code.
3. **Deterministic layer included** — Indian regex recognizers + checksums ship
   with the package, sent per request, and runnable standalone with no
   deployment at all.
4. **Fail-closed by default** — outages degrade safely; raw PII never leaks.

## What NOT to headline

- **The fallback mechanism.** Internal resilience detail. One line in the
  guarantees section. Do not lead with it, do not diagram it as a feature.
- **Transformers / Piiranha / standalone model benchmarking.** Not part of this
  setup. The NER model layer needs dedicated resources and belongs to a future
  project that actually uses it — that project will carry its own benchmarks.
  Do not mention model benchmarking in the article.
- **Accuracy numbers as the adapter's selling point.** Drop altogether. No
  per-engine recall/FP/latency tables in the article.
- **Layer configuration.** The article must NOT claim the adapter configures
  layers. It does not. The deployment does.

## The deployment model (the layer story)

- The Presidio deployment runs **spaCy by default** (`en_core_web_lg`). Adding
  a model layer or custom recognizers is a **deployment-side** decision.
- The package does not gate or configure those layers. It talks to whatever
  the deployment provides.
- What the package itself ships is the **deterministic layer**: Indian regex
  recognizers (`INDIAN_DEFAULTS`), client-side checksums (Verhoeff for Aadhaar,
  Luhn for cards), a curated entity allowlist, and shape post-filters — sent as
  per-request `ad_hoc_recognizers`, and also runnable standalone with zero
  deployment.

Article language: *"deployment-configured intelligence, package-owned
integration."*

## Adapter KPIs (the only table the article evaluates)

| KPI | Definition |
|---|---|
| Config surface | entities, custom patterns, anonymize format, recognizer set — switchable per call, no code changes |
| Compatibility | drop-in Mastra processor (3 hooks), `redactText` contract, Node ≥22, Mastra ≥1.57 |
| Behavioral guarantees | fail-closed contract, time-boxed custom regex workers (250 ms + 1 ms/KB), LRU cache, structured-message walk (tool calls, media, approvals) |
| Overhead | adapter latency excluding analyzer round-trip; cache hit rate on agent-loop repeats |

## Benchmarking

- The article presents **no accuracy tables**. Accuracy is the deployed
  analyzer's concern; model-layer benchmarks belong to the project that runs
  the model.
- The repo keeps comparison harnesses in `docs/evaluation/` for internal use.
  If referenced at all: one line — "comparison harnesses live in the repo."
  Do not import their numbers into the article narrative.
- Retired (2026-08-14): the planned split of the repo's benchmark corpora into
  document categories (~20 samples each) is dropped. Accuracy is out of scope
  for this story; the harnesses stay as-is for internal use.

## Suggested article structure

1. Hook: the problem is *integration*, not detection.
2. The adapter idea: one interface, deployment-configured intelligence
   (spaCy by default; model/custom recognizers optional on the deployment
   side).
3. Drop-in Mastra usage (the ~10-line example from `README.md`).
4. Deterministic layer walkthrough: Indian recognizers, Verhoeff validation,
   entity allowlist, custom patterns, anonymize formats, entity filtering.
5. Guarantees (fail-closed, worker timeouts, cache) — one paragraph, not a
   section.
6. Roadmap: obfuscation canonicalization, international recognizers. Model
   layer explicitly **out of scope** — deployment-side, future project.

## Writing rules

- No accuracy claims, no benchmark tables, no transformers discussion.
- Adapter = integration + config surface; deployment = intelligence.
- Plain language, concrete examples (the `curl` samples from `README.md`).
- Tone: engineering notes, not marketing copy.

## Repo evidence map (for the writing agent)

Pointers to facts the article can lean on, verified against the repo on
2026-08-14. Source examples and claims only from here.

- **Drop-in Mastra example**: `README.md` "Usage" (~10 lines: custom patterns,
  presidio config, fallback, cacheSize, anonymize, warmup, processor wiring).
- **curl samples**: `README.md` "Query samples" (Hinglish chat + spaCy name
  detection, entity filtering, custom patterns, fail-closed 400, engine
  report).
- **Deployment**: `deploy/docker-compose.yml` runs the stock
  `ghcr.io/data-privacy-stack/presidio-analyzer:2.2.362`; spaCy
  (`en_core_web_lg`) confirmed loaded at boot (`deploy/README.md`).
- **Deterministic layer internals**: `src/analyzer.ts` (`INDIAN_DEFAULTS`,
  Verhoeff/Luhn post-filters, PERSON shape filter, allowlist) and
  `src/index.ts` (processor hooks, worker timeout 250 ms + 1 ms/KB, LRU
  cache, fail-closed paths).
- **Adapter KPI table sources**: config surface and behavioral guarantees are
  backed by `README.md` + `src/`; overhead means the adapter's own latency,
  never the analyzer round-trip.
- **Benchmark harnesses** (`docs/evaluation/`): internal only. The README no
  longer headlines engine accuracy numbers (aligned with this positioning on
  2026-08-14); do not quote numbers from `benchmark-results.md`.
- **Roadmap anchors**: obfuscation canonicalization (leet speak / spaced
  chars / `[at]` emails defeat every engine) and international recognizers
  (SSN/SIN/NI/TFN/NRIC/Steuer-ID missing) — both stated as limitations in
  `README.md` "Guarantees and limitations".

### Pre-flight checklist

1. Draft following "Suggested article structure"; take examples only from the
   pointers above.
2. Grep the draft for banned terms before finalizing:
   `recall|FP|false positive|accuracy|%|transformers|piiranha|model layer|ms|p95`
   — every hit needs removal or explicit justification.
3. Verify every config claim against `README.md` + `src/`.
4. Fallback mechanism: at most one line, inside the guarantees paragraph.
5. The only table allowed is the Adapter KPIs table above.
