# PII Redaction Backend — Research Report

**Date:** 2026-08-11 · **Project:** mastra-pii (`@kripamishra/mastra-pii`)

## 1. Problem

The current Alpha 1 backend wraps `@openredaction/core@1.1.5` (lite mode). It is not
working for the project's actual use case, and the requirement is a **TypeScript-native
engine** — a "Presidio in TS". A Python sidecar (spaCy/Presidio over HTTP) is explicitly
rejected. This report evaluates every credible option, verified empirically against the
project's test corpus (`tests.json`, extracted to `docs/evaluation/indian_pii_testsuite.json`).

### Why the current engine fails (measured, not anecdotal)

On the 20-case Indian-PII corpus (39 true PII spans):

| Metric | openredaction lite |
|---|---|
| Typed recall (correct entity type on correct span) | **30.8%** |
| Coverage (any detection overlapping a true span) | 66.7% |
| False-positive detections | **27** |
| Fully-correct messages | 2/20 |

Root causes observed:

- **No NER at all.** openredaction is purely regex (570+ patterns). `NAME` detection is a
  naive capitalized-phrase heuristic that mangles Hinglish:
  `"Aadhar verify kar lo"` and `"Name is Kriya Shankar"` are redacted as `NAME`, while the
  actual name `Kripa Shankar Mishra` is partially leaked ("Mishra" survives).
- **Wrong-type noise.** Emits `PHONE_UK` for `+91` numbers, `ZIP_CODE_US` for PIN codes,
  plus `TWITTER_USER_ID`, `INSTAGRAM_USERNAME`, `TURKMENISTAN_PASSPORT` etc. — 27 false
  positives across 20 short messages.
- **Zero Indian entity coverage** in typed terms: Aadhaar 0/3, PAN 0/3, Voter ID 0/1,
  UPI 0/1, IFSC 0/1, bank account 0/2.
- Previous profiling also found worker-thread spawn overhead (~75 ms/spawn, serialized per
  batch) on the custom-pattern path.

## 2. What "Presidio in TS" means

Presidio = **Analyzer** (recognizer registry: pattern recognizers + an ML NER model + score
fusion + validators) → **Anonymizer** (redact/replace/mask/hash operators). A faithful TS
equivalent must provide, in-process, in Node:

1. Pattern recognizers for structured PII (regex + checksum validators),
2. An optional NER model for contextual entities (names, addresses),
3. Span merging with priority/confidence,
4. Anonymizer operators (placeholder/mask/hash/replace),
5. Zero Python, no sidecar process, no mandatory network calls.

## 3. Candidate landscape (verified)

### 3.1 Packaged TS libraries

| Package | Type | Verified on corpus | Verdict |
|---|---|---|---|
| `@openredaction/core` 1.1.5 (current) | regex, 570+ patterns | 30.8% typed / 27 FP | Not fit; no NER, wrong-type noise |
| `@redactpii/node` 1.0.17 (fork of solvvy/redact-pii, 114k dl/mo) | regex, zero-dep | 30.8% typed, content-destroying (`ABCDE`, `SBIN`, `ASAP` stripped) | Deterministic-only, US-centric, 5 rule types; not a foundation |
| `@siddicky/anonymizerts` 1.0.3 (Presidio API clone, transformers.js) | regex + NER | 23.1% typed (patterns), NER adds 0 | Presidio-shaped API but 65 dl/mo, single maintainer, generic `bert-base-NER` fails Hinglish (`"bhai"` → PERSON), transformers v3 |
| `@microsoft/recognizers-text-suite` | sequence/date/number recognizers (same family Presidio uses) | not run — stale (no active maintenance), no names/SSN/cards | Reusable building block only, not a solution |

### 3.2 NER models runnable in-process via `@huggingface/transformers` (ONNX)

| Model | License | Types / languages | Size | Verified |
|---|---|---|---|---|
| **Piiranha v1 ONNX** (`onnx-community/piiranha-v1-...-ONNX`) | **CC-BY-NC-ND-4.0** (non-commercial) | 17 PII types (givenname, surname, phone, email, credit card, DOB, passport, DL, bank, tax#, ssn, addr parts…) / EN,DE,FR,RU,IT,ZH — **no Hindi** | ~317 MB int8 | 17.9% typed on this corpus; caught 2/6 names (best of all NERs tested) |
| **Kiji PII ONNX** (`DataikuNLP/kiji-pii-model-onnx`) | **Apache-2.0** (commercial OK) | 26 types incl. national-id, passport, DOB, SSN… | ~330 MB artifact set (INT8) | not run — needs custom ONNX session (dual head: PII + coref); model card warns synthetic training data |
| `dslim/bert-base-NER` (Xenova mirror) | MIT | PER/LOC/ORG/MISC only | ~90 MB | 0/6 names on Hinglish, hallucinated `bhai`→PERSON |

Key finding: **no off-the-shelf NER model covers Hindi/Hinglish PII** (Piiranha's six
languages exclude Hindi; Kiji is Apache-2.0 but not validated on Hinglish). Any NER layer
needs evaluation or fine-tuning on Hinglish data before it can be trusted for names.

### 3.3 Cloud APIs with first-class TS SDKs (fallback tier)

| Service | TS SDK | Notes |
|---|---|---|
| AWS Comprehend `DetectPII` | `@aws-sdk/client-comprehend` | 20+ types, per-entity confidence, redaction action; network + cost + data residency |
| Azure AI Language PII | `@azure/ai-language-text` | Redacted-text output natively; domain filtering (phi); network + cost |
| Google Cloud DLP | `@google-cloud/dlp` | InfoType registry, deidentify templates; network + cost |

All violate the local/offline property and none are "Presidio-like" (they're remote APIs).
Viable only as an optional `model`-layer provider for customers who accept egress.

### 3.4 Other options considered and rejected

- **Mastra's built-in `PIIDetector` processor** (`@mastra/core/processors`): LLM-agent-based
  detection with local-regex fast path for streaming. It's an LLM-call-per-buffer design —
  cost/latency/nondeterminism — and duplicates what this package exists to replace. Keep as
  a reference for the `model` layer only.
- **LLM prompt redaction** (custom): nondeterministic, expensive, leaks to model provider.
- **Sidecar Presidio/spaCy**: rejected by requirement.

## 4. Benchmark results (definitive run)

Corpus: 20 cases, 39 true spans, 19 entity types (Aadhaar, PAN, Voter ID, UPI, IFSC, bank
a/c, card, expiry, CVV, phone, address, vehicle, DL, secret, passport, DOB, email, IP,
name). Methodology and full per-type tables: `docs/evaluation/benchmark-results.md`.
Harness: `docs/evaluation/bench.mjs` (self-contained, reproducible).

| Engine | Typed recall | Coverage | FP | Fully-correct | Latency (20 cases) |
|---|---|---|---|---|---|
| `@openredaction/core` lite (current) | 30.8% | 66.7% | 27 | 2/20 | 123 ms |
| `@redactpii/node` | 30.8% | 30.8% | 0* | 2/20* | 1 ms |
| `@siddicky/anonymizerts` (patterns) | 23.1% | 35.9% | 1 | 2/20 | 1 ms |
| `@siddicky/anonymizerts` (+ bert-base-NER) | 23.1% | 35.9% | 10 | 2/20 | ~500 ms |
| **In-house TS recognizer registry (prototype)** | **69.2%** | **71.8%** | **2** | **8/20** | **2 ms** |
| Piiranha ONNX (SOTA PII NER, no Hindi) | 17.9% | 25.6% | 2 | 0/20 | ~380 ms |

\* `redactpii` has no span API; measured by value-stripping (lenient), and its aggressive
NAME rule destroys legitimate tokens (PAN halves, words like `ASAP`, `SBIN`).

The prototype = **17 regex recognizers + 1 Verhoeff validator, ~120 lines, zero
dependencies** — and it beats every packaged library. Its 10 misses decompose as:

- NAME 0/6, ADDRESS 0/1 → **the NER layer's job** (7 spans; no tested NER covers them)
- AADHAAR 1/3 → 2 corpus values are AI-generated fakes that **fail the real Verhoeff
  checksum** (strict mode intentionally rejects; lenient mode catches them — configurable)
- PHONE 5/8 → 3 are unreachable corpus traps (spoken-out digits, `O`-for-`0`, fragmented
  across a sentence)

Structured-PII ceiling for this corpus: **27/29 reachable spans (93%)** with the prototype
pattern set alone.

## 5. Recommendation

**Build the analyzer in-house as a Presidio-style TS engine, inside this package.** Do not
adopt `anonymizerts` or `@redactpii/node` as the foundation; use them only as pattern
references. The existing `src/index.ts` already implements the hard parts (span merging by
priority, fail-closed processor, worker time-bounding, Mastra message traversal) — replace
the engine behind `redactText()`.

### Architecture (mirrors Presidio)

```
LayeredPii.redactText(text)
  └─ RecognizerRegistry            (in-repo, TS)
       ├─ PatternRecognizer[]      (regex + validator: Verhoeff for Aadhaar, Luhn for cards)
       ├─ NERRecognizer (optional) — @huggingface/transformers + ONNX model
       └─ score fusion + span merge (priority, confidence, allow-list)
  └─ Anonymizer operators          (placeholder / mask / hash / replace) — already partially in place
```

### Phased plan

1. **Phase A (deterministic layer, replaces openRedaction today):**
   - Port the prototype recognizer set (~17 patterns: Aadhaar+Verhoeff, PAN, Voter ID,
     UPI, IFSC, bank a/c, card+Luhn, Indian phone incl. `+91`/5-5 dash, email, IP, DOB,
     vehicle reg, DL, passport, expiry, CVV, `sk-` keys, password-context secrets).
   - Keep it a private module; keep the fail-closed contract and `[REDACTION_FAILED]`.
   - Delete `@openredaction/core` dependency.
   - **Acceptance:** benchmark ≥ 60% typed recall, ≤ 5 FP on the corpus; re-run
     `docs/evaluation/bench.mjs`.

2. **Phase B (NER layer, optional):**
   - `@huggingface/transformers` token-classification with a **license-compatible** model
     (Kiji = Apache-2.0, needs a small custom ONNX session wrapper; Piiranha = better
     accuracy but non-commercial — evaluation-only).
   - Gate model download at `warmup()`; keep `allowRemoteModels` off for offline deploys.
   - **Evaluate on Hinglish before shipping** — no tested model covers names in
     Hindi/Hinglish; fine-tuning a small DeBERTa NER on Hinglish chat data is the
     upgrade path if Phase B numbers don't clear the bar.
   - Name/address recognition is the only capability that strictly requires this layer.

3. **Phase C (model layer, optional):** pluggable cloud providers (AWS Comprehend /
   Azure PII / GCP DLP) or Mastra `PIIDetector` for customers who accept egress.

### Risks & notes

- **Licensing is the binding constraint for NER:** Piiranha (best accuracy) is
  CC-BY-NC-ND — do not ship it in a commercial package. Kiji (Apache-2.0) is the default
  candidate but was trained on synthetic data and needs validation.
- **Validators are what make regex trustworthy** (Aadhaar Verhoeff, card Luhn): they kill
  the 12-digit-bank-account-is-Aadhaar class of false positives, at the cost of missing
  synthetic/fake values — make strict/lenient a per-entity config.
- Model size: NER adds ~100–330 MB to cold start unless quantized and cached; keep NER
  lazy (opt-in), matching the current `layers` design (`deterministic | ner | model`).
- The corpus itself contains traps and artifacts (see benchmark doc); treat per-type
  numbers, not the global %, as the review target.

## 6. Files

- `docs/evaluation/benchmark-results.md` — methodology + full per-type tables
- `docs/evaluation/indian_pii_testsuite.json` — extracted 20-case corpus (source: `tests.json`, a Gemini export containing the embedded suite)
- `docs/evaluation/bench.mjs` — reproducible harness (all engines incl. openredaction, redactpii, anonymizerts, Piiranha, prototype)
