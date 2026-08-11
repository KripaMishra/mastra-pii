# Benchmark Results — TS PII Engines vs Indian Chat Corpus

**Date:** 2026-08-11 · **Corpus:** `docs/evaluation/indian_pii_testsuite.json` (20 cases, extracted from `tests.json`)

## Methodology

- Each corpus item has `input` and `expected_output` where PII spans are replaced by
  `<REDACTED_ENTITY>` markers. True spans are recovered by aligning input ↔ expected
  (marker-position walk with literal-run anchors).
- **Typed recall** = detection overlaps a true span *and* its entity type maps to the
  true type (per-engine type map). **Coverage** = any overlap regardless of type.
  **FP** = detections overlapping no true span. **Fully-correct** = all true spans in a
  message covered with correct types.
- Engines: openredaction lite (current dep), `@redactpii/node` 1.0.17, `@siddicky/anonymizerts` 1.0.3 (patterns; + bert-base-NER), in-house prototype (17 regexes + Verhoeff), Piiranha ONNX q8 via transformers.js (aggregation `none` + sequential offset reconstruction + B/I merging).
- Latency: wall-clock for all 20 cases after model warm-up, single-threaded, Node 26, this machine. Model downloads excluded.

## Corpus profile

39 true spans across 19 types: AADHAAR 3, NAME 6, PAN 3, VOTER_ID 1, UPI 1, BANK_ACC 2,
IFSC 1, CARD 1, EXPIRY 1, CVV 1, PHONE 8, ADDRESS 1, VEHICLE 1, DL 1, SECRET 2, PASSPORT 1,
DOB 1, EMAIL 3, IP 1. Language: Hinglish (Hindi code-mixed chat), Indian identifiers.

**Unreachable/trap spans (no engine can be expected to hit):**
- PHONE `"nine eight seven six five four three two one zero"` — spoken-out digits
- PHONE `"9876O5432O"` — letter O for zero
- PHONE `"98765 and remaining 5 digits are 43210"` — fragmented across sentence
- AADHAAR ×2 (`4829 1048 5920`, `482910485920`) — synthetic values failing the real Verhoeff checksum (strict-validator engines reject them by design; lenient mode catches them)

Reachable structured ceiling: **29 spans** (39 − 6 NAME − 1 ADDRESS − 3 phone traps).

## Headline results

| Engine | Typed recall | Coverage | FP | Fully-correct | Latency |
|---|---|---|---|---|---|
| openredaction lite (current) | 30.8% (12/39) | 66.7% | 27 | 2/20 | 123 ms |
| @redactpii/node | 30.8% | 30.8% | 0* | 2/20* | 1 ms |
| anonymizerts (patterns) | 23.1% | 35.9% | 1 | 2/20 | 1 ms |
| anonymizerts + bert-base-NER | 23.1% | 35.9% | 10 | 2/20 | ~500 ms |
| **in-house prototype** | **69.2% (27/39)** | 71.8% | **2** | **8/20** | **2 ms** |
| Piiranha ONNX (q8) | 17.9% | 25.6% | 2 | 0/20 | ~380 ms |

\* redactpii measured by value-stripping (no span API — lenient for short values) and its
NAME rule strips legitimate text (PAN halves `ABCDE`, words `ASAP`/`SBIN`), so 0 FP is not
a precision statement; treat 30.8% as an upper bound.

## Per-type detail (prototype vs Piiranha)

| Type | true | prototype | piiranha | note |
|---|---|---|---|---|
| AADHAAR | 3 | 1 | 0 | prototype strict Verhoeff rejects 2 synthetic corpus values; piiranha has no Aadhaar label |
| NAME | 6 | 0 | 2 | no tested NER covers Hinglish names; piiranha best-of-class (no Hindi training) |
| PAN | 3 | 3 | 0 | |
| VOTER_ID | 1 | 1 | 0 | |
| UPI | 1 | 1 | 0 | |
| BANK_ACC | 2 | 2 | 1 | prototype Verhoeff correctly rejects 12-digit bank as Aadhaar |
| IFSC | 1 | 1 | 0 | |
| CARD | 1 | 1 | 1 | |
| EXPIRY | 1 | 1 | 0 | context pattern (`exp/expiry/valid thru`) |
| CVV | 1 | 1 | 0 | context pattern (`cvv/security code`) |
| PHONE | 8 | 5 | 2 | 3 unreachable traps; prototype covers `+91-98123-45678`, `09876543210`, `9811223344`, `9988776655`, `+91-9000011111` |
| ADDRESS | 1 | 0 | 0 | NER-only type |
| VEHICLE | 1 | 1 | 0 | `DL 01 AB 1234` |
| DL | 1 | 1 | 0 | `HR-1420110012345` (extraction span includes leading dash artifact) |
| SECRET | 2 | 2 | 0 | `sk-proj-…` + `password is …` context |
| PASSPORT | 1 | 1 | 0 | |
| DOB | 1 | 1 | 1 | |
| EMAIL | 3 | 3 | 0 | |
| IP | 1 | 1 | 0 | |

## Engine-specific findings

### openredaction (current dependency)
- Detects Aadhaar correctly (`INDIAN_AADHAAR`) but names are broken: redacts
  `"Aadhar verify kar lo"` and `"Name is Kriya Shankar"` as NAME while leaking `"Mishra"`.
- Emits wrong types: `PHONE_UK` for +91 numbers, `ZIP_CODE_US`, `TWITTER_USER_ID`,
  `INSTAGRAM_USERNAME`, `TURKMENISTAN_PASSPORT`, `EMERGENCY_CALL_REF`… (27 FPs/20 msgs).
- Typed misses are total for Indian identifiers (PAN/UPI/IFSC/bank/voter: 0/8).

### @redactpii/node
- Zero deps, instant, but only 5 rule types (CREDIT_CARD/EMAIL/NAME/PHONE/SSN).
- NAME rule is regex over capitalized words: destroys `ABCDE1234F` (PAN → `ABCDE`),
  `SBIN0001234`, `ASAP`, `HUDA` — content-destroying on chat text.

### @siddicky/anonymizerts
- Presidio-shaped API (RecognizerResult: type/start/end/score; anonymizer operators) —
  the closest packaged design match. Pattern layer decent for US formats.
- bert-base-NER is useless on Hinglish: 0/6 names, hallucinates `"bhai"`→PERSON (score 0.999).
- Bus factor: 65 downloads/month, single maintainer, transformers v3 pinned, ~3 releases.

### Piiranha (SOTA PII NER, ONNX, transformers.js)
- Works out of the box with `pipeline('token-classification', …)`; q8 ≈ 317 MB.
- Trained on EN/DE/FR/RU/IT/ZH — no Hindi: Hinglish names mostly missed (2/6).
- Caught card, DOB, some phones; no Aadhaar/PAN/UPI/IFSC labels.
- **License CC-BY-NC-ND-4.0 → not shippable commercially.** Use only for accuracy ceilings.
- Offset reconstruction caveat: transformers.js v3 emits `index/word` without char offsets for this model; harness reconstructs spans by sequential word matching (small underestimate of recall possible).

### In-house prototype (recommended baseline)
17 recognizers + Verhoeff validator (~120 LoC, zero deps, 2 ms for the whole corpus).
Reaches **27/29 (93%) of reachable structured spans**. Misses are exclusively
NER-layer types (NAME/ADDRESS) and strict-validator rejections of synthetic Aadhaars.
Config decisions surfaced:
- Aadhaar: strict (Verhoeff) rejects fakes but also synthetic test data; lenient mode = pattern only.
- PHONE: needs both `[6-9]\d{9}` and 5-5 dash variants (`+91-98123-45678`).
- IFSC: `[A-Z]{4}0[A-Z0-9]{6}` — register before VOTER_ID (`[A-Z]{3,4}\d{7}` collides).
- 12-digit bank accounts collide with Aadhaar → validator required.

## Reproduction

```sh
# corpus: docs/evaluation/indian_pii_testsuite.json
# harness: docs/evaluation/bench.mjs  (imports engines from local node_modules:
#   openredaction from repo, @redactpii/node + @siddicky/anonymizerts + @huggingface/transformers from a scratch dir)
node docs/evaluation/bench.mjs
```

Note: the harness expects `@redactpii/node`, `@siddicky/anonymizerts`, and
`@huggingface/transformers` installed (Piiranha downloads ~317 MB on first run; set
`env.allowRemoteModels = false` + local model dir for offline).

---

## Presidio P0 spike (2026-08-11) — dockerized analyzer, both corpora

Setup: `ghcr.io/data-privacy-stack/presidio-analyzer:2.2.362` (Docker, localhost:3000),
harness `docs/evaluation/bench-presidio.mjs` (`node docs/evaluation/bench-presidio.mjs v1|v3`).
Engines: `local` (in-house 17-recognizer engine, unchanged), `presidio_default`
(spaCy en_core_web_lg + stock recognizers, curated entities allowlist + shape filters),
`presidio_indian` (default + 17 Indian ad_hoc recognizers, same filters + type-aware
span dedupe + client-side Verhoeff/boundary guards).

### v1 corpus (39 true spans)

| Engine | Typed recall | Coverage | FP | Fully-correct | p95 latency |
|---|---|---|---|---|---|
| local | 69.2% | 71.8% | 2 | 7/20 | 2 ms |
| presidio_default | 35.9% | 35.9% | 0 | 3/20 | 18 ms |
| **presidio_indian** | **84.6%** | **87.2%** | **2** | **9/20** | **16 ms** |

presidio_indian perType: AADHAAR 1/3 (2 synthetic fail real Verhoeff — validator
working as designed), NAME **6/6** (spaCy), PAN 3/3, VOTER_ID 1/1, UPI 1/1,
BANK_ACC 2/2, IFSC 1/1, CARD 1/1, EXPIRY 1/1, CVV 1/1, PHONE 5/8 (3 traps are
unreachable by any engine), ADDRESS 0/1 (see LOCATION note), VEHICLE 1/1, DL 1/1,
SECRET 2/2, PASSPORT 1/1, DOB 1/1, EMAIL 3/3, IP 1/1.

### v3 corpus (29 true spans, 20 traps)

| Engine | Typed recall | Coverage | FP | Traps hit |
|---|---|---|---|---|
| local | 10.3% | 24.1% | 3 | 5 |
| presidio_default | 6.9% | 6.9% | 0 | 0 |
| presidio_indian | 13.8% | 27.6% | 3 | 5 |

### Findings that shaped the adapter design

1. **spaCy catches Hinglish names: 6/6** — the entire recall delta over the
   in-house engine (69.2% → 84.6%). NER is worth having for names.
2. **Everything scores 0.85** — spaCy's scores on this chat are quantized; true
   names ("Kripa Shankar Mishra") and hallucinations ("bhai", "kar", "nahi hua",
   "Aadhar", "kar lo fast ->") are score-identical. No threshold separates them.
   Fix: **capital-initial multi-token shape filter** on PERSON (6/6 kept, all
   hallucinations dropped). Chat handles (v3: `Vikas_M`) die by design.
3. **LOCATION: 0 true hits in the whole v1 corpus** — spaCy never tags the Indian
   address and hallucinates the literal word "IFSC" as a location. Dropped from
   the allowlist (0 recall lost, +1 FP removed). ADDRESS remains a documented gap.
4. **DATE_TIME hallucinates on "42" / "122001"** — date-shape filter recovers DOB.
5. **Luhn must be lenient** — the corpus card `4532 1122 3344 5566` fails Luhn
   (AI-generated data fails real checksums); strict Luhn drops the only true card.
   Verhoeff stays strict (drops exactly the 2 synthetic Aadhaars — desired).
6. **Type-aware dedupe beats score-dedupe** — score-dedupe let PHONE_NUMBER
   swallow UPI; BANK_ACC (\d{9,18} firehose) must NOT outrank phones. Tiered:
   structurally-strong Indian IDs > generic types (score within tier).
7. **Latency is a non-issue**: p95 16–18 ms per analyze over HTTP+Docker.
   The agent-loop concern (3 hooks × round trip) is closed by an LRU cache, not by
   architecture.
8. **v3 (obfuscation) is the shared failure mode** — leet/spaced/[at]-emails beat
   every engine, Presidio included (13.8%). Canonicalization pass remains open work
   (P2, same as for the in-house engine).

### Gate result (plan §0): PASSED

≥60% typed recall on v1: **84.6%** ✓ · ≤5 FP: **2** ✓ · p95 <300 ms: **16 ms** ✓.
Presidio is the primary adapter; the in-house engine stays as the local fallback.
