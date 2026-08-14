#!/usr/bin/env node
// P0 spike harness: Presidio container (default NER) vs Presidio + Indian
// ad_hoc recognizers vs the in-house local engine, on corpus v1, v3, or resume.
// Usage: node docs/evaluation/bench-presidio.mjs v1|v3|resume
// Requires: docker compose -f deploy/docker-compose.yml up -d (port 3000)
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';

const CORPUS = process.argv[2] ?? 'v1';
const BASE = process.env.PRESIDIO_URL ?? 'http://localhost:3000';

// ---------- corpus ----------
const loadSuite = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'))
  .test_sections.map(s => ({ id: s.section_id, cat: s.category, input: s.input_transcript, expected: s.expected_redacted_transcript, traps: s.false_positive_traps || [], pii_entities: s.pii_entities }));
const cases = CORPUS === 'v3'
  ? loadSuite('../../test_2.json')
  : CORPUS === 'resume'
    ? loadSuite('./resume_pii_testsuite.json')
    : JSON.parse(readFileSync(new URL('./indian_pii_testsuite.json', import.meta.url), 'utf8'))
        .map(c => ({ id: c.id, cat: c.category, input: c.input, expected: c.expected_output, traps: [] }));

// v3 corpus type names -> recognizer names
const V3_NORM = { UPI_ID: 'UPI', DRIVING_LICENSE: 'DL', SECRET_KEY: 'SECRET', DATE_OF_BIRTH: 'DOB' };
const normType = t => V3_NORM[t] ?? t;

// ---------- validators (client-side, Presidio ad_hoc recognizers are pure regex) ----------
const VERHOEFF_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VERHOEFF_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
function verhoeff(num) {
  let c = 0;
  const digits = String(num).split('').reverse().map(Number);
  for (let i = 0; i < digits.length; i++) c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][digits[i]]];
  return c === 0;
}
function luhn(num) {
  const d = String(num).replace(/\D/g, '').split('').reverse().map(Number);
  let sum = 0;
  for (let i = 0; i < d.length; i++) sum += i % 2 ? (d[i] * 2 > 9 ? d[i] * 2 - 9 : d[i] * 2) : d[i];
  return sum % 10 === 0;
}

// ---------- recognizer set (port of RECS, 17 patterns + context) ----------
const INDIAN_DEFAULTS = [
  { name: 'IFSC', supported_language: 'en', supported_entity: 'IFSC', patterns: [{ name: 'ifsc', regex: '\\b[A-Z]{4}0[A-Z0-9]{6}\\b', score: 0.6 }], context: ['ifsc', 'bank', 'branch'] },
  { name: 'AADHAAR', supported_language: 'en', supported_entity: 'AADHAAR', patterns: [{ name: 'aadhaar', regex: '\\b[1-9]\\d{3}[ ]?\\d{4}[ ]?\\d{4}\\b', score: 0.6 }], context: ['aadhaar', 'aadhar', 'uidai', 'adhaar'] },
  { name: 'PAN', supported_language: 'en', supported_entity: 'PAN', patterns: [{ name: 'pan', regex: '\\b[A-Z]{5}\\d{4}[A-Z]\\b', score: 0.6 }], context: ['pan', 'permanent account number'] },
  { name: 'VOTER_ID', supported_language: 'en', supported_entity: 'VOTER_ID', patterns: [{ name: 'voter', regex: '\\b[A-Z]{3,4}\\d{7}\\b', score: 0.55 }], context: ['voter', 'epic'] },
  { name: 'UPI', supported_language: 'en', supported_entity: 'UPI', patterns: [{ name: 'upi', regex: '\\b[\\w.-]{2,}@(?:ok[a-z]+|ybl|paytm|apl|axl|ibl|upi|icici|sbi|hdfc|kotak|yesbank|federal|jio|payzapp|amazonpay|phonepe|cred|freecharge|mobikwik|yono)\\b', score: 0.6 }], context: ['upi', 'handle', 'pay'] },
  { name: 'CARD', supported_language: 'en', supported_entity: 'CARD', patterns: [{ name: 'card', regex: '\\b\\d{4}[ -]?\\d{4}[ -]?\\d{4}[ -]?\\d{4}\\b', score: 0.6 }], context: ['card', 'credit', 'debit'] },
  { name: 'PHONE', supported_language: 'en', supported_entity: 'PHONE', patterns: [{ name: 'phone', regex: '(?:\\+91[ -]?|0)?[6-9]\\d{4}[ -]\\d{5}\\b|(?:\\+91[ -]?|0)?[6-9]\\d{9}\\b', score: 0.6 }], context: ['phone', 'mobile', 'call', 'reach'] },
  { name: 'EMAIL', supported_language: 'en', supported_entity: 'EMAIL', patterns: [{ name: 'email', regex: '\\b[\\w.+-]+@[\\w-]+\\.[\\w.]+\\b', score: 0.6 }], context: ['email', 'mail'] },
  { name: 'IP', supported_language: 'en', supported_entity: 'IP', patterns: [{ name: 'ip', regex: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', score: 0.6 }], context: ['ip', 'address'] },
  { name: 'BANK_ACC', supported_language: 'en', supported_entity: 'BANK_ACC', patterns: [{ name: 'acc', regex: '\\b\\d{9,18}\\b', score: 0.4 }], context: ['account', 'acc', 'bank'] },
  { name: 'DOB', supported_language: 'en', supported_entity: 'DOB', patterns: [{ name: 'dob', regex: '\\b\\d{1,2}[/-]\\d{1,2}[/-]\\d{2,4}\\b', score: 0.4 }], context: ['dob', 'birth', 'born'] },
  { name: 'VEHICLE', supported_language: 'en', supported_entity: 'VEHICLE', patterns: [{ name: 'vehicle', regex: '\\b[A-Z]{2}[ ]?\\d{1,2}[ ]?[A-Z]{1,2}[ ]?\\d{4}\\b', score: 0.5 }], context: ['vehicle', 'registration', 'reg', 'car'] },
  { name: 'DL', supported_language: 'en', supported_entity: 'DL', patterns: [{ name: 'dl', regex: '\\b[A-Z]{2}[-/]?\\d{2}[-/]?\\d{4,11}\\b', score: 0.5 }], context: ['driving', 'license', 'dl'] },
  { name: 'PASSPORT', supported_language: 'en', supported_entity: 'PASSPORT', patterns: [{ name: 'passport', regex: '\\b[A-Z][1-9]\\d{6}\\b', score: 0.5 }], context: ['passport'] },
  { name: 'EXPIRY', supported_language: 'en', supported_entity: 'EXPIRY', patterns: [{ name: 'expiry', regex: '(?:exp|expiry|valid (?:thru|through))[^\\d]{0,8}(\\d{2}/\\d{2})', score: 0.5 }], context: ['expiry', 'exp', 'valid'] },
  { name: 'CVV', supported_language: 'en', supported_entity: 'CVV', patterns: [{ name: 'cvv', regex: '(?:cvv|security code)[^\\d]{0,8}(\\d{3})', score: 0.5 }], context: ['cvv', 'security code'] },
  { name: 'SECRET', supported_language: 'en', supported_entity: 'SECRET', patterns: [{ name: 'secret', regex: '(?:password|secret|pin)[^\\w]{0,6}([\\w!@#$%^&*]{4,})|\\bsk-[A-Za-z0-9_-]{20,}\\b', score: 0.55 }], context: ['password', 'secret', 'pin'] },
];

// ---------- Presidio client ----------
// Curated entity allowlist: spaCy NER types we trust + Indian ad_hoc types.
// Without this, Presidio's default recognizers fire at score 1.0 on Indian numbers
// (UK_NHS on any 10-digit run, US_BANK_NUMBER, US_DRIVER_LICENSE...) -> FP noise.
const ENTITY_ALLOWLIST = ['PERSON', 'LOCATION', 'PHONE_NUMBER', 'EMAIL_ADDRESS', 'DATE_TIME', 'CREDIT_CARD', 'IP_ADDRESS',
  'IFSC', 'AADHAAR', 'PAN', 'VOTER_ID', 'UPI', 'CARD', 'PHONE', 'EMAIL', 'IP', 'BANK_ACC', 'DOB', 'VEHICLE', 'DL', 'PASSPORT', 'EXPIRY', 'CVV', 'SECRET'];

async function presidioAnalyze(text, adHoc) {
  const body = { text, language: 'en', score_threshold: 0.35, entities: ENTITY_ALLOWLIST };
  if (adHoc) body.ad_hoc_recognizers = adHoc;
  const t0 = performance.now();
  const res = await fetch(`${BASE}/analyze`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  const ms = performance.now() - t0;
  if (!res.ok) throw new Error(`analyze ${res.status}: ${await res.text()}`);
  const spans = await res.json();
  return { ms, spans: spans.map(s => ({ type: s.entity_type, start: s.start, end: s.end, score: s.score })) };
}

const PRESIDIO_MAP = {
  PERSON: 'NAME', LOCATION: 'ADDRESS', PHONE_NUMBER: 'PHONE', EMAIL_ADDRESS: 'EMAIL',
  DATE_TIME: 'DOB', CREDIT_CARD: 'CARD', IP_ADDRESS: 'IP', US_SSN: 'SSN',
  US_BANK_NUMBER: 'BANK_ACC', US_DRIVER_LICENSE: 'DL', US_PASSPORT: 'PASSPORT', US_PHONE: 'PHONE',
};

// Presidio returns overlapping spans of different types (default + ad_hoc recognizers).
// Product behavior: type-aware merge — Indian-specific ad_hoc types beat generic defaults
// (UPI must not lose to PHONE_NUMBER just because the phone recognizer scores higher);
// within the same priority tier, keep the higher score.
const SPECIFIC = new Set(['IFSC', 'AADHAAR', 'PAN', 'VOTER_ID', 'UPI', 'DL', 'PASSPORT', 'EXPIRY', 'CVV', 'SECRET']); // BANK_ACC stays generic: its d{9,18} firehose must not outrank PHONE_NUMBER
function dedupe(spans) {
  const out = [];
  for (const s of spans.sort((a, b) => (Number(SPECIFIC.has(b.type)) - Number(SPECIFIC.has(a.type))) || (b.score - a.score))) {
    if (!out.some(o => o.start < s.end && s.start < o.end)) out.push(s);
  }
  return out.sort((a, b) => a.start - b.start);
}

// client-side post-filters (adapter-level, language invariants not corpus tuning):
// - AADHAAR: Verhoeff checksum + boundary guard (v3 trap: SN-482910485920-ACER)
// - CARD: LENIENT luhn (AI-generated test cards fail checksums; drop only if span
//   is clearly a 16-digit VID pattern that isn't a card — VID handled below)
// - PERSON: spaCy scores EVERYTHING 0.85 on Hinglish chat (names AND "bhai"/"kar lo fast ->").
//   No threshold separates them — shape filter instead: capital-initial multi-token names.
// - LOCATION: dropped (0 true hits in corpus; hallucinates on the literal word "IFSC")
// - DATE_TIME: date-shaped only (kills spaCy tagging "42", "122001" as dates)
// - PHONE_NUMBER: score >= 0.75 (kills the US recognizer's 0.40 base-score noise)
function postFilter(spans, text) {
  return spans.filter(s => {
    if (s.type === 'AADHAAR') {
      const v = text.slice(s.start, s.end).replace(/\s/g, '');
      if (!verhoeff(v)) return false;
      const before = text[s.start - 1], after = text[s.end];
      if (before && /[A-Za-z0-9_.\-/]/.test(before)) return false;
      if (after && /[A-Za-z0-9_.\-/]/.test(after)) return false;
    }
    if (s.type === 'PERSON') {
      const v = text.slice(s.start, s.end);
      if (!/^[A-Z][A-Za-z]+( [A-Z][A-Za-z]+)+$/.test(v)) return false;
    }
    if (s.type === 'LOCATION') return false;
    if (s.type === 'DATE_TIME') {
      const v = text.slice(s.start, s.end);
      if (!/^\d{1,2}[/-]\d{1,2}[/-]\d{2,4}$/.test(v)) return false;
    }
    if (s.type === 'PHONE_NUMBER' && s.score < 0.75) return false;
    return true;
  });
}

// ---------- engines ----------
const engines = {};

// local in-house engine (reference; RECS from bench.mjs)
{
  const RECS = [
    { type: 'IFSC', priority: 80, re: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g },
    { type: 'AADHAAR', priority: 90, re: /\b[1-9]\d{3}[ ]?\d{4}[ ]?\d{4}\b/g, validate: v => verhoeff(v.replace(/ /g, '')) },
    { type: 'PAN', priority: 90, re: /\b[A-Z]{5}\d{4}[A-Z]\b/g },
    { type: 'VOTER_ID', priority: 80, re: /\b[A-Z]{3,4}\d{7}\b/g },
    { type: 'UPI', priority: 80, re: /\b[\w.-]{2,}@(?:ok[a-z]+|ybl|paytm|apl|axl|ibl|upi|icici|sbi|hdfc|kotak|yesbank|federal|jio|payzapp|amazonpay|phonepe|cred|freecharge|mobikwik|yono)\b/gi },
    { type: 'CARD', priority: 70, re: /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/g },
    { type: 'PHONE', priority: 70, re: /(?:\+91[ -]?|0)?[6-9]\d{4}[ -]\d{5}\b|(?:\+91[ -]?|0)?[6-9]\d{9}\b/g },
    { type: 'EMAIL', priority: 70, re: /\b[\w.+-]+@[\w-]+\.[\w.]+\b/g },
    { type: 'IP', priority: 70, re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
    { type: 'BANK_ACC', priority: 40, re: /\b\d{9,18}\b/g },
    { type: 'DOB', priority: 40, re: /\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b/g },
    { type: 'VEHICLE', priority: 60, re: /\b[A-Z]{2}[ ]?\d{1,2}[ ]?[A-Z]{1,2}[ ]?\d{4}\b/g },
    { type: 'DL', priority: 60, re: /\b[A-Z]{2}[-/]?\d{2}[-/]?\d{4,11}\b/g },
    { type: 'PASSPORT', priority: 60, re: /\b[A-Z][1-9]\d{6}\b/g },
    { type: 'EXPIRY', priority: 60, re: /(?:exp|expiry|valid (?:thru|through))[^\d]{0,8}(\d{2}\/\d{2})/gi },
    { type: 'CVV', priority: 60, re: /(?:cvv|security code)[^\d]{0,8}(\d{3})/gi },
    { type: 'SECRET', priority: 60, re: /(?:password|secret|pin)[^\w]{0,6}([\w!@#$%^&*]{4,})|\bsk-[A-Za-z0-9_-]{20,}\b/gi },
  ];
  engines.local = {
    typeMatch: (c, t) => t === c,
    async detect(text) {
      const spans = [];
      for (const rec of RECS) {
        rec.re.lastIndex = 0;
        let m;
        while ((m = rec.re.exec(text))) {
          const value = m[1] ?? m[0];
          if (rec.validate && !rec.validate(value)) continue;
          const start = m[1] ? m.index + m[0].indexOf(m[1]) : m.index;
          spans.push({ type: rec.type, start, end: start + value.length, score: rec.priority / 100 });
        }
      }
      spans.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
      const out = [];
      for (const s of spans) {
        const prev = out[out.length - 1];
        if (prev && s.start < prev.end) { if (s.end > prev.end) out.push(s); continue; }
        out.push(s);
      }
      return out;
    },
  };
}

engines.presidio_default = {
  mapType: t => PRESIDIO_MAP[t] ?? t,
  typeMatch: (c, t) => (PRESIDIO_MAP[t] ?? t) === c || t === c,
  async detect(text) {
    const { spans, ms } = await presidioAnalyze(text, null);
    this.lastMs = ms;
    return dedupe(postFilter(spans, text));
  },
};

engines.presidio_indian = {
  mapType: t => PRESIDIO_MAP[t] ?? t,
  typeMatch: (c, t) => (PRESIDIO_MAP[t] ?? t) === c || t === c,
  async detect(text) {
    const { spans, ms } = await presidioAnalyze(text, INDIAN_DEFAULTS);
    this.lastMs = ms;
    return dedupe(postFilter(spans, text));
  },
};

// ---------- metrics (same as bench.mjs / bench-v3.mjs) ----------
function extractTrueSpans(c) {
  // Preferred: explicit pii_entities[].entity anchors (exact, length-independent).
  if (c.pii_entities && c.pii_entities.length > 0) {
    const spans = [];
    // Per-value cursor so repeated identical values resolve to successive
    // occurrences instead of every match collapsing onto the first.
    const cursor = new Map();
    for (const e of c.pii_entities) {
      const from = cursor.get(e.entity) ?? 0;
      const start = c.input.indexOf(e.entity, from);
      if (start === -1) {
        console.warn(`  !! entity not found in input: ${e.type} ${JSON.stringify(e.entity)}`);
        continue;
      }
      cursor.set(e.entity, start + e.entity.length);
      spans.push({ type: normType(e.type), value: e.entity, start, end: start + e.entity.length });
    }
    return spans.sort((a, b) => a.start - b.start);
  }
  // Fallback: marker-position walk (works when marker length == replaced value length).
  const markerRe = /<REDACTED_([A-Z_]+)>/g;
  const markers = [];
  let m;
  while ((m = markerRe.exec(c.expected))) markers.push({ type: normType(m[1]), index: m.index, length: m[0].length });
  const input = c.input, expected = c.expected;
  const spans = [];
  let inp = 0, exp = 0;
  for (let k = 0; k < markers.length; k++) {
    const mk = markers[k];
    while (exp < mk.index) { if (expected[exp] === input[inp]) inp++; exp++; }
    const after = exp + mk.length;
    const next = markers[k + 1];
    const runEnd = next ? next.index : expected.length;
    const literal = expected.slice(after, runEnd);
    const valueStart = inp;
    let value;
    if (literal.length === 0) {
      value = input.slice(inp);
    } else {
      const rel = input.indexOf(literal, inp);
      value = input.slice(inp, rel === -1 ? input.length : rel);
      inp = rel === -1 ? input.length : rel + literal.length;
    }
    spans.push({ type: mk.type, value, start: valueStart, end: valueStart + value.length });
    exp = after;
  }
  return spans;
}
function overlaps(a, b) { return a.start < b.end && b.start < a.end; }

async function runEngine(name, eng, log) {
  const stats = { trueSpans: 0, coveredAny: 0, coveredTyped: 0, fps: 0, ms: 0, perType: {}, exactMatch: 0, n: cases.length, trapHits: [], lat: [] };
  const trueCounts = {};
  for (const c of cases) {
    const trueSpans = extractTrueSpans(c);
    for (const t of trueSpans) trueCounts[t.type] = (trueCounts[t.type] ?? 0) + 1;
    stats.trueSpans += trueSpans.length;
    const t0 = performance.now();
    const detections = await eng.detect(c.input);
    const dt = performance.now() - t0;
    stats.ms += dt;
    if (typeof eng.lastMs === 'number') stats.lat.push(eng.lastMs);
    const trueRanges = trueSpans.map(t => ({ type: t.type, start: t.start, end: t.end }));
    const any = detections.filter(d => trueRanges.some(t => overlaps(d, t)));
    const typed = detections.filter(d => trueRanges.some(t => overlaps(d, t) && eng.typeMatch(t.type, d.type)));
    // per-true-span accounting: a true span is covered-typed iff ANY detection matches it (no double count)
    const typedBySpan = trueRanges.filter(t => detections.some(d => overlaps(d, t) && eng.typeMatch(t.type, d.type)));
    stats.coveredTyped += typedBySpan.length;
    stats.coveredAny += trueRanges.filter(t => detections.some(d => overlaps(d, t))).length;
    stats.fps += detections.filter(d => !trueRanges.some(t => overlaps(d, t))).length;

    for (const d of typed) { const k = eng.mapType ? eng.mapType(d.type) : d.type; stats.perType[k] = (stats.perType[k] ?? 0) + 1; }
    const red = detections.reduce((s, d) => s + (d.end - d.start), 0);
    const expectedRed = trueRanges.reduce((s, t) => s + (t.end - t.start), 0);
    if (red === expectedRed && detections.length === trueRanges.length && detections.every((d, i) => d.start === trueRanges[i].start && d.end === trueRanges[i].end)) stats.exactMatch++;
    for (const tr of c.traps || []) {
      const idx = c.input.indexOf(tr.value);
      const hit = idx >= 0 ? detections.some(d => overlaps(d, { start: idx, end: idx + tr.value.length })) : detections.some(d => d.text === tr.value);
      if (hit) stats.trapHits.push(tr.value);
    }
  }
  const recall = (stats.coveredTyped / stats.trueSpans) * 100;
  const cov = (stats.coveredAny / stats.trueSpans) * 100;
  console.log(`### ${name}  (${Math.round(stats.ms)}ms total${stats.lat.length ? `, p50 ${Math.round(stats.lat.sort((a,b)=>a-b)[Math.floor(stats.lat.length/2)])}ms, p95 ${Math.round(stats.lat[Math.ceil(stats.lat.length*0.95)-1])}ms` : ''})`);
  console.log(`  recall(typed): ${recall.toFixed(1)}%  coverage(any): ${cov.toFixed(1)}%  FP detections: ${stats.fps}`);
  const perType = Object.entries(trueCounts).map(([t, n]) => `${t}:${stats.perType[t] ?? 0}/${n}`).join(', ');
  console.log(`  perType: {${perType}}`);
  console.log(`  fully-correct cases: ${stats.exactMatch}/${stats.n}`);
  if (stats.trapHits.length) console.log(`  TRAP HITS: ${stats.trapHits.length} -> ${stats.trapHits.join(' | ')}`);
  else console.log(`  TRAP HITS: 0`);
  return { recall, cov, fps: stats.fps, exact: stats.exactMatch, perType, traps: stats.trapHits.length };
}

const results = {};
console.log(`corpus: ${CORPUS} | cases: ${cases.length} | presidio: ${BASE}\n`);
for (const [name, eng] of Object.entries(engines)) {
  try { results[name] = await runEngine(name, eng, false); }
  catch (e) { console.log(`### ${name} FAILED: ${e.message}`); }
}
