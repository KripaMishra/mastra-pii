// Reproducible PII engine benchmark (see benchmark-results.md).
// Needs: repo node_modules (openredaction) + scratch installs of @redactpii/node,
// @siddicky/anonymizerts, @huggingface/transformers (Piiranha downloads ~317MB once).

// Definitive benchmark: candidate TS PII engines vs the Indian PII test corpus
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';

const corpus1 = JSON.parse(readFileSync(new URL('./indian_pii_testsuite.json', import.meta.url), 'utf8'));

// ---------- true span extraction (robust: multi-char anchors) ----------
function extractTrueSpans(input, expected) {
  const spans = [];
  const markerRe = /<REDACTED_([A-Z_]+)>/g;
  const markers = [];
  let m;
  while ((m = markerRe.exec(expected))) markers.push({ type: m[1], index: m.index, length: m[0].length });
  let inp = 0, exp = 0;
  for (let k = 0; k < markers.length; k++) {
    const mk = markers[k];
    while (exp < mk.index) { if (expected[exp] === input[inp]) inp++; exp++; }
    const after = exp + mk.length;
    // literal run until next marker or end
    const next = markers[k + 1];
    const runEnd = next ? next.index : expected.length;
    const literal = expected.slice(after, runEnd);
    let value;
    const valueStart = inp;
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

const MAP = {
  NAME: 'PERSON', ADDRESS: 'LOCATION', EMAIL: 'EMAIL_ADDRESS', PHONE: 'PHONE_NUMBER',
  CARD: 'CREDIT_CARD', IP: 'IP_ADDRESS', SSN: 'US_SSN',
};
const overlaps = (a, b) => a.start < b.end && b.start < a.end;

const engines = {};

// 1. openredaction (current dependency)
{
  const { LiteOpenRedaction } = await import(new URL('../../node_modules/@openredaction/core/dist/lite.mjs', import.meta.url).href);
  const red = new LiteOpenRedaction({ redactionMode: 'placeholder' });
  engines.openredaction = {
    typeMatch: (corpus, t) => t === corpus || ({ INDIAN_AADHAAR: 'AADHAAR', CREDIT_CARD: 'CARD', IP_ADDRESS: 'IP', DATE_OF_BIRTH: 'DOB', DRIVING_LICENSE_US: 'DL', DRIVER_ID: 'DL', PASSPORT_US: 'PASSPORT', US_SSN: 'SSN', EMAIL_ADDRESS: 'EMAIL', PHONE_NUMBER: 'PHONE' })[t] === corpus,
    async detect(text) {
      const res = await red.detect(text);
      return (res.detections || []).map(d => ({ type: d.type, start: Array.isArray(d.position) ? d.position[0] : d.start, end: Array.isArray(d.position) ? d.position[1] : d.end, score: d.confidence ?? 1, text: d.value ?? '' }));
    },
  };
}

// 2. @redactpii/node (no spans — output-only heuristic)
{
  const { Redactor } = await import('@redactpii/node');
  const red = new Redactor({ rules: { CREDIT_CARD: true, EMAIL: true, NAME: true, PHONE: true, SSN: true } });
  engines.redactpii = { async detect(text) { return { redacted: red.redact(text) }; } };
  engines.redactpii.typeMatch = () => false;
}

// 3. @siddicky/anonymizerts pattern-only
// 4. @siddicky/anonymizerts + NER (bert-base-NER)
{
  const mod = await import('@siddicky/anonymizerts');
  const anonP = new mod.PresidioAnalyzer({ useNER: false });
  engines.anonymizerts_patterns = { typeMatch: (corpus, t) => MAP[corpus] === t || t === corpus, async detect(text) { return (await anonP.analyze(text)).map(d => ({ type: d.entityType, start: d.start, end: d.end, score: d.score, text: d.text })); } };
  const anonN = new mod.PresidioAnalyzer({ useNER: true });
  const t0 = performance.now();
  await anonN.initialize();
  engines.anonymizerts_ner = {
    typeMatch: (corpus, t) => MAP[corpus] === t || t === corpus,
    nerInitMs: Math.round(performance.now() - t0),
    async detect(text) { return (await anonN.analyze(text)).map(d => ({ type: d.entityType, start: d.start, end: d.end, score: d.score, text: d.text })); },
  };
}

// 5. prototype: in-house TS recognizer registry (Indian PII patterns)
// Verhoeff checksum (Aadhaar uses it) — the Presidio 'validator' concept
const VERHOEFF_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VERHOEFF_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
const VERHOEFF_INV = [0,4,3,2,1,5,6,7,8,9];
function verhoeff(num) {
  let c = 0;
  const digits = String(num).split('').reverse().map(Number);
  for (let i = 0; i < digits.length; i++) c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][digits[i]]];
  return c === 0;
}

{
  const RECS = [
    { type: 'IFSC', priority: 80, re: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g },
    { type: 'AADHAAR', priority: 90, re: /\b[1-9]\d{3}[ ]?\d{4}[ ]?\d{4}\b/g, validate: (v) => verhoeff(v.replace(/ /g, '')) },
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
  engines.custom_ts_prototype = {
    typeMatch: (corpus, t) => t === corpus,
    async detect(text) {
      const spans = [];
      for (const rec of RECS) {
        rec.re.lastIndex = 0;
        let m;
        while ((m = rec.re.exec(text))) {
          const value = m[1] ?? m[0];
          if (rec.validate && !rec.validate(value)) continue;
          const start = m[1] ? m.index + m[0].indexOf(m[1]) : m.index;
          spans.push({ type: rec.type, start, end: start + value.length, score: rec.priority / 100, text: value });
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

// 6. piiranha ONNX via transformers.js (accuracy ceiling, CC-BY-NC-ND)
{
  const { pipeline } = await import('@huggingface/transformers');
  const t0 = performance.now();
  const ner = await pipeline('token-classification', 'onnx-community/piiranha-v1-detect-personal-information-ONNX', { dtype: 'q8' });
  const PIIRANHA_MAP = {
    GIVENNAME: 'NAME', SURNAME: 'NAME', TELEPHONENUM: 'PHONE', EMAIL: 'EMAIL',
    CREDITCARDNUMBER: 'CARD', DATEOFBIRTH: 'DOB', DRIVERLICENSENUM: 'DL',
    IDCARDNUM: 'ID', ACCOUNTNUM: 'BANK_ACC', TAXNUM: 'PAN',
    PASSWORD: 'SECRET', USERNAME: 'SECRET', SOCIALNUM: 'SSN',
    STREET: 'ADDRESS', CITY: 'ADDRESS', BUILDINGNUM: 'ADDRESS', ZIPCODE: 'ADDRESS',
  };
  engines.piiranha = {
    typeMatch: (corpus, t) => PIIRANHA_MAP[t] === corpus || t === corpus,
    nerInitMs: Math.round(performance.now() - t0),
    async detect(text) {
      const toks = await ner(text, { aggregation_strategy: 'none', ignore_labels: ['O'] });
      const dets = [];
      let pos = 0;
      for (const t of toks) {
        const w = t.word.replace(/^##/, '');
        const found = text.indexOf(w, pos);
        if (found === -1) continue;
        dets.push({ type: t.entity.replace(/^[BI]-/, ''), start: found, end: found + w.length, score: t.score, text: w });
        pos = found + w.length;
      }
      // merge B/I runs of same type
      const merged = [];
      for (const d of dets) {
        const prev = merged[merged.length - 1];
        if (prev && prev.type === d.type && d.start <= prev.end) prev.end = d.end;
        else merged.push({ ...d });
      }
      return merged;
    },
  };
}

// ---------- evaluation ----------
const cases = corpus1.map(c => ({ id: c.id, cat: c.category, input: c.input, expected: c.expected_output }));
const results = {};
for (const [name, eng] of Object.entries(engines)) {
  const stats = { trueSpans: 0, coveredAny: 0, coveredTyped: 0, fps: 0, ms: 0, perType: {}, exactMatch: 0, n: cases.length };
  const t0 = performance.now();
  for (const c of cases) {
    const spans = extractTrueSpans(c.input, c.expected);
    stats.trueSpans += spans.length;
    if (name === 'redactpii') {
      const { redacted } = await eng.detect(c.input);
      let all = true;
      for (const s of spans) {
        stats.perType[s.type] ??= { n: 0, hit: 0 };
        stats.perType[s.type].n++;
        const hit = s.value.length < 4 || !redacted.includes(s.value);
        if (hit) { stats.coveredAny++; stats.coveredTyped++; stats.perType[s.type].hit++; } else all = false;
      }
      if (all && spans.length > 0) stats.exactMatch++;
      continue;
    }
    const detections = await eng.detect(c.input);
    const trueRanges = spans.map(s => ({ start: s.start, end: s.end }));
    stats.fps += detections.filter(d => !trueRanges.some(t => overlaps(d, t))).length;
    let allCovered = true;
    for (const s of spans) {
      stats.perType[s.type] ??= { n: 0, hit: 0 };
      stats.perType[s.type].n++;
      const hit = detections.find(d => overlaps(d, s));
      const typed = detections.find(d => overlaps(d, s) && eng.typeMatch(s.type, d.type));
      if (hit) stats.coveredAny++; else allCovered = false;
      if (typed) { stats.coveredTyped++; stats.perType[s.type].hit++; } else allCovered = false;
    }
    if (allCovered && spans.length > 0) stats.exactMatch++;
  }
  stats.ms = Math.round(performance.now() - t0);
  results[name] = stats;
}

// ---------- report ----------
const typeTotals = {};
for (const c of cases) for (const s of extractTrueSpans(c.input, c.expected)) typeTotals[s.type] = (typeTotals[s.type] ?? 0) + 1;
console.log('cases: ' + cases.length + ' | true spans: ' + Object.values(typeTotals).reduce((a, b) => a + b, 0));
console.log('per-type true counts:', JSON.stringify(typeTotals));
console.log();
for (const [name, r] of Object.entries(results)) {
  console.log(`### ${name}  (${r.ms}ms, nerInit=${r.nerInitMs ?? 'n/a'}ms)`);
  console.log(`  recall(typed): ${(100 * r.coveredTyped / r.trueSpans).toFixed(1)}%  coverage(any): ${(100 * r.coveredAny / r.trueSpans).toFixed(1)}%  FP detections: ${r.fps}`);
  const missed = Object.entries(r.perType).filter(([, v]) => v.hit < v.n).map(([t, v]) => `${t}:${v.hit}/${v.n}`);
  if (name === "custom_ts_prototype" || name === "piiranha") console.log("  perType:", JSON.stringify(Object.fromEntries(Object.entries(r.perType).map(([t,v]) => [t, v.hit + "/" + v.n]))));
  if (missed.length) console.log(`  misses: ${missed.join(', ')}`);
  console.log(`  fully-correct cases: ${r.exactMatch}/${r.n}`);
}
