import { parentPort } from 'node:worker_threads';

const MAX_MATCHES = 10_000;

parentPort?.once('message', ({ text, patterns }) => {
  try {
    if (typeof text !== 'string' || !Array.isArray(patterns)) throw new Error('invalid request');
    const spans = [];
    for (const [patternIndex, pattern] of patterns.entries()) {
      if (!pattern || typeof pattern.source !== 'string' || typeof pattern.flags !== 'string') {
        throw new Error('invalid pattern');
      }
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(text)) !== null) {
        const length = match[0].length;
        if (length === 0) {
          parentPort?.postMessage({ ok: false, reason: 'zero-width', patternIndex });
          return;
        }
        if (spans.length >= MAX_MATCHES) {
          parentPort?.postMessage({ ok: false, reason: 'too-many-matches' });
          return;
        }
        spans.push({ patternIndex, start: match.index, end: match.index + length });
      }
    }
    parentPort?.postMessage({ ok: true, spans });
  } catch {
    parentPort?.postMessage({ ok: false });
  }
});
