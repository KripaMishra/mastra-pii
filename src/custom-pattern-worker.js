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
        if (length === 0 || spans.length >= MAX_MATCHES) throw new Error('unsafe match');
        spans.push({ patternIndex, start: match.index, end: match.index + length });
      }
    }
    parentPort?.postMessage({ ok: true, spans });
  } catch {
    parentPort?.postMessage({ ok: false });
  }
});
