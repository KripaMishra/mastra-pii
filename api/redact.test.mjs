import { Readable } from 'node:stream';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import handler from './redact.mjs';

function response() {
  const headers = new Map();
  return {
    headers,
    statusCode: 200,
    payload: undefined,
    setHeader(name, value) { headers.set(name, value); },
    status(code) {
      this.statusCode = code;
      return { json: (payload) => { this.payload = payload; return payload; } };
    },
    end(body) { this.payload = JSON.parse(body); },
  };
}

async function invoke(body, { method = 'POST', stream = false, chunks } = {}) {
  const req = stream ? Readable.from(chunks ?? [body]) : { body };
  req.method = method;
  const res = response();
  await handler(req, res);
  return res;
}

describe('redaction API contract', () => {
  it('rejects custom regexes that match the empty string with HTTP 400', async () => {
    const result = await invoke({ text: 'safe', config: { patterns: [{ name: 'empty', regex: 'a*' }] } });
    expect(result.statusCode).toBe(400);
    expect(result.payload.error).toMatch(/non-empty|empty/i);
  });

  it('accepts documented pattern.type aliases', async () => {
    const result = await invoke({ text: 'CANARY-123', config: { patterns: [{ type: 'token', regex: 'CANARY-[0-9]+' }] } });
    expect(result.statusCode).toBe(200);
    expect(result.payload.output).toContain('[CUSTOM_1]');
  });

  it('accepts non-global custom regex flags', async () => {
    const result = await invoke({ text: 'A', config: { patterns: [{ name: 'letter', regex: 'a', flags: 'i' }] } });
    expect(result.statusCode).toBe(200);
    expect(result.payload.output).toContain('[CUSTOM_1]');
  });

  it('rejects zero-width custom regexes with non-global flags', async () => {
    const result = await invoke({ text: 'ab', config: { patterns: [{ name: 'boundary', regex: 'a+|(?=b)', flags: 'i' }] } });
    expect(result.statusCode).toBe(400);
    expect(result.payload.error).toMatch(/non-empty|zero-width/i);
  });

  it('counts only placeholders created by this request', async () => {
    const result = await invoke({ text: 'Existing [EMAIL_99] and alpha@example.test' });
    expect(result.statusCode).toBe(200);
    expect(result.payload.redactionCount).toBe(1);

    const unchanged = await invoke({ text: 'Existing [EMAIL_99]' });
    expect(unchanged.payload.redactionCount).toBe(0);

    const transformed = await invoke({
      text: 'Existing [EMAIL_99]',
      config: { patterns: [{ name: 'replace-existing', regex: '\\[EMAIL_99\\]' }] },
    });
    expect(transformed.statusCode).toBe(200);
    expect(transformed.payload.redactionCount).toBe(1);
  });

  it('preserves an existing failure placeholder as literal input', async () => {
    const result = await invoke({ text: 'Existing [REDACTION_FAILED] and alpha@example.test' });
    expect(result.statusCode).toBe(200);
    expect(result.payload.output).toContain('[REDACTION_FAILED]');
    expect(result.payload.redactionCount).toBe(1);
  });

  it('does not classify an existing failure placeholder as a detector failure', async () => {
    const result = await invoke({ text: 'Existing [REDACTION_FAILED]' });
    expect(result.statusCode).toBe(200);
    expect(result.payload.output).toBe('Existing [REDACTION_FAILED]');
    expect(result.payload.redactionCount).toBe(0);
  });

  it('rejects zero-width regexes that match the request text', async () => {
    const result = await invoke({ text: 'safe', config: { patterns: [{ name: 'boundary', regex: '\\b' }] } });
    expect(result.statusCode).toBe(400);
    expect(result.payload.error).toMatch(/non-empty|zero-width/i);
  });

  it('does not run catastrophic zero-width regexes on the request thread', async () => {
    const result = await invoke({
      text: `${'a'.repeat(5_000)}!`,
      config: { patterns: [{ name: 'lookahead', regex: '(?=(a+)+$)' }] },
    });
    expect(result.statusCode).toBe(400);
    expect(result.payload.error).toMatch(/timed out/i);
  });

  it('returns an error response when redaction fails closed', async () => {
    const result = await invoke({
      text: 'x'.repeat(10_001),
      config: { patterns: [{ name: 'too-many-matches', regex: 'x' }] },
    });
    expect(result.statusCode).toBe(500);
    expect(result.payload.error).toMatch(/redaction failed/i);
    expect(result.payload.output).toBeUndefined();
  });

  it('bounds request, config, and input body sizes', async () => {
    const request = await invoke(JSON.stringify({ text: 'x'.repeat(1_200_000) }), { stream: true });
    expect(request.statusCode).toBe(413);

    const config = await invoke({ text: 'safe', config: { id: 'x'.repeat(70_000) } });
    expect(config.statusCode).toBe(413);

    const pattern = await invoke({ text: 'safe', config: { patterns: [{ name: 'large', regex: 'x'.repeat(4_097) }] } });
    expect(pattern.statusCode).toBe(413);

    const body = await invoke({ text: 'x'.repeat(1_000_001) });
    expect(body.statusCode).toBe(413);
  });

  it('preserves UTF-8 when a streamed body splits a code point', async () => {
    const body = Buffer.from(JSON.stringify({ text: 'café' }));
    const split = body.indexOf(0xc3) + 1;
    const result = await invoke(undefined, {
      stream: true,
      chunks: [body.subarray(0, split), body.subarray(split)],
    });
    expect(result.statusCode).toBe(200);
    expect(result.payload.output).toBe('café');
  });

  it('resolves the custom-pattern worker next to the handler for the Vercel includeFiles layout', async () => {
    const workerPath = fileURLToPath(new URL('../dist/custom-pattern-worker.js', import.meta.url));
    expect(existsSync(workerPath)).toBe(true);
    const result = await invoke({ text: 'CANARY-1', config: { patterns: [{ name: 'canary', regex: 'CANARY-[0-9]+' }] } });
    expect(result.statusCode).toBe(200);
    expect(result.payload.output).toContain('[CUSTOM_1]');
  });

  it('does not advertise wildcard CORS for the same-origin console', async () => {
    const result = await invoke(undefined, { method: 'OPTIONS' });
    expect(result.statusCode).toBe(204);
    expect(result.headers.get('Access-Control-Allow-Origin')).toBeUndefined();
  });
});
