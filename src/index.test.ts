import { describe, expect, it } from 'vitest';
import type { MastraDBMessage } from '@mastra/core/agent/message-list';
import { createLayeredPii } from './index.js';

const message = (parts: unknown[], extra: Record<string, unknown> = {}): MastraDBMessage => ({
  id: 'synthetic-message',
  role: 'user',
  createdAt: new Date(0),
  content: { format: 2, parts, ...extra },
} as MastraDBMessage);

function containsSensitive(text: string): boolean {
  return /(?:canary|alpha@example\.test|123-45-6789)\b/i.test(text);
}

function outputHasSensitive(value: unknown): boolean {
  return containsSensitive(JSON.stringify(value));
}

describe('Alpha 1 deterministic PII redaction', () => {
  it('redacts structured identifiers with stable taxonomy placeholders', async () => {
    const pii = createLayeredPii();
    const output = await pii.redactText(`email ${'alpha'}@${'example.test'} and SSN 123-45-6789`);
    expect(output.includes('[EMAIL_1]')).toBe(true);
    expect(output.includes('[SSN_1]')).toBe(true);
    expect(containsSensitive(output)).toBe(false);
  });

  it('normalizes representative dependency detections to stable entities', async () => {
    const cases = [
      ['email', 'email alpha@example.test', '[EMAIL_1]'],
      ['phone', 'phone +44 7700 900123', '[PHONE_1]'],
      ['ssn', 'SSN 123-45-6789', '[SSN_1]'],
      ['credit card', 'card 4111 1111 1111 1111', '[CREDIT-CARD_1]'],
      ['bank account', 'bank account 12345678', '[BANK-ACCOUNT_1]'],
      ['public IP', 'IP 192.0.2.1', '[IP-ADDRESS_1]'],
      ['UUID', 'device UUID 550e8400-e29b-41d4-a716-446655440000', '[UUID_1]'],
      ['passport', 'passport number AB123456', '[PASSPORT_1]'],
      ['date of birth', 'DOB 01/02/1990', '[DATE-OF-BIRTH_1]'],
      ['credential', 'secret=abcd1234', '[TOKEN_1]'],
      ['medical ID', 'NHS number 943 476 5919', '[MEDICAL-ID_1]'],
    ] as const;
    const pii = createLayeredPii();
    for (const [, input, placeholder] of cases) {
      const output = await pii.redactText(input);
      expect(output.includes(placeholder)).toBe(true);
      expect(containsSensitive(output)).toBe(false);
    }
  });

  it('normalizes credential forms before account forms for entity filtering', async () => {
    const pii = createLayeredPii({ entities: ['token'] });
    const output = await pii.redactText(
      'STRIPE_API_KEY=sk_test_51H8abc12345678901234567890 ' +
      'GCP_SERVICE_ACCOUNT {"type":"service_account","private_key_id":"1234567890123456789012345678901234567890"}',
    );
    expect(output.includes('sk_test_')).toBe(false);
    expect(output.includes('1234567890123456789012345678901234567890')).toBe(false);
    expect(output.includes('[TOKEN_1]')).toBe(true);
    expect(output.includes('[TOKEN_2]')).toBe(true);
  });

  it('does not treat embedded ip text as an ip entity', async () => {
    const pii = createLayeredPii({
      patterns: [{ name: 'striped', regex: /STRIPE-[A-Z]+/g, entity: 'custom' }],
      entities: ['ip-address'],
    });
    expect(await pii.redactText('STRIPE-KEY')).toBe('STRIPE-KEY');
  });

  it('accepts the issue-shaped deterministic layer option', async () => {
    const pii = createLayeredPii({ layers: ['deterministic'] });
    const output = await pii.redactText('Email alpha@example.test', { layers: ['deterministic'] });
    expect(output.includes('[EMAIL_1]')).toBe(true);
    expect(containsSensitive(output)).toBe(false);
  });

  it('rejects deferred NER and model layers', () => {
    expect(() => createLayeredPii({ layers: ['ner'] })).toThrow('not available');
    expect(() => createLayeredPii({ layers: ['model'] })).toThrow('not available');
    const pii = createLayeredPii();
    expect(pii.redactText('safe', { layers: ['ner'] })).rejects.toThrow('not available');
    expect(pii.redactText('safe', { layers: ['model'] })).rejects.toThrow('not available');
  });

  it('redacts configured patterns as part of deterministic', async () => {
    const pii = createLayeredPii({
      patterns: [{ name: 'synthetic-key', regex: /CANARY-[0-9]+/g, entity: 'token' }],
    });
    const output = await pii.redactText('value CANARY-12345');
    expect(output).toBe('value [TOKEN_1]');
  });

  it('merges a transitive overlap group to its full union', async () => {
    const pii = createLayeredPii({
      patterns: [
        { name: 'prefix', regex: /A1-B2/g, entity: 'custom', priority: 1 },
        { name: 'middle', regex: /B2-C3/g, entity: 'token', priority: 2 },
        { name: 'suffix', regex: /C3-D4/g, entity: 'email', priority: 3 },
      ],
    });
    const output = await pii.redactText('A1-B2-C3-D4');
    expect(output).toBe('[CUSTOM_1]');
    expect(output.includes('A1')).toBe(false);
    expect(output.includes('D4')).toBe(false);
  });

  it('keeps the longest span across an overlap group with different starts', async () => {
    const pii = createLayeredPii({
      patterns: [
        { name: 'short', regex: /OVERLAP-12/g, entity: 'custom', priority: 1 },
        { name: 'long', regex: /12-TAIL-EXTRA-LONG/g, entity: 'token', priority: 2 },
      ],
    });
    const output = await pii.redactText('OVERLAP-12-TAIL-EXTRA-LONG');
    expect(output.includes('[TOKEN_1]')).toBe(true);
    expect(output.includes('[CUSTOM_1]')).toBe(false);
    expect(containsSensitive(output)).toBe(false);
  });

  it('strips sticky and forces global on custom regex clones', async () => {
    const pii = createLayeredPii({
      patterns: [{ name: 'sticky', regex: /STICKY-[0-9]+/y, entity: 'token' }],
    });
    const output = await pii.redactText('prefix STICKY-42 suffix STICKY-43');
    expect(output.includes('[TOKEN_1]')).toBe(true);
    expect(output.includes('[TOKEN_2]')).toBe(true);
    expect(containsSensitive(output)).toBe(false);
  });

  it('fails closed for invalid and bounded-over-limit local input', async () => {
    const pii = createLayeredPii();
    expect(await pii.redactText(null as unknown as string)).toBe('[REDACTION_FAILED]');
    expect(await pii.redactText('x'.repeat(1_000_001))).toBe('[REDACTION_FAILED]');
  });

  it('redacts reasoning and reasoning detail text while cloning all objects', async () => {
    const detail = { type: 'text', text: 'detail synthetic@example.test', signature: 'sig' };
    const redactedDetail = { type: 'redacted', data: 'opaque' };
    const reasoning = { type: 'reasoning', reasoning: 'reason synthetic@example.test', details: [detail, redactedDetail] };
    const original = message([reasoning]);
    const before = structuredClone(original);
    const pii = createLayeredPii();
    const result = await pii.processor.processInput?.({
      messages: [original], systemMessages: [], messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    const output = result && 'messages' in result ? result.messages[0] : undefined;
    expect(original).toEqual(before);
    expect(outputHasSensitive(output)).toBe(false);
    expect(output?.content.parts[0]).not.toBe(reasoning);
    const outputReasoning = output?.content.parts[0] as typeof reasoning;
    expect(outputReasoning.details[0]).not.toBe(detail);
    expect(outputReasoning.details[1]).not.toBe(redactedDetail);
    expect(outputReasoning.details[1]).toEqual(redactedDetail);
  });

  it('fails closed for malformed reasoning details without leaking data', async () => {
    const original = message([{ type: 'reasoning', reasoning: 'secret synthetic@example.test', details: [{ type: 'text', text: 123 }] }]);
    const pii = createLayeredPii();
    const result = await pii.processor.processInput?.({
      messages: [original], systemMessages: [], messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    const output = result && 'messages' in result ? result.messages[0] : undefined;
    expect(outputHasSensitive(output)).toBe(false);
    expect(output?.content.parts[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
  });

  it('redacts every MastraDB textual representation and clones parts', async () => {
    const image = { type: 'image', image: 'synthetic-image' };
    const original = message([
      { type: 'text', text: 'synthetic@example.test' },
      image,
    ], { content: 'copy synthetic@example.test', reasoning: 'reason synthetic@example.test' });
    const before = structuredClone(original);
    const pii = createLayeredPii();
    const result = await pii.processor.processInput?.({
      messages: [original],
      systemMessages: [],
      messageList: {} as never,
      abort: () => { throw new Error('abort'); },
      state: {},
      retryCount: 0,
    });
    expect(original).toEqual(before);
    const outputMessages = result && 'messages' in result ? result.messages : [];
    const output = outputMessages[0];
    expect(outputHasSensitive(output)).toBe(false);
    expect(output?.content.parts[1]).not.toBe(image);
    expect(output?.content.parts[1]).toEqual(before.content.parts[1]);
    expect(output?.content.parts[0]).not.toBe(original.content.parts[0]);
  });

  it('redacts system messages and fails closed for malformed input without leaking data', async () => {
    const systemPart = { type: 'image', image: 'synthetic-image' };
    const malformed = message([], { content: 'synthetic@example.test', parts: null });
    const pii = createLayeredPii();
    const result = await pii.processor.processInput?.({
      messages: [malformed],
      systemMessages: [
        { role: 'system', content: 'system synthetic@example.test' },
        { role: 'user', content: [{ type: 'text', text: 'user synthetic@example.test' }, systemPart] },
      ] as never,
      messageList: {} as never,
      abort: () => { throw new Error('abort'); },
      state: {},
      retryCount: 0,
    });
    const messages = result && 'messages' in result ? result.messages : [];
    const systemMessages = result && 'systemMessages' in result ? result.systemMessages : [];
    expect(outputHasSensitive(messages)).toBe(false);
    expect(outputHasSensitive(systemMessages)).toBe(false);
    expect(systemMessages[1]?.content[1]).not.toBe(systemPart);
    expect(systemMessages[1]?.content[1]).toEqual(systemPart);
    expect(messages[0]?.content.parts[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
  });

  it('does not mutate caller-owned messages and warmup is idempotent', async () => {
    const pii = createLayeredPii({
      id: 'alpha-one',
      patterns: [{ name: 'synthetic-canary', regex: /CANARY-[A-Z]+/g, entity: 'custom' }],
    });
    const first = pii.warmup();
    expect(await Promise.all([first, pii.warmup()])).toEqual([undefined, undefined]);
    const original = message([{ type: 'text', text: 'CANARY-ALPHA synthetic@example.test' }]);
    const before = structuredClone(original);
    await pii.processor.processInput?.({
      messages: [original],
      systemMessages: [],
      messageList: {} as never,
      abort: () => { throw new Error('abort'); },
      state: {},
      retryCount: 0,
    });
    expect(original).toEqual(before);
  });
});
