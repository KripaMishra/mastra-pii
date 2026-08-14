import { Worker } from 'node:worker_threads';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it, vi } from 'vitest';
import type { MastraDBMessage } from '@mastra/core/agent/message-list';
import {
  createLayeredPii,
  createLocalAdapter,
  createPresidioAdapter,
  INDIAN_DEFAULTS,
} from './index.js';
import type { Analyzer } from './index.js';

const message = (parts: unknown[], extra: Record<string, unknown> = {}): MastraDBMessage => ({
  id: 'synthetic-message',
  role: 'user',
  createdAt: new Date(0),
  content: { format: 2, parts, ...extra },
} as MastraDBMessage);

function containsSensitive(text: string): boolean {
  return /(?:canary|synthetic@example\.test|alpha@example\.test|7316 7253 5875|ABCDE1234F)\b/i.test(text);
}

function outputHasSensitive(value: unknown): boolean {
  const serialized = JSON.stringify(value);
  return typeof serialized === 'string' && containsSensitive(serialized);
}

const processorArgs = (prompt: unknown[], stepNumber: number) => ({
  prompt,
  model: {} as never,
  stepNumber,
  steps: [],
  state: {},
  retryCount: 0,
  abort: () => { throw new Error('abort'); },
});

describe('Alpha 1 deterministic PII redaction', () => {
  it('redacts bounded documents while preserving structure', async () => {
    const pii = createLayeredPii();
    const output = await pii.redactDocument({
      email: 'alpha@example.test',
      nested: { phone: '+91 98765 43210', aadhaar: '7316 7253 5875', verified: true, attempts: 2 },
    });
    expect(output).toEqual({
      email: '[EMAIL_1]',
      nested: { phone: '[PHONE_1]', aadhaar: '[AADHAAR_1]', verified: true, attempts: 2 },
    });

    let tooDeep: unknown = 'safe';
    for (let depth = 0; depth < 33; depth += 1) tooDeep = { value: tooDeep };
    expect(() => pii.redactDocument(tooDeep)).toThrow('payload limit exceeded');
    expect(() => pii.redactDocument(Array(10_000).fill(null))).toThrow('payload limit exceeded');
  });

  it('redacts structured identifiers with stable taxonomy placeholders', async () => {
    const pii = createLayeredPii();
    const output = await pii.redactText(`email ${'alpha'}@${'example.test'} and Aadhaar 7316 7253 5875`);
    expect(output.includes('[EMAIL_1]')).toBe(true);
    expect(output.includes('[AADHAAR_1]')).toBe(true);
    expect(containsSensitive(output)).toBe(false);
  });

  it('normalizes representative dependency detections to stable entities', async () => {
    const cases = [
      ['email', 'email alpha@example.test', '[EMAIL_1]'],
      ['phone', 'phone +91 98765 43210', '[PHONE_1]'],
      ['aadhaar', 'Aadhaar 7316 7253 5875', '[AADHAAR_1]'],
      ['pan', 'PAN ABCDE1234F', '[PAN_1]'],
      ['upi', 'UPI 9999999999@ybl', '[UPI_1]'],
      ['ifsc', 'IFSC SBIN0001234', '[IFSC_1]'],
      ['bank account', 'bank account 123456789', '[BANK-ACCOUNT_1]'],
      ['public IP', 'IP 192.0.2.1', '[IP-ADDRESS_1]'],
      ['passport', 'passport number Z1234567', '[PASSPORT_1]'],
      ['date of birth', 'DOB 01/02/1990', '[DATE-OF-BIRTH_1]'],
      ['credential', 'secret=abcd1234', '[TOKEN_1]'],
      ['voter id', 'voter id ABC1234567', '[VOTER-ID_1]'],
      ['driving license', 'DL MH-12-2011-0012345', '[DRIVING-LICENSE_1]'],
      ['vehicle', 'vehicle DL 01 AB 1234', '[VEHICLE_1]'],
      ['credit card', 'card 4532 1122 3344 5566', '[CREDIT-CARD_1]'],
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
      'STRIPE_KEY=sk-51H8abc12345678901234567890 ' +
      'password=hunter2 ' +
      'account 9876543210',
    );
    expect(output.includes('sk-51H8abc')).toBe(false);
    expect(output.includes('hunter2')).toBe(false);
    expect(output.includes('9876543210')).toBe(true);
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
    expect(output.includes('[TOKEN_1]')).toBe(true);
    expect(containsSensitive(output)).toBe(false);
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
    expect(output.includes('[EMAIL_1]')).toBe(true);
    expect(output.includes('A1')).toBe(false);
    expect(output.includes('D4')).toBe(false);
  });

  it('uses full regex matches rather than capture groups', async () => {
    const pii = createLayeredPii({
      patterns: [{ name: 'capture', regex: /(CANARY)-[0-9]+/g, entity: 'token' }],
    });
    const output = await pii.redactText('value CANARY-12345');
    expect(output.includes('[TOKEN_1]')).toBe(true);
    expect(containsSensitive(output)).toBe(false);
  });

  it('uses configured priority with deterministic declaration-order ties', async () => {
    const highPriority = createLayeredPii({ patterns: [
      { name: 'low', regex: /CANARY-[0-9]+/g, entity: 'custom', priority: 1 },
      { name: 'high', regex: /CANARY-[0-9]+/g, entity: 'token', priority: 9 },
    ] });
    const tied = createLayeredPii({ patterns: [
      { name: 'first', regex: /CANARY-[0-9]+/g, entity: 'custom', priority: 5 },
      { name: 'second', regex: /CANARY-[0-9]+/g, entity: 'token', priority: 5 },
    ] });
    const highOutput = await highPriority.redactText('CANARY-12345');
    const tiedOutput = await tied.redactText('CANARY-12345');
    expect(highOutput.includes('[TOKEN_1]')).toBe(true);
    expect(tiedOutput.includes('[CUSTOM_1]')).toBe(true);
    expect(containsSensitive(highOutput) || containsSensitive(tiedOutput)).toBe(false);
  });

  it('runs every custom pattern against original text and redacts the overlap union', async () => {
    const pii = createLayeredPii({ patterns: [
      { name: 'left', regex: /CANARY-LEFT-CENTER/g, entity: 'custom', priority: 1 },
      { name: 'right', regex: /CENTER-RIGHT/g, entity: 'token', priority: 2 },
    ] });
    const output = await pii.redactText('CANARY-LEFT-CENTER-RIGHT');
    expect(output.includes('[TOKEN_1]')).toBe(true);
    expect(containsSensitive(output) || output.includes('RIGHT')).toBe(false);
  });

  it('terminates catastrophic custom regexes and fails closed', async () => {
    const pii = createLayeredPii({ patterns: [{ name: 'catastrophic', regex: /(a+)+$/g, entity: 'custom' }] });
    const started = Date.now();
    const output = await pii.redactText(`${'a'.repeat(50)}!`);
    expect(output === '[REDACTION_FAILED]').toBe(true);
    expect(Date.now() - started < 2_000).toBe(true);
  });

  it('batches and dedupes custom-pattern detection with one worker per chunk', async () => {
    const originalPostMessage = Worker.prototype.postMessage;
    const originalTerminate = Worker.prototype.terminate;
    const activeWorkers = new WeakSet<Worker>();
    let active = 0;
    let maximumActive = 0;
    let terminated = 0;
    const postMessage = vi.spyOn(Worker.prototype, 'postMessage').mockImplementation(function (
      this: Worker,
      ...args: Parameters<Worker['postMessage']>
    ) {
      activeWorkers.add(this);
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      return originalPostMessage.apply(this, args);
    });
    const terminate = vi.spyOn(Worker.prototype, 'terminate').mockImplementation(async function (this: Worker) {
      const result = await originalTerminate.call(this);
      if (activeWorkers.delete(this)) {
        active -= 1;
        terminated += 1;
      }
      return result;
    });
    try {
      const pii = createLayeredPii({ patterns: [{ name: 'canary', regex: /CANARY-[0-9]+/g, entity: 'custom' }] });
      const toolResult = (rows: unknown[]) => [{ role: 'tool', content: [{
        type: 'tool-result', toolCallId: 'call-1', toolName: 'lookup', output: { type: 'json', value: { rows } },
      }] }];
      // 40 identical strings dedupe to one detection: a single worker call.
      const duplicated = await pii.processor.processLLMRequest(processorArgs(
        toolResult(Array.from({ length: 40 }, () => 'CANARY-1')), 0) as never,
      );
      expect(outputHasSensitive(duplicated)).toBe(false);
      expect(terminated).toBe(1);
      // 300 unique strings split into two chunks: two serialized worker calls.
      const chunked = await pii.processor.processLLMRequest(processorArgs(
        toolResult(Array.from({ length: 300 }, (_, index) => `CANARY-${index}`)), 1) as never,
      );
      expect(outputHasSensitive(chunked)).toBe(false);
      expect(terminated).toBe(3);
      expect(maximumActive).toBe(1);
      expect(active).toBe(0);
    } finally {
      postMessage.mockRestore();
      terminate.mockRestore();
    }
  });

  it('times out worker startup and completes cleanup before settling', async () => {
    const originalEmit = Worker.prototype.emit;
    const originalTerminate = Worker.prototype.terminate;
    let terminated = false;
    const emit = vi.spyOn(Worker.prototype, 'emit').mockImplementation(function (
      this: Worker,
      event: string | symbol,
      ...args: unknown[]
    ) {
      if (event === 'online') return true;
      return originalEmit.call(this, event, ...args);
    });
    const terminate = vi.spyOn(Worker.prototype, 'terminate').mockImplementation(async function (this: Worker) {
      const result = await originalTerminate.call(this);
      terminated = true;
      return result;
    });
    try {
      const pii = createLayeredPii({ patterns: [{ name: 'canary', regex: /CANARY-[0-9]+/g, entity: 'custom' }] });
      const started = Date.now();
      expect(await pii.redactText('CANARY-1')).toBe('[REDACTION_FAILED]');
      expect(Date.now() - started).toBeLessThan(1_000);
      expect(terminated).toBe(true);
    } finally {
      emit.mockRestore();
      terminate.mockRestore();
    }
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
    const image = { type: 'image', image: new Uint8Array([1, 2, 3]) };
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
    const systemPart = { type: 'image', image: new Uint8Array([1, 2, 3]) };
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

  it('deep-redacts known Mastra and Core tool fields without mutation', async () => {
    const toolInvocation = {
      state: 'result', toolCallId: 'call-1', toolName: 'lookup',
      args: { customer: 'synthetic@example.test' },
      result: { nested: ['synthetic@example.test'] },
      rawInput: { query: 'synthetic@example.test' },
      errorText: 'failed synthetic@example.test',
      approval: { id: 'approval-1', reason: 'approve synthetic@example.test' },
    };
    const toolPart = { type: 'tool-invocation', toolInvocation, title: 'title synthetic@example.test' };
    const original = message([toolPart], { toolInvocations: [toolInvocation] });
    const systemMessages = [
      { role: 'assistant', content: [{ type: 'tool-call', toolCallId: 'call-2', toolName: 'lookup', args: { query: 'synthetic@example.test' } }] },
      { role: 'tool', content: [{
        type: 'tool-result', toolCallId: 'call-2', toolName: 'lookup', result: { value: 'synthetic@example.test' },
        experimental_content: [{ type: 'text', text: 'synthetic@example.test' }],
      }] },
    ];
    const beforeMessage = structuredClone(original);
    const beforeSystem = structuredClone(systemMessages);
    const pii = createLayeredPii();
    const result = await pii.processor.processInput({
      messages: [original], systemMessages: systemMessages as never, messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    expect(original).toEqual(beforeMessage);
    expect(systemMessages).toEqual(beforeSystem);
    expect(outputHasSensitive(result)).toBe(false);
    const output = 'messages' in result ? result.messages[0] : undefined;
    const outputInvocation = (output?.content.parts[0] as typeof toolPart | undefined)?.toolInvocation;
    expect(outputInvocation).not.toBe(toolInvocation);
    expect(outputInvocation?.args).not.toBe(toolInvocation.args);
    expect(outputInvocation?.result).not.toBe(toolInvocation.result);
  });

  it('copies structural identifiers verbatim while redacting their surrounding fields', async () => {
    const invocation = (toolCallId: string, toolName: string, approvalId = 'approval-safe') => ({
      state: 'approval-requested', toolCallId, toolName,
      args: { query: 'CANARY-QUERY synthetic@example.test' },
      approval: { id: approvalId },
    });
    const messages = [
      message([{ type: 'tool-invocation', toolInvocation: invocation('CANARY-CALL', 'CANARY-TOOL') }]),
      message([{ type: 'tool-invocation', toolInvocation: invocation('call-safe', 'lookup', 'CANARY-APPROVAL') }]),
      message([{ type: 'text', text: 'safe' }], { toolInvocations: [invocation('call-safe', 'lookup')] }),
    ];
    const systemMessages = [
      { role: 'assistant', content: [{ type: 'tool-call', toolCallId: 'CANARY-CALL', toolName: 'lookup', args: { query: 'CANARY-QUERY' } }] },
      { role: 'tool', content: [{ type: 'tool-result', toolCallId: 'CANARY-CALL', toolName: 'lookup', result: { query: 'CANARY-QUERY' } }] },
    ];
    const beforeMessages = structuredClone(messages);
    const beforeSystemMessages = structuredClone(systemMessages);
    const pii = createLayeredPii({ patterns: [{ name: 'identifier-canary', regex: /CANARY-[A-Z]+/g }] });
    const result = await pii.processor.processInput({
      messages, systemMessages: systemMessages as never, messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    expect(messages).toEqual(beforeMessages);
    expect(systemMessages).toEqual(beforeSystemMessages);
    const outputMessages = 'messages' in result ? result.messages : [];
    const outputSystemMessages = 'systemMessages' in result ? result.systemMessages : [];
    expect(outputMessages).toHaveLength(messages.length);
    const firstInvocation = (outputMessages[0]?.content.parts[0] as { toolInvocation?: Record<string, unknown> }).toolInvocation;
    const secondApproval = (outputMessages[1]?.content.parts[0] as { toolInvocation?: { approval?: Record<string, unknown> } }).toolInvocation?.approval;
    const legacyInvocation = (outputMessages[2]?.content.toolInvocations as Record<string, unknown>[] | undefined)?.[0];
    expect(firstInvocation).toMatchObject({ toolCallId: 'CANARY-CALL', toolName: 'CANARY-TOOL' });
    expect(firstInvocation?.args).toMatchObject({ query: expect.stringContaining('[CUSTOM_1]') });
    expect(secondApproval).toMatchObject({ id: 'CANARY-APPROVAL' });
    expect(legacyInvocation).toMatchObject({ toolCallId: 'call-safe', toolName: 'lookup' });
    expect(JSON.stringify(firstInvocation?.args)).not.toContain('CANARY-QUERY');
    expect(JSON.stringify(outputSystemMessages)).not.toContain('CANARY-QUERY');
    expect(JSON.stringify(outputSystemMessages)).toContain('CANARY-CALL');
    expect(outputSystemMessages).toHaveLength(systemMessages.length);
  });

  it('copies modern tool identifiers verbatim while redacting tool payloads', async () => {
    const prompt = [
      { role: 'assistant', content: [{ type: 'tool-call', toolCallId: 'CANARY-CALL', toolName: 'CANARY-TOOL', input: { query: 'CANARY-QUERY synthetic@example.test' } }] },
      { role: 'tool', content: [{ type: 'tool-result', toolCallId: 'call-safe', toolName: 'lookup', output: { type: 'json', value: { query: 'CANARY-QUERY synthetic@example.test' } } }] },
    ];
    const before = structuredClone(prompt);
    const pii = createLayeredPii({ patterns: [{ name: 'identifier-canary', regex: /CANARY-[A-Z]+/g }] });
    const result = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    expect(prompt).toEqual(before);
    const output = result && 'prompt' in result ? result.prompt : undefined;
    expect(output).toHaveLength(prompt.length);
    const callPart = output?.[0]?.content[0] as { toolCallId?: string; toolName?: string; input?: { query?: string } } | undefined;
    const resultPart = output?.[1]?.content[0] as { output?: { value?: { query?: string } } } | undefined;
    expect(callPart).toMatchObject({ toolCallId: 'CANARY-CALL', toolName: 'CANARY-TOOL' });
    expect(callPart?.input?.query).toContain('[CUSTOM_1]');
    expect(resultPart?.output?.value?.query).toContain('[CUSTOM_1]');
    expect(JSON.stringify(output)).not.toContain('CANARY-QUERY');
    expect(JSON.stringify(output)).toContain('CANARY-CALL');
  });

  it('preserves provider-generated UUID tool call ids verbatim', async () => {
    const toolCallId = 'call_550e8400-e29b-41d4-a716-446655440000';
    const pii = createLayeredPii();
    const prompt = [{ role: 'tool', content: [{
      type: 'tool-result', toolCallId, toolName: 'lookup', output: { type: 'json', value: { note: 'safe' } },
    }] }];
    const result = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    expect(result && 'prompt' in result ? result.prompt?.[0]?.content[0] : undefined).toMatchObject({ toolCallId });
  });

  it('preserves safe tool and approval identifiers exactly so call-result pairing survives', async () => {
    const toolCallId = 'call-safe-1';
    const toolName = 'lookup-safe';
    const approvalId = 'approval-safe-1';
    const legacyInvocation = {
      state: 'approval-requested', toolCallId, toolName,
      args: { customer: 'synthetic@example.test' },
      approval: { id: approvalId, reason: 'approve synthetic@example.test' },
    };
    const mastraMessages = [message(
      [{ type: 'tool-invocation', toolInvocation: legacyInvocation }],
      { toolInvocations: [legacyInvocation] },
    )];
    const systemMessages = [
      { role: 'assistant', content: [{ type: 'tool-call', toolCallId, toolName, args: { customer: 'synthetic@example.test' } }] },
      { role: 'tool', content: [{ type: 'tool-result', toolCallId, toolName, result: { customer: 'synthetic@example.test' } }] },
    ];
    const prompt = [
      { role: 'assistant', content: [{ type: 'tool-call', toolCallId, toolName, input: { customer: 'synthetic@example.test' } }] },
      { role: 'tool', content: [{ type: 'tool-result', toolCallId, toolName, output: { type: 'json', value: { customer: 'synthetic@example.test' } } }] },
    ];
    const beforeMastra = structuredClone(mastraMessages);
    const beforeSystem = structuredClone(systemMessages);
    const beforePrompt = structuredClone(prompt);
    const pii = createLayeredPii();
    const input = await pii.processor.processInput({
      messages: mastraMessages, systemMessages: systemMessages as never, messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    const llm = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    expect(mastraMessages).toEqual(beforeMastra);
    expect(systemMessages).toEqual(beforeSystem);
    expect(prompt).toEqual(beforePrompt);
    expect(outputHasSensitive(input) || outputHasSensitive(llm)).toBe(false);

    const outputMastra = 'messages' in input ? input.messages[0] : undefined;
    const outputLegacy = (outputMastra?.content.parts[0] as typeof mastraMessages[0]['content']['parts'][number] & { toolInvocation: typeof legacyInvocation }).toolInvocation;
    const outputLegacyCopy = outputMastra?.content.toolInvocations?.[0];
    const outputSystem = 'systemMessages' in input ? input.systemMessages : [];
    const outputPrompt = llm && 'prompt' in llm ? llm.prompt : undefined;
    expect(outputLegacy).toMatchObject({ toolCallId, toolName, approval: { id: approvalId } });
    expect(outputLegacy).not.toBe(legacyInvocation);
    expect(outputLegacy.approval).not.toBe(legacyInvocation.approval);
    expect(outputLegacyCopy).toMatchObject({ toolCallId, toolName, approval: { id: approvalId } });
    expect(outputSystem.map((item) => typeof item.content === 'string' ? undefined : item.content[0])).toEqual([
      expect.objectContaining({ toolCallId, toolName }),
      expect.objectContaining({ toolCallId, toolName }),
    ]);
    expect(outputPrompt?.map((item) => item.role === 'system' ? undefined : item.content[0])).toEqual([
      expect.objectContaining({ toolCallId, toolName }),
      expect.objectContaining({ toolCallId, toolName }),
    ]);
  });

  it('fails closed when identifier validation itself returns the failure placeholder', async () => {
    const failedIdentifier = 'x'.repeat(1_000_001);
    const mastraMessages = [message([{ type: 'tool-invocation', toolInvocation: {
      state: 'approval-requested', toolCallId: 'call-safe', toolName: 'lookup', args: {}, approval: { id: failedIdentifier },
    } }])];
    const prompt = [{ role: 'assistant', content: [{
      type: 'tool-call', toolCallId: failedIdentifier, toolName: 'lookup', input: {},
    }] }];
    const beforeMastra = structuredClone(mastraMessages);
    const beforePrompt = structuredClone(prompt);
    const pii = createLayeredPii();
    const input = await pii.processor.processInput({
      messages: mastraMessages, systemMessages: [], messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    const llm = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    expect(mastraMessages).toEqual(beforeMastra);
    expect(prompt).toEqual(beforePrompt);
    const outputMastra = 'messages' in input ? input.messages[0] : undefined;
    const outputPrompt = llm && 'prompt' in llm ? llm.prompt?.[0] : undefined;
    expect(outputMastra?.content.parts[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    expect(outputPrompt).toEqual({ role: 'system', content: '[REDACTION_FAILED]' });
  });

  it('sanitizes Mastra metadata, annotations, sources, and data parts without mutation', async () => {
    const messageProviderMetadata = { vendor: { note: 'synthetic@example.test' } };
    const contentProviderMetadata = { vendor: { note: 'synthetic@example.test' } };
    const metadata = { customer: 'synthetic@example.test' };
    const annotations = [{ note: 'synthetic@example.test' }];
    const textProviderMetadata = { vendor: { note: 'synthetic@example.test' } };
    const sourceProviderMetadata = { vendor: { note: 'synthetic@example.test' } };
    const nestedSourceProviderMetadata = { vendor: { note: 'synthetic@example.test' } };
    const documentProviderMetadata = { vendor: { note: 'synthetic@example.test' } };
    const dataProviderMetadata = { vendor: { note: 'synthetic@example.test' } };
    const data = { customer: { note: 'synthetic@example.test' } };
    const original = {
      ...message([
        { type: 'text', text: 'safe', providerMetadata: textProviderMetadata },
        {
          type: 'source',
          source: {
            sourceType: 'url', id: 'synthetic@example.test', url: 'https://example.test/synthetic@example.test',
            title: 'synthetic@example.test', providerMetadata: nestedSourceProviderMetadata,
          },
          providerMetadata: sourceProviderMetadata,
        },
        {
          type: 'source-document', sourceId: 'synthetic@example.test', mediaType: 'text/plain',
          title: 'synthetic@example.test', filename: 'synthetic@example.test', providerMetadata: documentProviderMetadata,
        },
        { type: 'data-customer', id: 'data-1', data, providerMetadata: dataProviderMetadata },
      ], { metadata, annotations, providerMetadata: contentProviderMetadata }),
      providerMetadata: messageProviderMetadata,
    } as unknown as MastraDBMessage;
    const before = structuredClone(original);
    const pii = createLayeredPii();
    const result = await pii.processor.processInput({
      messages: [original], systemMessages: [], messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    expect(original).toEqual(before);
    expect(outputHasSensitive(result)).toBe(false);
    const output = 'messages' in result ? result.messages[0] : undefined;
    const outputRecord = output as unknown as { providerMetadata: unknown };
    const content = output?.content as unknown as { metadata: unknown; annotations: unknown; providerMetadata: unknown; parts: Record<string, unknown>[] };
    expect(outputRecord.providerMetadata).not.toBe(messageProviderMetadata);
    expect(content.metadata).not.toBe(metadata);
    expect(content.annotations).not.toBe(annotations);
    expect(content.providerMetadata).not.toBe(contentProviderMetadata);
    expect(content.parts[0]?.providerMetadata).not.toBe(textProviderMetadata);
    expect((content.parts[1]?.source as { providerMetadata: unknown }).providerMetadata).not.toBe(nestedSourceProviderMetadata);
    expect(content.parts[1]?.providerMetadata).not.toBe(sourceProviderMetadata);
    expect(content.parts[2]?.providerMetadata).not.toBe(documentProviderMetadata);
    expect(content.parts[3]?.data).not.toBe(data);
    expect(content.parts[3]?.providerMetadata).not.toBe(dataProviderMetadata);
  });

  it('redacts providerOptions on Mastra, Core, and prompt messages and parts without mutation', async () => {
    const mastraMessageOptions = { vendor: { note: 'synthetic@example.test' } };
    const mastraContentOptions = { vendor: { note: 'synthetic@example.test' } };
    const mastraPartOptions = { vendor: { note: 'synthetic@example.test' } };
    const mastraPart = { type: 'text', text: 'safe', providerOptions: mastraPartOptions };
    const mastra = {
      ...message([mastraPart], { providerOptions: mastraContentOptions }),
      providerOptions: mastraMessageOptions,
    } as unknown as MastraDBMessage;
    const coreMessageOptions = { vendor: { note: 'synthetic@example.test' } };
    const corePartOptions = { vendor: { note: 'synthetic@example.test' } };
    const core = {
      role: 'user', providerOptions: coreMessageOptions,
      content: [{ type: 'text', text: 'safe', providerOptions: corePartOptions }],
    };
    const promptMessageOptions = { vendor: { note: 'synthetic@example.test' } };
    const promptPartOptions = { vendor: { note: 'synthetic@example.test' } };
    const prompt = [{
      role: 'user', providerOptions: promptMessageOptions,
      content: [{ type: 'text', text: 'safe', providerOptions: promptPartOptions }],
    }];
    const mastraBefore = structuredClone(mastra);
    const coreBefore = structuredClone(core);
    const promptBefore = structuredClone(prompt);
    const pii = createLayeredPii();
    const input = await pii.processor.processInput({
      messages: [mastra], systemMessages: [core] as never, messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    const llm = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    expect(mastra).toEqual(mastraBefore);
    expect(core).toEqual(coreBefore);
    expect(prompt).toEqual(promptBefore);
    expect(outputHasSensitive(input) || outputHasSensitive(llm)).toBe(false);
    const outputMastra = 'messages' in input ? input.messages[0] : undefined;
    const outputCore = 'systemMessages' in input ? input.systemMessages[0] : undefined;
    const outputPrompt = llm && 'prompt' in llm ? llm.prompt?.[0] : undefined;
    expect((outputMastra as unknown as { providerOptions: unknown }).providerOptions).not.toBe(mastraMessageOptions);
    expect((outputMastra?.content as unknown as { providerOptions: unknown }).providerOptions).not.toBe(mastraContentOptions);
    expect((outputMastra?.content.parts[0] as unknown as { providerOptions: unknown }).providerOptions).not.toBe(mastraPartOptions);
    expect((outputCore as unknown as { providerOptions: unknown }).providerOptions).not.toBe(coreMessageOptions);
    expect((outputCore?.content[0] as unknown as { providerOptions: unknown }).providerOptions).not.toBe(corePartOptions);
    expect((outputPrompt as unknown as { providerOptions: unknown }).providerOptions).not.toBe(promptMessageOptions);
    expect((outputPrompt?.content[0] as unknown as { providerOptions: unknown }).providerOptions).not.toBe(promptPartOptions);
  });

  it('redacts JSON property values while preserving object key names and descriptors', async () => {
    const providerOptions = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(providerOptions, 'synthetic@example.test', {
      value: { safe: true }, enumerable: true, configurable: false, writable: false,
    });
    const prompt = [{ role: 'user', content: [{ type: 'text', text: 'safe', providerOptions }] }];
    const pii = createLayeredPii();
    const result = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    const output = result && 'prompt' in result ? result.prompt?.[0] : undefined;
    const outputOptions = (output?.content[0] as unknown as { providerOptions: Record<string, unknown> }).providerOptions;
    // Keys are schema identifiers and are copied verbatim; the email-shaped key
    // is deliberately preserved while its nested object is cloned.
    expect(outputOptions).not.toBe(providerOptions);
    expect(Object.getPrototypeOf(outputOptions)).toBeNull();
    expect(Object.keys(outputOptions)).toEqual(['synthetic@example.test']);
    expect(Object.getOwnPropertyDescriptor(outputOptions, 'synthetic@example.test')).toMatchObject({
      enumerable: true, configurable: false, writable: false,
    });
    expect(Object.keys(providerOptions)).toEqual(['synthetic@example.test']);

    // PII-shaped keys no longer collide: both keys survive unchanged.
    const collision = { 'synthetic@example.test': true, '[EMAIL_1]': false };
    const kept = await pii.processor.processLLMRequest(processorArgs([{
      role: 'user', content: [{ type: 'text', text: 'safe', providerOptions: collision }],
    }], 0) as never);
    expect(kept && 'prompt' in kept ? kept.prompt?.[0]?.content[0] : undefined).toMatchObject({ providerOptions: collision });
  });

  it('redacts string values nested under PII-shaped keys', async () => {
    const pii = createLayeredPii();
    const prompt = [{ role: 'user', content: [{ type: 'text', text: 'safe', providerOptions: {
      'synthetic@example.test': 'alpha@example.test',
    } }] }];
    const result = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    const output = result && 'prompt' in result ? result.prompt?.[0] : undefined;
    const outputOptions = (output?.content[0] as unknown as { providerOptions: Record<string, unknown> }).providerOptions;
    expect(outputOptions).toEqual({ 'synthetic@example.test': '[EMAIL_1]' });
    expect(JSON.stringify(output)).not.toContain('alpha@example.test');
  });

  it('defaults custom pattern priority above built-in detections', async () => {
    const pii = createLayeredPii({ patterns: [{ name: 'whole-email', regex: /[a-z]+@[a-z.]+/g }] });
    expect(await pii.redactText('alpha@example.test')).toBe('[CUSTOM_1]');
  });

  it('allows repeated sibling references while rejecting true array cycles', async () => {
    const shared = { note: 'synthetic@example.test' };
    const providerOptions = { items: [shared, shared] };
    const pii = createLayeredPii();
    const result = await pii.processor.processLLMRequest(processorArgs([{
      role: 'user', content: [{ type: 'text', text: 'safe', providerOptions }],
    }], 0) as never);
    const output = result && 'prompt' in result ? result.prompt?.[0] : undefined;
    const outputItems = ((output?.content[0] as unknown as { providerOptions: { items: unknown[] } }).providerOptions.items);
    expect(outputHasSensitive(output)).toBe(false);
    expect(outputItems).toHaveLength(2);
    expect(outputItems[0]).toEqual(outputItems[1]);
    expect(outputItems[0]).not.toBe(outputItems[1]);
    expect(providerOptions.items[0]).toBe(providerOptions.items[1]);

    const cycle: unknown[] = [];
    cycle.push(cycle);
    const failed = await pii.processor.processLLMRequest(processorArgs([{
      role: 'user', content: [{ type: 'text', text: 'safe', providerOptions: { cycle } }],
    }], 0) as never);
    expect(failed && 'prompt' in failed ? failed.prompt?.[0] : undefined).toEqual({ role: 'system', content: '[REDACTION_FAILED]' });
  });

  it('fails only the containing message closed for malformed, cyclic, or over-depth providerOptions', async () => {
    const cyclic: Record<string, unknown> = { value: 'synthetic@example.test' };
    cyclic.self = cyclic;
    let deep: Record<string, unknown> = { value: 'synthetic@example.test' };
    for (let index = 0; index < 40; index += 1) deep = { child: deep };
    const mastra = message([
      { type: 'text', text: 'safe', providerOptions: cyclic },
    ]);
    const core = {
      role: 'user', providerOptions: deep,
      content: [{ type: 'text', text: 'safe' }],
    };
    const prompt = [{
      role: 'user', content: [{ type: 'text', text: 'safe', providerOptions: { invalid: 1n } }],
    }];
    const pii = createLayeredPii();
    const input = await pii.processor.processInput({
      messages: [mastra], systemMessages: [core] as never, messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    const llm = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    const outputMastra = 'messages' in input ? input.messages[0] : undefined;
    const outputCore = 'systemMessages' in input ? input.systemMessages[0] : undefined;
    const outputPrompt = llm && 'prompt' in llm ? llm.prompt?.[0] : undefined;
    expect(outputMastra?.content.parts[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    expect(outputCore).toEqual({ role: 'system', content: '[REDACTION_FAILED]' });
    expect(outputPrompt).toEqual({ role: 'system', content: '[REDACTION_FAILED]' });
    expect(outputHasSensitive([outputMastra, outputCore, outputPrompt])).toBe(false);
  });

  it('fails the containing message closed for cyclic or over-depth tool payloads', async () => {
    const cyclic: Record<string, unknown> = { value: 'synthetic@example.test' };
    cyclic.self = cyclic;
    let deep: Record<string, unknown> = { value: 'synthetic@example.test' };
    for (let index = 0; index < 40; index += 1) deep = { child: deep };
    const pii = createLayeredPii();
    for (const payload of [cyclic, deep]) {
      const original = message([{ type: 'tool-invocation', toolInvocation: {
        state: 'result', toolCallId: 'call', toolName: 'lookup', args: {}, result: payload,
      } }]);
      const result = await pii.processor.processInput({
        messages: [original], systemMessages: [], messageList: {} as never,
        abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
      });
      const output = 'messages' in result ? result.messages[0] : undefined;
      expect(outputHasSensitive(output)).toBe(false);
      expect(output?.content.parts[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    }
  });

  it('sanitizes every LLM call including a tool continuation and preserves safe media', async () => {
    const pii = createLayeredPii();
    const firstPrompt = [{ role: 'user', content: [{ type: 'text', text: 'first synthetic@example.test' }] }];
    const media = new Uint8Array([1, 2, 3]);
    const continuationPrompt = [
      { role: 'assistant', content: [
        { type: 'tool-call', toolCallId: 'call-1', toolName: 'lookup', input: { query: 'synthetic@example.test' } },
      ] },
      { role: 'tool', content: [
        { type: 'tool-result', toolCallId: 'call-1', toolName: 'lookup', output: { type: 'json', value: { customer: 'synthetic@example.test' } } },
        { type: 'tool-result', toolCallId: 'call-2', toolName: 'lookup', output: { type: 'error-text', value: 'synthetic@example.test' } },
      ] },
      { role: 'user', content: [{ type: 'file', data: media, mediaType: 'application/octet-stream', filename: 'synthetic@example.test' }] },
    ];
    const firstBefore = structuredClone(firstPrompt);
    const continuationBefore = structuredClone(continuationPrompt);
    const first = await pii.processor.processLLMRequest(processorArgs(firstPrompt, 0) as never);
    const continuation = await pii.processor.processLLMRequest(processorArgs(continuationPrompt, 1) as never);
    expect(firstPrompt).toEqual(firstBefore);
    expect(continuationPrompt).toEqual(continuationBefore);
    expect(outputHasSensitive(first) || outputHasSensitive(continuation)).toBe(false);
    const prompt = continuation && 'prompt' in continuation ? continuation.prompt : undefined;
    const outputMedia = prompt?.[2]?.content[0] as { data?: unknown } | undefined;
    expect(outputMedia?.data).toEqual(media);
    expect(outputMedia?.data).not.toBe(media);
  });

  it('replaces unsupported media with a part-level marker while cloning opaque binary media', async () => {
    const mastraBinary = new Uint8Array([4, 5, 6]);
    const coreBinary = new Uint8Array([7, 8, 9]).buffer;
    const promptBinary = new Uint8Array([10, 11, 12]);
    const coreUrl = new URL('https://example.test/synthetic@example.test');
    const promptUrl = new URL('https://example.test/synthetic@example.test');
    const mastraMessages = [
      message([{ type: 'file', data: 'data:text/plain,synthetic@example.test', mimeType: 'text/plain' }]),
      message([{ type: 'text', text: 'keep me synthetic@example.test' }], { experimental_attachments: [{ url: 'https://example.test/uploads/synthetic@example.test', name: 'synthetic@example.test' }] }),
      message([{ type: 'file', data: mastraBinary, mimeType: 'application/octet-stream' }]),
    ];
    const coreMessages = [
      { role: 'user', content: [{ type: 'image', image: coreUrl }] },
      { role: 'tool', content: [{
        type: 'tool-result', toolCallId: 'call-1', toolName: 'lookup', result: {},
        experimental_content: [{ type: 'image', data: 'c3ludGhldGljQGV4YW1wbGUudGVzdA==' }],
      }] },
      { role: 'user', content: [{ type: 'file', data: coreBinary, mimeType: 'application/octet-stream' }] },
    ];
    const prompt = [
      { role: 'user', content: [{ type: 'file', data: 'synthetic@example.test', mediaType: 'text/plain' }] },
      { role: 'user', content: [{ type: 'file', data: promptUrl, mediaType: 'image/png' }] },
      { role: 'tool', content: [{
        type: 'tool-result', toolCallId: 'call-2', toolName: 'lookup',
        output: { type: 'content', value: [{ type: 'media', data: 'c3ludGhldGljQGV4YW1wbGUudGVzdA==', mediaType: 'text/plain' }] },
      }] },
      { role: 'user', content: [{ type: 'file', data: promptBinary, mediaType: 'application/octet-stream' }] },
    ];
    const mastraBefore = structuredClone(mastraMessages);
    const pii = createLayeredPii();
    const input = await pii.processor.processInput({
      messages: mastraMessages, systemMessages: coreMessages as never, messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    const llm = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    expect(mastraMessages).toEqual(mastraBefore);
    expect((coreMessages[0]?.content[0] as { image: unknown }).image).toBe(coreUrl);
    expect((prompt[1]?.content[0] as { data: unknown }).data).toBe(promptUrl);
    expect((coreMessages[2]?.content[0] as { data: unknown }).data).toBe(coreBinary);
    expect((prompt[3]?.content[0] as { data: unknown }).data).toBe(promptBinary);
    const outputMastra = 'messages' in input ? input.messages : [];
    const outputCore = 'systemMessages' in input ? input.systemMessages : [];
    const outputPrompt = llm && 'prompt' in llm ? llm.prompt ?? [] : [];
    // Unsupported media fails closed at part granularity; the rest of each message survives.
    expect(outputMastra[0]?.content.parts[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    expect(outputMastra[0]?.id).toBe('synthetic-message');
    const attachments = outputMastra[1]?.content.experimental_attachments as { url?: string; name?: string }[] | undefined;
    expect(outputMastra[1]?.content.parts[0]).toMatchObject({ type: 'text', text: 'keep me [EMAIL_1]' });
    expect(attachments?.[0]?.url).toContain('[EMAIL_1]');
    expect(attachments?.[0]?.url).not.toContain('synthetic@example.test');
    expect(attachments?.[0]?.name).toBe('[EMAIL_1]');
    expect((outputCore[0]?.content as unknown[])[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    expect(outputCore[0]?.role).toBe('user');
    expect((outputCore[1]?.content as unknown[])[0]?.experimental_content).toEqual([{ type: 'text', text: '[REDACTION_FAILED]' }]);
    expect((outputPrompt[0]?.content as unknown[])[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    expect((outputPrompt[1]?.content as unknown[])[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    expect((outputPrompt[2]?.content as unknown[])[0]?.output).toMatchObject({ type: 'content', value: [{ type: 'text', text: '[REDACTION_FAILED]' }] });
    const outputMastraMedia = outputMastra[2]?.content.parts[0] as unknown as { data: unknown };
    const outputCoreMedia = (outputCore[2]?.content[0] as unknown as { data: unknown });
    const outputPromptMedia = (outputPrompt[3]?.content[0] as unknown as { data: unknown });
    expect(outputMastraMedia.data).toEqual(mastraBinary);
    expect(outputMastraMedia.data).not.toBe(mastraBinary);
    expect(outputCoreMedia.data).toEqual(coreBinary);
    expect(outputCoreMedia.data).not.toBe(coreBinary);
    expect(outputPromptMedia.data).toEqual(promptBinary);
    expect(outputPromptMedia.data).not.toBe(promptBinary);
    expect(outputHasSensitive([outputMastra, outputCore, outputPrompt])).toBe(false);
  });

  it('keeps unrelated text parts when a media part is unsupported', async () => {
    const pii = createLayeredPii();
    const image = { type: 'image', image: new URL('https://example.test/photo.png') };
    const original = message([{ type: 'text', text: 'user text synthetic@example.test' }, image]);
    const result = await pii.processor.processInput?.({
      messages: [original], systemMessages: [], messageList: {} as never,
      abort: () => { throw new Error('abort'); }, state: {}, retryCount: 0,
    });
    // The caller-owned URL part is untouched and the text part is unmodified.
    expect((original.content.parts[1] as { image: URL }).image).toBe(image.image);
    expect((original.content.parts[0] as { text: string }).text).toBe('user text synthetic@example.test');
    const output = result && 'messages' in result ? result.messages[0] : undefined;
    expect(output?.content.parts[0]).toMatchObject({ type: 'text', text: 'user text [EMAIL_1]' });
    expect(output?.content.parts[1]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    expect(outputHasSensitive(output)).toBe(false);
  });

  it('fails an LLM prompt message closed for unsupported tool payloads', async () => {
    const pii = createLayeredPii();
    const prompt = [{ role: 'assistant', content: [{
      type: 'tool-call', toolCallId: 'call-1', toolName: 'lookup', input: { value: 'synthetic@example.test', invalid: 1n },
    }] }];
    const result = await pii.processor.processLLMRequest(processorArgs(prompt, 1) as never);
    expect(outputHasSensitive(result)).toBe(false);
    const output = result && 'prompt' in result ? result.prompt?.[0] : undefined;
    expect(output).toEqual({ role: 'system', content: '[REDACTION_FAILED]' });
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

describe('adapter architecture (Presidio remote + local fallback)', () => {
  function withServer(handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, body: string) => void): Promise<{ url: string; close: () => Promise<void> }> {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk) => chunks.push(chunk as Buffer));
      req.on('end', () => handler(req, res, Buffer.concat(chunks).toString('utf8')));
    });
    return new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const address = server.address() as AddressInfo;
        resolve({
          url: `http://127.0.0.1:${address.port}`,
          close: () => new Promise((done) => server.close(() => done())),
        });
      });
    });
  }

  it('remote presidio adapter sends allowlist + ad_hoc recognizers and applies shape filters', async () => {
    const text = `bhai ${'Kripa Shankar Mishra'} IFSC 42 15/08/1995 7316 7253 5875 4829 1048 5920 9876543210`;
    const name = text.indexOf('Kripa Shankar Mishra');
    const date = text.indexOf('15/08/1995');
    const aadhaar = text.indexOf('7316 7253 5875');
    const badAadhaar = text.indexOf('4829 1048 5920');
    const phone = text.indexOf('9876543210');
    let seenBody = '';
    const { url, close } = await withServer((_req, res, body) => {
      seenBody = body;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify([
        { entity_type: 'PERSON', start: text.indexOf('bhai'), end: text.indexOf('bhai') + 4, score: 0.85 },
        { entity_type: 'PERSON', start: name, end: name + 20, score: 0.85 },
        { entity_type: 'LOCATION', start: text.indexOf('IFSC'), end: text.indexOf('IFSC') + 4, score: 0.85 },
        { entity_type: 'DATE_TIME', start: text.indexOf('42'), end: text.indexOf('42') + 2, score: 0.85 },
        { entity_type: 'DATE_TIME', start: date, end: date + 10, score: 0.85 },
        { entity_type: 'AADHAAR', start: aadhaar, end: aadhaar + 14, score: 0.6 },
        { entity_type: 'AADHAAR', start: badAadhaar, end: badAadhaar + 14, score: 0.6 },
        { entity_type: 'PHONE_NUMBER', start: phone, end: phone + 10, score: 0.4 },
      ]));
    });
    try {
      const adapter = createPresidioAdapter({ url, timeoutMs: 2000 });
      const spans = await adapter.analyze(text);
      const payload = JSON.parse(seenBody);
      expect(payload.entities).toContain('PERSON');
      expect(payload.entities).not.toContain('UK_NHS');
      expect(payload.ad_hoc_recognizers.length).toBe(INDIAN_DEFAULTS.length);
      // shape filters: no "bhai", no LOCATION "IFSC", no "42", no bad checksum, no 0.40 phone
      expect(spans.map((s) => [s.type, text.slice(s.start, s.end)])).toEqual([
        ['PERSON', 'Kripa Shankar Mishra'],
        ['DATE_TIME', '15/08/1995'],
        ['AADHAAR', '7316 7253 5875'],
      ]);
    } finally {
      await close();
    }
  });

  it('replaces the Presidio defaults with user recognizers', async () => {
    const text = 'employee EMP-1234';
    const recognizers = [{
      name: 'employee-id-recognizer',
      supported_language: 'en',
      supported_entity: 'SECRET',
      patterns: [{ name: 'employee-id', regex: '\\bEMP-\\d{4}\\b', score: 0.7 }],
      context: ['employee'],
    }];
    let seenBody = '';
    const { url, close } = await withServer((_req, res, body) => {
      seenBody = body;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify([{ entity_type: 'SECRET', start: 9, end: 17, score: 0.7 }]));
    });
    try {
      const spans = await createPresidioAdapter({ url, timeoutMs: 2000, recognizers }).analyze(text);
      const payload = JSON.parse(seenBody);
      expect(payload.ad_hoc_recognizers).toEqual(recognizers);
      expect(payload.ad_hoc_recognizers).not.toEqual(INDIAN_DEFAULTS);
      expect(spans).toEqual([{ type: 'SECRET', start: 9, end: 17, score: 0.7 }]);
    } finally {
      await close();
    }
  });

  it('runs configured local patterns in local and Presidio modes', async () => {
    const patterns = [{ name: 'synthetic-key', regex: /CANARY-[0-9]+/g, entity: 'token' }] as const;
    const local = await createLayeredPii({ patterns }).redactText('value CANARY-12345');
    const { url, close } = await withServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end('[]');
    });
    try {
      const remote = await createLayeredPii({ patterns, presidio: { url, timeoutMs: 2000 } })
        .redactText('value CANARY-12345');
      expect(local).toContain('[TOKEN_1]');
      expect(containsSensitive(local)).toBe(false);
      expect(remote).toContain('[TOKEN_1]');
      expect(containsSensitive(remote)).toBe(false);
    } finally {
      await close();
    }
  });

  it('drops detections from recognizers outside the Presidio entity allowlist', async () => {
    const text = 'employee EMP-1234';
    const recognizer = {
      name: 'employee-id-recognizer',
      supported_language: 'en',
      supported_entity: 'EMPLOYEE_ID',
      patterns: [{ name: 'employee-id', regex: '\\bEMP-\\d{4}\\b', score: 0.7 }],
    };
    let seenBody = '';
    const { url, close } = await withServer((_req, res, body) => {
      seenBody = body;
      const payload = JSON.parse(body);
      const detected = payload.entities.includes(recognizer.supported_entity)
        ? [{ entity_type: recognizer.supported_entity, start: 9, end: 17, score: 0.7 }]
        : [];
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(detected));
    });
    try {
      const spans = await createPresidioAdapter({ url, timeoutMs: 2000, recognizers: [recognizer] }).analyze(text);
      const payload = JSON.parse(seenBody);
      expect(payload.ad_hoc_recognizers).toEqual([recognizer]);
      expect(payload.entities).not.toContain(recognizer.supported_entity);
      expect(spans).toEqual([]);
    } finally {
      await close();
    }
  });

  it('type-aware dedupe: UPI beats the higher-scoring PHONE_NUMBER on overlap', async () => {
    const text = '9999999999@ybl';
    const { url, close } = await withServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify([
        { entity_type: 'PHONE_NUMBER', start: 0, end: 10, score: 0.75 },
        { entity_type: 'UPI', start: 0, end: 14, score: 0.6 },
      ]));
    });
    try {
      const adapter = createPresidioAdapter({ url, timeoutMs: 2000 });
      const spans = await adapter.analyze(text);
      expect(spans).toEqual([{ type: 'UPI', start: 0, end: 14, score: 0.6 }]);
    } finally {
      await close();
    }
  });

  it('does not retry 4xx responses', async () => {
    let calls = 0;
    const { url, close } = await withServer((_req, res) => {
      calls += 1;
      res.statusCode = 400;
      res.end();
    });
    try {
      const adapter = createPresidioAdapter({ url, timeoutMs: 2000 });
      await expect(adapter.analyze('safe')).rejects.toThrow('presidio analyze 400');
      expect(calls).toBe(1);
    } finally {
      await close();
    }
  });

  it('retries a 5xx response once and redacts after recovery', async () => {
    let calls = 0;
    const { url, close } = await withServer((_req, res) => {
      calls += 1;
      if (calls === 1) {
        res.statusCode = 500;
        res.end();
        return;
      }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify([{ entity_type: 'CUSTOM', start: 0, end: 8, score: 0.9 }]));
    });
    try {
      const pii = createLayeredPii({ presidio: { url, timeoutMs: 2000 }, fallback: 'strict' });
      expect(await pii.redactText('CANARY-1')).toBe('[CUSTOM_1]');
      expect(calls).toBe(2);
    } finally {
      await close();
    }
  });

  it('outage: local fallback by default, strict fails closed', async () => {
    const dead = { presidio: { url: 'http://127.0.0.1:1', timeoutMs: 300, retries: 0 } };
    const fallback = createLayeredPii({ ...dead, fallback: 'local' });
    const output = await fallback.redactText('PAN ABCDE1234F');
    expect(output).toBe('PAN [PAN_1]');
    const strict = createLayeredPii({ ...dead, fallback: 'strict' });
    const failed = await strict.redactText('PAN ABCDE1234F');
    expect(failed).toBe('[REDACTION_FAILED]');
  });

  it('warmup health-checks the remote service once', async () => {
    let healthCalls = 0;
    const { url, close } = await withServer((req, res) => {
      if (req.method === 'GET' && req.url === '/health') {
        healthCalls += 1;
        res.end('ok');
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    try {
      const pii = createLayeredPii({ presidio: { url, timeoutMs: 2000 } });
      await pii.warmup();
      await pii.warmup();
      expect(healthCalls).toBe(1);
    } finally {
      await close();
    }
  });

  it('LRU cache skips the analyzer for repeated texts; cacheSize 0 disables', async () => {
    let calls = 0;
    const counting: Analyzer = {
      id: 'counting',
      analyze: async (t) => {
        calls += 1;
        return createLocalAdapter().analyze(t);
      },
    };
    const pii = createLayeredPii({ analyzer: counting });
    await pii.redactText('PAN ABCDE1234F');
    await pii.redactText('PAN ABCDE1234F');
    expect(calls).toBe(1);
    const uncached = createLayeredPii({ analyzer: counting, cacheSize: 0 });
    await uncached.redactText('PAN ABCDE1234F');
    await uncached.redactText('PAN ABCDE1234F');
    expect(calls).toBe(3);
  });

  it('uniform anonymize format emits a fixed token', async () => {
    const pii = createLayeredPii({ anonymize: { format: 'uniform' } });
    const output = await pii.redactText('PAN ABCDE1234F phone 98765 43210');
    expect(output).not.toContain('[PAN_1]');
    expect(output).not.toContain('ABCDE1234F');
    expect(output).not.toContain('98765 43210');
    expect(output).toBe('PAN [REDACTED] phone [REDACTED]');
  });

  it('processOutputResult redacts the assistant output message', async () => {
    const pii = createLayeredPii();
    const output = await pii.processor.processOutputResult?.({
      messages: [message([{ type: 'text', text: 'your PAN is ABCDE1234F' }])],
      messageList: {} as never,
      state: {},
    });
    expect(JSON.stringify(output)).not.toContain('ABCDE1234F');
  });

  it('validates the adapter configuration surface', () => {
    expect(() => createLayeredPii({ analyzer: createLocalAdapter(), presidio: { url: 'http://x' } })).toThrow('both analyzer and presidio');
    expect(() => createLayeredPii({ fallback: 'nope' as never })).toThrow('fallback');
    expect(() => createLayeredPii({ cacheSize: -1 })).toThrow('cacheSize');
    expect(() => createLayeredPii({ anonymize: { format: 'masked' as never } })).toThrow('format');
  });
});
