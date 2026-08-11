import { Worker } from 'node:worker_threads';
import { describe, expect, it, vi } from 'vitest';
import type { MastraDBMessage } from '@mastra/core/agent/message-list';
import { createLayeredPii } from './index.js';

const message = (parts: unknown[], extra: Record<string, unknown> = {}): MastraDBMessage => ({
  id: 'synthetic-message',
  role: 'user',
  createdAt: new Date(0),
  content: { format: 2, parts, ...extra },
} as MastraDBMessage);

function containsSensitive(text: string): boolean {
  return /(?:canary|synthetic@example\.test|alpha@example\.test|123-45-6789)\b/i.test(text);
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

  it('serializes nested custom-pattern jobs and awaits every worker termination', async () => {
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
      const prompt = [{ role: 'assistant', content: [{
        type: 'tool-call', toolCallId: 'call-1', toolName: 'lookup',
        input: { values: Array.from({ length: 6 }, (_, index) => `CANARY-${index}`) },
      }] }];
      const output = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
      expect(outputHasSensitive(output)).toBe(false);
      expect(maximumActive).toBe(1);
      expect(active).toBe(0);
      expect(terminated).toBe(9);
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

  it('fails processInput messages closed when structural identifiers would be redacted', async () => {
    const invocation = (toolCallId: string, toolName: string, approvalId = 'approval-safe') => ({
      state: 'approval-requested', toolCallId, toolName, args: {}, approval: { id: approvalId },
    });
    const messages = [
      message([{ type: 'tool-invocation', toolInvocation: invocation('CANARY-CALL', 'lookup') }]),
      message([{ type: 'tool-invocation', toolInvocation: invocation('call-safe', 'CANARY-TOOL') }]),
      message([{ type: 'text', text: 'safe' }], { toolInvocations: [invocation('call-safe', 'lookup', 'CANARY-APPROVAL')] }),
    ];
    const systemMessages = [
      { role: 'assistant', content: [{ type: 'tool-call', toolCallId: 'CANARY-CALL', toolName: 'lookup', args: {} }] },
      { role: 'assistant', content: [{ type: 'tool-call', toolCallId: 'call-safe', toolName: 'CANARY-TOOL', args: {} }] },
      { role: 'tool', content: [{ type: 'tool-result', toolCallId: 'CANARY-CALL', toolName: 'lookup', result: {} }] },
      { role: 'tool', content: [{ type: 'tool-result', toolCallId: 'call-safe', toolName: 'CANARY-TOOL', result: {} }] },
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
    for (const output of outputMessages) {
      expect(output.content.parts[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    }
    expect(outputSystemMessages).toEqual(systemMessages.map(() => ({ role: 'system', content: '[REDACTION_FAILED]' })));
  });

  it('fails processLLMRequest messages closed when modern tool identifiers would be redacted', async () => {
    const prompt = [
      { role: 'assistant', content: [{ type: 'tool-call', toolCallId: 'CANARY-CALL', toolName: 'lookup', input: {} }] },
      { role: 'assistant', content: [{ type: 'tool-call', toolCallId: 'call-safe', toolName: 'CANARY-TOOL', input: {} }] },
      { role: 'tool', content: [{ type: 'tool-result', toolCallId: 'CANARY-CALL', toolName: 'lookup', output: { type: 'json', value: {} } }] },
      { role: 'tool', content: [{ type: 'tool-result', toolCallId: 'call-safe', toolName: 'CANARY-TOOL', output: { type: 'json', value: {} } }] },
    ];
    const before = structuredClone(prompt);
    const pii = createLayeredPii({ patterns: [{ name: 'identifier-canary', regex: /CANARY-[A-Z]+/g }] });
    const result = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    expect(prompt).toEqual(before);
    const output = result && 'prompt' in result ? result.prompt : undefined;
    expect(output).toEqual(prompt.map(() => ({ role: 'system', content: '[REDACTION_FAILED]' })));
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
    const data = { 'synthetic@example.test': { note: 'synthetic@example.test' } };
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
    const mastraMessageOptions = { vendor: { 'synthetic@example.test': true } };
    const mastraContentOptions = { vendor: { 'synthetic@example.test': true } };
    const mastraPartOptions = { vendor: { 'synthetic@example.test': true } };
    const mastraPart = { type: 'text', text: 'safe', providerOptions: mastraPartOptions };
    const mastra = {
      ...message([mastraPart], { providerOptions: mastraContentOptions }),
      providerOptions: mastraMessageOptions,
    } as unknown as MastraDBMessage;
    const coreMessageOptions = { vendor: { 'synthetic@example.test': true } };
    const corePartOptions = { vendor: { 'synthetic@example.test': true } };
    const core = {
      role: 'user', providerOptions: coreMessageOptions,
      content: [{ type: 'text', text: 'safe', providerOptions: corePartOptions }],
    };
    const promptMessageOptions = { vendor: { 'synthetic@example.test': true } };
    const promptPartOptions = { vendor: { 'synthetic@example.test': true } };
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

  it('redacts JSON property names, preserves plain-object descriptors, and fails closed on key collisions', async () => {
    const providerOptions = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(providerOptions, 'synthetic@example.test', {
      value: { safe: true }, enumerable: true, configurable: false, writable: false,
    });
    const prompt = [{ role: 'user', content: [{ type: 'text', text: 'safe', providerOptions }] }];
    const pii = createLayeredPii();
    const result = await pii.processor.processLLMRequest(processorArgs(prompt, 0) as never);
    const output = result && 'prompt' in result ? result.prompt?.[0] : undefined;
    const outputOptions = (output?.content[0] as unknown as { providerOptions: Record<string, unknown> }).providerOptions;
    expect(outputHasSensitive(output)).toBe(false);
    expect(Object.getPrototypeOf(outputOptions)).toBeNull();
    expect(Object.keys(outputOptions)).toEqual(['[EMAIL_1]']);
    expect(Object.getOwnPropertyDescriptor(outputOptions, '[EMAIL_1]')).toMatchObject({
      enumerable: true, configurable: false, writable: false,
    });
    expect(Object.keys(providerOptions)).toEqual(['synthetic@example.test']);

    const collision = { 'synthetic@example.test': true, '[EMAIL_1]': false };
    const failed = await pii.processor.processLLMRequest(processorArgs([{
      role: 'user', content: [{ type: 'text', text: 'safe', providerOptions: collision }],
    }], 0) as never);
    expect(failed && 'prompt' in failed ? failed.prompt?.[0] : undefined).toEqual({ role: 'system', content: '[REDACTION_FAILED]' });
    expect(outputHasSensitive(failed)).toBe(false);
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

  it('rejects string, URL, data-URL, and base64 media while cloning opaque binary media', async () => {
    const mastraBinary = new Uint8Array([4, 5, 6]);
    const coreBinary = new Uint8Array([7, 8, 9]).buffer;
    const promptBinary = new Uint8Array([10, 11, 12]);
    const coreUrl = new URL('https://example.test/synthetic@example.test');
    const promptUrl = new URL('https://example.test/synthetic@example.test');
    const mastraMessages = [
      message([{ type: 'file', data: 'data:text/plain,synthetic@example.test', mimeType: 'text/plain' }]),
      message([], { experimental_attachments: [{ url: 'https://example.test/synthetic@example.test' }] }),
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
    expect(outputMastra[0]?.content.parts[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    expect(outputMastra[1]?.content.parts[0]).toMatchObject({ type: 'text', text: '[REDACTION_FAILED]' });
    expect(outputCore[0]).toEqual({ role: 'system', content: '[REDACTION_FAILED]' });
    expect(outputCore[1]).toEqual({ role: 'system', content: '[REDACTION_FAILED]' });
    expect(outputPrompt.slice(0, 3)).toEqual(Array.from({ length: 3 }, () => ({ role: 'system', content: '[REDACTION_FAILED]' })));
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
