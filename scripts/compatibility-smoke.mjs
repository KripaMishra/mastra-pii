// @ts-check

import { Agent } from '@mastra/core/agent';
import { MessageList } from '@mastra/core/agent/message-list';
import { createLayeredPii } from '../dist/index.js';

/** @typedef {import('@mastra/core/agent/message-list').MastraDBMessage} MastraDBMessage */
/** @typedef {import('@mastra/core/processors').ProcessInputArgs} ProcessInputArgs */
/** @typedef {import('@mastra/core/processors').ProcessLLMRequestArgs} ProcessLLMRequestArgs */
/** @typedef {import('@mastra/core/processors').ProcessOutputResultArgs} ProcessOutputResultArgs */

const canary = 'COMPAT-CANARY-12345';
const pii = createLayeredPii({
  patterns: [{ name: 'compat-canary', regex: /COMPAT-CANARY-[0-9]+/g, entity: 'token' }],
});
const agent = new Agent({
  id: 'compatibility-smoke',
  name: 'Compatibility smoke',
  instructions: 'Compatibility smoke only',
  model: 'openai/gpt-4o-mini',
  inputProcessors: [pii.processor],
  outputProcessors: [pii.processor],
});
const abort = () => { throw new Error('processor aborted'); };

/** @type {MastraDBMessage} */
const inputMessage = {
  id: 'input',
  role: 'user',
  createdAt: new Date(0),
  content: { format: 2, parts: [{ type: 'text', text: canary }], content: canary },
};
/** @type {ProcessInputArgs} */
const inputArgs = {
  abort,
  retryCount: 0,
  state: {},
  agent,
  messageList: new MessageList(),
  messages: [inputMessage],
  systemMessages: [{ role: 'system', content: canary }],
};
const input = await pii.processor.processInput(inputArgs);

/** @type {MastraDBMessage} */
const outputMessage = {
  id: 'output',
  role: 'assistant',
  createdAt: new Date(0),
  content: { format: 2, parts: [{ type: 'text', text: canary }], content: canary },
};
/** @type {ProcessOutputResultArgs} */
const outputArgs = {
  abort,
  retryCount: 0,
  state: {},
  agent,
  messageList: new MessageList(),
  messages: [outputMessage],
  result: {
    text: canary,
    usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
    finishReason: 'stop',
    steps: [],
  },
};
const output = await pii.processor.processOutputResult(outputArgs);

/** @type {ProcessLLMRequestArgs} */
const llmRequestArgs = {
  abort,
  retryCount: 0,
  state: {},
  agent,
  model: /** @type {ProcessLLMRequestArgs['model']} */ ({}),
  stepNumber: 1,
  steps: [],
  prompt: [{
    role: 'tool',
    content: [{
      type: 'tool-result',
      toolCallId: 'compatibility-smoke',
      toolName: 'lookup',
      output: { type: 'json', value: { secret: canary } },
    }],
  }],
};
const llmRequest = await pii.processor.processLLMRequest(llmRequestArgs);

for (const [name, result] of Object.entries({ input, output, llmRequest })) {
  const serialized = JSON.stringify(result);
  if (serialized.includes(canary)) throw new Error(`${name} processor leaked PII`);
  if (!serialized.includes('[TOKEN_1]')) throw new Error(`${name} processor did not redact the canary`);
}
