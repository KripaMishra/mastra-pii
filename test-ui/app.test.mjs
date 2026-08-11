import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';

class FakeElement {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.children = [];
    this.listeners = new Map();
    this.dataset = {};
    this.value = '';
    this.hidden = false;
    this.textContent = '';
    this.className = '';
  }

  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this[name] = value; }
  removeAttribute(name) { delete this[name]; }
  addEventListener(name, callback) {
    const callbacks = this.listeners.get(name) ?? [];
    callbacks.push(callback);
    this.listeners.set(name, callbacks);
  }
  async dispatch(name, event = {}) {
    for (const callback of this.listeners.get(name) ?? []) await callback(event);
  }
  remove() { this.removed = true; }
  focus() {}
  get lastElementChild() { return this.children.at(-1); }
  querySelector(selector) {
    return this.querySelectorAll(selector)[0];
  }
  querySelectorAll(selector) {
    const descendants = this.children.flatMap((child) => [child, ...child.querySelectorAll(selector)]);
    if (selector === '.pattern-row') return descendants.filter((child) => child.className === 'pattern-row');
    if (selector === 'input[type="checkbox"]') return descendants.filter((child) => child.tagName === 'input' && child.type === 'checkbox');
    const field = selector.match(/^\[data-field="(.+)"\]$/)?.[1];
    return field ? descendants.filter((child) => child.dataset?.field === field) : [];
  }
}

function makeDocument() {
  const ids = [
    'input-text', 'char-count', 'processor-id', 'layer', 'entity-grid', 'entity-count',
    'pattern-list', 'output-card', 'output-empty', 'output-text', 'run-status',
    'redaction-count', 'duration', 'engine', 'summary-entities', 'summary-patterns', 'error-message',
    'run-redaction', 'load-sample', 'reset-config', 'add-pattern',
  ];
  const elements = new Map(ids.map((id) => [id, new FakeElement()]))
  elements.get('layer').value = 'deterministic';
  return {
    querySelector(selector) { return elements.get(selector.slice(1)); },
    createElement(tag) { return new FakeElement(tag); },
    addEventListener() {},
    elements,
  };
}

describe('test console error state', () => {
  it('renders a literal failure placeholder from a successful response', async () => {
    const document = makeDocument();
    const context = vm.createContext({
      document,
      fetch: async () => ({ ok: true, json: async () => ({ output: '[REDACTION_FAILED]', redactionCount: 0, durationMs: 1, config: { engine: 'local' } }) }),
      console,
      setTimeout,
    });
    vm.runInContext(await readFile(new URL('./app.js', import.meta.url), 'utf8'), context);

    document.elements.get('input-text').value = '[REDACTION_FAILED]';
    await document.elements.get('run-redaction').dispatch('click');

    expect(document.elements.get('run-status').textContent).toBe('COMPLETE');
    expect(document.elements.get('error-message').hidden).toBe(true);
  });

  it('shows an HTTP failure response as an error', async () => {
    const document = makeDocument();
    const context = vm.createContext({
      document,
      fetch: async () => ({ ok: false, json: async () => ({ error: 'Redaction failed.' }) }),
      console,
      setTimeout,
    });
    vm.runInContext(await readFile(new URL('./app.js', import.meta.url), 'utf8'), context);

    document.elements.get('input-text').value = 'synthetic@example.test';
    await document.elements.get('run-redaction').dispatch('click');

    expect(document.elements.get('run-status').textContent).toBe('ERROR');
    expect(document.elements.get('error-message').hidden).toBe(false);
  });
});
