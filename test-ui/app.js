const ENTITIES = [
  ['email', 'Email'],
  ['phone', 'Phone'],
  ['ssn', 'SSN'],
  ['credit-card', 'Credit card'],
  ['bank-account', 'Bank account'],
  ['ip-address', 'IP address'],
  ['uuid', 'UUID'],
  ['passport', 'Passport'],
  ['address', 'Address'],
  ['name', 'Name'],
  ['date-of-birth', 'Date of birth'],
  ['token', 'Token'],
  ['medical-id', 'Medical ID'],
  ['custom', 'Custom'],
  ['aadhaar', 'Aadhaar'],
  ['pan', 'PAN'],
  ['upi', 'UPI'],
  ['ifsc', 'IFSC'],
  ['voter-id', 'Voter ID'],
  ['driving-license', 'Driving license'],
  ['vehicle', 'Vehicle'],
];

const SAMPLE_TEXT = [
  'Contact alpha@example.test or +1 (415) 555-0134.',
  'The request came from 192.0.2.44 and device 550e8400-e29b-41d4-a716-446655440000.',
  'Internal reference: ACCT-123456.',
].join('\n');

const DEFAULT_PATTERN = {
  name: 'account-code',
  regex: 'ACCT-[0-9]{6}',
  entity: 'bank-account',
  priority: '2',
};

const elements = {
  input: document.querySelector('#input-text'),
  charCount: document.querySelector('#char-count'),
  processorId: document.querySelector('#processor-id'),
  layer: document.querySelector('#layer'),
  entityGrid: document.querySelector('#entity-grid'),
  entityCount: document.querySelector('#entity-count'),
  patternList: document.querySelector('#pattern-list'),
  outputEmpty: document.querySelector('#output-empty'),
  outputText: document.querySelector('#output-text'),
  status: document.querySelector('#run-status'),
  redactionCount: document.querySelector('#redaction-count'),
  duration: document.querySelector('#duration'),
  engine: document.querySelector('#engine'),
  summaryEntities: document.querySelector('#summary-entities'),
  summaryPatterns: document.querySelector('#summary-patterns'),
  error: document.querySelector('#error-message'),
  run: document.querySelector('#run-redaction'),
};

function entityCheckboxes() {
  return [...elements.entityGrid.querySelectorAll('input[type="checkbox"]')];
}

function activeEntities() {
  return entityCheckboxes().filter((input) => input.checked).map((input) => input.value);
}

function updateEntityCount() {
  const active = activeEntities().length;
  elements.entityCount.textContent = `${active} / ${ENTITIES.length} active`;
  elements.summaryEntities.textContent = String(active);
}

function updateCharCount() {
  elements.charCount.textContent = `${elements.input.value.length.toLocaleString()} chars`;
}

function entityOptions(selected = 'custom') {
  return ENTITIES.map(([value, label]) => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    option.selected = value === selected;
    return option;
  });
}

function makePatternRow(pattern = {}) {
  const row = document.createElement('div');
  row.className = 'pattern-row';

  const name = document.createElement('input');
  name.type = 'text';
  name.placeholder = 'name';
  name.value = pattern.name ?? '';
  name.dataset.field = 'name';
  name.setAttribute('aria-label', 'Pattern name');

  const regex = document.createElement('input');
  regex.type = 'text';
  regex.placeholder = 'regex source';
  regex.value = pattern.regex ?? '';
  regex.dataset.field = 'regex';
  regex.className = 'pattern-regex';
  regex.setAttribute('aria-label', 'Pattern regular expression');

  const entity = document.createElement('select');
  entity.dataset.field = 'entity';
  entity.setAttribute('aria-label', 'Pattern entity');
  entity.append(...entityOptions(pattern.entity));

  const priority = document.createElement('input');
  priority.type = 'number';
  priority.min = '0';
  priority.step = '1';
  priority.placeholder = '0';
  priority.value = pattern.priority ?? '';
  priority.dataset.field = 'priority';
  priority.setAttribute('aria-label', 'Pattern priority');

  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'remove-pattern';
  remove.setAttribute('aria-label', 'Remove custom pattern');
  remove.title = 'Remove pattern';
  remove.textContent = '×';
  remove.addEventListener('click', () => {
    row.remove();
    updatePatternSummary();
  });

  row.append(name, regex, entity, priority, remove);
  return row;
}

function patternRows() {
  return [...elements.patternList.querySelectorAll('.pattern-row')];
}

function configuredPatterns() {
  return patternRows()
    .map((row) => {
      const value = (field) => row.querySelector(`[data-field="${field}"]`).value.trim();
      const priority = value('priority');
      return {
        name: value('name'),
        regex: value('regex'),
        entity: value('entity'),
        ...(priority === '' ? {} : { priority: Number(priority) }),
      };
    })
    .filter((pattern) => pattern.name || pattern.regex);
}

function updatePatternSummary() {
  elements.summaryPatterns.textContent = String(configuredPatterns().length);
}

function buildConfig() {
  return {
    id: elements.processorId.value.trim() || undefined,
    layers: [elements.layer.value],
    entities: activeEntities(),
    patterns: configuredPatterns(),
  };
}

function clearOutput() {
  elements.outputEmpty.hidden = false;
  elements.outputText.hidden = true;
  elements.outputText.textContent = '';
  elements.redactionCount.textContent = '—';
  elements.duration.textContent = '—';
  elements.engine.textContent = '—';
  elements.status.textContent = 'READY';
  elements.status.className = 'run-status';
  elements.error.hidden = true;
  elements.error.textContent = '';
}

function resetConfig() {
  elements.processorId.value = 'mastra-pii';
  elements.layer.value = 'deterministic';
  entityCheckboxes().forEach((input) => { input.checked = true; });
  elements.patternList.replaceChildren(makePatternRow(DEFAULT_PATTERN));
  updateEntityCount();
  updatePatternSummary();
  clearOutput();
}

async function runRedaction() {
  const text = elements.input.value;
  if (!text.trim()) {
    elements.error.textContent = 'Add some input text before running the redactor.';
    elements.error.hidden = false;
    elements.status.textContent = 'WAITING';
    elements.status.className = 'run-status is-error';
    return;
  }

  elements.run.disabled = true;
  elements.run.setAttribute('aria-busy', 'true');
  elements.status.textContent = 'RUNNING';
  elements.status.className = 'run-status is-running';
  elements.error.hidden = true;
  elements.outputEmpty.hidden = true;
  elements.outputText.hidden = false;
  elements.outputText.textContent = 'Redacting…';

  try {
    const response = await fetch('/api/redact', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text, config: buildConfig() }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'The redaction request failed.');
    }

    elements.outputText.textContent = data.output;
    elements.redactionCount.textContent = String(data.redactionCount);
    elements.duration.textContent = `${data.durationMs} ms`;
    elements.engine.textContent = data.config.engine === 'presidio' ? 'presidio (remote)' : 'local deterministic';
    elements.status.textContent = 'COMPLETE';
    elements.status.className = 'run-status is-success';
  } catch (error) {
    elements.outputText.hidden = true;
    elements.outputEmpty.hidden = false;
    elements.error.textContent = error instanceof Error ? error.message : 'The redaction request failed.';
    elements.error.hidden = false;
    elements.status.textContent = 'ERROR';
    elements.status.className = 'run-status is-error';
    elements.redactionCount.textContent = '—';
    elements.duration.textContent = '—';
    elements.engine.textContent = '—';
  } finally {
    elements.run.disabled = false;
    elements.run.removeAttribute('aria-busy');
  }
}

function renderEntities() {
  elements.entityGrid.replaceChildren(...ENTITIES.map(([value, label]) => {
    const labelElement = document.createElement('label');
    labelElement.className = 'entity-option';
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = value;
    input.checked = true;
    input.addEventListener('change', updateEntityCount);
    const indicator = document.createElement('span');
    indicator.className = 'checkbox-indicator';
    const text = document.createElement('span');
    text.textContent = label;
    labelElement.append(input, indicator, text);
    return labelElement;
  }));
}

function loadSample() {
  elements.input.value = SAMPLE_TEXT;
  updateCharCount();
  clearOutput();
  elements.input.focus();
}

document.querySelector('#load-sample').addEventListener('click', loadSample);
document.querySelector('#reset-config').addEventListener('click', resetConfig);
document.querySelector('#add-pattern').addEventListener('click', () => {
  elements.patternList.append(makePatternRow());
  updatePatternSummary();
  elements.patternList.lastElementChild?.querySelector('[data-field="name"]').focus();
});
elements.input.addEventListener('input', updateCharCount);
elements.patternList.addEventListener('input', updatePatternSummary);
elements.run.addEventListener('click', runRedaction);
document.addEventListener('keydown', (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
    event.preventDefault();
    runRedaction();
  }
});

renderEntities();
loadSample();
resetConfig();
