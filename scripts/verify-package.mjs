import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const expectedFiles = [
  'LICENSE',
  'README.md',
  'dist/analyzer.d.ts',
  'dist/analyzer.js',
  'dist/custom-pattern-worker.js',
  'dist/index.d.ts',
  'dist/index.js',
  'package.json',
];
let tarball;
let consumer;

try {
  execFileSync('npm', ['run', 'check'], { cwd: root, stdio: 'inherit' });
  const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json'], { cwd: root, encoding: 'utf8' }));
  if (!Array.isArray(packed) || packed.length !== 1 || typeof packed[0]?.filename !== 'string' || !Array.isArray(packed[0]?.files)) {
    throw new Error('npm pack returned an unexpected result');
  }
  const actualFiles = packed[0].files.map(({ path }) => path).sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) throw new Error('package file allowlist mismatch');
  tarball = join(root, packed[0].filename);
  consumer = mkdtempSync(join(tmpdir(), 'mastra-pii-consumer-'));
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', tarball, '@mastra/core@1.57.0'], { cwd: consumer, stdio: 'inherit' });
  writeFileSync(join(consumer, 'tsconfig.json'), JSON.stringify({ compilerOptions: {
    target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', strict: true,
    noEmit: true, skipLibCheck: true,
  }, include: ['consumer.ts'] }));
  writeFileSync(join(consumer, 'consumer.ts'), `
import { createLayeredPii, type LayeredPii, type PiiProcessor } from '@kripamishra/mastra-pii';
import type { InputProcessor } from '@mastra/core/processors';
const pii: LayeredPii = createLayeredPii();
const processor: PiiProcessor = pii.processor;
const inputProcessor: InputProcessor = processor;
void inputProcessor;
await pii.redactText('safe');
`);
  execFileSync(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '-p', join(consumer, 'tsconfig.json')], { cwd: consumer, stdio: 'inherit' });
  writeFileSync(join(consumer, 'smoke.mjs'), `
import { createLayeredPii } from '@kripamishra/mastra-pii';
const pii = createLayeredPii({ patterns: [{ name: 'canary', regex: /CANARY-[0-9]+/g, entity: 'token' }] });
const redacted = await pii.redactText('CANARY-12345');
if (!redacted.includes('[TOKEN_1]') || /CANARY/i.test(redacted)) throw new Error('redaction smoke failed');
const result = await pii.processor.processLLMRequest({
  prompt: [{ role: 'tool', content: [{ type: 'tool-result', toolCallId: '1', toolName: 'lookup', output: { type: 'json', value: { secret: 'CANARY-12345' } } }] }],
  model: {}, stepNumber: 1, steps: [], state: {}, retryCount: 0, abort() { throw new Error('abort'); },
});
if (/CANARY/i.test(JSON.stringify(result))) throw new Error('processor smoke failed');
`);
  execFileSync(process.execPath, [join(consumer, 'smoke.mjs')], { cwd: consumer, stdio: 'inherit' });
  console.log(`verified ${expectedFiles.length} packed files and clean ESM consumer`);
} finally {
  if (consumer) rmSync(consumer, { recursive: true, force: true });
  if (tarball) rmSync(tarball, { force: true });
}
