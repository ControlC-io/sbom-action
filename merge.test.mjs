import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { merge } from './merge.mjs';

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const run = () =>
  merge({
    image: read('./fixtures/image.cdx.json'),
    lock: read('./fixtures/lock.cdx.json'),
    appPath: new URL('./fixtures/workspace/apps/api', import.meta.url).pathname,
    lockfile: new URL('./fixtures/workspace/pnpm-lock.yaml', import.meta.url).pathname,
  });
const byName = (sbom, name) => sbom.components.find((c) => c.name === name);
const bundled = (c) => c?.properties?.some((p) => p.name === 'controlc:bundled' && p.value === 'true');

test("marks the app's own dependencies as direct", () => {
  const sbom = run();
  const rootRef = sbom.metadata.component['bom-ref'];
  const entry = sbom.dependencies.find((d) => d.ref === rootRef);
  const directNames = entry.dependsOn.map((ref) => sbom.components.find((c) => c['bom-ref'] === ref).name).sort();
  assert.deepEqual(directNames, ['fastify', 'zod']);
});

test('adds bundled production libraries', () => {
  const sbom = run();
  assert.ok(bundled(byName(sbom, 'fastify')));
  assert.ok(bundled(byName(sbom, 'pino')), 'transitive production dependency');
  assert.ok(bundled(byName(sbom, 'zod')));
  assert.equal(sbom.components.filter((c) => c.name === 'semver').length, 1, 'already in the image: not duplicated');
  assert.ok(!bundled(byName(sbom, 'semver')));
});

test('drops devDependencies', () => {
  const sbom = run();
  assert.equal(byName(sbom, 'vitest'), undefined);
  assert.equal(byName(sbom, 'esbuild'), undefined);
});

test('keeps image packages unchanged', () => {
  const image = read('./fixtures/image.cdx.json');
  const sbom = run();
  for (const c of image.components) {
    assert.deepEqual(sbom.components.find((x) => x['bom-ref'] === c['bom-ref']), c);
  }
  assert.equal(sbom.components.find((c) => c.type === 'operating-system').name, 'alpine');
});
