import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { merge } from './merge.mjs';

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const run = () =>
  merge({
    image: read('./fixtures/image.cdx.json'),
    lock: read('./fixtures/lock.cdx.json'),
    appPath: fileURLToPath(new URL('./fixtures/workspace/apps/api', import.meta.url)),
    lockfile: fileURLToPath(new URL('./fixtures/workspace/pnpm-lock.yaml', import.meta.url)),
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

// ---- risky paths, built in temp workspaces -------------------------------------------------
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const comp = (name, version, extra = {}) => ({
  type: 'library',
  'bom-ref': `ref:${name}@${version}`,
  name,
  version,
  purl: `pkg:npm/${name.replace('@', '%40')}@${version}`,
  ...extra,
});
const emptyImage = () => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  metadata: { component: { type: 'container', 'bom-ref': 'img', name: 'img' } },
  components: [],
});
// files: { 'relative/path': string | object }; returns the directory
function workspace(files) {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-'));
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), typeof body === 'string' ? body : JSON.stringify(body));
  }
  return dir;
}
function mergeIn(dir, { app = '.', lockfile = 'pnpm-lock.yaml', lockComponents, image = emptyImage() }) {
  return merge({
    image,
    lock: { components: lockComponents },
    appPath: join(dir, app),
    lockfile: join(dir, lockfile),
  });
}
const names = (sbom, filter = () => true) => sbom.components.filter(filter).map((c) => `${c.name}@${c.version}`).sort();
const directOf = (sbom) =>
  sbom.dependencies
    .find((d) => d.ref === sbom.metadata.component['bom-ref'])
    .dependsOn.map((r) => sbom.components.find((c) => c['bom-ref'] === r))
    .map((c) => `${c.name}@${c.version}`)
    .sort();

test('pnpm: npm aliases keep their package and its subtree', () => {
  const dir = workspace({
    'package.json': { name: 'app', dependencies: { 'my-lodash': 'npm:lodash@4.17.21' } },
    'pnpm-lock.yaml': `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      my-lodash:
        specifier: npm:lodash@4.17.21
        version: lodash@4.17.21

snapshots:

  inner@1.0.0: {}

  lodash@4.17.21:
    dependencies:
      inner: 1.0.0
      string-width-cjs: string-width@4.2.3

  string-width@4.2.3: {}
`,
  });
  const sbom = mergeIn(dir, {
    lockComponents: [comp('lodash', '4.17.21'), comp('inner', '1.0.0'), comp('string-width', '4.2.3')],
  });
  assert.deepEqual(names(sbom), ['inner@1.0.0', 'lodash@4.17.21', 'string-width@4.2.3']);
  assert.deepEqual(directOf(sbom), ['lodash@4.17.21']);
});

test('pnpm: the importer’s own peer variant is walked', () => {
  const dir = workspace({
    'package.json': { name: 'app', dependencies: { 'react-dom': '18.0.0' } },
    'pnpm-lock.yaml': `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      react-dom:
        specifier: 18.0.0
        version: 18.0.0(react@18.0.0)

snapshots:

  react-dom@18.0.0(react@18.0.0):
    dependencies:
      react: 18.0.0

  react-dom@18.0.0(react@17.0.0):
    dependencies:
      react: 17.0.0

  react@17.0.0: {}

  react@18.0.0: {}
`,
  });
  const sbom = mergeIn(dir, {
    lockComponents: [comp('react-dom', '18.0.0'), comp('react', '17.0.0'), comp('react', '18.0.0')],
  });
  assert.deepEqual(names(sbom), ['react-dom@18.0.0', 'react@18.0.0']);
});

test('pnpm: workspace cycles and link: dependencies terminate', () => {
  const dir = workspace({
    'package.json': { name: 'root', private: true },
    'apps/a/package.json': { name: 'a', dependencies: { b: 'workspace:*', 'left-pad': '1.3.0' } },
    'packages/b/package.json': { name: 'b', dependencies: { a: 'workspace:*', c: 'link:../c', zod: '3.25.67' } },
    'packages/c/package.json': { name: 'c', dependencies: { tiny: '1.0.0' } },
    'pnpm-lock.yaml': `lockfileVersion: '9.0'

importers:

  apps/a:
    dependencies:
      b:
        specifier: workspace:*
        version: link:../../packages/b
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

  packages/b:
    dependencies:
      a:
        specifier: workspace:*
        version: link:../../apps/a
      c:
        specifier: link:../c
        version: link:../c
      zod:
        specifier: 3.25.67
        version: 3.25.67

  packages/c:
    dependencies:
      tiny:
        specifier: 1.0.0
        version: 1.0.0

snapshots:

  left-pad@1.3.0: {}

  tiny@1.0.0: {}

  zod@3.25.67: {}
`,
  });
  const sbom = mergeIn(dir, {
    app: 'apps/a',
    lockComponents: [comp('left-pad', '1.3.0'), comp('zod', '3.25.67'), comp('tiny', '1.0.0')],
  });
  assert.deepEqual(directOf(sbom), ['left-pad@1.3.0', 'tiny@1.0.0', 'zod@3.25.67']);
});

test('matches lockfile scan components by name AND version, and direct by name@version', () => {
  const dir = workspace({
    'package.json': { name: 'app', dependencies: { zod: '3.25.67' } },
    'pnpm-lock.yaml': `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      zod:
        specifier: 3.25.67
        version: 3.25.67

snapshots:

  zod@3.25.67: {}
`,
  });
  const sbom = mergeIn(dir, { lockComponents: [comp('zod', '3.0.0'), comp('zod', '3.25.67')] });
  assert.deepEqual(names(sbom), ['zod@3.25.67']);
  assert.deepEqual(directOf(sbom), ['zod@3.25.67']);
});

test('scoped packages match their %40 purl, also when the image has the same one unencoded', () => {
  const dir = workspace({
    'package.json': { name: 'app', dependencies: { '@scope/pkg': '1.0.0', '@other/lib': '2.0.0' } },
    'pnpm-lock.yaml': `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@other/lib':
        specifier: 2.0.0
        version: 2.0.0
      '@scope/pkg':
        specifier: 1.0.0
        version: 1.0.0

snapshots:

  '@other/lib@2.0.0': {}

  '@scope/pkg@1.0.0': {}
`,
  });
  const image = emptyImage();
  image.components.push({ ...comp('@other/lib', '2.0.0'), purl: 'pkg:npm/@other/lib@2.0.0' });
  const sbom = mergeIn(dir, { image, lockComponents: [comp('@scope/pkg', '1.0.0'), comp('@other/lib', '2.0.0')] });
  assert.deepEqual(names(sbom), ['@other/lib@2.0.0', '@scope/pkg@1.0.0']);
  assert.ok(bundled(byName(sbom, '@scope/pkg')));
  assert.ok(!bundled(byName(sbom, '@other/lib')));
  assert.deepEqual(directOf(sbom), ['@other/lib@2.0.0', '@scope/pkg@1.0.0']);
});

// ---- npm package-lock.json ------------------------------------------------------------------
const npmFixture = () => {
  const dir = fileURLToPath(new URL('./fixtures/npm/', import.meta.url));
  const packages = JSON.parse(readFileSync(join(dir, 'package-lock.json'), 'utf8')).packages;
  // what Syft reports for the lockfile: every package, dev ones included
  const lockComponents = Object.entries(packages)
    .filter(([p, e]) => p.startsWith('node_modules/') && !e.link)
    .map(([p, e]) => comp(e.name ?? p.slice(p.lastIndexOf('node_modules/') + 13), e.version));
  return { dir, lockComponents };
};

test('npm: direct and bundled production libraries from package-lock.json, dev dropped', () => {
  const { dir, lockComponents } = npmFixture();
  assert.ok(lockComponents.some((c) => c.name === 'vitest'), 'fixture sanity: vitest is in the scan');
  const sbom = mergeIn(dir, { app: 'apps/api', lockfile: 'package-lock.json', lockComponents });
  assert.deepEqual(directOf(sbom), ['fastify@5.4.0', 'zod@3.25.67']);
  assert.ok(bundled(byName(sbom, 'fastify')));
  assert.ok(bundled(byName(sbom, 'pino')), 'transitive production dependency');
  assert.equal(byName(sbom, 'vitest'), undefined);
  assert.equal(byName(sbom, 'esbuild'), undefined);
  assert.equal(byName(sbom, '@fx/schema'), undefined, 'workspace packages are not libraries');
});

test('npm: the same production closure as pnpm for the same workspace', () => {
  const { dir, lockComponents } = npmFixture();
  const npm = mergeIn(dir, { app: 'apps/api', lockfile: 'package-lock.json', lockComponents });
  const pnpm = run();
  assert.deepEqual(directOf(npm), directOf(pnpm));
  assert.equal(names(npm).length > 10, true);
});

// ---- a lockfile snapshot key that is not there ------------------------------------------------
import { spawnSync } from 'node:child_process';

const missingSnapshot = () =>
  workspace({
    'package.json': { name: 'app', dependencies: { fastify: '5.4.0' } },
    'pnpm-lock.yaml': `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      fastify:
        specifier: 5.4.0
        version: 5.4.0

snapshots:

  fastify@5.4.1:
    dependencies:
      pino: 9.0.0

  pino@9.0.0: {}
`,
  });

test('pnpm: a missing snapshot key is reported, naming the key and the lockfile', () => {
  const dir = missingSnapshot();
  const warnings = [];
  const sbom = merge({
    image: emptyImage(),
    lock: { components: [comp('fastify', '5.4.0'), comp('pino', '9.0.0')] },
    appPath: dir,
    lockfile: join(dir, 'pnpm-lock.yaml'),
    warn: (m) => warnings.push(m),
  });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /fastify@5\.4\.0/);
  assert.ok(warnings[0].includes(join(dir, 'pnpm-lock.yaml')), warnings[0]);
  assert.deepEqual(names(sbom), ['fastify@5.4.0'], 'the subtree under the missing key is not reachable');
});

test('pnpm: a complete lockfile reports nothing', () => {
  const warnings = [];
  merge({
    image: read('./fixtures/image.cdx.json'),
    lock: read('./fixtures/lock.cdx.json'),
    appPath: fileURLToPath(new URL('./fixtures/workspace/apps/api', import.meta.url)),
    lockfile: fileURLToPath(new URL('./fixtures/workspace/pnpm-lock.yaml', import.meta.url)),
    warn: (m) => warnings.push(m),
  });
  assert.deepEqual(warnings, []);
});

test('cli: a missing snapshot key prints a GitHub Actions ::warning:: and still writes the SBOM', () => {
  const dir = missingSnapshot();
  writeFileSync(join(dir, 'image.cdx.json'), JSON.stringify(emptyImage()));
  writeFileSync(join(dir, 'lock.cdx.json'), JSON.stringify({ components: [comp('fastify', '5.4.0')] }));
  const r = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL('./merge.mjs', import.meta.url)),
      '--image', join(dir, 'image.cdx.json'),
      '--lock', join(dir, 'lock.cdx.json'),
      '--app', dir,
      '--lockfile', join(dir, 'pnpm-lock.yaml'),
      '--out', join(dir, 'sbom.cdx.json'),
    ],
    { encoding: 'utf8' },
  );
  assert.equal(r.status, 0, r.stderr);
  const line = r.stdout.split('\n').find((l) => l.startsWith('::warning'));
  assert.ok(line, r.stdout);
  assert.match(line, /fastify@5\.4\.0/);
  assert.ok(line.includes('pnpm-lock.yaml'), line);
  assert.ok(JSON.parse(readFileSync(join(dir, 'sbom.cdx.json'), 'utf8')).components.length === 1);
});
