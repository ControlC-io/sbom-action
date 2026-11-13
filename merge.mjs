#!/usr/bin/env node
// Merges Syft's SBOM of a pushed image with the npm libraries a bundler compiled into it.
//
//   node merge.mjs --image image.cdx.json --lock lock.cdx.json --app apps/api \
//                  [--lockfile pnpm-lock.yaml] --out sbom.cdx.json
//
// Only node: built-ins are used. The production closure comes from the package.json files and
// the pnpm lockfile (lockfileVersion 9), never from Syft, which does not flag dev dependencies.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const BUNDLED = { name: 'controlc:bundled', value: 'true' };
const PROD_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];

// --- the part of YAML a pnpm lockfile uses: nested maps, scalars, and inline {..} / [..] kept raw.
export function parseLockfile(text) {
  const root = {};
  const stack = [{ indent: -1, node: root }];
  for (const raw of text.split('\n')) {
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const m = raw.trim().match(/^(?:'((?:[^']|'')*)'|"([^"]*)"|([^:'"][^:]*?|[^'"][^\s]*?)):(?:\s+(.*))?$/);
    if (!m) continue;
    const key = (m[1] ?? m[2] ?? m[3]).replace(/''/g, "'");
    const rest = m[4]?.trim();
    while (stack.at(-1).indent >= indent) stack.pop();
    const parent = stack.at(-1).node;
    if (rest === undefined || rest === '') {
      const node = {};
      parent[key] = node;
      stack.push({ indent, node });
    } else {
      parent[key] = rest.replace(/^'(.*)'$/, '$1').replace(/^"(.*)"$/, '$1');
    }
  }
  return root;
}

const stripPeers = (v) => String(v).replace(/\(.*$/, '');

function purlOf(c) {
  const m = /^pkg:npm\/([^@?#]+(?:@[^@?#]+)?)@([^?#]+)/.exec(c.purl ?? '');
  if (!m) return null;
  // purl encodes the scope's "@" as %40; the name may also be written "@scope/name".
  return { name: decodeURIComponent(m[1]), version: decodeURIComponent(m[2]) };
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function merge({ image, lock, appPath, lockfile }) {
  const lockDir = dirname(resolve(lockfile));
  const lf = parseLockfile(readFileSync(lockfile, 'utf8'));
  if (!lf.importers || !lf.snapshots) {
    throw new Error(`${lockfile}: not a pnpm lockfile v9 (no importers/snapshots)`);
  }

  // importer path (relative to the lockfile) -> package.json
  const pkgByImporter = new Map();
  const importerByName = new Map();
  for (const imp of Object.keys(lf.importers)) {
    try {
      const pkg = readJson(join(lockDir, imp, 'package.json'));
      pkgByImporter.set(imp, pkg);
      if (pkg.name) importerByName.set(pkg.name, imp);
    } catch {
      /* importer without package.json on disk */
    }
  }
  const appImporter = relative(lockDir, resolve(appPath)) || '.';
  if (!pkgByImporter.has(appImporter)) {
    throw new Error(`app path ${appPath} is not a workspace package of ${lockfile}`);
  }

  // Direct names + production closure (name@version), walking workspace packages recursively.
  const direct = new Map(); // name -> resolved version
  const closure = new Set();
  const seenImporters = new Set();
  const queue = [];
  const visitImporter = (imp) => {
    if (seenImporters.has(imp)) return;
    seenImporters.add(imp);
    const pkg = pkgByImporter.get(imp);
    const resolved = lf.importers[imp] ?? {};
    for (const field of PROD_FIELDS) {
      for (const [name, spec] of Object.entries(pkg[field] ?? {})) {
        if (String(spec).startsWith('workspace:')) {
          const target = importerByName.get(name);
          if (target) visitImporter(target);
          continue;
        }
        const entry = resolved.dependencies?.[name] ?? resolved.optionalDependencies?.[name];
        const version = entry?.version && stripPeers(entry.version);
        if (!version) continue; // an unresolved peer dependency: not installed, nothing to list
        direct.set(name, version);
        queue.push(`${name}@${stripPeers(entry.version)}`);
      }
    }
  };
  visitImporter(appImporter);
  const snapshotKeys = new Map(Object.keys(lf.snapshots).map((k) => [stripPeers(k), k]));
  while (queue.length) {
    const id = queue.pop();
    const plain = stripPeers(id);
    if (closure.has(plain)) continue;
    closure.add(plain);
    const snap = lf.snapshots[snapshotKeys.get(plain) ?? id] ?? {};
    for (const field of ['dependencies', 'optionalDependencies']) {
      for (const [name, version] of Object.entries(snap[field] ?? {})) {
        queue.push(String(version).startsWith('npm:') ? String(version).slice(4) : `${name}@${version}`);
      }
    }
  }

  const out = structuredClone(image);
  out.components ??= [];
  const refs = new Set(out.components.map((c) => c['bom-ref']).filter(Boolean));
  const idOf = (c) => {
    const p = purlOf(c);
    return p && `${p.name}@${p.version}`;
  };
  const inImage = new Map();
  for (const c of out.components) {
    const id = idOf(c);
    if (id && !inImage.has(id)) inImage.set(id, c);
  }

  // Bundled production libraries: in the lockfile scan, in the closure, not already in the image.
  const added = new Map();
  for (const c of lock.components ?? []) {
    const id = idOf(c);
    if (!id || !closure.has(id) || inImage.has(id) || added.has(id)) continue;
    const copy = structuredClone(c);
    let ref = copy['bom-ref'] ?? `pkg:npm/${id}`;
    while (refs.has(ref)) ref = `lock:${ref}`;
    copy['bom-ref'] = ref;
    refs.add(ref);
    copy.properties = [...(copy.properties ?? []), { ...BUNDLED }];
    added.set(id, copy);
    out.components.push(copy);
  }

  // Direct dependencies: the root component depends on the packages the app's developers chose.
  out.metadata ??= {};
  out.metadata.component ??= { type: 'application', name: 'image' };
  const root = out.metadata.component;
  root['bom-ref'] ??= 'controlc:root';
  const directRefs = [];
  for (const [name, version] of direct) {
    const c = inImage.get(`${name}@${version}`) ?? added.get(`${name}@${version}`);
    if (c && !directRefs.includes(c['bom-ref'])) directRefs.push(c['bom-ref']);
  }
  out.dependencies ??= [];
  const entry = out.dependencies.find((d) => d.ref === root['bom-ref']);
  if (entry) entry.dependsOn = directRefs;
  else out.dependencies.unshift({ ref: root['bom-ref'], dependsOn: directRefs });
  return out;
}

function main(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) args[argv[i].replace(/^--/, '')] = argv[i + 1];
  for (const k of ['image', 'lock', 'app', 'out']) {
    if (!args[k]) throw new Error(`missing --${k}`);
  }
  const sbom = merge({
    image: readJson(args.image),
    lock: readJson(args.lock),
    appPath: args.app,
    lockfile: args.lockfile ?? join(process.cwd(), 'pnpm-lock.yaml'),
  });
  writeFileSync(args.out, JSON.stringify(sbom, null, 2) + '\n');
  const bundled = sbom.components.filter((c) => c.properties?.some((p) => p.name === BUNDLED.name)).length;
  const direct = sbom.dependencies.find((d) => d.ref === sbom.metadata.component['bom-ref']).dependsOn.length;
  console.log(`${sbom.components.length} components, ${bundled} bundled, ${direct} direct -> ${args.out}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    console.error(`merge.mjs: ${e.message}`);
    process.exit(1);
  }
}
