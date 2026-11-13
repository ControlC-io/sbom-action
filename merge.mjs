#!/usr/bin/env node
// Merges Syft's SBOM of a pushed image with the npm libraries a bundler compiled into it.
//
//   node merge.mjs --image image.cdx.json --lock lock.cdx.json --app apps/api \
//                  [--lockfile pnpm-lock.yaml] --out sbom.cdx.json
//
// Only node: built-ins are used. The production closure comes from the package.json files and
// the pnpm lockfile (lockfileVersion 9), never from Syft, which does not flag dev dependencies.
import { readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, normalize, relative, resolve } from 'node:path';
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

// A pnpm dependency value is either a version ("5.4.0") or, for an npm alias, the real package id
// ("lodash@4.17.21"). Returns the exact snapshot key (peer suffix kept) for it.
function pnpmKey(name, value) {
  const v = String(value);
  const plain = stripPeers(v);
  return /^(@?[^@:]+)@./.test(plain) && !/^[a-z]+:/.test(plain) ? v : `${name}@${v}`;
}

function purlOf(c) {
  const m = /^pkg:npm\/([^?#]+)/.exec(c.purl ?? '');
  if (!m) return null;
  const at = m[1].lastIndexOf('@');
  if (at <= 0) return null;
  // purl encodes the scope's "@" as %40; decode before comparing.
  return { name: decodeURIComponent(m[1].slice(0, at)), version: decodeURIComponent(m[1].slice(at + 1)) };
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

// Each reader returns { direct: Set<"name@version">, closure: Set<"name@version"> } for the app.
function readPnpm(lockfile, appPath) {
  const lockDir = dirname(resolve(lockfile));
  const lf = parseLockfile(readFileSync(lockfile, 'utf8'));
  if (!lf.importers || !lf.snapshots) {
    throw new Error(`${lockfile}: not a pnpm lockfile v9 (no importers/snapshots)`);
  }
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

  const direct = new Set();
  const closure = new Set();
  const seenImporters = new Set();
  const queue = []; // exact snapshot keys, peer suffix kept
  const visitImporter = (imp) => {
    if (seenImporters.has(imp)) return;
    seenImporters.add(imp);
    const pkg = pkgByImporter.get(imp);
    const resolved = lf.importers[imp] ?? {};
    for (const field of PROD_FIELDS) {
      for (const [name, spec] of Object.entries(pkg[field] ?? {})) {
        const entry = resolved.dependencies?.[name] ?? resolved.optionalDependencies?.[name];
        const version = entry?.version == null ? '' : String(entry.version);
        if (String(spec).startsWith('workspace:') || version.startsWith('link:')) {
          const byPath = version.startsWith('link:') ? normalize(join(imp, version.slice(5))) : null;
          const target = byPath && pkgByImporter.has(byPath) ? byPath : importerByName.get(name);
          if (target) visitImporter(target);
          continue;
        }
        if (!version) continue; // an unresolved peer dependency: not installed, nothing to list
        const key = pnpmKey(name, version);
        direct.add(stripPeers(key));
        queue.push(key);
      }
    }
  };
  visitImporter(appImporter);
  const seen = new Set();
  while (queue.length) {
    const key = queue.pop();
    if (seen.has(key)) continue;
    seen.add(key);
    closure.add(stripPeers(key));
    const snap = lf.snapshots[key] ?? {};
    for (const field of ['dependencies', 'optionalDependencies']) {
      for (const [name, version] of Object.entries(snap[field] ?? {})) queue.push(pnpmKey(name, version));
    }
  }
  return { direct, closure };
}

// npm package-lock.json, lockfileVersion 2 or 3 ("packages" map).
function readNpm(lockfile, appPath) {
  const lockDir = dirname(resolve(lockfile));
  const lf = readJson(lockfile);
  const packages = lf.packages;
  if (!packages) throw new Error(`${lockfile}: not an npm lockfile v2/v3 (no packages)`);
  const appKey = relative(lockDir, resolve(appPath)).split('\\').join('/');
  if (!(appKey in packages)) throw new Error(`app path ${appPath} is not a package of ${lockfile}`);
  const nameOf = (path) => path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
  const find = (from, dep) => {
    let prefix = from;
    for (;;) {
      const path = prefix ? `${prefix}/node_modules/${dep}` : `node_modules/${dep}`;
      if (path in packages) return path;
      if (!prefix) return null;
      const i = prefix.lastIndexOf('/node_modules/');
      prefix = i === -1 ? '' : prefix.slice(0, i);
    }
  };
  const idOf = (path) => `${packages[path].name ?? nameOf(path)}@${packages[path].version}`;

  const direct = new Set();
  const closure = new Set();
  const seen = new Set();
  const visit = (path, isApp) => {
    if (seen.has(path)) return;
    seen.add(path);
    const entry = packages[path];
    for (const field of PROD_FIELDS) {
      for (const dep of Object.keys(entry[field] ?? {})) {
        const target = find(path, dep);
        if (!target) continue; // optional or peer dependency that was not installed
        const t = packages[target];
        if (t.link) {
          if (t.resolved in packages) visit(t.resolved, false);
          continue;
        }
        if (t.dev) continue;
        if (isApp || isWorkspace.has(path)) direct.add(idOf(target));
        visit(target, false);
      }
    }
    if (!isApp && !isWorkspace.has(path)) closure.add(idOf(path));
  };
  // Workspace packages are the targets of link entries; their own deps count as direct.
  const isWorkspace = new Set(Object.values(packages).filter((p) => p.link).map((p) => p.resolved));
  isWorkspace.add(appKey);
  visit(appKey, true);
  return { direct, closure };
}

export function merge({ image, lock, appPath, lockfile }) {
  const { direct, closure } = basename(lockfile) === 'package-lock.json'
    ? readNpm(lockfile, appPath)
    : readPnpm(lockfile, appPath);

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
  for (const id of direct) {
    const c = inImage.get(id) ?? added.get(id);
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
