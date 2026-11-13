# sbom-action

A composite GitHub Action that generates a CycloneDX SBOM for a container image you just pushed to
GHCR, adds the npm libraries a bundler compiled into it, marks which packages the app's developers
chose, and attaches the SBOM to the image's digest. The image's own manifest is not changed.

It holds no secrets and is public so repositories in any GitHub organisation can use it.

## Use

```yaml
- uses: ControlC-io/sbom-action@v1.0.0
  with:
    image: ghcr.io/owner/name@sha256:...   # required, the pushed digest
    app-path: apps/api                     # folder of the deployed app's package.json (default .)
    lockfile: pnpm-lock.yaml               # pnpm lockfile v9 (default pnpm-lock.yaml)
    token: ${{ github.token }}             # default; needs packages: write
```

The job needs `permissions: packages: write` and a checkout of the repository (for the lockfile).
Run it only after an image was actually pushed.

## What it does

1. Syft (pinned) scans the pushed image: OS packages, runtimes, anything installed in the image.
2. Syft scans the checkout, which reads the lockfile.
3. `merge.mjs` computes the app's **production** dependency closure from the `package.json` files
   and the lockfile (the app's `dependencies`, `optionalDependencies`, `peerDependencies`, plus the
   same for each `workspace:` package it uses, and everything those pull in). Lockfile libraries in
   that closure and missing from the image scan are added. devDependencies are left out.
4. ORAS attaches the result with artifact type `application/vnd.cyclonedx+json`, then prints
   `oras discover` so the build log shows it.

## What is in the SBOM

- The OS is a component of `type: "operating-system"` (Syft: `alpine`, `debian`, ...). Node and other
  runtimes Syft finds are components too (Node: `type: "application"`, `pkg:generic/node@...`).
- **Direct**: the top-level `dependencies[]` entry whose `ref` is `metadata.component.bom-ref` lists
  the `bom-ref` of each package named in the app's `package.json` or in a workspace package's it uses.
  Workspace packages themselves are never listed.
- **Bundled**: each library added from the lockfile has
  `properties: [{ "name": "controlc:bundled", "value": "true" }]`.
- Image components pass through untouched.

## How the SBOM is found

**Tag `sha256-<hex>`.** GHCR does not support the OCI referrers API: checked in this repository's
self-test, `GET /v2/<repo>/referrers/<digest>` answered **404**. ORAS therefore falls back to the
referrers tag schema, which GHCR serves: `GET /v2/<repo>/manifests/sha256-<hex>` answered **200**
with an OCI image index.

To find the SBOM for an image `ghcr.io/owner/name@sha256:<hex>`:

1. Get a registry token (`https://ghcr.io/token?service=ghcr.io&scope=repository:owner/name:pull`,
   basic auth with a token that can read the package).
2. `GET https://ghcr.io/v2/owner/name/manifests/sha256-<hex>` with
   `Accept: application/vnd.oci.image.index.v1+json`. The index's `manifests[]` lists each attached
   artifact with its `artifactType`; pick the one with `application/vnd.cyclonedx+json`
   (if several, the newest by `annotations["org.opencontainers.image.created"]`).
3. `GET .../manifests/<that digest>`: its `layers[0].digest` is the SBOM blob, fetched from
   `.../blobs/<digest>`.

The self-test run proving this: see the Actions tab, workflow `self-test`.

## Self-test

`.github/workflows/self-test.yml` builds a throwaway image from `fixtures/workspace` (a small pnpm
workspace: `@fx/api` depends on `fastify` and the workspace package `@fx/schema`, which depends on
`zod`; `vitest` is a dev dependency), runs the action, and checks that exactly one CycloneDX artifact
is attached, that `vitest` is absent and an OS component is present, and which lookup GHCR supports.

`node --test` runs the unit tests of `merge.mjs` (Node 22, no dependencies).

## Limits

- pnpm lockfile v9 only. Other package managers are not read; the action fails with a clear message.
