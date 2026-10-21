# CRA Label SBOM

A free GitHub Action that turns the dependency files in your repository into a **CycloneDX 1.6** and an **SPDX 2.3** software bill of materials, each with an attestation signed by CRA Label using **ML-DSA-65** (FIPS 204). No account, no API key, and no source code leaves your runner.

It produces the same SBOMs as the free generator at [cralabel.com/sbom.html](https://cralabel.com/sbom.html), and it writes a job summary with component counts, dev-only and unpinned dependencies, the signature status, and whether the repository has a vulnerability contact.

## Usage

```yaml
name: SBOM
on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: Shauliko/cralabel-sbom-action@v1
```

The SBOMs and attestations are uploaded as the build artifact `cra-sbom`. A live example runs in [cralabel-sbom-action-demo](https://github.com/Shauliko/cralabel-sbom-action-demo/actions).

### Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Directory to scan, relative to the repository root. |
| `sign` | `true` | Ask cralabel.com to sign an attestation over the SBOM hashes. Set to `false` and nothing leaves the runner. |
| `upload-artifact` | `true` | Upload the files as a build artifact. |
| `artifact-name` | `cra-sbom` | Artifact name. In a matrix, give each job its own name, for example `cra-sbom-${{ matrix.os }}`. |

### Outputs

`files` (dependency files processed), `components` (total, dev-only excluded), `signed` (`true` when every SBOM was signed), `sbom-dir` (where the files are).

## What leaves your runner

The SBOMs are built inside the runner. Your source code, your dependency files and the SBOM content stay there.

When `sign` is `true`, the Action sends one request to `https://cralabel.com/api/attest` containing, for each dependency file:

- the file's base name, for example `package-lock.json` (no directory path);
- its ecosystem and its component count;
- the SHA-256 hashes of the generated `cyclonedx.json` and `spdx.json`, with their serial number and document namespace.

The repository is identified only by a SHA-256 digest of `cralabel-action:owner/repo`, which CRA Label keeps for rate limiting together with the time of the request and the country the request came from. Nothing else about the request is stored.

Because CRA Label sees only hashes, the attestation records `"signingMode": "hash-only"`. It proves that these exact SBOM files existed at the signing time and were presented by this Action. It does not claim that CRA Label inspected their content.

## Verifying an attestation

Open [cralabel.com/sbom.html](https://cralabel.com/sbom.html), expand "Verify an attestation", and upload `attestation.json` together with the matching `cyclonedx.json` and `spdx.json`. You can also check it offline against the public key at [cralabel.com/cralabel-signing-key.pem](https://cralabel.com/cralabel-signing-key.pem) (key id `3637019e0701a99a`). The signature covers the canonical JSON of the attestation with its `signature` member removed. When the runner's Node.js supports ML-DSA, the Action also verifies each signature in the runner and says so in the summary.

## Which files it reads

| Ecosystem | Files, in order of preference per directory |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `package.json` |
| Python | `Pipfile.lock`; otherwise every `requirements*.txt`; otherwise `pyproject.toml` |
| Go | `go.sum`, `go.mod` |
| Rust | `Cargo.lock`, `Cargo.toml` |
| Java | `pom.xml` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock`, `composer.json` |

A lockfile gives the full resolved dependency tree. A manifest alone gives direct dependencies, and any version ranges in it are reported as unpinned. Hidden directories and `node_modules`, `vendor`, `venv`, `target`, `dist`, `build` are skipped.

## Limits and failure behaviour

Signing is free and limited to about 120 requests per repository per hour. Each run makes one request for up to 50 dependency files. Above the limit, or if cralabel.com cannot be reached, the SBOMs are still built and uploaded unsigned, and the summary says why. The Action never fails your build.

It needs Node.js 18 or newer on the runner, which every GitHub-hosted runner has.

## The Cyber Resilience Act

Regulation (EU) 2024/2847 requires manufacturers of products with digital elements sold in the EU to draw up an SBOM "covering at the very least the top-level dependencies" (Annex I, Part II, point 1) and to keep it in their technical documentation (Annex VII). This Action produces that document. It is not a conformity assessment, it does not certify anything, and it is not legal advice. More at [cralabel.com/learn](https://cralabel.com/learn/).

## License

[MIT](LICENSE)
