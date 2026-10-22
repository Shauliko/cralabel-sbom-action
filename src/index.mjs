// CRA Label SBOM: GitHub Action entry point.
// Builds CycloneDX 1.6 and SPDX 2.3 SBOMs from the repository's dependency files inside the runner, then asks
// cralabel.com to sign an attestation over their SHA-256 hashes. Dependency files and SBOM content never leave
// the runner. The step never fails the build: problems are reported in the job summary.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { parseManifest, buildCycloneDX, buildSPDX, facts, sha256 } from './sbom.mjs';
import { KEY_ID, PUBLIC_KEY_PEM } from './key.mjs';

const VERSION = '1.0.0';
const API = 'https://cralabel.com/api/attest';
const FALLBACK_LINE = 'Since 11 September 2026 the CRA requires manufacturers to report actively exploited vulnerabilities within 24 hours (Art. 14). CRA Label is building a drafter for that report; [get an email when it opens](https://cralabel.com/?ref=gh-action#access).';

const input = (name, def) => {
  const v = process.env[`INPUT_${name}`];
  return (v === undefined || v.trim() === '' ? def : v).trim();
};
const workspace = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd());
const scanRoot = path.resolve(workspace, input('PATH', '.'));
const doSign = input('SIGN', 'true').toLowerCase() !== 'false';
const uploading = input('UPLOAD_ARTIFACT', 'true').toLowerCase() !== 'false';
const artifactName = input('ARTIFACT_NAME', 'cra-sbom');
const outDir = path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'cra-sbom');
const repo = process.env.GITHUB_REPOSITORY || path.basename(workspace);
const commit = process.env.GITHUB_SHA || '';

const SKIP = new Set(['node_modules', 'vendor', 'venv', '__pycache__', 'target', 'dist', 'build', 'bower_components']);
// Per directory and ecosystem the first file present wins, so a lockfile beats its manifest.
const PRIORITY = {
  npm: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'package.json'],
  golang: ['go.sum', 'go.mod'],
  cargo: ['cargo.lock', 'cargo.toml'],
  composer: ['composer.lock', 'composer.json'],
  maven: ['pom.xml'],
  gem: ['gemfile.lock'],
};
const ECO_NAME = { npm: 'npm', pypi: 'PyPI', golang: 'Go', cargo: 'Cargo', maven: 'Maven', gem: 'RubyGems', composer: 'Composer' };
const SUPPORTED = 'package-lock.json, npm-shrinkwrap.json, yarn.lock, package.json, Pipfile.lock, requirements*.txt, pyproject.toml, go.sum, go.mod, Cargo.lock, Cargo.toml, pom.xml, Gemfile.lock, composer.lock, composer.json';

function discover(dir, depth, found) {
  if (depth > 8 || found.length >= 200) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  const files = new Map(entries.filter(e => e.isFile()).map(e => [e.name.toLowerCase(), e.name]));
  const add = (eco, lower) => found.push({ eco, file: path.join(dir, files.get(lower)) });
  for (const [eco, order] of Object.entries(PRIORITY)) {
    const hit = order.find(n => files.has(n));
    if (hit) add(eco, hit);
  }
  // Python: Pipfile.lock alone if present, otherwise every requirements*.txt, otherwise pyproject.toml.
  if (files.has('pipfile.lock')) add('pypi', 'pipfile.lock');
  else {
    const reqs = [...files.keys()].filter(n => /^requirements.*\.txt$/.test(n)).sort();
    if (reqs.length) reqs.forEach(n => add('pypi', n));
    else if (files.has('pyproject.toml')) add('pypi', 'pyproject.toml');
  }
  for (const e of entries) {
    if (e.isDirectory() && !e.name.startsWith('.') && !SKIP.has(e.name)) discover(path.join(dir, e.name), depth + 1, found);
  }
}

function canonicalize(v) {
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

// true = signature checked here and valid; false = invalid; null = this Node version cannot check ML-DSA.
function verifyInRunner(att) {
  try {
    const { signature, ...rest } = att;
    if (!signature || signature.keyId !== KEY_ID) return false;
    return crypto.verify(null, Buffer.from(canonicalize(rest), 'utf8'), crypto.createPublicKey(PUBLIC_KEY_PEM), Buffer.from(signature.value, 'base64'));
  } catch { return null; }
}

function securityContact() {
  const candidates = [['', 'security.md'], ['.github', 'security.md'], ['docs', 'security.md'], ['', 'security.txt'], ['.well-known', 'security.txt'], ['.github', 'security.txt']];
  for (const [dir, name] of candidates) {
    try {
      const hit = fs.readdirSync(path.join(workspace, dir)).find(x => x.toLowerCase() === name);
      if (hit) return path.posix.join(dir, hit);
    } catch { /* directory absent */ }
  }
  return null;
}

// The summary line can be updated server-side; accept it only if every link points at cralabel.com.
function safeLine(s) {
  if (typeof s !== 'string' || s.length > 600 || /[<>]/.test(s)) return null;
  const links = [...s.matchAll(/\]\(([^)]+)\)/g)].map(m => m[1]);
  return links.every(u => u.startsWith('https://cralabel.com/')) ? s : null;
}

const cell = s => String(s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

async function main() {
  fs.mkdirSync(outDir, { recursive: true });
  const found = [];
  discover(scanRoot, 0, found);

  const results = [];
  for (const f of found) {
    const rel = path.relative(workspace, f.file).split(path.sep).join('/');
    let m;
    try {
      const text = fs.readFileSync(f.file, 'utf8');
      if (text.length > 20e6) throw new Error('file larger than 20 MB');
      m = parseManifest(path.basename(f.file), text);
    } catch (e) { results.push({ rel, error: String(e.message || e).slice(0, 140) }); continue; }
    if (!m.components.length) { results.push({ rel, error: 'no dependencies listed' }); continue; }
    const relDir = path.posix.dirname(rel);
    const project = m.name || (relDir === '.' ? repo : `${repo}/${relDir}`);
    const cdx = buildCycloneDX(m, project);
    cdx.metadata.properties.push({ name: 'cralabel:repository', value: repo }, { name: 'cralabel:source-path', value: rel });
    if (commit) cdx.metadata.properties.push({ name: 'cralabel:git-commit', value: commit });
    const spdx = buildSPDX(m, project);
    const cdxText = JSON.stringify(cdx, null, 2), spdxText = JSON.stringify(spdx, null, 2);
    const dir = path.join(outDir, rel.replace(/[^A-Za-z0-9._-]+/g, '_'));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'cyclonedx.json'), cdxText);
    fs.writeFileSync(path.join(dir, 'spdx.json'), spdxText);
    results.push({ rel, dir, m, f: facts(m), cdx, spdx, cdxHash: sha256(cdxText), spdxHash: sha256(spdxText) });
  }
  const ok = results.filter(r => !r.error);

  let signNote = '', summaryLine = FALLBACK_LINE;
  if (!doSign) signNote = 'not requested (`sign: false`), so nothing left the runner.';
  else if (ok.length) {
    const repoKey = sha256('cralabel-action:' + repo);
    for (let i = 0; i < ok.length; i += 50) {
      const batch = ok.slice(i, i + 50);
      const body = {
        version: VERSION, repoKey,
        items: batch.map(r => ({
          sourceFile: path.posix.basename(r.rel).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80),
          ecosystem: r.m.ecosystem, components: r.f.components, resolvedTree: r.f.resolvedTree,
          artifacts: {
            'cyclonedx.json': { sha256: r.cdxHash, serialNumber: r.cdx.serialNumber },
            'spdx.json': { sha256: r.spdxHash, documentNamespace: r.spdx.documentNamespace },
          },
        })),
      };
      try {
        const res = await fetch(API, { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': `cralabel-sbom-action/${VERSION}` }, body: JSON.stringify(body), signal: AbortSignal.timeout(20000) });
        const j = await res.json().catch(() => ({}));
        if (res.status === 429) { signNote = 'skipped: this repository reached the limit of 120 signing requests per hour. The SBOMs below were still built.'; break; }
        if (!res.ok || !Array.isArray(j.attestations)) { signNote = `skipped: cralabel.com answered ${res.status}. The SBOMs below were still built.`; break; }
        summaryLine = safeLine(j.summaryLine) || summaryLine;
        batch.forEach((r, k) => {
          const att = j.attestations[k];
          const a = att && att.artifacts;
          if (!a || a['cyclonedx.json'].sha256 !== r.cdxHash || a['spdx.json'].sha256 !== r.spdxHash) return;
          r.att = att;
          r.verified = verifyInRunner(att);
          fs.writeFileSync(path.join(r.dir, 'attestation.json'), JSON.stringify(att, null, 2));
        });
      } catch (e) { signNote = `skipped: cralabel.com could not be reached (${String(e.name || e)}). The SBOMs below were still built.`; break; }
    }
  }

  const total = ok.reduce((s, r) => s + r.f.components, 0);
  const dev = ok.reduce((s, r) => s + r.f.devOnly, 0);
  const unpinned = ok.reduce((s, r) => s + r.f.unpinned, 0);
  const signed = ok.filter(r => r.att).length;
  const verified = ok.filter(r => r.verified === true).length;
  const contact = securityContact();

  const L = ['## CRA Label SBOM', ''];
  if (!results.length) {
    L.push(`No supported dependency files were found under \`${path.relative(workspace, scanRoot) || '.'}\`. Supported: ${SUPPORTED}.`, '');
  } else {
    L.push('| Dependency file | Ecosystem | Components | Dev-only | Unpinned | Signature |', '|---|---|---:|---:|---:|---|');
    for (const r of results) {
      if (r.error) { L.push(`| \`${cell(r.rel)}\` | | | | | skipped: ${cell(r.error)} |`); continue; }
      const sig = r.att ? (r.verified === true ? 'Signed, verified in runner' : 'Signed') : 'Unsigned';
      L.push(`| \`${cell(r.rel)}\` | ${ECO_NAME[r.m.ecosystem] || r.m.ecosystem} | ${r.f.components} ${r.f.resolvedTree ? '(full tree)' : '(direct)'} | ${r.f.devOnly} | ${r.f.unpinned} | ${sig} |`);
    }
    L.push('', `**Totals:** ${ok.length} dependency ${ok.length === 1 ? 'file' : 'files'}, ${total} components, ${dev} dev-only, ${unpinned} unpinned.`);
    if (unpinned) L.push('', 'Unpinned versions make an SBOM describe a range instead of what shipped. Committing a lockfile next to the manifest gives exact versions.');
    if (signNote) L.push('', `**Signature:** ${signNote}`);
    else if (ok.length) L.push('', `**Signature:** ${signed} of ${ok.length} attestations signed by CRA Label with ML-DSA-65 (key \`${KEY_ID}\`)${verified ? `, ${verified} verified in this runner` : ''}. Only SHA-256 hashes, counts, file names and a hashed repository key left the runner.`);
  }
  L.push('', contact
    ? `**Vulnerability contact:** found in \`${contact}\`.`
    : '**Vulnerability contact:** none found. For products in the CRA’s scope, manufacturers must have a coordinated vulnerability disclosure policy and a contact address for vulnerability reports (Annex I, Part II, points 5 and 6). A `SECURITY.md` in the repository root or in `.github/` is the usual place.');
  if (ok.length) {
    L.push('', uploading
      ? `**Artifact:** \`${artifactName}\` holds \`cyclonedx.json\`, \`spdx.json\`${signed ? ' and `attestation.json`' : ''} for each dependency file. Anyone can check an attestation at https://cralabel.com/sbom.html.`
      : `**Files:** written to \`${outDir}\` (artifact upload turned off).`);
  }
  L.push('', '---', '', summaryLine, '');
  const md = L.join('\n');

  fs.writeFileSync(path.join(outDir, 'summary.md'), md);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n');
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, [`files=${ok.length}`, `components=${total}`, `signed=${ok.length > 0 && signed === ok.length}`, `sbom-dir=${outDir}`].join('\n') + '\n');
  }
  console.log(md);
}

main().catch(e => {
  console.log(`::warning title=CRA Label SBOM::The SBOM step hit an unexpected error and was skipped: ${String(e && e.message || e).slice(0, 300)}`);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `files=0\ncomponents=0\nsigned=false\nsbom-dir=${outDir}\n`);
});
