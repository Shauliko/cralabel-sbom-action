// Manifest parsers + SBOM builders (CycloneDX 1.6 JSON, SPDX 2.3 JSON).
// Direct dependencies from manifests; full resolved trees from lockfiles.
// Nothing here touches the network — the user's manifest never leaves the request.
import { createHash, randomUUID } from 'node:crypto';

const GENERATOR = { name: 'CRA Label SBOM Generator', version: '1.0.0', url: 'https://cralabel.com/sbom.html' };

const enc = (s) => encodeURIComponent(s).replace(/%40/g, '%40');
const purlOf = (type, name, version, namespace) => {
  const ns = namespace ? String(namespace).split('/').map(enc).join('/') + '/' : '';
  return `pkg:${type}/${ns}${enc(name)}${version ? '@' + enc(version) : ''}`;
};
const cleanVer = (v) => String(v || '').trim().replace(/^[=v]+/, '') || '';
const unpinned = (v) => /[\^~><*|x]|,|\s(or|\|\|)\s/.test(String(v || '')) || String(v || '').trim() === '' || /^(latest|\*)$/.test(String(v || ''));

/* ---------- parsers ---------- */
function npmManifest(text) {
  const j = JSON.parse(text);
  const comps = [];
  for (const [scope, deps] of [['required', j.dependencies], ['optional', j.optionalDependencies], ['excluded', j.devDependencies]]) {
    for (const [name, spec] of Object.entries(deps || {})) comps.push({ name, version: cleanVer(spec), purl: purlOf('npm', name, unpinned(spec) ? '' : cleanVer(spec)), scope, spec: String(spec) });
  }
  return { name: j.name, version: j.version, components: comps, resolved: false };
}
function npmLock(text) {
  const j = JSON.parse(text);
  const comps = [];
  if (j.packages) {
    for (const [path, p] of Object.entries(j.packages)) {
      if (!path) continue;
      const name = p.name || path.replace(/^.*node_modules\//, '');
      comps.push({ name, version: p.version || '', purl: purlOf('npm', name, p.version), scope: p.dev ? 'excluded' : (p.optional ? 'optional' : 'required') });
    }
  } else if (j.dependencies) {
    const walk = (deps) => { for (const [name, p] of Object.entries(deps || {})) { comps.push({ name, version: p.version || '', purl: purlOf('npm', name, p.version), scope: p.dev ? 'excluded' : 'required' }); walk(p.dependencies); } };
    walk(j.dependencies);
  }
  return { name: j.name, version: j.version, components: dedupe(comps), resolved: true };
}
function yarnLock(text) {
  const comps = [];
  const re = /^"?((?:@[^\s"/]+\/)?[^\s"@]+)@[^\n]*:\n(?:[^\n]*\n)*?\s+version:?\s+"?([^"\n]+)"?/gm;
  let m; while ((m = re.exec(text))) comps.push({ name: m[1], version: m[2], purl: purlOf('npm', m[1], m[2]), scope: 'required' });
  return { components: dedupe(comps), resolved: true };
}
function requirementsTxt(text) {
  const comps = [];
  for (let line of text.split('\n')) {
    line = line.replace(/#.*$/, '').trim();
    if (!line || line.startsWith('-')) continue;
    const m = line.match(/^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(?:(==|>=|<=|~=|!=|>|<|===)\s*([^\s;,]+))?(.*)$/);
    if (!m) continue;
    const name = m[1].toLowerCase().replace(/[_.]/g, '-'), op = m[3] || '', v = m[4] || '';
    const pinned = op === '==' || op === '===';
    comps.push({ name, version: pinned ? v : (op + v), purl: purlOf('pypi', name, pinned ? v : ''), scope: 'required', spec: op + v });
  }
  return { components: comps, resolved: false };
}
function pyproject(text) {
  const comps = [];
  const sec = text.match(/\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
  if (sec) for (const q of sec[1].match(/"[^"]+"|'[^']+'/g) || []) {
    const r = requirementsTxt(q.slice(1, -1)); comps.push(...r.components);
  }
  const poetry = text.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(\n\[|$)/);
  if (poetry) for (const line of poetry[1].split('\n')) {
    const m = line.match(/^\s*([A-Za-z0-9_.\-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")/);
    if (m && m[1].toLowerCase() !== 'python') { const name = m[1].toLowerCase(), spec = m[2] || m[3] || ''; comps.push({ name, version: cleanVer(spec), purl: purlOf('pypi', name, unpinned(spec) ? '' : cleanVer(spec)), scope: 'required', spec }); }
  }
  const nm = text.match(/\[project\][\s\S]*?\nname\s*=\s*"([^"]+)"/), vm = text.match(/\[project\][\s\S]*?\nversion\s*=\s*"([^"]+)"/);
  return { name: nm && nm[1], version: vm && vm[1], components: dedupe(comps), resolved: false };
}
function pipfileLock(text) {
  const j = JSON.parse(text); const comps = [];
  for (const [scope, deps] of [['required', j.default], ['excluded', j.develop]]) for (const [name, p] of Object.entries(deps || {})) {
    const v = cleanVer(String(p.version || '').replace(/^==/, '')); comps.push({ name: name.toLowerCase(), version: v, purl: purlOf('pypi', name.toLowerCase(), v), scope });
  }
  return { components: comps, resolved: true };
}
function goMod(text) {
  const comps = []; let mod = (text.match(/^module\s+(\S+)/m) || [])[1];
  const body = (text.match(/require\s*\(([\s\S]*?)\)/g) || []).map(b => b.slice(b.indexOf('(') + 1, -1)).join('\n') + '\n' + (text.match(/^require\s+[^(\n]+$/gm) || []).map(l => l.replace(/^require\s+/, '')).join('\n');
  for (const line of body.split('\n')) {
    const m = line.trim().match(/^(\S+)\s+(v\S+)(\s*\/\/\s*indirect)?/);
    if (m) { const parts = m[1].split('/'); const name = parts.pop(); comps.push({ name: m[1], version: m[2], purl: purlOf('golang', name, m[2], parts.join('/')), scope: m[3] ? 'optional' : 'required' }); }
  }
  return { name: mod, components: comps, resolved: false };
}
function goSum(text) {
  const comps = [];
  for (const line of text.split('\n')) { const m = line.trim().match(/^(\S+)\s+(v[^\s/]+)(\/go\.mod)?\s+h1:/); if (m && !m[3]) { const parts = m[1].split('/'); const name = parts.pop(); comps.push({ name: m[1], version: m[2], purl: purlOf('golang', name, m[2], parts.join('/')), scope: 'required' }); } }
  return { components: dedupe(comps), resolved: true };
}
function cargoToml(text) {
  const comps = []; const nm = text.match(/\[package\][\s\S]*?\nname\s*=\s*"([^"]+)"/), vm = text.match(/\[package\][\s\S]*?\nversion\s*=\s*"([^"]+)"/);
  for (const [scope, key] of [['required', 'dependencies'], ['excluded', 'dev-dependencies'], ['required', 'build-dependencies']]) {
    const sec = text.match(new RegExp('\\[' + key + '\\]([\\s\\S]*?)(\\n\\[|$)'));
    if (!sec) continue;
    for (const line of sec[1].split('\n')) { const m = line.match(/^\s*([A-Za-z0-9_\-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")/); if (m) { const spec = m[2] || m[3] || ''; const pinned = /^=\s*\d/.test(spec); comps.push({ name: m[1], version: cleanVer(spec), purl: purlOf('cargo', m[1], pinned ? cleanVer(spec) : ''), scope, spec }); } }
  }
  return { name: nm && nm[1], version: vm && vm[1], components: comps, resolved: false };
}
function cargoLock(text) {
  const comps = []; const re = /\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g; let m;
  while ((m = re.exec(text))) comps.push({ name: m[1], version: m[2], purl: purlOf('cargo', m[1], m[2]), scope: 'required' });
  return { components: comps, resolved: true };
}
function pomXml(text) {
  const comps = []; const props = {}; const pm = text.match(/<properties>([\s\S]*?)<\/properties>/);
  if (pm) for (const p of pm[1].matchAll(/<([\w.\-]+)>([^<]*)<\/\1>/g)) props[p[1]] = p[2].trim();
  const sub = (v) => String(v || '').replace(/\$\{([\w.\-]+)\}/g, (_, k) => props[k] || '');
  const depsBlock = text.replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g, '');
  for (const d of depsBlock.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = (d[1].match(/<groupId>([^<]+)</) || [])[1], a = (d[1].match(/<artifactId>([^<]+)</) || [])[1], v = sub((d[1].match(/<version>([^<]+)</) || [])[1]), sc = (d[1].match(/<scope>([^<]+)</) || [])[1];
    if (g && a) comps.push({ name: a, group: g.trim(), version: v, purl: purlOf('maven', a, v, g.trim()), scope: sc === 'test' ? 'excluded' : 'required' });
  }
  const nm = text.match(/<artifactId>([^<]+)<\/artifactId>/), vm = text.match(/<\/parent>[\s\S]*?<version>([^<]+)<\/version>/) || text.match(/<version>([^<]+)<\/version>/);
  return { name: nm && nm[1], version: vm && sub(vm[1]), components: comps, resolved: false };
}
function gemfileLock(text) {
  const comps = []; const specs = text.match(/^\s*specs:\n([\s\S]*?)\n\n/m);
  if (specs) for (const line of specs[1].split('\n')) { const m = line.match(/^    ([A-Za-z0-9_\-.]+) \(([^)]+)\)$/); if (m) comps.push({ name: m[1], version: m[2], purl: purlOf('gem', m[1], m[2]), scope: 'required' }); }
  return { components: dedupe(comps), resolved: true };
}
function composerJson(text) {
  const j = JSON.parse(text); const comps = [];
  for (const [scope, deps] of [['required', j.require], ['excluded', j['require-dev']]]) for (const [name, spec] of Object.entries(deps || {})) {
    if (name === 'php' || name.startsWith('ext-')) continue;
    const [vendor, pkg] = name.split('/'); comps.push({ name: pkg || name, group: pkg ? vendor : undefined, version: cleanVer(spec), purl: purlOf('composer', pkg || name, unpinned(spec) ? '' : cleanVer(spec), pkg ? vendor : undefined), scope, spec: String(spec) });
  }
  return { name: j.name, version: j.version, components: comps, resolved: false };
}
function composerLock(text) {
  const j = JSON.parse(text); const comps = [];
  for (const [scope, list] of [['required', j.packages], ['excluded', j['packages-dev']]]) for (const p of list || []) {
    const [vendor, pkg] = String(p.name).split('/'); comps.push({ name: pkg || p.name, group: pkg ? vendor : undefined, version: cleanVer(p.version), purl: purlOf('composer', pkg || p.name, cleanVer(p.version), pkg ? vendor : undefined), scope });
  }
  return { components: comps, resolved: true };
}
function dedupe(comps) { const seen = new Set(); return comps.filter(c => { const k = c.purl; if (seen.has(k)) return false; seen.add(k); return true; }); }

const PARSERS = [
  ['package-lock.json', 'npm', npmLock], ['npm-shrinkwrap.json', 'npm', npmLock], ['package.json', 'npm', npmManifest], ['yarn.lock', 'npm', yarnLock],
  ['pipfile.lock', 'pypi', pipfileLock], ['pyproject.toml', 'pypi', pyproject], ['requirements', 'pypi', requirementsTxt],
  ['go.sum', 'golang', goSum], ['go.mod', 'golang', goMod],
  ['cargo.lock', 'cargo', cargoLock], ['cargo.toml', 'cargo', cargoToml],
  ['pom.xml', 'maven', pomXml], ['gemfile.lock', 'gem', gemfileLock],
  ['composer.lock', 'composer', composerLock], ['composer.json', 'composer', composerJson],
];
export const SUPPORTED = PARSERS.map(p => p[0]);

export function parseManifest(filename, text) {
  const fn = String(filename || '').toLowerCase().split(/[\\/]/).pop();
  const hit = PARSERS.find(([k]) => fn === k || (k === 'requirements' && /^requirements.*\.txt$/.test(fn)));
  if (!hit) throw new Error(`Unsupported file "${fn}". Supported: ${SUPPORTED.join(', ')}, requirements*.txt`);
  const [, ecosystem, parse] = hit;
  const r = parse(text);
  return { ...r, ecosystem, filename: fn };
}

/* ---------- builders ---------- */
export function buildCycloneDX(m, projectName) {
  const ts = new Date().toISOString();
  const root = { type: 'application', 'bom-ref': 'root', name: projectName || m.name || m.filename, version: m.version || undefined };
  const components = m.components.map((c, i) => ({
    type: 'library', 'bom-ref': c.purl || `c${i}`, name: c.name, group: c.group, version: c.version || undefined, purl: c.purl, scope: c.scope === 'optional' ? 'optional' : (c.scope === 'excluded' ? 'excluded' : 'required'),
  }));
  return {
    bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: `urn:uuid:${randomUUID()}`, version: 1,
    metadata: { timestamp: ts, tools: { components: [{ type: 'application', name: GENERATOR.name, version: GENERATOR.version, externalReferences: [{ type: 'website', url: GENERATOR.url }] }] }, component: root,
      properties: [{ name: 'cralabel:source-file', value: m.filename }, { name: 'cralabel:resolved-tree', value: String(!!m.resolved) }, { name: 'cralabel:regulatory-basis', value: 'Regulation (EU) 2024/2847, Annex I Part II(1) — top-level dependencies at minimum' }] },
    components,
    dependencies: [{ ref: 'root', dependsOn: components.filter(c => c.scope !== 'excluded').map(c => c['bom-ref']) }],
  };
}
export function buildSPDX(m, projectName) {
  const ts = new Date().toISOString(); const name = projectName || m.name || m.filename;
  const sid = (c, i) => 'SPDXRef-Package-' + (c.purl || c.name + i).replace(/[^A-Za-z0-9.\-]/g, '-').slice(0, 120) + '-' + i;
  const packages = m.components.map((c, i) => ({
    SPDXID: sid(c, i), name: c.group ? `${c.group}/${c.name}` : c.name, versionInfo: c.version || 'NOASSERTION', downloadLocation: 'NOASSERTION', filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION',
    externalRefs: c.purl ? [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: c.purl }] : undefined,
  }));
  const rootId = 'SPDXRef-Package-root';
  return {
    spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT', name: `${name}-sbom`,
    documentNamespace: `https://cralabel.com/spdx/${randomUUID()}`,
    creationInfo: { created: ts, creators: [`Tool: ${GENERATOR.name}-${GENERATOR.version}`], comment: 'Generated from ' + m.filename + '. Basis: Regulation (EU) 2024/2847, Annex I Part II(1).' },
    packages: [{ SPDXID: rootId, name, versionInfo: m.version || 'NOASSERTION', downloadLocation: 'NOASSERTION', filesAnalyzed: false, licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION' }, ...packages],
    relationships: [{ spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: rootId },
      ...packages.map(p => ({ spdxElementId: rootId, relationshipType: 'DEPENDS_ON', relatedSpdxElement: p.SPDXID }))],
  };
}
export function facts(m) {
  const req = m.components.filter(c => c.scope !== 'excluded');
  return {
    ecosystem: m.ecosystem, sourceFile: m.filename, resolvedTree: !!m.resolved,
    components: req.length, devOnly: m.components.length - req.length,
    unpinned: req.filter(c => !c.purl || !c.purl.includes('@')).length,
  };
}
export const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
export { GENERATOR };
