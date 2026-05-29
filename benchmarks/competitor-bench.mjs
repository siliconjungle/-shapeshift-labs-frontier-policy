import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { AbilityBuilder, createMongoAbility } from '@casl/ability';
import { AccessControl } from 'accesscontrol';
import { newEnforcer, newModelFromString, StringAdapter } from 'casbin';
import { compilePolicy, createPolicyManifest } from '../dist/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const packageDir = path.resolve(__dirname, '..');
const repoRoot = path.basename(path.dirname(packageDir)) === 'packages'
  ? path.resolve(packageDir, '..', '..')
  : packageDir;
const args = parseArgs(process.argv.slice(2));
const rounds = readPositiveInt(args.rounds, 50);
const outPath = args.out ? path.resolve(repoRoot, args.out) : null;

const frontierPolicy = compilePolicy(createPolicyManifest({
  id: 'competitor.policy',
  rules: [
    { id: 'read-profile', effect: 'allow', action: 'read', resources: ['profile'], capabilities: ['profile.read'] },
    { id: 'write-profile', effect: 'allow', action: 'write', resources: ['profile'], capabilities: ['profile.write'] },
    { id: 'deny-secret', effect: 'deny', action: 'read', resources: ['profile.secret'], priority: 10 }
  ]
}));

const { can, build } = new AbilityBuilder(createMongoAbility);
can('read', 'profile');
can('write', 'profile');
const caslAbility = build();

const accessControl = new AccessControl({
  editor: {
    profile: {
      'read:any': ['*'],
      'update:any': ['*']
    }
  }
});

const casbinModel = newModelFromString(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`);
const casbinAdapter = new StringAdapter(`
p, editor, profile, read
p, editor, profile, write
g, user:u1, editor
`);
const casbinEnforcer = await newEnforcer(casbinModel, casbinAdapter);

let cursor = 0;
const rows = [
  measure('frontier-policy:evaluate', 256, () => {
    const action = cursor++ % 2 === 0 ? 'read' : 'write';
    return frontierPolicy.evaluate({
      subject: { id: 'user:u1', capabilities: ['profile.read', 'profile.write'] },
      action,
      resources: ['profile']
    }).allowed ? 1 : 0;
  }),
  measure('casl:ability-can', 256, () => {
    const action = cursor++ % 2 === 0 ? 'read' : 'write';
    return caslAbility.can(action, 'profile') ? 1 : 0;
  }),
  measure('accesscontrol:can', 256, () => {
    const action = cursor++ % 2 === 0 ? 'readAny' : 'updateAny';
    return accessControl.can('editor')[action]('profile').granted ? 1 : 0;
  }),
  await measureAsync('casbin:enforce', 64, async () => {
    const action = cursor++ % 2 === 0 ? 'read' : 'write';
    return await casbinEnforcer.enforce('user:u1', 'profile', action) ? 1 : 0;
  })
];

const report = {
  package: '@shapeshift-labs/frontier-policy',
  type: 'competitor',
  generatedAt: new Date().toISOString(),
  node: process.version,
  platform: process.platform + ' ' + process.arch,
  rounds,
  competitors: {
    '@casl/ability': readVersion('@casl/ability'),
    accesscontrol: readVersion('accesscontrol'),
    casbin: readVersion('casbin')
  },
  rows
};

if (outPath) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n');
}

console.log('frontier-policy competitor benchmark');
console.log('Node ' + report.node + ' on ' + report.platform + ', rounds=' + rounds);
console.log('Fixture'.padEnd(32) + 'Median'.padStart(12) + 'p95'.padStart(12));
for (const row of rows) {
  console.log(row.fixture.padEnd(32) + formatUs(row.medianUs).padStart(12) + formatUs(row.p95Us).padStart(12));
}
if (outPath) console.log('\nwrote ' + path.relative(repoRoot, outPath));

function measure(fixture, batchSize, fn) {
  const values = [];
  let sink = 0;
  for (let round = 0; round < rounds; round++) {
    const started = performance.now();
    for (let i = 0; i < batchSize; i++) sink += fn();
    values[values.length] = ((performance.now() - started) * 1000) / batchSize;
  }
  if (sink === -1) console.log('sink=' + sink);
  values.sort((left, right) => left - right);
  return { fixture, medianUs: percentile(values, 0.5), p95Us: percentile(values, 0.95) };
}

async function measureAsync(fixture, batchSize, fn) {
  const values = [];
  let sink = 0;
  for (let round = 0; round < rounds; round++) {
    const started = performance.now();
    for (let i = 0; i < batchSize; i++) sink += await fn();
    values[values.length] = ((performance.now() - started) * 1000) / batchSize;
  }
  if (sink === -1) console.log('sink=' + sink);
  values.sort((left, right) => left - right);
  return { fixture, medianUs: percentile(values, 0.5), p95Us: percentile(values, 0.95) };
}

function percentile(values, p) {
  return values[Math.min(values.length - 1, Math.floor((values.length - 1) * p))] ?? 0;
}

function readVersion(name) {
  let current = path.dirname(require.resolve(name));
  while (current !== path.dirname(current)) {
    const candidate = path.join(current, 'package.json');
    if (fs.existsSync(candidate)) return JSON.parse(fs.readFileSync(candidate, 'utf8')).version;
    current = path.dirname(current);
  }
  return 'unknown';
}

function formatUs(value) {
  if (value >= 1000) return (value / 1000).toFixed(2) + ' ms';
  return value.toFixed(2) + ' us';
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--rounds') out.rounds = argv[++i];
    else if (arg === '--out') out.out = argv[++i];
    else if (arg === '--help' || arg === '-h') {
      console.log('Usage: npm run bench:competitors -- [--rounds 50] [--out benchmarks/results/frontier-policy-competitors-latest.json]');
      process.exit(0);
    }
  }
  return out;
}

function readPositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}
