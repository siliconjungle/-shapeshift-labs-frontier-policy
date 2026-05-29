import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import {
  compilePolicy,
  createPolicyManifest,
  createPolicyProof,
  createPolicyRegistryGraph,
  decodePolicyJsonl,
  encodePolicyJsonl,
  evaluatePolicy,
  projectPolicyValue,
  queryPolicyManifest,
  redactPolicyManifest,
  redactPolicyValue,
  tracePolicyImpact
} from '../dist/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(__dirname, '..');
const repoRoot = path.basename(path.dirname(packageDir)) === 'packages'
  ? path.resolve(packageDir, '..', '..')
  : packageDir;
const args = parseArgs(process.argv.slice(2));
const ruleCount = readPositiveInt(args.rules, 1000);
const rounds = readPositiveInt(args.rounds, 30);
const outPath = args.out ? path.resolve(repoRoot, args.out) : null;

const input = makePolicyInput(ruleCount);
let manifest = createPolicyManifest(input);
let evaluator = compilePolicy(manifest);
let decision = evaluator.evaluate(makeContext(0));
let jsonl = encodePolicyJsonl([decision]);
let cursor = 0;
const value = { profile: { id: 'u1', email: 'u1@example.test', privateNotes: 'secret', plan: 'pro' } };

const rows = [
  measure('create-manifest-' + ruleCount, 1, () => {
    manifest = createPolicyManifest(input);
    return manifest.rules.length;
  }),
  measure('compile-policy-' + ruleCount, 1, () => {
    evaluator = compilePolicy(manifest);
    return evaluator.manifest.rules.length;
  }),
  measure('evaluate-compiled-' + ruleCount, 64, () => {
    decision = evaluator.evaluate(makeContext(cursor++));
    return decision.matchedRules.length;
  }),
  measure('evaluate-one-shot-' + ruleCount, 16, () => {
    decision = evaluatePolicy(manifest, makeContext(cursor++));
    return decision.matchedRules.length;
  }),
  measure('query-resource-' + ruleCount, 32, () => queryPolicyManifest(manifest, { resources: ['path:/rows/' + (cursor++ % ruleCount)] }).rules.length),
  measure('trace-impact-' + ruleCount, 8, () => tracePolicyImpact(manifest, { nodes: ['capability:bench.read'] }).ruleIds.length),
  measure('registry-graph-' + ruleCount, 1, () => {
    const graph = createPolicyRegistryGraph(manifest, { package: '@shapeshift-labs/frontier-policy' });
    return graph.entries.length + graph.edges.length;
  }),
  measure('redact-value-' + ruleCount, 16, () => JSON.stringify(redactPolicyValue(value, decision)).length),
  measure('project-value-' + ruleCount, 16, () => JSON.stringify(projectPolicyValue(value, decision)).length),
  measure('jsonl-encode-' + ruleCount, 4, () => {
    jsonl = encodePolicyJsonl([decision]);
    return jsonl.length;
  }),
  measure('jsonl-decode-' + ruleCount, 4, () => decodePolicyJsonl(jsonl).length),
  measure('redact-manifest-' + ruleCount, 1, () => redactPolicyManifest(manifest).rules.length),
  measure('proof-' + ruleCount, 4, () => createPolicyProof(manifest).hash.length)
];

const report = {
  package: '@shapeshift-labs/frontier-policy',
  version: readPackageVersion(),
  generatedAt: new Date().toISOString(),
  node: process.version,
  platform: process.platform + ' ' + process.arch,
  ruleCount,
  rounds,
  rows
};

if (outPath) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n');
}

console.log(report.package + ' package benchmark');
console.log('Node ' + report.node + ' on ' + report.platform + ', rules=' + ruleCount + ', rounds=' + rounds);
console.log('These are Frontier-only package measurements, not competitor comparisons.');
console.log('');
console.log(padRight('Fixture', 34) + padLeft('Median', 12) + padLeft('p95', 12));
for (const row of rows) {
  console.log(padRight(row.fixture, 34) + padLeft(formatUs(row.medianUs), 12) + padLeft(formatUs(row.p95Us), 12));
}
if (outPath) console.log('\nwrote ' + path.relative(repoRoot, outPath));

function makePolicyInput(count) {
  const rules = [];
  for (let i = 0; i < count; i++) {
    rules.push({
      id: 'row-' + i + '-read',
      effect: i % 11 === 0 ? 'redact' : i % 13 === 0 ? 'project' : 'allow',
      action: i % 5 === 0 ? 'sync' : 'read',
      resources: ['path:/rows/' + i, 'route:/rows/:id'],
      capabilities: ['bench.read'],
      redact: i % 11 === 0 ? '/rows/' + i + '/secret' : undefined,
      project: i % 13 === 0 ? ['/rows/' + i + '/id', '/rows/' + i + '/value'] : undefined,
      reason: 'bench rule ' + i,
      priority: i % 17,
      tags: ['bench', i % 2 === 0 ? 'even' : 'odd']
    });
  }
  rules.push({
    id: 'deny-danger',
    effect: 'deny',
    action: 'delete',
    resources: ['path:/rows/*'],
    priority: 100
  });
  return {
    id: 'bench.policy',
    subjects: [
      {
        id: 'user:bench',
        provider: 'bench-idp',
        externalId: 'bench',
        roles: ['reader'],
        groups: ['staff'],
        capabilities: ['bench.read'],
        claims: { tenant: 'bench' },
        metadata: { token: 'secret' }
      }
    ],
    rules,
    metadata: { token: 'bench-secret' }
  };
}

function makeContext(index) {
  return {
    subject: 'user:bench',
    action: index % 7 === 0 ? 'sync' : index % 29 === 0 ? 'delete' : 'read',
    resources: ['path:/rows/' + (index % ruleCount)],
    claims: { tenant: 'bench' }
  };
}

function measure(fixture, batchSize, fn, innerOps = 1) {
  const values = [];
  let sink = 0;
  for (let round = 0; round < rounds; round++) {
    const started = performance.now();
    for (let i = 0; i < batchSize; i++) sink += fn();
    values[values.length] = ((performance.now() - started) * 1000) / (batchSize * innerOps);
  }
  if (sink === -1) console.log('sink=' + sink);
  values.sort((left, right) => left - right);
  return {
    fixture,
    medianUs: percentile(values, 0.5),
    p95Us: percentile(values, 0.95)
  };
}

function percentile(values, p) {
  return values[Math.min(values.length - 1, Math.floor((values.length - 1) * p))] ?? 0;
}

function formatUs(value) {
  if (value >= 1000) return (value / 1000).toFixed(2) + ' ms';
  return value.toFixed(2) + ' us';
}

function padRight(value, width) {
  return String(value).padEnd(width, ' ');
}

function padLeft(value, width) {
  return String(value).padStart(width, ' ');
}

function readPackageVersion() {
  return JSON.parse(fs.readFileSync(path.join(packageDir, 'package.json'), 'utf8')).version;
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--rules') out.rules = argv[++i];
    else if (arg === '--rounds') out.rounds = argv[++i];
    else if (arg === '--out') out.out = argv[++i];
    else if (arg === '--help' || arg === '-h') {
      console.log('Usage: npm run bench -- [--rules 1000] [--rounds 30] [--out benchmarks/results/frontier-policy-package-bench-latest.json]');
      process.exit(0);
    }
  }
  return out;
}

function readPositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}
