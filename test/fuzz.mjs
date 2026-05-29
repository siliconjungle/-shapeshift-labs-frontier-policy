import assert from 'node:assert';
import {
  compilePolicy,
  createPolicyManifest,
  decodePolicyJsonl,
  encodePolicyJsonl,
  evaluatePolicy,
  evaluatePolicyAsync,
  projectPolicyValue,
  redactPolicyValue
} from '../dist/index.js';

const args = parseArgs(process.argv.slice(2));
const cases = readPositiveInt(args.cases, 500);
let seed = readPositiveInt(args.seed, 0x9e3779b9);
let checked = 0;

for (let i = 0; i < cases; i++) {
  const scenario = makeScenario(i);
  const manifest = createPolicyManifest({ id: 'fuzz-' + i, rules: scenario.rules });
  const evaluator = compilePolicy(manifest, { defaultAccess: scenario.defaultAccess });
  const compiled = evaluator.evaluate(scenario.context);
  const direct = evaluatePolicy(manifest, scenario.context, { defaultAccess: scenario.defaultAccess });
  const reference = referenceEvaluate(manifest.rules, scenario.context, scenario.defaultAccess);

  assert.deepStrictEqual(compiled, direct);
  assert.strictEqual(compiled.allowed, reference.allowed);
  assert.strictEqual(compiled.access, reference.access);
  assert.deepStrictEqual(compiled.deniedRules, reference.deniedRules);
  assert.deepStrictEqual(compiled.allowedRules, reference.allowedRules);

  const asyncDecision = await evaluatePolicyAsync(manifest, scenario.context, {
    defaultAccess: scenario.defaultAccess,
    subjectResolver: async () => scenario.context.subject
  });
  assert.deepStrictEqual(asyncDecision, compiled);

  const jsonl = encodePolicyJsonl([compiled]);
  assert.strictEqual(decodePolicyJsonl(jsonl).length, 1);

  const value = { profile: { id: 'u1', email: 'a@example.test', secret: 'hidden' } };
  const redacted = redactPolicyValue(value, compiled);
  const projected = projectPolicyValue(value, compiled);
  assert.notStrictEqual(redacted, value);
  assert.notStrictEqual(projected, value);
  checked++;
}

console.log('frontier-policy fuzz ok: ' + checked + ' cases');

function makeScenario(index) {
  const owner = 'u' + (index % 4);
  const action = pick(['read', 'write', 'delete', 'sync']);
  const resource = pick(['path:/profile/email', 'path:/profile/secret', 'fetch:/api/profile', 'tool:profile.summarize']);
  const capabilities = maybe() ? ['profile.read', 'profile.email.write'] : ['profile.read'];
  const roles = maybe() ? ['admin'] : ['editor'];
  const rules = [
    {
      id: 'allow-read',
      effect: 'allow',
      action: 'read',
      resources: ['path:/profile/*'],
      capabilities: ['profile.read']
    },
    {
      id: 'allow-write-email',
      effect: 'allow',
      action: 'write',
      resources: ['path:/profile/email'],
      capabilities: ['profile.email.write'],
      claims: { tenant: 'acme' }
    },
    {
      id: 'deny-secret',
      effect: 'deny',
      action: ['read', 'write'],
      resources: ['path:/profile/secret'],
      priority: 10
    },
    {
      id: 'redact-secret',
      effect: 'redact',
      action: ['read', 'agent.read'],
      resources: ['path:/profile/secret'],
      redact: '/profile/secret'
    },
    {
      id: 'project-sync',
      effect: 'project',
      action: 'sync',
      resources: ['path:/profile'],
      project: ['/profile/id', '/profile/email']
    },
    {
      id: 'admin-delete-approval',
      effect: 'require-approval',
      action: 'delete',
      resources: ['path:/profile/*'],
      roles: ['admin']
    }
  ];
  return {
    defaultAccess: maybe() ? 'allow' : 'deny',
    rules: shuffle(rules),
    context: {
      subject: {
        id: 'user:' + owner,
        roles,
        capabilities,
        claims: { tenant: maybe() ? 'acme' : 'other' }
      },
      action,
      resources: [resource]
    }
  };
}

function referenceEvaluate(rules, context, defaultAccess) {
  const sorted = rules.slice().sort((left, right) => {
    if (right.priority !== left.priority) return right.priority - left.priority;
    if (left.effect === 'deny' && right.effect !== 'deny') return -1;
    if (right.effect === 'deny' && left.effect !== 'deny') return 1;
    return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
  });
  let denied = false;
  let allowed = false;
  let approval = false;
  const deniedRules = [];
  const allowedRules = [];
  for (const rule of sorted) {
    if (!matches(rule, context)) continue;
    if (rule.effect === 'allow') {
      allowed = true;
      allowedRules.push(rule.id);
    }
    if (rule.effect === 'deny') {
      denied = true;
      deniedRules.push(rule.id);
    }
    if (rule.effect === 'require-approval' || rule.requiresApproval) approval = true;
  }
  const access = denied ? 'deny' : approval ? 'approval-required' : allowed || defaultAccess === 'allow' ? 'allow' : 'deny';
  return { allowed: access === 'allow', access, deniedRules, allowedRules };
}

function matches(rule, context) {
  const actions = [].concat(rule.action ?? [], rule.actions ?? []);
  if (actions.length && !actions.includes(context.action)) return false;
  const resources = [].concat(rule.resource ?? [], rule.resources ?? []);
  if (resources.length && !resources.some((pattern) => context.resources.some((resource) => wildcard(pattern, resource)))) return false;
  for (const capability of rule.capabilities ?? []) {
    if (!context.subject.capabilities.includes(capability)) return false;
  }
  if (rule.roles?.length && !rule.roles.some((role) => context.subject.roles.includes(role))) return false;
  if (rule.claims) {
    for (const [key, expected] of Object.entries(rule.claims)) {
      const values = Array.isArray(expected) ? expected : [expected];
      if (!values.includes(context.subject.claims[key])) return false;
    }
  }
  return true;
}

function wildcard(pattern, value) {
  if (pattern === value || pattern === '*') return true;
  if (!pattern.includes('*')) return false;
  const [head, tail] = pattern.split('*');
  return value.startsWith(head) && value.endsWith(tail);
}

function shuffle(values) {
  const out = values.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = nextInt(i + 1);
    const item = out[i];
    out[i] = out[j];
    out[j] = item;
  }
  return out;
}

function pick(values) {
  return values[nextInt(values.length)];
}

function maybe() {
  return (next() & 1) === 1;
}

function nextInt(max) {
  return next() % max;
}

function next() {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed;
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--cases') out.cases = argv[++i];
    else if (argv[i] === '--seed') out.seed = argv[++i];
  }
  return out;
}

function readPositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}
