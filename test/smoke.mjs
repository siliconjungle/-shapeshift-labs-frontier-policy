import assert from 'node:assert';
import {
  compilePolicy,
  createPolicyManifest,
  createPolicyProof,
  createPolicyRecord,
  createPolicyRegistryGraph,
  decodePolicyJsonl,
  definePolicy,
  encodePolicyJsonl,
  evaluatePolicy,
  evaluatePolicyAsync,
  projectPolicyValue,
  queryPolicyManifest,
  redactPolicyManifest,
  redactPolicyValue,
  tracePolicyImpact
} from '../dist/index.js';

const manifest = createPolicyManifest({
  id: 'profile.policy',
  package: '@app/profile',
  feature: 'profile',
  subjects: [
    {
      id: 'user:u1',
      provider: 'external-idp',
      externalId: 'ext-1',
      roles: ['editor'],
      groups: ['staff'],
      capabilities: ['profile.read', 'profile.email.write'],
      claims: { tenant: 'acme', plan: 'pro' },
      metadata: { token: 'secret' }
    }
  ],
  rules: [
    {
      id: 'allow-email-write',
      effect: 'allow',
      action: 'write',
      resources: ['path:/profile/email'],
      capabilities: ['profile.email.write'],
      claims: { tenant: 'acme' },
      reason: 'editor can update own profile email',
      priority: 10
    },
    {
      id: 'private-notes-redaction',
      effect: 'redact',
      action: ['read', 'agent.read'],
      resources: ['path:/profile/privateNotes'],
      redact: '/profile/privateNotes',
      reason: 'private notes are not exposed to agents'
    },
    {
      id: 'sync-profile-public',
      effect: 'project',
      action: 'sync',
      resources: ['path:/profile'],
      project: [['profile', 'id'], ['profile', 'email']],
      reason: 'only public profile fields sync remotely'
    },
    {
      id: 'deny-delete',
      effect: 'deny',
      action: 'delete',
      resources: ['path:/profile/*'],
      reason: 'profile deletion requires a separate workflow',
      priority: 20
    },
    {
      id: 'allow-fetch',
      effect: 'allow-effect',
      action: 'load',
      resources: ['fetch:/api/profile'],
      effects: ['fetch:/api/profile']
    },
    {
      id: 'agent-tool',
      effect: 'allow-tool',
      action: 'agent.run',
      tools: ['profile.summarize'],
      capabilities: ['profile.read']
    }
  ],
  metadata: { token: 'manifest-secret' }
});

assert.strictEqual(definePolicy({ id: 'minimal' }).id, 'minimal');
assert.strictEqual(manifest.summary.ruleCount, 6);
assert.strictEqual(manifest.summary.redactionRules, 1);
assert.strictEqual(manifest.summary.projectionRules, 1);

const evaluator = compilePolicy(manifest);
const decision = evaluator.evaluate({
  subject: 'user:u1',
  action: 'write',
  resources: ['path:/profile/email'],
  capabilities: ['profile.email.write'],
  claims: { tenant: 'acme' }
});
assert.strictEqual(decision.allowed, true);
assert.deepStrictEqual(decision.allowedRules, ['allow-email-write']);
assert.deepStrictEqual(decision.reasons, ['editor can update own profile email']);

const denied = evaluatePolicy(manifest, {
  subject: manifest.subjects[0],
  action: 'delete',
  resources: ['path:/profile/email']
});
assert.strictEqual(denied.allowed, false);
assert.strictEqual(denied.access, 'deny');
assert.deepStrictEqual(denied.deniedRules, ['deny-delete']);

const redactionDecision = evaluator.evaluate({
  subject: manifest.subjects[0],
  action: 'agent.read',
  resources: ['path:/profile/privateNotes']
}, { defaultAccess: 'allow' });
assert.strictEqual(redactionDecision.allowed, true);
assert.deepStrictEqual(redactionDecision.redactions, ['path:/profile/privateNotes']);

const profile = {
  profile: {
    id: 'u1',
    email: 'new@example.test',
    privateNotes: 'sensitive',
    role: 'editor'
  }
};
assert.deepStrictEqual(redactPolicyValue(profile, redactionDecision), {
  profile: {
    id: 'u1',
    email: 'new@example.test',
    privateNotes: '[redacted]',
    role: 'editor'
  }
});

const syncDecision = evaluator.evaluate({
  subject: manifest.subjects[0],
  action: 'sync',
  resources: ['path:/profile']
}, { defaultAccess: 'allow' });
assert.deepStrictEqual(syncDecision.syncProjection, ['path:/profile/id', 'path:/profile/email']);
assert.deepStrictEqual(projectPolicyValue(profile, syncDecision), {
  profile: {
    id: 'u1',
    email: 'new@example.test'
  }
});

const effectDecision = evaluator.evaluate({
  subject: manifest.subjects[0],
  action: 'load',
  resources: ['fetch:/api/profile']
}, { defaultAccess: 'allow' });
assert.deepStrictEqual(effectDecision.allowedEffects, ['fetch:/api/profile']);

const toolDecision = evaluator.evaluate({
  subject: manifest.subjects[0],
  action: 'agent.run',
  resources: ['tool:profile.summarize'],
  capabilities: ['profile.read'],
  tools: ['profile.summarize']
}, { defaultAccess: 'allow' });
assert.deepStrictEqual(toolDecision.allowedTools, ['profile.summarize']);

const externalDecision = await evaluatePolicyAsync(manifest, {
  subject: { provider: 'external-idp', externalId: 'ext-1' },
  action: 'write',
  resources: ['path:/profile/email']
}, {
  subjectResolver: async (subject) => {
    assert.strictEqual(subject.provider, 'external-idp');
    return {
      id: 'user:u1',
      provider: 'external-idp',
      externalId: 'ext-1',
      roles: ['editor'],
      groups: ['staff'],
      capabilities: ['profile.email.write'],
      claims: { tenant: 'acme' }
    };
  }
});
assert.strictEqual(externalDecision.allowed, true);
assert.strictEqual(externalDecision.subject.externalId, 'ext-1');

const query = queryPolicyManifest(manifest, { resources: ['path:/profile/email'] });
assert.deepStrictEqual(query.ids, ['allow-email-write']);

const graph = createPolicyRegistryGraph(manifest);
assert.ok(graph.entries.some((entry) => entry.id === 'profile.policy'));
assert.ok(graph.entries.some((entry) => entry.id === 'allow-email-write'));
assert.ok(graph.edges.some((edge) => edge.to === 'capability:profile.email.write'));

const impact = tracePolicyImpact(manifest, { paths: ['/profile/email'] });
assert.ok(impact.ruleIds.includes('allow-email-write'));

const record = createPolicyRecord({ decision });
assert.strictEqual(record.entryId, 'allow-email-write');
const jsonl = encodePolicyJsonl([decision, redactionDecision]);
assert.strictEqual(decodePolicyJsonl(jsonl).length, 2);
assert.notStrictEqual(createPolicyProof(manifest).hash.length, 0);
assert.strictEqual(JSON.stringify(redactPolicyManifest(manifest)).includes('manifest-secret'), false);
