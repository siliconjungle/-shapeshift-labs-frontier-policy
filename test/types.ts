import {
  compilePolicy,
  createPolicyManifest,
  evaluatePolicy,
  evaluatePolicyAsync,
  type FrontierPolicyDecision,
  type FrontierPolicyEvaluationContext,
  type FrontierPolicyManifest,
  type FrontierPolicyRuleInput,
  type FrontierPolicySubjectResolver
} from '../dist/index.js';

const rules: FrontierPolicyRuleInput[] = [
  {
    id: 'profile.write',
    effect: 'allow',
    action: 'write',
    resources: ['path:/profile/email'],
    capabilities: ['profile.email.write']
  }
];

const manifest: FrontierPolicyManifest = createPolicyManifest({ id: 'profile.policy', rules });
const evaluator = compilePolicy(manifest);
const context: FrontierPolicyEvaluationContext = {
  subject: { provider: 'external', externalId: 'u1' },
  action: 'write',
  resources: ['path:/profile/email']
};
const decision: FrontierPolicyDecision = evaluatePolicy(evaluator, context, { defaultAccess: 'deny' });
const resolver: FrontierPolicySubjectResolver = async (subject) => ({
  id: typeof subject === 'string' ? subject : subject?.externalId ?? 'u1',
  capabilities: ['profile.email.write']
});
const asyncDecision: Promise<FrontierPolicyDecision> = evaluatePolicyAsync(manifest, context, { subjectResolver: resolver });

void decision;
void asyncDecision;
