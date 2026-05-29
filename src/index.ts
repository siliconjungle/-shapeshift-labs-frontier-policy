import type { JsonObject, JsonValue } from '@shapeshift-labs/frontier';
import { cloneJson } from '@shapeshift-labs/frontier/clone';
import {
  createFrontierRegistryGraph,
  frontierRegistryImpact,
  normalizeFrontierRegistryPath,
  type FrontierRegistryEdge,
  type FrontierRegistryEntry,
  type FrontierRegistryGraph,
  type FrontierRegistryImpact,
  type FrontierRegistryImpactInput,
  type FrontierRegistryPath,
  type FrontierRegistryRecord,
  type FrontierRegistrySource
} from '@shapeshift-labs/frontier/registry';

export const FRONTIER_POLICY_MANIFEST_KIND = 'frontier.policy.manifest';
export const FRONTIER_POLICY_MANIFEST_VERSION = 1;
export const FRONTIER_POLICY_DECISION_KIND = 'frontier.policy.decision';
export const FRONTIER_POLICY_DECISION_VERSION = 1;
export const FRONTIER_POLICY_QUERY_KIND = 'frontier.policy.query';
export const FRONTIER_POLICY_QUERY_VERSION = 1;
export const FRONTIER_POLICY_IMPACT_KIND = 'frontier.policy.impact';
export const FRONTIER_POLICY_IMPACT_VERSION = 1;
export const FRONTIER_POLICY_JSONL_KIND = 'frontier.policy.jsonl';
export const FRONTIER_POLICY_JSONL_VERSION = 1;
export const FRONTIER_POLICY_PROOF_KIND = 'frontier.policy.proof';
export const FRONTIER_POLICY_PROOF_VERSION = 1;

export type FrontierPolicyEffect =
  | 'allow'
  | 'deny'
  | 'require-approval'
  | 'redact'
  | 'project'
  | 'allow-effect'
  | 'deny-effect'
  | 'allow-tool'
  | 'deny-tool'
  | 'audit'
  | string;

export type FrontierPolicyAccess = 'allow' | 'deny' | 'approval-required';
export type FrontierPolicySubjectReference = string | FrontierPolicySubjectInput | FrontierPolicySubject;
export type FrontierPolicyResolverResult = FrontierPolicySubjectInput | FrontierPolicySubject | null | undefined;
export type FrontierPolicyMaybePromise<T> = T | Promise<T>;

export interface FrontierPolicySourceInput {
  file: string;
  line?: number;
  column?: number;
  symbol?: string;
  exportName?: string;
  package?: string;
}

export interface FrontierPolicySubjectInput {
  id?: string;
  kind?: string;
  provider?: string;
  externalId?: string;
  roles?: readonly string[];
  groups?: readonly string[];
  capabilities?: readonly string[];
  claims?: unknown;
  attributes?: unknown;
  tags?: readonly string[];
  metadata?: unknown;
}

export interface FrontierPolicySubject {
  id: string;
  kind: string;
  provider?: string;
  externalId?: string;
  roles: string[];
  groups: string[];
  capabilities: string[];
  claims: JsonObject;
  attributes: JsonObject;
  tags: string[];
  metadata?: JsonObject;
}

export interface FrontierPolicySubjectResolverContext {
  manifest?: FrontierPolicyManifest;
  action?: string;
  resources: string[];
  route?: string;
  feature?: string;
  package?: string;
  metadata?: JsonObject;
}

export type FrontierPolicySubjectResolver = (
  subject: FrontierPolicySubjectReference | undefined,
  context: FrontierPolicySubjectResolverContext
) => FrontierPolicyMaybePromise<FrontierPolicyResolverResult>;

export interface FrontierPolicyCondition {
  all?: readonly FrontierPolicyCondition[];
  any?: readonly FrontierPolicyCondition[];
  not?: FrontierPolicyCondition;
  path?: FrontierRegistryPath;
  equals?: JsonValue;
  value?: JsonValue;
  in?: readonly JsonValue[];
  contains?: JsonValue;
  exists?: boolean;
  capability?: string;
  capabilities?: readonly string[];
  role?: string;
  roles?: readonly string[];
  group?: string;
  groups?: readonly string[];
  claim?: string;
  claimEquals?: JsonValue;
}

export interface FrontierPolicyRuleInput {
  id?: string;
  effect?: FrontierPolicyEffect;
  action?: string | readonly string[];
  actions?: readonly string[];
  resource?: string | readonly string[];
  resources?: readonly string[];
  subjects?: readonly string[];
  providers?: readonly string[];
  roles?: readonly string[];
  groups?: readonly string[];
  capabilities?: readonly string[];
  claims?: Record<string, JsonValue | readonly JsonValue[]>;
  when?: FrontierPolicyCondition;
  conditions?: readonly FrontierPolicyCondition[];
  redact?: FrontierRegistryPath | readonly FrontierRegistryPath[];
  redactions?: readonly FrontierRegistryPath[];
  project?: FrontierRegistryPath | readonly FrontierRegistryPath[];
  projection?: readonly FrontierRegistryPath[];
  effects?: readonly string[];
  tools?: readonly string[];
  requiresApproval?: boolean;
  priority?: number;
  reason?: string;
  owner?: string;
  package?: string;
  feature?: string;
  tags?: readonly string[];
  source?: FrontierRegistrySource;
  metadata?: unknown;
}

export interface FrontierPolicyRule {
  id: string;
  effect: FrontierPolicyEffect;
  actions: string[];
  resources: string[];
  subjects: string[];
  providers: string[];
  roles: string[];
  groups: string[];
  capabilities: string[];
  claims: Record<string, JsonValue[]>;
  conditions: FrontierPolicyCondition[];
  redactions: string[];
  projection: string[];
  effects: string[];
  tools: string[];
  requiresApproval: boolean;
  priority: number;
  reason?: string;
  owner?: string;
  package?: string;
  feature?: string;
  tags: string[];
  source?: FrontierRegistrySource;
  metadata?: JsonObject;
}

export interface FrontierPolicyManifestInput {
  id?: string;
  package?: string;
  feature?: string;
  owner?: string;
  rules?: readonly FrontierPolicyRuleInput[];
  subjects?: readonly FrontierPolicySubjectInput[];
  resources?: readonly string[];
  capabilities?: readonly string[];
  effects?: readonly string[];
  tools?: readonly string[];
  tags?: readonly string[];
  source?: FrontierRegistrySource;
  metadata?: unknown;
}

export interface FrontierPolicyManifest {
  kind: typeof FRONTIER_POLICY_MANIFEST_KIND;
  version: typeof FRONTIER_POLICY_MANIFEST_VERSION;
  id: string;
  package?: string;
  feature?: string;
  owner?: string;
  rules: FrontierPolicyRule[];
  subjects: FrontierPolicySubject[];
  resources: string[];
  capabilities: string[];
  effects: string[];
  tools: string[];
  tags: string[];
  source?: FrontierRegistrySource;
  metadata?: JsonObject;
  summary: FrontierPolicySummary;
}

export interface FrontierPolicySummary {
  ruleCount: number;
  subjectCount: number;
  resourceCount: number;
  capabilityCount: number;
  effectCount: number;
  toolCount: number;
  allowRules: number;
  denyRules: number;
  redactionRules: number;
  projectionRules: number;
  approvalRules: number;
}

export interface FrontierPolicyEvaluationContext {
  subject?: FrontierPolicySubjectReference;
  actor?: FrontierPolicySubjectReference;
  action?: string;
  actions?: readonly string[];
  resource?: string | readonly string[];
  resources?: readonly string[];
  capabilities?: readonly string[];
  roles?: readonly string[];
  groups?: readonly string[];
  claims?: unknown;
  attributes?: unknown;
  route?: string;
  feature?: string;
  package?: string;
  effects?: readonly string[];
  tools?: readonly string[];
  state?: unknown;
  environment?: unknown;
  metadata?: unknown;
}

export interface FrontierPolicyEvaluationOptions {
  defaultAccess?: 'allow' | 'deny';
  subjectResolver?: FrontierPolicySubjectResolver;
  manifest?: FrontierPolicyManifest;
}

export interface FrontierPolicyDecisionRule {
  id: string;
  effect: FrontierPolicyEffect;
  priority: number;
  reason?: string;
  resources: string[];
  actions: string[];
  tags: string[];
}

export interface FrontierPolicyDecision {
  kind: typeof FRONTIER_POLICY_DECISION_KIND;
  version: typeof FRONTIER_POLICY_DECISION_VERSION;
  allowed: boolean;
  access: FrontierPolicyAccess;
  defaultAccess: 'allow' | 'deny';
  requiresApproval: boolean;
  action?: string;
  actions: string[];
  resources: string[];
  subject: FrontierPolicySubject;
  matchedRules: FrontierPolicyDecisionRule[];
  deniedRules: string[];
  allowedRules: string[];
  redactions: string[];
  projection: string[];
  syncProjection: string[];
  allowedEffects: string[];
  deniedEffects: string[];
  allowedTools: string[];
  deniedTools: string[];
  reasons: string[];
  tags: string[];
  metadata?: JsonObject;
}

export interface FrontierPolicyEvaluator {
  readonly manifest: FrontierPolicyManifest;
  readonly defaultAccess: 'allow' | 'deny';
  evaluate(context: FrontierPolicyEvaluationContext, options?: Omit<FrontierPolicyEvaluationOptions, 'manifest'>): FrontierPolicyDecision;
  evaluateAsync(context: FrontierPolicyEvaluationContext, options?: Omit<FrontierPolicyEvaluationOptions, 'manifest'>): Promise<FrontierPolicyDecision>;
  explain(context: FrontierPolicyEvaluationContext, options?: Omit<FrontierPolicyEvaluationOptions, 'manifest'>): FrontierPolicyDecision;
}

export interface FrontierPolicyQueryInput {
  ids?: readonly string[];
  features?: readonly string[];
  packages?: readonly string[];
  owners?: readonly string[];
  resources?: readonly string[];
  actions?: readonly string[];
  effects?: readonly string[];
  tools?: readonly string[];
  capabilities?: readonly string[];
  tags?: readonly string[];
}

export interface FrontierPolicyQueryResult {
  kind: typeof FRONTIER_POLICY_QUERY_KIND;
  version: typeof FRONTIER_POLICY_QUERY_VERSION;
  ids: string[];
  rules: FrontierPolicyRule[];
  subjects: FrontierPolicySubject[];
  resources: string[];
  actions: string[];
  effects: string[];
  tools: string[];
  capabilities: string[];
}

export interface FrontierPolicyImpact extends Omit<FrontierRegistryImpact, 'kind' | 'version'> {
  kind: typeof FRONTIER_POLICY_IMPACT_KIND;
  version: typeof FRONTIER_POLICY_IMPACT_VERSION;
  ruleIds: string[];
  subjectIds: string[];
}

export interface FrontierPolicyRecordInput {
  id?: string;
  entryId?: string;
  causeId?: string;
  parentId?: string;
  startedAt?: number;
  endedAt?: number;
  durationMs?: number;
  decision: FrontierPolicyDecision;
  status?: 'ok' | 'error' | 'skipped' | string;
  metadata?: unknown;
  error?: string;
}

export interface FrontierPolicyProof {
  kind: typeof FRONTIER_POLICY_PROOF_KIND;
  version: typeof FRONTIER_POLICY_PROOF_VERSION;
  id: string;
  hash: string;
  ruleCount: number;
  subjectCount: number;
  resourceCount: number;
  capabilityCount: number;
}

const hasOwn = Object.prototype.hasOwnProperty;
const policyGraphCache = new WeakMap<FrontierPolicyManifest, FrontierRegistryGraph>();

export function createPolicyManifest(input: FrontierPolicyManifestInput = {}): FrontierPolicyManifest {
  const rules = (input.rules ?? []).map(normalizePolicyRule);
  rules.sort(compareRules);
  const subjects = (input.subjects ?? []).map((subject, index) => normalizeSubject(subject, 'subject-' + index));
  const resources = sortedUnique((input.resources ?? []).concat(...rules.map((rule) => rule.resources)));
  const capabilities = sortedUnique((input.capabilities ?? []).concat(...rules.map((rule) => rule.capabilities), ...subjects.map((subject) => subject.capabilities).flat()));
  const effects = sortedUnique((input.effects ?? []).concat(...rules.map((rule) => rule.effects)));
  const tools = sortedUnique((input.tools ?? []).concat(...rules.map((rule) => rule.tools)));
  const manifest: FrontierPolicyManifest = {
    kind: FRONTIER_POLICY_MANIFEST_KIND,
    version: FRONTIER_POLICY_MANIFEST_VERSION,
    id: input.id === undefined ? 'policy' : readString(input.id, 'policy id'),
    package: optionalString(input.package, 'policy package'),
    feature: optionalString(input.feature, 'policy feature'),
    owner: optionalString(input.owner, 'policy owner'),
    rules,
    subjects,
    resources,
    capabilities,
    effects,
    tools,
    tags: uniqueStrings(input.tags ?? []),
    source: input.source,
    metadata: input.metadata === undefined ? undefined : readJsonObject(input.metadata, 'policy metadata'),
    summary: {
      ruleCount: rules.length,
      subjectCount: subjects.length,
      resourceCount: resources.length,
      capabilityCount: capabilities.length,
      effectCount: effects.length,
      toolCount: tools.length,
      allowRules: rules.filter((rule) => rule.effect === 'allow').length,
      denyRules: rules.filter((rule) => rule.effect === 'deny').length,
      redactionRules: rules.filter((rule) => rule.effect === 'redact' || rule.redactions.length !== 0).length,
      projectionRules: rules.filter((rule) => rule.effect === 'project' || rule.projection.length !== 0).length,
      approvalRules: rules.filter((rule) => rule.effect === 'require-approval' || rule.requiresApproval).length
    }
  };
  return manifest;
}

export function definePolicy(input: FrontierPolicyManifestInput = {}): FrontierPolicyManifest {
  return createPolicyManifest(input);
}

export function compilePolicy(
  manifestOrRules: FrontierPolicyManifestInput | FrontierPolicyManifest | readonly FrontierPolicyRuleInput[],
  options: FrontierPolicyEvaluationOptions = {}
): FrontierPolicyEvaluator {
  const manifest = isRuleArray(manifestOrRules)
    ? createPolicyManifest({ rules: manifestOrRules })
    : isPolicyManifest(manifestOrRules)
      ? manifestOrRules
      : createPolicyManifest(manifestOrRules);
  const defaultAccess = normalizeDefaultAccess(options.defaultAccess);
  return {
    manifest,
    defaultAccess,
    evaluate(context, nextOptions = {}) {
      return evaluateCompiledPolicy(manifest, context, {
        ...options,
        ...nextOptions,
        defaultAccess: nextOptions.defaultAccess ?? options.defaultAccess ?? defaultAccess
      });
    },
    async evaluateAsync(context, nextOptions = {}) {
      return evaluateCompiledPolicyAsync(manifest, context, {
        ...options,
        ...nextOptions,
        defaultAccess: nextOptions.defaultAccess ?? options.defaultAccess ?? defaultAccess
      });
    },
    explain(context, nextOptions = {}) {
      return this.evaluate(context, nextOptions);
    }
  };
}

export function evaluatePolicy(
  policyOrRules: FrontierPolicyEvaluator | FrontierPolicyManifest | FrontierPolicyManifestInput | readonly FrontierPolicyRuleInput[],
  context: FrontierPolicyEvaluationContext,
  options: FrontierPolicyEvaluationOptions = {}
): FrontierPolicyDecision {
  if (isPolicyEvaluator(policyOrRules)) return policyOrRules.evaluate(context, options);
  const manifest = isRuleArray(policyOrRules)
    ? createPolicyManifest({ rules: policyOrRules })
    : isPolicyManifest(policyOrRules)
      ? policyOrRules
      : createPolicyManifest(policyOrRules);
  return evaluateCompiledPolicy(manifest, context, { ...options, manifest });
}

export async function evaluatePolicyAsync(
  policyOrRules: FrontierPolicyEvaluator | FrontierPolicyManifest | FrontierPolicyManifestInput | readonly FrontierPolicyRuleInput[],
  context: FrontierPolicyEvaluationContext,
  options: FrontierPolicyEvaluationOptions = {}
): Promise<FrontierPolicyDecision> {
  if (isPolicyEvaluator(policyOrRules)) return policyOrRules.evaluateAsync(context, options);
  const manifest = isRuleArray(policyOrRules)
    ? createPolicyManifest({ rules: policyOrRules })
    : isPolicyManifest(policyOrRules)
      ? policyOrRules
      : createPolicyManifest(policyOrRules);
  return evaluateCompiledPolicyAsync(manifest, context, { ...options, manifest });
}

export function queryPolicyManifest(
  manifest: FrontierPolicyManifest,
  query: FrontierPolicyQueryInput = {}
): FrontierPolicyQueryResult {
  const ids = new Set(query.ids ?? []);
  const features = new Set(query.features ?? []);
  const packages = new Set(query.packages ?? []);
  const owners = new Set(query.owners ?? []);
  const resources = new Set(query.resources ?? []);
  const actions = new Set(query.actions ?? []);
  const effects = new Set(query.effects ?? []);
  const tools = new Set(query.tools ?? []);
  const capabilities = new Set(query.capabilities ?? []);
  const tags = new Set(query.tags ?? []);
  const hasFilter = ids.size + features.size + packages.size + owners.size + resources.size + actions.size + effects.size + tools.size + capabilities.size + tags.size > 0;
  const rules = hasFilter ? manifest.rules.filter((rule) => {
    if (ids.has(rule.id)) return true;
    if (rule.feature !== undefined && features.has(rule.feature)) return true;
    if (rule.package !== undefined && packages.has(rule.package)) return true;
    if (rule.owner !== undefined && owners.has(rule.owner)) return true;
    if (intersectsSet(rule.resources, resources)) return true;
    if (intersectsSet(rule.actions, actions)) return true;
    if (intersectsSet(rule.effects, effects)) return true;
    if (intersectsSet(rule.tools, tools)) return true;
    if (intersectsSet(rule.capabilities, capabilities)) return true;
    if (intersectsSet(rule.tags, tags)) return true;
    return false;
  }) : manifest.rules.slice();
  const subjects = manifest.subjects.filter((subject) => {
    if (!hasFilter) return true;
    if (ids.has(subject.id)) return true;
    if (intersectsSet(subject.capabilities, capabilities)) return true;
    if (intersectsSet(subject.tags, tags)) return true;
    return false;
  });
  return {
    kind: FRONTIER_POLICY_QUERY_KIND,
    version: FRONTIER_POLICY_QUERY_VERSION,
    ids: rules.map((rule) => rule.id),
    rules,
    subjects,
    resources: sortedUnique(rules.flatMap((rule) => rule.resources)),
    actions: sortedUnique(rules.flatMap((rule) => rule.actions)),
    effects: sortedUnique(rules.flatMap((rule) => rule.effects)),
    tools: sortedUnique(rules.flatMap((rule) => rule.tools)),
    capabilities: sortedUnique(rules.flatMap((rule) => rule.capabilities))
  };
}

export function createPolicyRegistryGraph(
  manifest: FrontierPolicyManifest,
  input: { package?: string; feature?: string; owner?: string; generatedAt?: number; metadata?: unknown } = {}
): FrontierRegistryGraph {
  const entries: FrontierRegistryEntry[] = [{
    id: manifest.id,
    kind: 'policy-manifest',
    package: input.package ?? manifest.package,
    feature: input.feature ?? manifest.feature,
    owner: input.owner ?? manifest.owner,
    source: manifest.source,
    touches: manifest.resources,
    produces: manifest.capabilities,
    tags: manifest.tags,
    metadata: {
      ruleCount: manifest.summary.ruleCount,
      subjectCount: manifest.summary.subjectCount
    }
  }];
  const edges: FrontierRegistryEdge[] = [];
  for (const rule of manifest.rules) {
    const ruleMetadata: JsonObject = {
      effect: rule.effect,
      priority: rule.priority,
      requiresApproval: rule.requiresApproval
    };
    if (rule.reason !== undefined) ruleMetadata.reason = rule.reason;
    entries[entries.length] = {
      id: rule.id,
      kind: 'policy-rule',
      package: rule.package ?? input.package ?? manifest.package,
      feature: rule.feature ?? input.feature ?? manifest.feature,
      owner: rule.owner ?? input.owner ?? manifest.owner,
      source: rule.source,
      touches: rule.resources,
      consumes: rule.capabilities,
      produces: rule.redactions.concat(rule.projection, rule.effects, rule.tools),
      tags: rule.tags,
      metadata: ruleMetadata
    };
    edges[edges.length] = { from: manifest.id, to: rule.id, kind: 'contains' };
    for (const action of rule.actions) edges[edges.length] = { from: rule.id, to: 'action:' + action, kind: 'handles' };
    for (const capability of rule.capabilities) edges[edges.length] = { from: rule.id, to: 'capability:' + capability, kind: 'depends-on' };
    for (const resource of rule.resources) edges[edges.length] = { from: rule.id, to: resource, kind: 'touches' };
  }
  for (const subject of manifest.subjects) {
    const subjectMetadata: JsonObject = {
      kind: subject.kind,
      roles: subject.roles as unknown as JsonValue,
      groups: subject.groups as unknown as JsonValue
    };
    if (subject.provider !== undefined) subjectMetadata.provider = subject.provider;
    entries[entries.length] = {
      id: 'subject:' + subject.id,
      kind: 'policy-subject',
      package: input.package ?? manifest.package,
      feature: input.feature ?? manifest.feature,
      owner: input.owner ?? manifest.owner,
      produces: subject.capabilities,
      tags: subject.tags,
      metadata: subjectMetadata
    };
    edges[edges.length] = { from: manifest.id, to: 'subject:' + subject.id, kind: 'declares' };
  }
  return createFrontierRegistryGraph({
    entries,
    edges,
    generatedAt: input.generatedAt,
    metadata: input.metadata === undefined ? manifest.metadata : readJsonObject(input.metadata, 'registry metadata')
  });
}

export function tracePolicyImpact(
  manifest: FrontierPolicyManifest,
  input: FrontierRegistryImpactInput
): FrontierPolicyImpact {
  let graph = policyGraphCache.get(manifest);
  if (graph === undefined) {
    graph = createPolicyRegistryGraph(manifest);
    policyGraphCache.set(manifest, graph);
  }
  const impact = frontierRegistryImpact(graph, input);
  const nodeSet = new Set(impact.nodes);
  const ruleIds = manifest.rules
    .filter((rule) => nodeSet.has(rule.id) || nodeSet.has('entry:' + rule.id) || nodeSet.has('node:' + rule.id))
    .map((rule) => rule.id);
  const subjectIds = manifest.subjects
    .filter((subject) => nodeSet.has('subject:' + subject.id) || nodeSet.has('entry:subject:' + subject.id) || nodeSet.has('node:subject:' + subject.id))
    .map((subject) => subject.id);
  return {
    ...impact,
    kind: FRONTIER_POLICY_IMPACT_KIND,
    version: FRONTIER_POLICY_IMPACT_VERSION,
    ruleIds,
    subjectIds
  };
}

export function createPolicyRecord(input: FrontierPolicyRecordInput): FrontierRegistryRecord {
  const decision = input.decision;
  return {
    id: input.id ?? 'policy:' + decision.action + ':' + decision.subject.id + ':' + hashStable(decision),
    entryId: input.entryId ?? decision.matchedRules[0]?.id ?? 'policy',
    kind: 'policy-decision',
    causeId: input.causeId,
    parentId: input.parentId,
    status: input.status ?? (decision.allowed ? 'ok' : 'skipped'),
    startedAt: input.startedAt,
    endedAt: input.endedAt,
    durationMs: input.durationMs,
    input: createRecordInput(decision),
    output: createRecordOutput(decision),
    reads: decision.resources,
    affected: decision.redactions.concat(decision.projection),
    metadata: input.metadata === undefined ? undefined : readJsonObject(input.metadata, 'policy record metadata'),
    error: input.error
  };
}

export function encodePolicyJsonl(value: FrontierPolicyManifest | readonly FrontierPolicyDecision[] | readonly FrontierRegistryRecord[]): string {
  const items = Array.isArray(value) ? value : [value];
  return items.map((item) => JSON.stringify(item)).join('\n') + (items.length === 0 ? '' : '\n');
}

export function decodePolicyJsonl(text: string): Array<FrontierPolicyManifest | FrontierPolicyDecision | FrontierRegistryRecord> {
  const out: Array<FrontierPolicyManifest | FrontierPolicyDecision | FrontierRegistryRecord> = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    if (line.trim().length === 0) continue;
    out[out.length] = JSON.parse(line) as FrontierPolicyManifest | FrontierPolicyDecision | FrontierRegistryRecord;
  }
  return out;
}

export function redactPolicyManifest(
  manifest: FrontierPolicyManifest,
  options: { redactKeys?: readonly string[] } = {}
): FrontierPolicyManifest {
  const keys = new Set((options.redactKeys ?? ['token', 'secret', 'authorization', 'password']).map((key) => key.toLowerCase()));
  return redactObject(manifest, keys) as FrontierPolicyManifest;
}

export function createPolicyProof(manifest: FrontierPolicyManifest): FrontierPolicyProof {
  return {
    kind: FRONTIER_POLICY_PROOF_KIND,
    version: FRONTIER_POLICY_PROOF_VERSION,
    id: manifest.id,
    hash: hashStable(redactPolicyManifest(manifest)),
    ruleCount: manifest.summary.ruleCount,
    subjectCount: manifest.summary.subjectCount,
    resourceCount: manifest.summary.resourceCount,
    capabilityCount: manifest.summary.capabilityCount
  };
}

export function redactPolicyValue(value: JsonValue, decision: FrontierPolicyDecision, replacement: JsonValue = '[redacted]'): JsonValue {
  const cloned = cloneJson(value);
  for (const path of decision.redactions) setPathValue(cloned, resourceToPath(path), replacement);
  return cloned;
}

export function projectPolicyValue(value: JsonValue, decision: FrontierPolicyDecision): JsonValue {
  const cloned = cloneJson(value);
  if (decision.projection.length === 0) return redactPolicyValue(cloned, decision);
  const out: JsonObject = {};
  for (const path of decision.projection) {
    const normalized = resourceToPath(path);
    const found = getPathValue(value, normalized);
    if (found !== undefined) setPathValue(out, normalized, cloneJson(found));
  }
  return redactPolicyValue(out, decision);
}

function createRecordInput(decision: FrontierPolicyDecision): JsonObject {
  const input: JsonObject = {
    resources: decision.resources as unknown as JsonValue,
    subject: decision.subject.id
  };
  if (decision.action !== undefined) input.action = decision.action;
  return input;
}

function createRecordOutput(decision: FrontierPolicyDecision): JsonObject {
  return {
    allowed: decision.allowed,
    access: decision.access,
    requiresApproval: decision.requiresApproval,
    redactions: decision.redactions as unknown as JsonValue,
    projection: decision.projection as unknown as JsonValue
  };
}

function evaluateCompiledPolicy(
  manifest: FrontierPolicyManifest,
  context: FrontierPolicyEvaluationContext,
  options: FrontierPolicyEvaluationOptions
): FrontierPolicyDecision {
  if (options.subjectResolver !== undefined) {
    throw new Error('evaluatePolicy() cannot use an async or external subjectResolver; use evaluatePolicyAsync()');
  }
  const normalizedContext = normalizeContext(context, manifest, undefined);
  return evaluateNormalized(manifest, normalizedContext, options);
}

async function evaluateCompiledPolicyAsync(
  manifest: FrontierPolicyManifest,
  context: FrontierPolicyEvaluationContext,
  options: FrontierPolicyEvaluationOptions
): Promise<FrontierPolicyDecision> {
  let resolved: FrontierPolicyResolverResult;
  if (options.subjectResolver !== undefined) {
    resolved = await options.subjectResolver(context.subject ?? context.actor, {
      manifest,
      action: context.action,
      resources: normalizeResourceList(context.resource, context.resources),
      route: context.route,
      feature: context.feature,
      package: context.package,
      metadata: context.metadata === undefined ? undefined : readJsonObject(context.metadata, 'policy context metadata')
    });
  }
  const normalizedContext = normalizeContext(context, manifest, resolved);
  return evaluateNormalized(manifest, normalizedContext, options);
}

type NormalizedContext = {
  subject: FrontierPolicySubject;
  action?: string;
  actions: string[];
  resources: string[];
  capabilities: string[];
  roles: string[];
  groups: string[];
  effects: string[];
  tools: string[];
  data: JsonObject;
  metadata?: JsonObject;
};

function evaluateNormalized(
  manifest: FrontierPolicyManifest,
  context: NormalizedContext,
  options: FrontierPolicyEvaluationOptions
): FrontierPolicyDecision {
  const defaultAccess = normalizeDefaultAccess(options.defaultAccess);
  const matchedRules: FrontierPolicyDecisionRule[] = [];
  const deniedRules: string[] = [];
  const allowedRules: string[] = [];
  const redactions: string[] = [];
  const projection: string[] = [];
  const allowedEffects: string[] = [];
  const deniedEffects: string[] = [];
  const allowedTools: string[] = [];
  const deniedTools: string[] = [];
  const reasons: string[] = [];
  const tags: string[] = [];
  let explicitlyAllowed = false;
  let denied = false;
  let requiresApproval = false;

  for (const rule of manifest.rules) {
    if (!ruleMatches(rule, context)) continue;
    matchedRules[matchedRules.length] = {
      id: rule.id,
      effect: rule.effect,
      priority: rule.priority,
      reason: rule.reason,
      resources: rule.resources.slice(),
      actions: rule.actions.slice(),
      tags: rule.tags.slice()
    };
    addUniqueStrings(tags, rule.tags);
    if (rule.reason !== undefined) addUniqueString(reasons, rule.reason);
    if (rule.requiresApproval || rule.effect === 'require-approval') requiresApproval = true;
    addUniqueStrings(redactions, rule.redactions);
    addUniqueStrings(projection, rule.projection);
    if (rule.effect === 'allow') {
      explicitlyAllowed = true;
      allowedRules[allowedRules.length] = rule.id;
    } else if (rule.effect === 'deny') {
      denied = true;
      deniedRules[deniedRules.length] = rule.id;
    } else if (rule.effect === 'redact') {
      if (rule.redactions.length === 0) addUniqueStrings(redactions, rule.resources.filter((resource) => resource.startsWith('path:') || resource.startsWith('/')));
    } else if (rule.effect === 'project') {
      if (rule.projection.length === 0) addUniqueStrings(projection, rule.resources.filter((resource) => resource.startsWith('path:') || resource.startsWith('/')));
    } else if (rule.effect === 'allow-effect') {
      addUniqueStrings(allowedEffects, rule.effects.length === 0 ? rule.resources.filter((resource) => resource.startsWith('fetch:') || resource.startsWith('storage:') || resource.startsWith('websocket:')) : rule.effects);
    } else if (rule.effect === 'deny-effect') {
      addUniqueStrings(deniedEffects, rule.effects.length === 0 ? rule.resources.filter((resource) => resource.startsWith('fetch:') || resource.startsWith('storage:') || resource.startsWith('websocket:')) : rule.effects);
    } else if (rule.effect === 'allow-tool') {
      addUniqueStrings(allowedTools, rule.tools);
    } else if (rule.effect === 'deny-tool') {
      addUniqueStrings(deniedTools, rule.tools);
    }
  }

  const access: FrontierPolicyAccess = denied
    ? 'deny'
    : requiresApproval
      ? 'approval-required'
      : explicitlyAllowed || defaultAccess === 'allow'
        ? 'allow'
        : 'deny';

  return {
    kind: FRONTIER_POLICY_DECISION_KIND,
    version: FRONTIER_POLICY_DECISION_VERSION,
    allowed: access === 'allow',
    access,
    defaultAccess,
    requiresApproval,
    action: context.action,
    actions: context.actions,
    resources: context.resources,
    subject: context.subject,
    matchedRules,
    deniedRules,
    allowedRules,
    redactions,
    projection,
    syncProjection: projection.slice(),
    allowedEffects,
    deniedEffects,
    allowedTools,
    deniedTools,
    reasons,
    tags,
    metadata: context.metadata
  };
}

function normalizeContext(
  context: FrontierPolicyEvaluationContext,
  manifest: FrontierPolicyManifest,
  resolved: FrontierPolicyResolverResult
): NormalizedContext {
  const subjectInput = resolved ?? findManifestSubject(manifest, context.subject ?? context.actor) ?? context.subject ?? context.actor ?? 'anonymous';
  const subject = normalizeSubject(mergeSubjectInput(subjectInput, context), 'anonymous');
  const actions = uniqueStrings((context.actions ?? []).concat(context.action === undefined ? [] : [context.action]));
  const resources = normalizeResourceList(context.resource, context.resources);
  const capabilities = uniqueStrings((context.capabilities ?? []).concat(subject.capabilities));
  const roles = uniqueStrings((context.roles ?? []).concat(subject.roles));
  const groups = uniqueStrings((context.groups ?? []).concat(subject.groups));
  const claims = mergeObjects(subject.claims, context.claims);
  const attributes = mergeObjects(subject.attributes, context.attributes);
  const metadata = context.metadata === undefined ? undefined : readJsonObject(context.metadata, 'policy context metadata');
  const subjectData: JsonObject = {
    id: subject.id,
    kind: subject.kind,
    roles: roles as unknown as JsonValue,
    groups: groups as unknown as JsonValue,
    capabilities: capabilities as unknown as JsonValue,
    claims,
    attributes,
    tags: subject.tags as unknown as JsonValue
  };
  if (subject.provider !== undefined) subjectData.provider = subject.provider;
  if (subject.externalId !== undefined) subjectData.externalId = subject.externalId;
  const data: JsonObject = {
    subject: subjectData,
    actor: subject.id,
    actions: actions as unknown as JsonValue,
    resources: resources as unknown as JsonValue,
    capabilities: capabilities as unknown as JsonValue,
    roles: roles as unknown as JsonValue,
    groups: groups as unknown as JsonValue,
    claims,
    attributes,
    effects: uniqueStrings(context.effects ?? []) as unknown as JsonValue,
    tools: uniqueStrings(context.tools ?? []) as unknown as JsonValue
  };
  const action = context.action ?? actions[0];
  if (action !== undefined) data.action = action;
  if (context.route !== undefined) data.route = context.route;
  const feature = context.feature ?? manifest.feature;
  const packageName = context.package ?? manifest.package;
  if (feature !== undefined) data.feature = feature;
  if (packageName !== undefined) data.package = packageName;
  if (context.state !== undefined) data.state = toJsonValue(context.state, 'policy context state');
  if (context.environment !== undefined) data.environment = toJsonValue(context.environment, 'policy context environment');
  if (metadata !== undefined) data.metadata = metadata;
  return {
    subject,
    action: context.action ?? actions[0],
    actions,
    resources,
    capabilities,
    roles,
    groups,
    effects: uniqueStrings(context.effects ?? []),
    tools: uniqueStrings(context.tools ?? []),
    data,
    metadata
  };
}

function findManifestSubject(
  manifest: FrontierPolicyManifest,
  reference: FrontierPolicySubjectReference | undefined
): FrontierPolicySubject | undefined {
  if (reference === undefined) return undefined;
  if (typeof reference === 'string') {
    return manifest.subjects.find((subject) => subject.id === reference || subject.externalId === reference);
  }
  return manifest.subjects.find((subject) => {
    if (reference.id !== undefined && subject.id === reference.id) return true;
    if (reference.externalId !== undefined && subject.externalId === reference.externalId && (reference.provider === undefined || subject.provider === reference.provider)) return true;
    return false;
  });
}

function ruleMatches(rule: FrontierPolicyRule, context: NormalizedContext): boolean {
  if (rule.actions.length !== 0 && !stringListMatches(rule.actions, context.actions)) return false;
  if (rule.resources.length !== 0 && !resourceListMatches(rule.resources, context.resources)) return false;
  if (rule.subjects.length !== 0 && !stringListMatches(rule.subjects, [context.subject.id, context.subject.externalId ?? ''])) return false;
  if (rule.providers.length !== 0 && (context.subject.provider === undefined || !rule.providers.includes(context.subject.provider))) return false;
  if (rule.roles.length !== 0 && !intersectsArray(rule.roles, context.roles)) return false;
  if (rule.groups.length !== 0 && !intersectsArray(rule.groups, context.groups)) return false;
  for (const capability of rule.capabilities) {
    if (!context.capabilities.includes(capability)) return false;
  }
  for (const [claim, expected] of Object.entries(rule.claims)) {
    const value = getPathValue(context.data.claims, parseLoosePath(claim));
    if (!expected.some((item) => sameJsonValue(item, value))) return false;
  }
  for (const condition of rule.conditions) {
    if (!conditionMatches(condition, context)) return false;
  }
  return true;
}

function conditionMatches(condition: FrontierPolicyCondition, context: NormalizedContext): boolean {
  if (condition.all !== undefined) {
    for (const child of condition.all) if (!conditionMatches(child, context)) return false;
  }
  if (condition.any !== undefined) {
    let ok = false;
    for (const child of condition.any) {
      if (conditionMatches(child, context)) {
        ok = true;
        break;
      }
    }
    if (!ok) return false;
  }
  if (condition.not !== undefined && conditionMatches(condition.not, context)) return false;
  if (condition.capability !== undefined && !context.capabilities.includes(condition.capability)) return false;
  if (condition.capabilities !== undefined) {
    for (const capability of condition.capabilities) if (!context.capabilities.includes(capability)) return false;
  }
  if (condition.role !== undefined && !context.roles.includes(condition.role)) return false;
  if (condition.roles !== undefined && !intersectsArray(condition.roles, context.roles)) return false;
  if (condition.group !== undefined && !context.groups.includes(condition.group)) return false;
  if (condition.groups !== undefined && !intersectsArray(condition.groups, context.groups)) return false;
  if (condition.claim !== undefined) {
    const value = getPathValue(context.data.claims, parseLoosePath(condition.claim));
    if (condition.claimEquals !== undefined && !sameJsonValue(condition.claimEquals, value)) return false;
    if (condition.exists !== undefined && (value !== undefined) !== condition.exists) return false;
  }
  if (condition.path !== undefined) {
    const value = getPathValue(context.data, normalizeInputPath(condition.path));
    if (condition.exists !== undefined && (value !== undefined) !== condition.exists) return false;
    const expected = condition.equals !== undefined ? condition.equals : condition.value;
    if (expected !== undefined && !sameJsonValue(expected, value)) return false;
    if (condition.in !== undefined && !condition.in.some((item) => sameJsonValue(item, value))) return false;
    if (condition.contains !== undefined && !containsJsonValue(value, condition.contains)) return false;
  }
  return true;
}

function normalizePolicyRule(rule: FrontierPolicyRuleInput, index: number): FrontierPolicyRule {
  if (rule === null || typeof rule !== 'object' || Array.isArray(rule)) throw new TypeError('policy rule must be an object');
  const effect = rule.effect === undefined ? 'allow' : readString(rule.effect, 'policy rule effect');
  const resources = normalizeResourceList(rule.resource, rule.resources);
  const redactions = normalizePathResources(rule.redact, rule.redactions);
  const projection = normalizePathResources(rule.project, rule.projection);
  return {
    id: rule.id === undefined ? 'rule-' + index : readString(rule.id, 'policy rule id'),
    effect,
    actions: uniqueStrings((normalizeStringList(rule.action, 'policy rule action')).concat(rule.actions ?? [])),
    resources,
    subjects: uniqueStrings(rule.subjects ?? []),
    providers: uniqueStrings(rule.providers ?? []),
    roles: uniqueStrings(rule.roles ?? []),
    groups: uniqueStrings(rule.groups ?? []),
    capabilities: uniqueStrings(rule.capabilities ?? []),
    claims: normalizeClaims(rule.claims),
    conditions: rule.when === undefined ? [...(rule.conditions ?? [])] : [rule.when].concat(rule.conditions ?? []),
    redactions,
    projection,
    effects: uniqueStrings(rule.effects ?? []),
    tools: uniqueStrings(rule.tools ?? []),
    requiresApproval: rule.requiresApproval === true,
    priority: rule.priority === undefined ? 0 : readFiniteNumber(rule.priority, 'policy rule priority'),
    reason: optionalString(rule.reason, 'policy rule reason'),
    owner: optionalString(rule.owner, 'policy rule owner'),
    package: optionalString(rule.package, 'policy rule package'),
    feature: optionalString(rule.feature, 'policy rule feature'),
    tags: uniqueStrings(rule.tags ?? []),
    source: rule.source,
    metadata: rule.metadata === undefined ? undefined : readJsonObject(rule.metadata, 'policy rule metadata')
  };
}

function normalizeSubject(subject: FrontierPolicySubjectInput | FrontierPolicySubject | string, fallbackId: string): FrontierPolicySubject {
  if (typeof subject === 'string') {
    return {
      id: subject,
      kind: 'user',
      roles: [],
      groups: [],
      capabilities: [],
      claims: {},
      attributes: {},
      tags: []
    };
  }
  if (subject === null || typeof subject !== 'object' || Array.isArray(subject)) throw new TypeError('policy subject must be a string or object');
  return {
    id: subject.id === undefined ? subject.externalId ?? fallbackId : readString(subject.id, 'policy subject id'),
    kind: subject.kind === undefined ? 'user' : readString(subject.kind, 'policy subject kind'),
    provider: optionalString(subject.provider, 'policy subject provider'),
    externalId: optionalString(subject.externalId, 'policy subject externalId'),
    roles: uniqueStrings(subject.roles ?? []),
    groups: uniqueStrings(subject.groups ?? []),
    capabilities: uniqueStrings(subject.capabilities ?? []),
    claims: subject.claims === undefined ? {} : readJsonObject(subject.claims, 'policy subject claims'),
    attributes: subject.attributes === undefined ? {} : readJsonObject(subject.attributes, 'policy subject attributes'),
    tags: uniqueStrings(subject.tags ?? []),
    metadata: subject.metadata === undefined ? undefined : readJsonObject(subject.metadata, 'policy subject metadata')
  };
}

function mergeSubjectInput(
  subjectInput: FrontierPolicyResolverResult | FrontierPolicySubjectReference,
  context: FrontierPolicyEvaluationContext
): FrontierPolicySubjectInput | FrontierPolicySubject | string {
  if (subjectInput === null || subjectInput === undefined) subjectInput = context.subject ?? context.actor ?? 'anonymous';
  if (typeof subjectInput === 'string') {
    return {
      id: subjectInput,
      capabilities: context.capabilities,
      roles: context.roles,
      groups: context.groups,
      claims: context.claims,
      attributes: context.attributes
    };
  }
  const base = subjectInput as FrontierPolicySubjectInput | FrontierPolicySubject;
  return {
    ...base,
    capabilities: uniqueStrings((base.capabilities ?? []).concat(context.capabilities ?? [])),
    roles: uniqueStrings((base.roles ?? []).concat(context.roles ?? [])),
    groups: uniqueStrings((base.groups ?? []).concat(context.groups ?? [])),
    claims: mergeObjects(base.claims, context.claims),
    attributes: mergeObjects(base.attributes, context.attributes)
  };
}

function normalizeResourceList(resource: string | readonly string[] | undefined, resources: readonly string[] | undefined): string[] {
  return uniqueStrings(normalizeStringList(resource, 'policy resource').concat(resources ?? []));
}

function normalizePathResources(
  value: FrontierRegistryPath | readonly FrontierRegistryPath[] | undefined,
  values: readonly FrontierRegistryPath[] | undefined
): string[] {
  const out: string[] = [];
  if (value !== undefined) {
    if (Array.isArray(value) && isPathList(value)) {
      out[out.length] = 'path:' + normalizeFrontierRegistryPath(value as FrontierRegistryPath);
    } else if (Array.isArray(value)) {
      for (const item of value as readonly FrontierRegistryPath[]) out[out.length] = 'path:' + normalizeFrontierRegistryPath(item);
    } else {
      out[out.length] = 'path:' + normalizeFrontierRegistryPath(value as FrontierRegistryPath);
    }
  }
  if (values !== undefined) {
    for (const item of values) out[out.length] = 'path:' + normalizeFrontierRegistryPath(item);
  }
  return uniqueStrings(out);
}

function resourceToPath(resource: string): string[] {
  const raw = resource.startsWith('path:') ? resource.slice(5) : resource;
  return normalizeInputPath(raw);
}

function normalizeInputPath(path: FrontierRegistryPath): string[] {
  if (Array.isArray(path)) return path.map((part) => String(part));
  if (typeof path !== 'string') throw new TypeError('path must be a string or path array');
  return parseLoosePath(path);
}

function parseLoosePath(path: string): string[] {
  if (path.length === 0 || path === '/') return [];
  if (path.startsWith('path:')) return parseLoosePath(path.slice(5));
  if (path.startsWith('/')) return path.slice(1).split('/').filter(Boolean).map(unescapePointer);
  return path.split('.').filter(Boolean);
}

function normalizeStringList(value: string | readonly string[] | undefined, label: string): string[] {
  if (value === undefined) return [];
  if (typeof value === 'string') return [value];
  if (!Array.isArray(value)) throw new TypeError(label + ' must be a string or string array');
  return value.map((item) => readString(item, label));
}

function normalizeClaims(claims: Record<string, JsonValue | readonly JsonValue[]> | undefined): Record<string, JsonValue[]> {
  const out: Record<string, JsonValue[]> = {};
  if (claims === undefined) return out;
  for (const key of Object.keys(claims)) {
    const value = claims[key];
    const values = Array.isArray(value) ? value : [value];
    out[key] = values.map((item) => toJsonValue(item, 'policy claim value'));
  }
  return out;
}

function compareRules(left: FrontierPolicyRule, right: FrontierPolicyRule): number {
  if (right.priority !== left.priority) return right.priority - left.priority;
  if (left.effect === 'deny' && right.effect !== 'deny') return -1;
  if (right.effect === 'deny' && left.effect !== 'deny') return 1;
  return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
}

function isPolicyManifest(value: unknown): value is FrontierPolicyManifest {
  return isObject(value) && value.kind === FRONTIER_POLICY_MANIFEST_KIND && Array.isArray(value.rules);
}

function isRuleArray(value: unknown): value is readonly FrontierPolicyRuleInput[] {
  return Array.isArray(value);
}

function isPolicyEvaluator(value: unknown): value is FrontierPolicyEvaluator {
  return isObject(value) && isPolicyManifest(value.manifest) && typeof value.evaluate === 'function';
}

function normalizeDefaultAccess(access?: 'allow' | 'deny'): 'allow' | 'deny' {
  if (access === undefined) return 'deny';
  if (access !== 'allow' && access !== 'deny') throw new TypeError('defaultAccess must be allow or deny');
  return access;
}

function stringListMatches(patterns: readonly string[], values: readonly string[]): boolean {
  for (const pattern of patterns) {
    if (pattern === '*') return true;
    for (const value of values) {
      if (value.length !== 0 && wildcardMatch(pattern, value)) return true;
    }
  }
  return false;
}

function resourceListMatches(patterns: readonly string[], values: readonly string[]): boolean {
  return stringListMatches(patterns, values);
}

function wildcardMatch(pattern: string, value: string): boolean {
  if (pattern === value) return true;
  if (!pattern.includes('*')) return false;
  const parts = pattern.split('*');
  let offset = 0;
  if (parts[0] && !value.startsWith(parts[0])) return false;
  offset = parts[0].length;
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    if (part.length === 0) continue;
    const found = value.indexOf(part, offset);
    if (found < 0) return false;
    offset = found + part.length;
  }
  const last = parts[parts.length - 1];
  return last.length === 0 || value.endsWith(last);
}

function getPathValue(value: unknown, path: readonly string[]): JsonValue | undefined {
  let current: unknown = value;
  for (const segment of path) {
    if (current === undefined || current === null) return undefined;
    if (Array.isArray(current)) {
      const index = Number(segment);
      if (!Number.isInteger(index) || index < 0 || index >= current.length) return undefined;
      current = current[index];
      continue;
    }
    if (!isObject(current) || !hasOwn.call(current, segment)) return undefined;
    current = current[segment];
  }
  return current === undefined ? undefined : toJsonValue(current, 'path value');
}

function setPathValue(root: JsonValue, path: readonly string[], value: JsonValue): void {
  if (!isObject(root) && !Array.isArray(root)) return;
  let current: JsonObject | JsonValue[] = root as JsonObject | JsonValue[];
  for (let i = 0; i < path.length; i++) {
    const segment = path[i];
    const last = i === path.length - 1;
    if (Array.isArray(current)) {
      const index = Number(segment);
      if (!Number.isInteger(index) || index < 0) return;
      if (last) {
        current[index] = value;
        return;
      }
      if (!isObject(current[index]) && !Array.isArray(current[index])) current[index] = {};
      current = current[index] as JsonObject | JsonValue[];
      continue;
    }
    if (last) {
      current[segment] = value;
      return;
    }
    if (!isObject(current[segment]) && !Array.isArray(current[segment])) current[segment] = {};
    current = current[segment] as JsonObject | JsonValue[];
  }
}

function containsJsonValue(value: JsonValue | undefined, expected: JsonValue): boolean {
  if (Array.isArray(value)) return value.some((item) => sameJsonValue(item, expected));
  if (typeof value === 'string' && typeof expected === 'string') return value.includes(expected);
  return sameJsonValue(value, expected);
}

function sameJsonValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function readString(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new TypeError(label + ' must be a string');
  return value;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  return readString(value, label);
}

function readFiniteNumber(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new TypeError(label + ' must be a finite number');
  return value;
}

function readJsonObject(value: unknown, label: string): JsonObject {
  const json = toJsonValue(value, label);
  if (!isObject(json)) throw new TypeError(label + ' must be a JSON object');
  return json;
}

function toJsonValue(value: unknown, label: string): JsonValue {
  if (value === undefined) throw new TypeError(label + ' must not be undefined');
  try {
    return cloneJson(value as JsonValue);
  } catch {
    throw new TypeError(label + ' must be JSON-serializable');
  }
}

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function mergeObjects(left: unknown, right: unknown): JsonObject {
  const out: JsonObject = {};
  if (isObject(left)) Object.assign(out, readJsonObject(left, 'policy object'));
  if (isObject(right)) Object.assign(out, readJsonObject(right, 'policy object'));
  return out;
}

function uniqueStrings(values: readonly string[]): string[] {
  const out: string[] = [];
  addUniqueStrings(out, values);
  return out;
}

function sortedUnique(values: readonly string[]): string[] {
  return uniqueStrings(values).sort();
}

function addUniqueStrings(out: string[], values: readonly string[]): void {
  for (const value of values) addUniqueString(out, readString(value, 'string list item'));
}

function addUniqueString(out: string[], value: string): void {
  if (!out.includes(value)) out[out.length] = value;
}

function intersectsArray(left: readonly string[], right: readonly string[]): boolean {
  for (const item of left) if (right.includes(item)) return true;
  return false;
}

function intersectsSet(left: readonly string[], right: Set<string>): boolean {
  for (const item of left) if (right.has(item)) return true;
  return false;
}

function isPathList(value: readonly unknown[]): boolean {
  return value.every((item) => typeof item === 'string' || typeof item === 'number');
}

function unescapePointer(value: string): string {
  return value.replace(/~1/g, '/').replace(/~0/g, '~');
}

function redactObject(value: unknown, keys: Set<string>): unknown {
  if (Array.isArray(value)) return value.map((item) => redactObject(item, keys));
  if (!isObject(value)) return value;
  const out: JsonObject = {};
  for (const key of Object.keys(value)) {
    out[key] = keys.has(key.toLowerCase()) ? '[redacted]' : redactObject(value[key], keys) as JsonValue;
  }
  return out;
}

function hashStable(value: unknown): string {
  const text = stableStringify(value);
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  if (isObject(value)) {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((key) => JSON.stringify(key) + ':' + stableStringify(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}
