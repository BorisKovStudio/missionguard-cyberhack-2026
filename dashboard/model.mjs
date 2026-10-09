// Presentation validation is not authorization. The trusted executor owns policy.
export const OPERATIONS = Object.freeze(['events.list', 'events.get', 'analyses.get']);
export const REASONS = Object.freeze(['ok', 'invalid_request', 'mission_not_found', 'identity_mismatch', 'hash_mismatch', 'expired', 'revoked', 'operation_denied', 'resource_denied', 'field_denied', 'limit_denied', 'budget_exhausted', 'idempotency_conflict', 'adapter_unavailable', 'store_unavailable', 'upstream_unknown', 'pending']);
const MODES = ['synthetic_lab', 'eventmatch_live', 'replay'];
const STATUSES = ['allowed', 'denied', 'unknown', 'pending'];
const EVENTS = ['admitted', 'completed', 'denied', 'replayed', 'revoked', 'unknown'];
const FIELDS = Object.freeze({
  'events.list': ['event_id', 'title', 'starts_at', 'source_url', 'updated_at'],
  'events.get': ['event_id', 'title', 'starts_at', 'source_url', 'updated_at'],
  'analyses.get': ['event_id', 'summary', 'topics', 'source_url', 'updated_at'],
});
export class ReceiptError extends Error { constructor() { super('Receipt does not match the local interface. No result displayed.'); } }
function check(value) { if (!value) throw new ReceiptError(); }
function object(value) { check(value !== null && typeof value === 'object' && !Array.isArray(value)); }
function keys(value, names) { object(value); check(Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name))); }
function text(value, max = 1000) { check(typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uD800-\uDFFF]/u.test(value)); }
function integer(value, max = Number.MAX_SAFE_INTEGER) { check(Number.isSafeInteger(value) && value >= 0 && value <= max); }
function list(value, max) { check(Array.isArray(value) && value.length <= max); }
function strings(value, max = 100) { list(value, max); for (const item of value) text(item, 1000); }
function version(value) { check(value === '1.0'); }
function validateMission(mission) {
  keys(mission, ['schema_version', 'mission_id', 'purpose', 'actor_id', 'org_id', 'audience', 'environment', 'connection_ref', 'registry_version', 'expires_at', 'budget', 'grants']);
  version(mission.schema_version); version(mission.registry_version);
  for (const name of ['mission_id', 'actor_id', 'org_id', 'connection_ref']) { text(mission[name], 80); check(/^[A-Za-z0-9_.:-]+$/u.test(mission[name])); }
  text(mission.purpose); check(mission.audience === 'missionguard-executor-v1');
  check(['synthetic_lab', 'eventmatch_live'].includes(mission.environment));
  integer(mission.expires_at); keys(mission.budget, ['max_calls', 'max_rows']);
  integer(mission.budget.max_calls, 100); integer(mission.budget.max_rows, 1000);
  check(mission.budget.max_calls > 0 && mission.budget.max_rows > 0);
  list(mission.grants, 3); check(mission.grants.length > 0);
  const operations = new Set();
  for (const grant of mission.grants) {
    keys(grant, ['operation', 'resource_ids', 'fields', 'max_rows_per_call']);
    check(OPERATIONS.includes(grant.operation) && !operations.has(grant.operation)); operations.add(grant.operation);
    strings(grant.resource_ids); strings(grant.fields); integer(grant.max_rows_per_call, 100);
    check(grant.resource_ids.length > 0 && grant.fields.length > 0 && grant.max_rows_per_call > 0);
    check(new Set(grant.resource_ids).size === grant.resource_ids.length && new Set(grant.fields).size === grant.fields.length);
    check(grant.fields.every(field => FIELDS[grant.operation].includes(field)));
  }
}
function validateResult(result, execution, mission) {
  if (result === null) return;
  keys(result, ['rows', 'fetched_at', 'source']);
  check(execution.status === 'allowed' && execution.reason === 'ok' && (result.source === 'synthetic_fixture' || (result.source === 'akash_public_synthetic_http' && mission.environment === 'synthetic_lab' && mission.connection_ref === 'akash-public-fixture-v1')));
  integer(result.fetched_at); list(result.rows, 100);
  const grant = mission.grants.find(item => item.operation === execution.operation);
  check(grant && result.rows.length <= grant.max_rows_per_call);
  for (const row of result.rows) {
    object(row); check(Object.keys(row).length > 0);
    check(Object.keys(row).every(field => grant.fields.includes(field) && FIELDS[execution.operation].includes(field)));
    if (Object.hasOwn(row, 'event_id')) check(grant.resource_ids.includes(row.event_id));
    for (const [field, value] of Object.entries(row)) {
      if (field === 'updated_at') integer(value);
      else if (field === 'topics') { list(value, 20); for (const topic of value) text(topic, 120); }
      else if (['source_url', 'starts_at'].includes(field) && value === null) continue;
      else if (field === 'title') text(value, 300);
      else if (field === 'summary') text(value, 4000);
      else if (field === 'starts_at') {
        text(value, 40);
        check(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/u.test(value) && Number.isFinite(Date.parse(value)));
      } else if (field === 'source_url') {
        text(value, 2048); check(!/[\u0000-\u0020\u007F]/u.test(value));
        let url; try { url = new URL(value); } catch { throw new ReceiptError(); }
        check(['http:', 'https:'].includes(url.protocol) && !url.username && !url.password);
      } else text(value, 80);
    }
  }
}
export function validateReceipt(receipt) {
  keys(receipt, ['schema_version', 'mode', 'mission', 'contract_hash', 'budget', 'revoked', 'executions', 'audit_events', 'limitations']);
  version(receipt.schema_version); check(MODES.includes(receipt.mode)); validateMission(receipt.mission);
  check(receipt.mode === 'replay' || receipt.mode === receipt.mission.environment);
  check(typeof receipt.contract_hash === 'string' && /^[a-f0-9]{64}$/u.test(receipt.contract_hash));
  check(typeof receipt.revoked === 'boolean');
  keys(receipt.budget, ['calls_used', 'calls_limit', 'rows_reserved', 'rows_limit']);
  for (const value of Object.values(receipt.budget)) integer(value);
  check(receipt.budget.calls_limit === receipt.mission.budget.max_calls && receipt.budget.rows_limit === receipt.mission.budget.max_rows);
  check(receipt.budget.calls_used <= receipt.budget.calls_limit && receipt.budget.rows_reserved <= receipt.budget.rows_limit);
  list(receipt.executions, 100); list(receipt.audit_events, 1000); strings(receipt.limitations, 100);
  const executionIds = new Set();
  for (const execution of receipt.executions) {
    keys(execution, ['execution_id', 'operation', 'status', 'reason', 'replayed', 'result', 'created_at']);
    text(execution.execution_id, 80); check(!executionIds.has(execution.execution_id)); executionIds.add(execution.execution_id);
    check(OPERATIONS.includes(execution.operation) && STATUSES.includes(execution.status) && REASONS.includes(execution.reason));
    check(execution.status !== 'allowed' || execution.reason === 'ok');
    check((execution.status === 'allowed') === (execution.result !== null));
    check(typeof execution.replayed === 'boolean'); integer(execution.created_at);
    validateResult(execution.result, execution, receipt.mission);
  }
  const eventIds = new Set();
  for (const event of receipt.audit_events) {
    keys(event, ['schema_version', 'event_id', 'mission_alias', 'mode', 'event_type', 'operation', 'reason', 'timestamp', 'calls_used', 'rows_reserved', 'latency_ms']);
    version(event.schema_version); text(event.event_id, 80); text(event.mission_alias, 80);
    check(MODES.includes(event.mode) && EVENTS.includes(event.event_type) && [...OPERATIONS, 'unknown'].includes(event.operation) && REASONS.includes(event.reason));
    check(event.mode === receipt.mode);
    check(!eventIds.has(event.event_id)); eventIds.add(event.event_id);
    for (const field of ['timestamp', 'calls_used', 'rows_reserved', 'latency_ms']) integer(event[field]);
    check(event.calls_used <= receipt.budget.calls_used && event.rows_reserved <= receipt.budget.rows_reserved);
  }
  return receipt;
}
export function timeLabel(seconds) {
  if (!Number.isSafeInteger(seconds) || !Number.isFinite(new Date(seconds * 1000).getTime())) return 'Unknown';
  return new Intl.DateTimeFormat('en-US', { timeZone: 'America/Los_Angeles', timeZoneName: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(seconds * 1000));
}
export function sourceLabel(value) {
  if (typeof value !== 'string') return 'Source not supplied';
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.hostname !== 'example.invalid' || url.username || url.password || url.port || url.search || url.hash) return 'Unverified source withheld';
    if (!/^\/synthetic\/[A-Za-z0-9/_-]+$/u.test(url.pathname)) return 'Unverified source withheld';
    return url.hostname + url.pathname;
  } catch { return 'Unverified source withheld'; }
}
export function projectReceipt(input, { now = Math.floor(Date.now() / 1000) } = {}) {
  const receipt = validateReceipt(input);
  const unverifiedLive = receipt.mode === 'eventmatch_live' || receipt.mission.environment === 'eventmatch_live';
  const replay = receipt.mode === 'replay';
  const incomplete = receipt.executions.some(item => ['pending', 'unknown'].includes(item.status));
  const candidates = new Map();
  const analyses = new Map();
  if (!unverifiedLive) for (const execution of receipt.executions) {
    if (execution.status !== 'allowed' || execution.reason !== 'ok' || !execution.result) continue;
    for (const row of execution.result.rows) {
      if (!row.event_id) continue;
      if (execution.operation === 'analyses.get') analyses.set(row.event_id, row);
      else candidates.set(row.event_id, { ...candidates.get(row.event_id), ...row });
    }
  }
  const events = [...candidates.values()].slice(0, 3).map(row => {
    const analysis = analyses.get(row.event_id);
    const unknowns = ['Attendance and pricing are not established by the approved evidence.'];
    if (!analysis?.summary) unknowns.push('Existing analysis not returned; relevance is not established.');
    if (!row.starts_at) unknowns.push('Event date not returned.');
    if (!row.source_url) unknowns.push('Event source not supplied.');
    return { title: row.title || 'Title not returned', date: typeof row.starts_at === 'string' && Number.isFinite(Date.parse(row.starts_at)) ? timeLabel(Math.floor(Date.parse(row.starts_at) / 1000)) : 'Date unknown', summary: analysis?.summary || 'No existing analysis in this receipt. No recommendation inferred.', topics: analysis?.topics || [], source: sourceLabel(row.source_url), analysisSource: analysis ? sourceLabel(analysis.source_url) : null, unknowns, hasAnalysis: Boolean(analysis?.summary) };
  });
  const state = unverifiedLive ? 'Live unavailable' : replay ? 'Replay receipt' : receipt.revoked ? 'Revoked' : incomplete ? 'Incomplete outcome' : now >= receipt.mission.expires_at ? 'Expired snapshot' : 'Approved · fixture';
  const completedFetches = receipt.executions.filter(item => item.status === 'allowed' && item.result !== null).map(item => item.result.fetched_at);
  const fetchedAt = unverifiedLive || completedFetches.length === 0 ? null : Math.max(...completedFetches);
  return { state, replay, incomplete, unverifiedLive, expired: now >= receipt.mission.expires_at, purpose: receipt.mission.purpose, hash: receipt.contract_hash, budget: unverifiedLive ? null : receipt.budget, expiry: timeLabel(receipt.mission.expires_at), events, trail: unverifiedLive ? [] : receipt.audit_events.slice(-50), grants: receipt.mission.grants.map(grant => ({ operation: grant.operation, resourceCount: grant.resource_ids.length, fields: grant.fields.join(', '), rowLimit: grant.max_rows_per_call })), limitations: receipt.limitations, fetchedAt, analysisCount: events.filter(event => event.hasAnalysis).length };
}
// Fixture state previews never call the executor and never create approval records.
export function fixtureScenario(receipt, state) {
  const copy = structuredClone(validateReceipt(receipt));
  if (state === 'replay') { copy.mode = 'replay'; for (const item of copy.executions) item.replayed = true; for (const event of copy.audit_events) event.mode = 'replay'; }
  if (state === 'revoked') copy.revoked = true;
  if (state === 'unknown' || state === 'pending') {
    for (const item of copy.executions) { item.status = state; item.reason = state === 'unknown' ? 'upstream_unknown' : 'pending'; item.result = null; }
    copy.audit_events = copy.audit_events.filter(event => event.event_type === 'admitted').map(event => ({ ...event, event_type: state === 'unknown' ? 'unknown' : 'admitted', reason: state === 'unknown' ? 'upstream_unknown' : 'pending' }));
  }
  return copy;
}
