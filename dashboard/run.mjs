import { projectReceipt, timeLabel } from './model.mjs';
const $ = id => document.getElementById(id);
$('read-manual-guild').addEventListener('click', async () => {
  $('read-manual-guild').disabled = true;
  $('manual-guild-output').textContent = '';
  $('manual-guild-status').textContent = 'Reading the fixed recorded manual result only…';
  try {
    const value = await readJSON('/api/manual-guild-result');
    if (value.schema_version !== 'dashboard-manual-guild-1' || value.execution_source !== 'manual_guild_test_ui' || value.fresh_per_click !== false || value.dataset !== 'synthetic' || value.agent_runtime !== 'guild_hosted_coded' || value.tool_runtime !== 'local_core_http' || value.model !== 'gpt-4o-2024-08-06' || value.output_kind !== 'untrusted_model_text_identifiers_redacted' || typeof value.output !== 'string' || value.output.length > 8192 || !/^[0-9a-f-]{36}$/.test(value.run_id) || !Number.isFinite(Date.parse(value.source_timestamp)) || !Number.isFinite(Date.parse(value.retrieved_at)) || !Number.isSafeInteger(value.usage.total_tokens) || value.billed_usd !== null) throw new Error('Invalid manual record');
    $('manual-guild-status').textContent = `Actual recorded manual run ${value.run_id} · ${value.model} · ${value.usage.total_tokens} tokens (${value.usage.input_tokens} input / ${value.usage.output_tokens} output) · completed ${value.source_timestamp} · retrieved ${value.retrieved_at} · list-price estimate $${value.estimated_usd}, billed amount unknown. Private draft / manual Test UI, NOT fresh per click or this mission. Platform retries unverified.`;
    $('manual-guild-output').textContent = 'Model output — untrusted text; evidence identifiers withheld: ' + value.output;
  } catch {
    $('manual-guild-status').textContent = 'Recorded result unavailable or unverified. No new model call was made. The current mission is unchanged.';
  } finally { $('read-manual-guild').disabled = false; }
});
let nonce = null;
let claimed = false;
let busy = false;
function controls() { $('run-mission').disabled = busy || claimed || !nonce || !$('confirm-run').checked; }
async function readJSON(path, options = {}) {
  const response = await fetch(path, { cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(20000), ...options });
  const raw = await response.text();
  if (raw.length > 131072 || !response.ok) throw new Error('Run unavailable or outcome unknown');
  return JSON.parse(raw);
}
function showRun(value) {
  if (value.schema_version !== 'dashboard-run-1' || value.execution_source !== 'local_core_http' || value.caller !== 'deterministic_local' || value.agent_runtime !== 'unavailable' || value.dataset !== 'synthetic' || !/^[0-9a-f-]{36}$/.test(value.run_id) || !Number.isSafeInteger(value.started_at) || !Number.isSafeInteger(value.completed_at) || value.completed_at < value.started_at) throw new Error('Unverified run envelope');
  const view = projectReceipt(value.receipt);
  const e = value.evidence;
  if (view.mode !== 'synthetic_lab' && value.receipt.mode !== 'synthetic_lab') throw new Error('Wrong provenance');
  if (e.allowed_status !== 'allowed' || e.replayed !== true || e.replay_new_dispatches !== 0 || e.denial_reason !== 'resource_denied' || e.denied_new_dispatches !== 0) throw new Error('Incomplete scenario evidence');
  if (!window.MissionGuardDashboard.present(value.receipt)) throw new Error('Invalid actual receipt');
  const remote = value.receipt.mission.connection_ref === 'akash-public-fixture-v1';
  $('snapshot').textContent = 'Actual hosted Core fetch · ' + timeLabel(view.fetchedAt);
  $('source-label').textContent = remote ? 'Core → Akash HTTP · synthetic' : 'Hosted Core HTTP · synthetic';
  $('notice').textContent = remote ? 'Actual hosted Core enforcement → Akash public synthetic API. Deterministic caller; no model, Guild, ClickHouse or live EventMatch execution in this run.' : 'Actual Core HTTP execution on the demo host · synthetic data · deterministic caller. This is NOT a hosted model, Guild, Akash, ClickHouse or live EventMatch run.';
  $('run-evidence').textContent = `Run ${value.run_id} · ${timeLabel(value.started_at)} → ${timeLabel(value.completed_at)} · Allow: actual read completed · Block: resource_denied, 0 new dispatches · Replay: 0 new dispatches · Agent/model runtime: unavailable.`;
}
async function recover() {
  try { showRun(await readJSON('/api/demo-result')); }
  catch { window.MissionGuardDashboard.present({}); $('run-evidence').textContent = 'Run pending / unknown or invalid. It may have executed. No execution retry is offered; read the result again only.'; }
}
$('confirm-run').addEventListener('change', controls);
$('read-run').addEventListener('click', recover);
$('run-mission').addEventListener('click', async () => {
  if (busy || claimed || !nonce || !$('confirm-run').checked) return;
  busy = true; claimed = true; controls(); $('read-run').hidden = false;
  $('reload').disabled = true; $('fixture-state').disabled = true;
  window.MissionGuardDashboard.present({});
  $('run-evidence').textContent = 'Running the confirmed fixed policy through local Core HTTP… No automatic retry.';
  try { showRun(await readJSON('/api/demo-run', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Demo-CSRF': nonce }, body: '{"confirm_policy":"synthetic-read-v1"}' })); }
  catch { $('run-evidence').textContent = 'Run outcome unknown / unavailable. It may have executed. Do not retry execution. Use Read run result.'; }
  finally { nonce = null; busy = false; controls(); $('reload').disabled = false; $('fixture-state').disabled = false; }
});
for (const [id, event] of [['fixture-state', 'change'], ['reload', 'click']]) $(id).addEventListener(event, () => { $('run-evidence').textContent = 'Saved synthetic fixture / presentation preview selected. Not current run evidence. Use Read run result to return to the actual run.'; });
(async () => {
  if (location.origin !== 'https://missionguard.boriskov.com') return;
  try { const session = await readJSON('/api/demo-session'); if (session.policy === 'synthetic-read-v1' && /^[A-Za-z0-9_-]{43}$/.test(session.csrf_nonce)) nonce = session.csrf_nonce; }
  catch { $('read-run').hidden = false; await recover(); }
  controls();
})();
