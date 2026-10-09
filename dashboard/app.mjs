import { fixtureScenario, projectReceipt, timeLabel, ReceiptError } from './model.mjs';

const $ = id => document.getElementById(id);
let fixture = null;
let loadGeneration = 0;
const localHost = ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname);
const reasonLabels = Object.freeze({ ok: 'Completed successfully', pending: 'Admission reserved; outcome pending', resource_denied: 'Resource outside approved scope', operation_denied: 'Operation not approved', field_denied: 'Field outside approved scope', limit_denied: 'Per-call row limit exceeded', budget_exhausted: 'Cumulative budget exhausted', expired: 'Mission TTL expired', revoked: 'Mission revoked', identity_mismatch: 'Server identity binding mismatch', hash_mismatch: 'Contract reference mismatch', upstream_unknown: 'Upstream outcome unknown; do not retry', adapter_unavailable: 'Fixed adapter unavailable', store_unavailable: 'Durable ledger unavailable', invalid_request: 'Request failed closed-schema validation', mission_not_found: 'Approved mission not found', idempotency_conflict: 'Idempotency key/body conflict' });
const eventLabels = Object.freeze({ admitted: 'Reserved', completed: 'Allowed', denied: 'Denied', replayed: 'Replay · no new dispatch', revoked: 'Revoked', unknown: 'Unknown' });
function element(tag, value, className) { const node = document.createElement(tag); if (value !== undefined) node.textContent = value; if (className) node.className = className; return node; }
function setNotice(message, tone = 'neutral') { $('notice').textContent = message; $('notice').dataset.tone = tone; }
function clearData(title, explanation) {
  $('event-list').replaceChildren(); $('trail-body').replaceChildren(); $('empty-result').hidden = false;
  $('empty-result').querySelector('h3').textContent = title; $('empty-result').querySelector('p').textContent = explanation;
  $('result-count').textContent = 'No completed evidence'; $('trail-count').textContent = 'No current evidence';
  $('calls-value').textContent = '—'; $('rows-value').textContent = '—';
  for (const name of ['calls', 'rows']) { $(name + '-progress').removeAttribute('value'); $(name + '-progress').setAttribute('aria-label', name + ' reservations unknown'); }
}
function renderBudget(budget) {
  for (const [name, used, limit] of [['calls', budget?.calls_used, budget?.calls_limit], ['rows', budget?.rows_reserved, budget?.rows_limit]]) {
    $(name + '-value').textContent = budget ? `${used} / ${limit}` : '—';
    const bar = $(name + '-progress');
    if (budget) { bar.max = limit; bar.value = used; bar.setAttribute('aria-label', `${name} reserved: ${used} of ${limit}`); }
    else { bar.removeAttribute('value'); bar.setAttribute('aria-label', name + ' reservations unknown'); }
  }
}
function renderEvents(view) {
  $('event-list').replaceChildren();
  $('result-count').textContent = `${view.events.length} records · ${view.analysisCount} with analysis`;
  $('result-context').textContent = view.replay ? 'Historical projections only. No agent or adapter execution is occurring.' : view.incomplete ? 'Partial outcome. Only independently completed projections are shown; missing data stays unknown.' : 'Existing records only. No new analyses, inferred scores or refreshed data.';
  $('empty-result').hidden = view.events.length > 0;
  $('empty-result').querySelector('h3').textContent = view.unverifiedLive ? 'Live evidence unavailable' : view.incomplete ? 'No completed result evidence' : 'No event records returned';
  $('empty-result').querySelector('p').textContent = view.incomplete ? 'Pending / unknown may have been sent. Reservations remain consumed. No automatic retry.' : 'The UI does not substitute public-web results or synthetic data for live evidence.';
  for (const event of view.events) {
    const item = element('li', undefined, 'event-item');
    const body = element('article');
    body.append(element('h3', event.title));
    const meta = element('div', undefined, 'event-meta');
    meta.append(element('span', event.date), element('span', event.hasAnalysis ? 'Existing analysis returned' : 'Evidence gap', 'evidence-label'));
    body.append(meta, element('p', event.summary, 'event-summary'));
    body.append(element('p', 'Unknowns · ' + event.unknowns.join(' '), 'unknown-note'));
    const source = element('p', undefined, 'source-row'); source.append(element('strong', 'Event source '), document.createTextNode(event.source)); body.append(source);
    if (event.analysisSource) { const analysis = element('p', undefined, 'source-row'); analysis.append(element('strong', 'Analysis source '), document.createTextNode(event.analysisSource)); body.append(analysis); }
    item.append(body); $('event-list').append(item);
  }
}
function renderTrail(trail) {
  $('trail-body').replaceChildren(); $('trail-count').textContent = `${trail.length} sanitized events · last 50 max`;
  for (const event of trail) {
    const row = element('tr');
    const statusCell = element('td'); statusCell.append(element('span', eventLabels[event.event_type], 'decision ' + event.event_type));
    row.append(element('td', timeLabel(event.timestamp).split(', ').at(-1).replace(' PDT', '')), element('td', event.operation), statusCell, element('td', reasonLabels[event.reason] || event.reason), element('td', String(event.calls_used)));
    $('trail-body').append(row);
  }
}
function renderScope(view) {
  $('grant-list').replaceChildren();
  for (const grant of view.grants) {
    const row = element('li'); row.append(element('code', grant.operation), element('p', `${grant.resourceCount} explicit resources · max ${grant.rowLimit} rows / call`), element('p', 'Fields: ' + grant.fields)); $('grant-list').append(row);
  }
  $('limitation-list').replaceChildren(...view.limitations.map(value => element('li', value)));
}
function present(receipt, { preview = false } = {}) {
  const view = projectReceipt(receipt);
  $('hash').textContent = view.hash.slice(0, 12) + '…' + view.hash.slice(-8);
  $('purpose').textContent = view.purpose; $('expiry').textContent = view.expiry + (view.expired ? ' · expired now' : '');
  $('snapshot').textContent = view.fetchedAt === null ? 'No completed fetch · Unknown' : 'Fixed snapshot · ' + timeLabel(view.fetchedAt);
  $('source-label').textContent = view.unverifiedLive ? 'Unverified live' : view.replay ? 'Synthetic replay' : 'Synthetic fixture';
  $('mission-state').textContent = preview ? 'Pending approval · preview' : view.state;
  $('scope-heading').textContent = preview ? 'Policy preview' : 'Approved scope';
  renderScope(view);
  if (preview) {
    clearData('Awaiting server approval', 'Policy preview is not approval. No execution is available from this UI.');
    $('result-context').textContent = 'Illustrative policy only. No approved receipt or runtime budget is claimed for this preview.';
    $('snapshot').textContent = 'Policy preview · not an approved receipt';
    setNotice('Synthetic policy preview — not approved. Only the trusted server can approve; no execution or approval is performed here.', 'warning');
    return;
  }
  renderBudget(view.budget); renderEvents(view); renderTrail(view.trail);
  if (view.unverifiedLive) setNotice('Live unavailable — adapter contract, authentication, identity and bounds have not been verified. No live results displayed.', 'warning');
  else if (view.replay) setNotice('Synthetic replay — historical fixture evidence. No current agent, adapter dispatch or provider call. Reservations shown are recorded values.', 'neutral');
  else if (view.incomplete) setNotice('Synthetic outcome preview — pending / unknown may have been sent. No success is inferred and no automatic retry is available.', 'warning');
  else if (receipt.revoked) setNotice('Synthetic revoked receipt — no new admissions permitted. Already-admitted work can still complete; prior results remain historical evidence.', 'warning');
  else setNotice('Synthetic receipt — fictional data, fixed fixture clock, no live API or sponsor run. Read-only display; not production authentication.', 'neutral');
}
function unavailable(message) {
  clearData('Receipt unavailable', 'No fresh evidence or counters are known. Nothing is executed and no replay is silently substituted.');
  $('mission-state').textContent = 'Unavailable'; $('hash').textContent = '—'; $('snapshot').textContent = 'No current receipt'; $('purpose').textContent = 'Waiting for a trusted, scoped receipt.';
  $('expiry').textContent = 'Unknown'; $('source-label').textContent = 'Unavailable'; $('grant-list').replaceChildren(); $('limitation-list').replaceChildren();
  $('scope-heading').textContent = 'Scope unavailable';
  setNotice(message, 'warning');
}
function applyFixtureState() {
  if (!fixture) return;
  const state = $('fixture-state').value;
  if (state === 'unavailable') { unavailable('Unavailable fixture preview — no fresh receipt. Displayed counters are unknown, not zero.'); return; }
  present(fixtureScenario(fixture, state), { preview: state === 'preview' });
}
async function loadFixture() {
  const generation = ++loadGeneration;
  $('reload').disabled = true; $('fixture-state').disabled = true;
  clearData('Loading receipt', 'No execution or approval is available while the receipt is loading.');
  $('mission-state').textContent = 'Loading'; setNotice('Loading a local, synthetic receipt…');
  const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    if (!localHost || !['http:', 'https:'].includes(location.protocol)) throw new ReceiptError();
    const response = await fetch('./receipt.synthetic.json', { cache: 'no-store', credentials: 'omit', signal: controller.signal, redirect: 'error' });
    if (!response.ok) throw new ReceiptError();
    const raw = await response.text(); if (new TextEncoder().encode(raw).length > 1024 * 1024) throw new ReceiptError();
    const parsed = JSON.parse(raw); projectReceipt(parsed);
    if (generation !== loadGeneration) return;
    fixture = parsed; applyFixtureState();
  } catch {
    if (generation !== loadGeneration) return;
    fixture = null; unavailable('Local receipt unavailable or invalid. Only a localhost preview is supported. No provider call, execution or automatic retry was made.');
  } finally { clearTimeout(timeout); if (generation === loadGeneration) { $('reload').disabled = false; $('fixture-state').disabled = !fixture; } }
}
$('reload').addEventListener('click', loadFixture);
$('fixture-state').addEventListener('change', applyFixtureState);
// Integration seam: Core may present a scoped receipt, never an agent-supplied principal.
// This does not create a transport, production auth, approval or execution endpoint.
window.MissionGuardDashboard = Object.freeze({ present(receipt) { try { present(receipt); return true; } catch { unavailable('Receipt validation failed. No result displayed.'); return false; } } });
loadFixture();
