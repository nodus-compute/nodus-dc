"""Local read-only dashboard. Credentials stay only in page memory."""

HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark"><title>Nodus · Local GPUs</title>
<style>
:root{color-scheme:light;--bg:#f7f8fa;--surface:#fff;--subtle:#f3f5f8;--ink:#18202d;--muted:#687386;--line:#e3e7ed;--accent:#315efb;--good:#168269;--good-bg:#eaf7f2;--warn:#946518;--warn-bg:#fff6e5;--danger:#b13737;--shadow:0 2px 8px #14243d04}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input,select{font:inherit}button,a,input,select,summary{-webkit-tap-highlight-color:transparent}button{cursor:pointer}button:disabled{opacity:.5;cursor:default}button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible,a:focus-visible{outline:3px solid var(--accent);outline-offset:3px}button,input,select{border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--ink);min-height:40px;padding:9px 13px}button{font-weight:550}button:hover:not(:disabled){background:var(--subtle)}button.primary{background:var(--ink);color:var(--surface);border-color:var(--ink)}button.primary:hover:not(:disabled){opacity:.85}.muted{color:var(--muted)}[hidden]{display:none!important}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}h1,h2,h3,p{margin:0}h1{font-size:32px;line-height:1.2;letter-spacing:-1.1px;font-weight:650}h2{font-size:18px;letter-spacing:-.35px;font-weight:650}h3{font-size:15px;font-weight:600;line-height:1.4}code{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}.topbar{height:72px;border-bottom:1px solid var(--line);background:var(--surface)}.topbar-inner{max-width:1240px;height:100%;margin:auto;padding:0 36px;display:flex;align-items:center;justify-content:space-between;gap:16px}.brand{display:flex;align-items:center;gap:10px;font-size:18px;font-weight:700;letter-spacing:-.5px}.brand-mark{width:26px;height:26px;color:var(--ink)}.separator{height:18px;width:1px;background:var(--line);margin:0 6px}.brand-subtitle{font-size:13px;font-weight:450;letter-spacing:0;color:var(--muted)}.top-actions{display:flex;align-items:center;gap:16px}.text-button{border:0;background:none;min-height:36px;padding:6px;color:var(--muted);font-size:13px}.connection{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted)}.connection:before{content:"";width:6px;height:6px;border-radius:50%;background:var(--muted)}.connection[data-state="connected"]:before{background:var(--good)}main{max-width:1240px;margin:0 auto;padding:42px 36px 32px}.page-heading{display:flex;align-items:center;justify-content:space-between;gap:24px;margin-bottom:28px}.page-heading p{margin-top:9px;color:var(--muted)}.refresh-icon{margin-right:7px;vertical-align:-2px}.eyebrow{font-size:11px;font-weight:650;letter-spacing:1px;text-transform:uppercase;color:var(--muted)}.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}.unlock-card{padding:24px;margin-bottom:24px}.unlock-intro{display:flex;align-items:center;gap:10px;margin-bottom:16px}.unlock-intro span{display:grid;place-items:center;width:34px;height:34px;background:var(--subtle);border-radius:8px}.token-row{display:flex;gap:10px;max-width:620px}.token-row input{flex:1;min-width:0}.unlock-card label{display:block;font-size:12px;font-weight:550;margin-bottom:6px}.unlock-card p{margin-top:9px;font-size:12px;color:var(--muted)}#summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:22px}.metric{padding:21px 24px}.metric-label{font-size:12px;font-weight:550;color:var(--muted)}.metric strong{display:block;font-size:32px;line-height:1.2;font-weight:600;letter-spacing:-.9px;margin-top:11px;font-variant-numeric:tabular-nums}.metric-note{display:block;font-size:11px;margin-top:7px;color:var(--muted)}.status-row{display:flex;justify-content:space-between;align-items:center;gap:14px;font-size:12px;color:var(--muted);margin-bottom:26px}.status-row #status{flex:1}.status-row #freshness{font-variant-numeric:tabular-nums;text-align:right}.section-heading{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:16px}.filters{display:flex;gap:10px}.filters input{width:220px}.filters input,.filters select{font-size:12px;min-height:36px;padding:7px 11px}.resource-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.gpu-card{padding:22px;min-width:0}.gpu-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:23px}.gpu-title{display:flex;gap:12px;min-width:0}.gpu-icon{width:36px;height:36px;border:1px solid var(--line);border-radius:8px;display:grid;place-items:center;flex-shrink:0;color:var(--muted)}.gpu-title code{display:block;color:var(--muted);font-size:11px;margin-top:4px}.badge{display:inline-flex;align-items:center;gap:5px;border-radius:5px;background:var(--subtle);color:var(--muted);padding:3px 7px;font-size:10px;font-weight:600;white-space:nowrap}.badge[data-tone="good"]{color:var(--good);background:var(--good-bg)}.badge[data-tone="warn"]{color:var(--warn);background:var(--warn-bg)}.gpu-metrics{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:18px}.measure-heading{display:flex;align-items:baseline;justify-content:space-between;gap:7px;margin-bottom:9px}.measure-label{font-size:11px;color:var(--muted)}.measure-value{font-size:17px;font-weight:550;font-variant-numeric:tabular-nums;white-space:nowrap}.measure-value.small{font-size:12px}.bar{height:5px;background:var(--subtle);border-radius:6px;overflow:hidden}.bar-fill{height:100%;background:var(--accent);border-radius:6px;width:0}.measure-note{font-size:10px;color:var(--muted);margin-top:7px}.chips{display:flex;flex-wrap:wrap;gap:5px}.chip{background:var(--subtle);border:1px solid var(--line);border-radius:5px;padding:2px 6px;color:var(--muted);font-size:10px}.partitions{border-top:1px solid var(--line);margin-top:18px;padding-top:14px}.partition-heading{font-size:11px;font-weight:550;color:var(--muted);margin-bottom:10px}.partition{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px;padding:11px 0;border-top:1px solid var(--line)}.partition:first-of-type{border-top:0}.partition-name{font-size:12px;font-weight:550}.partition code{display:block;color:var(--muted);font-size:10px;margin-top:2px}.partition-memory{grid-column:1/-1;display:flex;align-items:center;gap:10px;font-size:10px;color:var(--muted)}.partition-memory .bar{flex:1;max-width:150px}.device-details{font-size:11px;color:var(--muted);margin-top:16px}.device-details summary{cursor:pointer;display:list-item;width:fit-content}.detail-list{margin:10px 0 0;display:grid;grid-template-columns:90px minmax(0,1fr);gap:6px 12px}.detail-list dt{color:var(--muted)}.detail-list dd{margin:0;overflow-wrap:anywhere;color:var(--ink)}.empty{grid-column:1/-1;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:48px 24px;min-height:220px;color:var(--muted);border:1px dashed var(--line);border-radius:12px}.empty svg{margin-bottom:14px;color:var(--muted)}.empty h3{color:var(--ink);margin-bottom:6px}.empty p{max-width:380px;font-size:12px}.bottom-grid{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:18px;margin-top:24px}.allocation-card{padding:22px;min-width:0}.allocation-card>summary{cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:15px;list-style:none}.allocation-card>summary::-webkit-details-marker{display:none}.allocation-card>summary:after{content:"+";font-size:20px;font-weight:400;color:var(--muted)}.allocation-card[open]>summary:after{content:"−"}.allocation-subtitle{color:var(--muted);font-size:12px;margin-top:4px}.table-wrap{overflow-x:auto;margin-top:20px}table{width:100%;min-width:620px;border-collapse:collapse;font-size:11px}th{text-align:left;color:var(--muted);font-weight:550;padding:0 12px 10px 0}td{border-top:1px solid var(--line);padding:12px 12px 12px 0;vertical-align:top;overflow-wrap:anywhere;max-width:220px}.participation-card{padding:22px}.participation-title{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.participation-card h2{font-size:14px}.participation-card p{font-size:12px;color:var(--muted);line-height:1.65}.participation-card a{display:inline-block;font-size:12px;font-weight:550;margin-top:14px}.notices{margin-top:18px;font-size:12px;color:var(--muted)}.notices summary{cursor:pointer}.notices pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;margin-top:10px}#error:not(:empty){padding:13px 16px;margin:0 0 22px;border:1px solid var(--danger);border-radius:8px;color:var(--danger);font-size:12px;white-space:pre-wrap}footer{display:flex;justify-content:space-between;gap:20px;border-top:1px solid var(--line);padding-top:20px;margin-top:32px;color:var(--muted);font-size:11px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#101419;--surface:#171c23;--subtle:#222932;--ink:#e6eaf0;--muted:#96a1b2;--line:#2c3540;--accent:#809dff;--good:#86d3b3;--good-bg:#19382e;--warn:#e9bc71;--warn-bg:#372d1c;--danger:#f39d9d;--shadow:none}}
@media(min-width:1100px){.gpu-card:only-child{max-width:700px}}
@media(max-width:850px){main{padding:30px 24px}.topbar-inner{padding:0 24px}.bottom-grid{grid-template-columns:1fr}.section-heading{align-items:flex-start}.filters input{width:170px}.metric{padding:18px}.gpu-metrics{gap:16px}.resource-grid{grid-template-columns:1fr}.gpu-card:only-child{max-width:none}}
@media(max-width:560px){main{padding:26px 16px}.topbar{height:60px}.topbar-inner{padding:0 16px}.brand-subtitle,.separator{display:none}.top-actions{gap:9px}.connection{font-size:10px}.page-heading{gap:14px;margin-bottom:22px;align-items:flex-start}h1{font-size:26px}.page-heading p{font-size:12px;max-width:200px}.page-heading button{font-size:11px;padding:8px 10px;min-height:36px}.refresh-icon{display:none}#summary{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.metric{padding:16px}.metric strong{font-size:28px}.metric-label{font-size:11px}.metric-note{font-size:10px}.status-row{display:block;font-size:11px;margin-bottom:23px}.status-row #freshness{text-align:left;margin-top:5px}.section-heading{display:block}.filters{margin-top:13px}.filters input{width:auto;flex:1;min-width:0}.filters select{max-width:135px}.gpu-card{padding:18px}.gpu-heading{gap:8px}.gpu-title{gap:10px}.gpu-title h3{font-size:14px}.gpu-icon{width:30px;height:30px}.badge{font-size:9px;padding:3px 6px}.gpu-metrics{gap:20px}.token-row{flex-direction:column}.unlock-card{padding:20px}.bottom-grid{gap:14px}.allocation-card,.participation-card{padding:18px}footer{display:block;font-size:10px}footer span{display:block;margin-bottom:6px}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
</style></head><body>
<div class="topbar"><div class="topbar-inner"><div class="brand"><svg class="brand-mark" viewBox="0 0 28 28" fill="none" aria-hidden="true"><rect width="28" height="28" rx="7" fill="currentColor"/><path d="M8 20V8l12 12V8" stroke="var(--surface)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Nodus</span><span class="separator"></span><span class="brand-subtitle">Local control</span></div><div class="top-actions"><span id="connection" class="connection">Not connected</span><button id="lock" class="text-button" type="button" hidden>Lock view</button></div></div></div>
<main><header class="page-heading"><div><h1>GPU overview</h1><p>Your hardware, allocations, and available capacity.</p></div><button id="refresh" type="button" disabled aria-busy="false"><svg class="refresh-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1"/></svg><span id="refresh-label">Refresh inventory</span></button></header>
<section id="login" class="card unlock-card" aria-labelledby="login-title"><div class="unlock-intro"><span aria-hidden="true">↳</span><div><h3 id="login-title">Connect to your local daemon</h3><div class="muted" style="font-size:12px">No Nodus account needed.</div></div></div><form id="token-form"><label for="token">Local API token</label><div class="token-row"><input id="token" type="password" autocomplete="off" required aria-describedby="token-help" placeholder="Enter your local token"><button id="unlock" type="submit" class="primary">Open dashboard</button></div><p id="token-help">Use the token file printed by your daemon. It stays in this page's memory.</p></form></section>
<p id="error" role="alert" aria-atomic="true"></p>
<section id="summary" aria-label="Resource summary"><div class="card metric"><span class="metric-label">Physical GPUs</span><strong id="gpus">—</strong><span class="metric-note">Detected on this host</span></div><div class="card metric"><span class="metric-label">Available GPUs</span><strong id="available-gpus">—</strong><span class="metric-note">Whole devices · local use</span></div><div class="card metric"><span class="metric-label">Available partitions</span><strong id="available-partitions">—</strong><span class="metric-note">Separate from whole GPUs</span></div><div class="card metric"><span class="metric-label">Held allocations</span><strong id="leases">—</strong><span class="metric-note">Includes reserved & draining</span></div></section>
<div class="status-row"><p id="status" role="status" aria-live="polite" aria-atomic="true">Connect to see your GPU inventory.</p><p id="freshness">No observation yet</p></div>
<section aria-labelledby="resources-heading"><div class="section-heading"><h2 id="resources-heading">Your resources</h2><div class="filters"><label class="sr-only" for="search">Search GPU or partition</label><input id="search" type="search" placeholder="Find GPU or partition…" autocomplete="off"><label class="sr-only" for="filter">Resource availability</label><select id="filter"><option value="all">All resources</option><option value="available">Available</option><option value="held">Held</option><option value="busy">Activity detected</option></select></div></div><div id="resources" class="resource-grid"></div></section>
<div class="bottom-grid"><details class="card allocation-card" id="allocation-details"><summary><div><h2>Allocations</h2><p id="allocation-summary" class="allocation-subtitle">Lease details and lifecycle history</p></div></summary><p class="muted" style="font-size:12px;margin-top:16px">Capacity stays held until cleanup is verified. Lifecycle actions are available through the CLI/API.</p><div class="table-wrap"><table><thead><tr><th scope="col">Lease / generation</th><th scope="col">Owner</th><th scope="col">Resources</th><th scope="col">State</th><th scope="col">Expires</th></tr></thead><tbody id="allocations"></tbody></table></div><p id="allocations-empty" class="muted" style="font-size:12px;margin-top:16px" hidden>No recorded allocations.</p></details><section class="card participation-card"><div class="participation-title"><h2>Nodus connection</h2><span id="external" class="badge">Unknown</span></div><p id="participation-description">Optional capacity participation. Your local GPU management works independently.</p><a href="https://github.com/nodus-compute/nodus-dc/blob/main/docs/operations.md" target="_blank" rel="noreferrer">Connection guide ↗</a></section></div>
<details id="warnings" class="notices" hidden><summary id="warning-summary">Inventory notices</summary><pre id="warning-body"></pre></details>
<footer><span>Local control · Development build · Hardware qualification incomplete</span><span>Host administrators remain trusted. <a href="https://github.com/nodus-compute/nodus-dc/blob/main/docs/threat-model.md" target="_blank" rel="noreferrer">Privacy & isolation ↗</a></span></footer></main>
<script>
let credential = '',
  lastStatus = null,
  receivedAt = 0,
  receivedWallAt = 0,
  lastClock = null,
  clockFailed = false,
  refreshFailed = false,
  renderedFresh = false,
  refreshSequence = 0,
  refreshing = false;
const REFRESH_TIMEOUT_MS = 120000;
const element = (id) => document.getElementById(id);
async function request(path, signal) {
  const r = await fetch(path, { signal, headers: { Authorization: 'Bearer ' + credential } });
  const data = await r.json();
  if (!r.ok) {
    const error = Error(data.error?.message || 'Request failed');
    error.status = r.status;
    throw error;
  }
  return data;
}
function node(tag, className, text) {
  const value = document.createElement(tag);
  if (className) value.className = className;
  if (text !== undefined) value.textContent = String(text);
  return value;
}
function cell(row, value) {
  row.append(node('td', '', value));
}
function fresh() {
  const a = lastStatus?.availability,
    p = performance.now(),
    w = Date.now(),
    prior = lastClock || { p: receivedAt, w: receivedWallAt };
  const elapsed = [p - receivedAt, w - receivedWallAt];
  if (
    ![p, w, receivedAt, receivedWallAt, prior.p, prior.w, ...elapsed].every(Number.isFinite) ||
    p < prior.p ||
    w < prior.w ||
    elapsed.some((x) => x < 0)
  )
    clockFailed = true;
  lastClock = { p, w };
  return (
    !refreshFailed &&
    !clockFailed &&
    a?.state === 'fresh' &&
    Number.isFinite(a.fresh_for_seconds) &&
    a.fresh_for_seconds >= Math.max(...elapsed) / 1000
  );
}
function utilization(value, current) {
  if (!current) return 'Unavailable';
  const text = String(value ?? '').trim();
  if (!/^\d+(?:\.\d+)?\s*%$/.test(text)) return 'Not reported';
  const n = Number(text.replace('%', ''));
  return Number.isFinite(n) && n >= 0 && n <= 100 ? n + ' %' : 'Not reported';
}

const reasonLabels = {
  available: 'Available',
  held: 'Held',
  busy: 'Activity detected',
  unhealthy: 'Needs attention',
  unsupported: 'Unavailable',
  observe_only: 'Observe only',
  scheduler_managed: 'Scheduler managed',
  unknown: 'Unknown',
  missing: 'Unknown',
  stale: 'Stale',
  clock_uncertain: 'Clock uncertain',
};
const modeLabels = {
  exclusive_gpu: 'Whole GPU',
  exclusive_host: 'Whole host',
  hardware_partition: 'MIG partition',
  gpu_configuration: 'Partition control',
  trusted_mps: 'Trusted MPS',
};
function shortId(value) {
  return value.length > 27 ? value.slice(0, 11) + '…' + value.slice(-10) : value;
}
function badge(text, reason) {
  const value = node('span', 'badge', text);
  value.dataset.tone =
    reason === 'available'
      ? 'good'
      : ['held', 'busy', 'unhealthy'].includes(reason)
        ? 'warn'
        : 'neutral';
  return value;
}
function state(resource, eligibility, current) {
  const reason = current ? eligibility.get(resource.id)?.reason || 'unknown' : 'stale';
  return { reason, label: current ? reasonLabels[reason] || 'Unknown' : 'Unavailable' };
}
function memory(resource, current) {
  const total = resource.details?.memory_capacity_bytes ?? resource.memory_bytes,
    used = resource.details?.memory_used_bytes;
  const validTotal = Number.isFinite(total) && total > 0,
    validUsed = current && validTotal && Number.isFinite(used) && used >= 0 && used <= total;
  return {
    total: validTotal ? total : null,
    used: validUsed ? used : null,
    ratio: validUsed ? used / total : null,
  };
}
function gib(value) {
  return (value / 1073741824).toFixed(1) + ' GiB';
}
function bar(ratio, label) {
  const value = node('div', 'bar');
  const fill = node('div', 'bar-fill');
  value.append(fill);
  if (ratio !== null) {
    fill.style.width = Math.max(0, Math.min(1, ratio)) * 100 + '%';
    value.setAttribute('role', 'meter');
    value.setAttribute('aria-label', label);
    value.setAttribute('aria-valuemin', '0');
    value.setAttribute('aria-valuemax', '100');
    value.setAttribute('aria-valuenow', String(Math.round(ratio * 100)));
  } else value.setAttribute('aria-hidden', 'true');
  return value;
}
function measure(label, value, ratio, note, small = false) {
  const out = node('div', 'measure'),
    heading = node('div', 'measure-heading');
  heading.append(
    node('span', 'measure-label', label),
    node('strong', 'measure-value' + (small ? ' small' : ''), value),
  );
  out.append(heading, bar(ratio, label), node('p', 'measure-note', note));
  return out;
}
function gpuIcon() {
  const icon = node('span', 'gpu-icon');
  icon.setAttribute('aria-hidden', 'true');
  icon.innerHTML =
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="6" y="6" width="12" height="12" rx="2"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 3v3m6-3v3m-6 12v3m6-3v3M3 9h3m-3 6h3m12-6h3m-3 6h3"/></svg>';
  return icon;
}
function empty(title, description) {
  const out = node('div', 'empty');
  out.append(gpuIcon(), node('h3', '', title), node('p', '', description));
  return out;
}
function matches(resource, eligibility, current) {
  const query = element('search').value.toLowerCase().trim(),
    filter = element('filter').value;
  return (
    (!query ||
      [resource.id, resource.name, resource.details?.profile]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
        .includes(query)) &&
    (filter === 'all' || (current && eligibility.get(resource.id)?.reason === filter))
  );
}
function details(resource, current) {
  const detail = node('details', 'device-details');
  detail.append(node('summary', '', 'Device details'));
  const rows = node('dl', 'detail-list');
  const values = [
    ['Resource ID', resource.id],
    ['Driver', resource.details?.driver_version || 'Not reported'],
    [
      'Observed state',
      !current
        ? 'Stale or unavailable'
        : !resource.healthy
          ? 'Unknown / unhealthy'
          : resource.busy
            ? 'Activity detected'
            : 'No activity observed',
    ],
    [
      'Allocation modes',
      (resource.modes || []).map((x) => modeLabels[x] || x).join(', ') || 'Observe only',
    ],
  ];
  for (const [key, value] of values) rows.append(node('dt', '', key), node('dd', '', value));
  detail.append(rows);
  return detail;
}
function renderResources(rs, eligibility, current) {
  const container = element('resources');
  const openDetails = new Set(
    Array.from(container.querySelectorAll('article'))
      .filter((x) => x.querySelector('details')?.open)
      .map((x) => x.dataset.resource),
  );
  container.replaceChildren();
  const devices = rs.filter((x) => x.kind === 'gpu');
  for (const gpu of devices) {
    const children = rs.filter((x) => x.kind === 'partition' && x.parent === gpu.id),
      visibleChildren =
        matches(gpu, eligibility, current) && element('filter').value === 'all'
          ? children
          : children.filter((x) => matches(x, eligibility, current));
    if (!matches(gpu, eligibility, current) && !visibleChildren.length) continue;
    const card = node('article', 'card gpu-card');
    card.dataset.resource = gpu.id;
    const heading = node('div', 'gpu-heading'),
      title = node('div', 'gpu-title'),
      titleText = node('div');
    titleText.append(node('h3', '', gpu.name || 'GPU'), node('code', '', shortId(gpu.id)));
    title.append(gpuIcon(), titleText);
    const local = state(gpu, eligibility, current);
    heading.append(
      title,
      badge(
        current && children.length ? 'Partitioned' : local.label,
        current && children.length ? 'partitioned' : local.reason,
      ),
    );
    card.append(heading);
    const mem = memory(gpu, current),
      util = utilization(gpu.details?.utilization_gpu, current),
      utilRatio = /^[0-9.]+ %$/.test(util) ? Number(util.replace('%', '')) / 100 : null,
      metrics = node('div', 'gpu-metrics');
    metrics.append(
      measure(
        'GPU utilization',
        utilRatio === null ? '—' : util,
        utilRatio,
        current
          ? utilRatio === null
            ? 'Not reported by driver'
            : 'Current observation'
          : 'Refresh to update',
      ),
      measure(
        'Memory used',
        mem.used === null ? '—' : gib(mem.used),
        mem.ratio,
        mem.total === null ? 'Capacity not reported' : 'of ' + gib(mem.total),
        mem.used !== null,
      ),
    );
    card.append(metrics);
    const chips = node('div', 'chips');
    for (const mode of gpu.modes || [])
      chips.append(node('span', 'chip', modeLabels[mode] || mode));
    if (!chips.children.length) chips.append(node('span', 'chip', 'Observe only'));
    card.append(chips);
    if (visibleChildren.length) {
      const group = node('div', 'partitions');
      group.append(
        node(
          'p',
          'partition-heading',
          visibleChildren.length + ' partition' + (visibleChildren.length === 1 ? '' : 's'),
        ),
      );
      for (const child of visibleChildren) {
        const row = node('div', 'partition'),
          label = node('div'),
          local = state(child, eligibility, current),
          mem = memory(child, current);
        label.append(
          node('span', 'partition-name', child.details?.profile || child.name || 'MIG partition'),
          node('code', '', shortId(child.id)),
        );
        row.append(label, badge(local.label, local.reason));
        const usage = node('div', 'partition-memory');
        usage.append(
          bar(mem.ratio, 'Partition memory'),
          node(
            'span',
            '',
            mem.used !== null
              ? gib(mem.used) + ' / ' + gib(mem.total)
              : !current
                ? 'Memory observation unavailable'
                : mem.total !== null
                  ? gib(mem.total) + ' capacity · usage not reported'
                  : 'Memory not reported',
          ),
        );
        row.append(usage);
        group.append(row);
      }
      card.append(group);
    }
    const info = details(gpu, current);
    info.open = openDetails.has(gpu.id);
    card.append(info);
    container.append(card);
  }
  if (!container.children.length)
    container.append(
      empty(
        devices.length ? 'No matching resources' : 'No GPU resources detected',
        devices.length
          ? 'Try another name, resource ID, or availability filter.'
          : 'Check the NVIDIA driver and daemon diagnostics, then refresh the inventory.',
      ),
    );
}
function locked() {
  element('resources').replaceChildren(
    empty(
      'Your GPUs will appear here',
      'Connect to the local daemon to view real utilization, memory, and allocation state.',
    ),
  );
  for (const id of ['gpus', 'leases', 'available-gpus', 'available-partitions'])
    element(id).textContent = '—';
  element('allocations').replaceChildren();
  element('allocation-summary').textContent = 'Lease details and lifecycle history';
  element('external').textContent = 'Unknown';
  element('external').dataset.tone = 'neutral';
  element('participation-description').textContent =
    'Optional capacity participation. Your local GPU management works independently.';
  element('warnings').hidden = true;
  element('warnings').open = false;
  element('warning-body').textContent = '';
  element('allocation-details').open = false;
  element('allocations-empty').hidden = true;
}
function render() {
  if (!lastStatus) {
    locked();
    return;
  }
  const s = lastStatus,
    inv = s.inventory,
    rs = inv?.resources || [],
    a = s.availability,
    current = fresh();
  renderedFresh = current;
  if (!current && !refreshing)
    element('status').textContent = refreshFailed
      ? 'Refresh failed. Availability is unavailable.'
      : 'Snapshot expired. Refresh to check current availability.';
  const eligibility = new Map((a?.resources || []).map((x) => [x.resource_id, x]));
  renderResources(rs, eligibility, current);
  const leases = s.leases || [],
    held = leases.filter((x) => x.state !== 'released');
  element('allocations').replaceChildren();
  for (const x of leases) {
    const row = node('tr');
    for (const value of [
      x.id + ' / ' + x.generation,
      x.owner,
      (x.resources || []).join(', '),
      x.state,
      new Date(x.expires_at * 1000).toLocaleString(),
    ])
      cell(row, value);
    element('allocations').append(row);
  }
  element('allocations-empty').hidden = leases.length > 0;
  element('allocation-summary').textContent =
    held.length + ' held · ' + leases.length + ' recorded';
  element('gpus').textContent = rs.filter((x) => x.kind === 'gpu').length;
  element('leases').textContent = held.length;
  element('available-gpus').textContent = current ? a.available_gpus : '—';
  element('available-partitions').textContent = current ? a.available_partitions : '—';
  const enabled =
    current && s.bridge_policy?.enabled && s.bridge_policy.expires_at > Date.now() / 1000;
  element('external').textContent = !current
    ? 'Unknown'
    : enabled
      ? 'Policy enabled'
      : 'Policy disabled';
  element('external').dataset.tone = enabled ? 'good' : 'neutral';
  element('participation-description').textContent = !current
    ? 'Refresh to check participation policy. Local management remains independent.'
    : enabled
      ? 'External work still requires a current authorized lease. This policy is not proof of paid usage or settled earnings.'
      : 'Your resources remain under local control. Connect through the CLI when you choose to participate.';
  element('freshness').textContent = inv
    ? 'Observed ' + new Date(inv.observed_at * 1000).toLocaleTimeString()
    : 'No observation yet';
  element('connection').textContent = refreshFailed ? 'Connection unavailable' : 'Local daemon';
  element('connection').dataset.state = refreshFailed ? 'unavailable' : 'connected';
  const warnings = inv?.warnings || [];
  element('warnings').hidden = !warnings.length;
  element('warning-summary').textContent =
    warnings.length + ' inventory notice' + (warnings.length === 1 ? '' : 's');
  element('warning-body').textContent = warnings.join('\n');
}
function busy(value) {
  refreshing = value;
  element('token').disabled = value;
  element('unlock').disabled = value;
  element('lock').disabled = value;
  element('refresh').disabled = value || !credential;
  element('refresh').setAttribute('aria-busy', String(value));
  element('refresh-label').textContent = value ? 'Refreshing…' : 'Refresh inventory';
}
async function refresh() {
  if (!credential || refreshing) return;
  const sequence = ++refreshSequence,
    controller = new AbortController(),
    focusTarget = document.activeElement;
  let timedOut = false;
  busy(true);
  element('error').textContent = '';
  element('status').textContent = 'Reading current GPU inventory…';
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, REFRESH_TIMEOUT_MS);
  try {
    await request('/v1/inventory', controller.signal);
    const requestedAt = performance.now(),
      requestedWallAt = Date.now(),
      s = await request('/v1/status', controller.signal);
    if (timedOut) throw Error('Refresh timed out');
    if (sequence !== refreshSequence) return;
    lastStatus = s;
    receivedAt = requestedAt;
    receivedWallAt = requestedWallAt;
    lastClock = null;
    clockFailed = false;
    refreshFailed = false;
    render();
    element('login').hidden = true;
    element('lock').hidden = false;
    element('status').textContent = renderedFresh
      ? 'Fresh snapshot · A new reservation confirms availability.'
      : 'Availability is stale or unavailable. Refresh to check again.';
  } catch (error) {
    if (sequence !== refreshSequence) return;
    refreshFailed = true;
    if (error.status === 401 || error.status === 403) {
      credential = '';
      lastStatus = null;
      element('login').hidden = false;
      element('lock').hidden = true;
    }
    render();
    element('connection').textContent = 'Connection unavailable';
    element('connection').dataset.state = 'unavailable';
    element('status').textContent = 'Refresh failed. Availability is unavailable.';
    element('error').textContent = timedOut
      ? 'The daemon did not respond within 120 seconds. Check it and try again.'
      : error.message || 'Check the local daemon and try again.';
  } finally {
    clearTimeout(timeout);
    busy(false);
    if (element('login').hidden && ['token', 'unlock'].includes(focusTarget?.id))
      element('refresh').focus();
    else if (
      document.hasFocus() &&
      document.activeElement === document.body &&
      ['token', 'unlock', 'refresh'].some((id) => element(id) === focusTarget)
    )
      focusTarget.focus();
  }
}
setInterval(() => {
  if (lastStatus && renderedFresh && !fresh()) {
    render();
    element('status').textContent = refreshing
      ? 'Refreshing. The previous observation is now stale.'
      : 'Snapshot expired. Refresh to check current availability.';
  } else if (
    lastStatus &&
    element('external').textContent === 'Policy enabled' &&
    lastStatus.bridge_policy?.expires_at <= Date.now() / 1000
  )
    render();
}, 1000);
element('token-form').onsubmit = (event) => {
  event.preventDefault();
  if (refreshing) return;
  credential = element('token').value;
  element('token').value = '';
  refresh();
};
element('refresh').onclick = refresh;
element('search').oninput = () => render();
element('filter').onchange = () => render();
element('lock').onclick = () => {
  if (refreshing) return;
  credential = '';
  lastStatus = null;
  renderedFresh = false;
  element('login').hidden = false;
  element('lock').hidden = true;
  element('connection').textContent = 'Not connected';
  element('connection').dataset.state = '';
  element('status').textContent = 'View locked. Enter your local token to reconnect.';
  element('freshness').textContent = 'No observation yet';
  element('error').textContent = '';
  element('search').value = '';
  element('filter').value = 'all';
  render();
  busy(false);
  element('token').focus();
};
locked();
</script></body></html>'''
