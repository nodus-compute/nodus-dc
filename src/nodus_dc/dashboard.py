"""Local dashboard. The bearer token stays only in this page's memory."""

HTML = r'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nodus · Local GPUs</title><style>
body{margin:0;background:#f3f5f7;color:#16233b;font:15px system-ui,sans-serif}main{max-width:1100px;margin:48px auto;padding:0 24px}
header{display:flex;justify-content:space-between;align-items:center}h1{font-size:32px;margin:8px 0}small,.muted{color:#5c6b80}
section{background:white;border:1px solid #dce2ea;border-radius:12px;padding:24px;margin:24px 0}input,button,select{font:inherit;padding:10px;border:1px solid #aeb9ca;border-radius:6px}
button{background:#1e4e9d;color:white;cursor:pointer}button:disabled{opacity:.65;cursor:default}input:focus-visible,button:focus-visible,a:focus-visible{outline:3px solid #2069c7;outline-offset:3px}.table-wrap{overflow-x:auto}table{min-width:650px;width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px 8px;border-bottom:1px solid #e4e8ee;font-size:13px}
code{font-size:12px;overflow-wrap:anywhere}.error{color:#a12020;white-space:pre-wrap}label{display:block;margin:8px 0}#summary{display:flex;gap:30px}.metric strong{display:block;font-size:28px}
@media(max-width:600px){main{margin:24px auto;padding:0 16px}section{padding:16px}header{display:block}#summary{flex-wrap:wrap;gap:20px}.metric strong{font-size:24px}input{box-sizing:border-box;width:100%;max-width:100%}}
</style><main><header><div><small>NODUS · LOCAL CONTROL</small><h1>Your GPU resources</h1><p class="muted">Local management works without a platform account.</p></div><span id="connection">Locked</span></header>
<section id="login"><form id="token-form"><label for="token">Local API token</label><input id="token" type="password" autocomplete="off" size="48" required aria-describedby="token-help"><button id="unlock" type="submit">Unlock local view</button><p id="token-help" class="muted">Use the local token file printed by the daemon. The token is kept in memory until this page closes.</p></form></section>
<p id="status" role="status" aria-live="polite" aria-atomic="true">Enter your local API token to view inventory.</p>
<section><div id="summary"><div class="metric"><strong id="gpus">—</strong>Physical GPUs</div><div class="metric"><strong id="leases">—</strong>Held allocations</div><div class="metric"><strong id="available-gpus">—</strong>Locally available GPUs</div><div class="metric"><strong id="available-partitions">—</strong>Locally available partitions</div><div class="metric"><strong id="external">—</strong>Capacity participation</div></div><p id="freshness" class="muted">No inventory read.</p><button id="refresh" type="button" disabled aria-busy="false">Refresh inventory</button></section>
<section><h2>Inventory</h2><p class="muted">Local availability is a snapshot; allocation still requires a fresh reservation. GPU and partition counts are separate. External work requires its own authorization and eligibility checks.</p><div class="table-wrap"><table><thead><tr><th>Resource</th><th>Kind</th><th>Memory</th><th>GPU utilization</th><th>Modes</th><th>Observed state</th><th>Local allocation</th></tr></thead><tbody id="resources"></tbody></table></div></section>
<section><h2>Allocations</h2><p class="muted">Reserved, draining and quarantined resources remain held. A release appears only after cleanup verification.</p><div class="table-wrap"><table><thead><tr><th>Lease / generation</th><th>Owner</th><th>Resources</th><th>State</th><th>Expires</th></tr></thead><tbody id="allocations"></tbody></table></div></section>
<p class="muted">Hardware qualification has not been completed for this development build. Detailed allocation and lifecycle actions are available through the CLI/API.</p><p id="error" class="error" role="alert" aria-atomic="true"></p></main>
<script>
let credential='',lastStatus=null,receivedAt=0,receivedWallAt=0,lastClock=null,clockFailed=false,refreshFailed=false,renderedFresh=false,refreshSequence=0,refreshing=false;
const REFRESH_TIMEOUT_MS=120000;
const element=id=>document.getElementById(id);
async function request(path,signal){const r=await fetch(path,{signal,headers:{Authorization:'Bearer '+credential}});const data=await r.json();if(!r.ok)throw Error(data.error?.message||'Request failed');return data;}
function cell(row,value){const td=document.createElement('td');td.textContent=String(value);row.append(td);}
function fresh(){const a=lastStatus?.availability,p=performance.now(),w=Date.now(),prior=lastClock||{p:receivedAt,w:receivedWallAt};
const elapsed=[p-receivedAt,w-receivedWallAt];if(![p,w,receivedAt,receivedWallAt,prior.p,prior.w,...elapsed].every(Number.isFinite)||p<prior.p||w<prior.w||elapsed.some(x=>x<0))clockFailed=true;
lastClock={p,w};return !refreshFailed&&!clockFailed&&a?.state==='fresh'&&Number.isFinite(a.fresh_for_seconds)&&a.fresh_for_seconds>=Math.max(...elapsed)/1000;}
function utilization(value,current){if(!current)return 'Unavailable';const text=String(value??'').trim();if(!/^\d+(?:\.\d+)?\s*%$/.test(text))return 'Not reported';const n=Number(text.replace('%',''));return Number.isFinite(n)&&n>=0&&n<=100?n+' %':'Not reported';}
function render(){if(!lastStatus)return;const s=lastStatus,inv=s.inventory,rs=inv?.resources||[],a=s.availability,current=fresh();renderedFresh=current;
const eligibility=new Map((a?.resources||[]).map(x=>[x.resource_id,x]));const reasons={available:'Available',held:'Held by allocation',busy:'Activity detected',unhealthy:'Unknown / unhealthy',unsupported:'Unsupported',observe_only:'Observe only',scheduler_managed:'Scheduler managed',unknown:'Unknown',missing:'Unknown',stale:'Stale',clock_uncertain:'Clock uncertain'};
element('resources').replaceChildren();for(const x of rs){const memory=x.details?.memory_capacity_bytes??x.memory_bytes,tr=document.createElement('tr'),local=eligibility.get(x.id);for(const v of [x.id,x.kind,Number.isFinite(memory)&&memory>0?(memory/1073741824).toFixed(1)+' GiB':'Driver-defined',utilization(x.details?.utilization_gpu,current),(x.modes||[]).join(', ')||'Observe only',!current?'Unknown / stale':!x.healthy?'Unknown / unhealthy':x.busy?'Activity detected':'No activity observed',current?(reasons[local?.reason]||'Unknown'):'Unavailable'])cell(tr,v);element('resources').append(tr);}
element('allocations').replaceChildren();for(const x of s.leases){const tr=document.createElement('tr');for(const v of [x.id+' / '+x.generation,x.owner,x.resources.join(', '),x.state,new Date(x.expires_at*1000).toLocaleString()])cell(tr,v);element('allocations').append(tr);}
element('gpus').textContent=rs.filter(x=>x.kind==='gpu').length;element('leases').textContent=s.leases.filter(x=>x.state!=='released').length;element('available-gpus').textContent=current?a.available_gpus:'—';element('available-partitions').textContent=current?a.available_partitions:'—';element('external').textContent=!current?'Unknown':s.bridge_policy?.enabled&&s.bridge_policy.expires_at>Date.now()/1000?'Enabled by policy':'Disabled';element('freshness').textContent=(current?'Fresh observation · ':refreshFailed?'Refresh failed; last recorded state · ':'Stale or unavailable observation · ')+(inv?new Date(inv.observed_at*1000).toLocaleString():'No inventory');element('connection').textContent=refreshFailed?'Connection unavailable':'Local connection';}
function busy(value){refreshing=value;element('token').disabled=value;element('unlock').disabled=value;element('refresh').disabled=value||!credential;element('refresh').setAttribute('aria-busy',String(value));element('refresh').textContent=value?'Refreshing…':'Refresh inventory';}
async function refresh(){
if(!credential||refreshing)return;
const sequence=++refreshSequence,controller=new AbortController(),focusTarget=document.activeElement;let timedOut=false;
busy(true);element('error').textContent='';element('status').textContent='Refreshing inventory…';
// Bound the complete read sequence, including response bodies. This cancels the
// browser wait; it does not assert cancellation of the daemon's hardware scan.
const timeout=setTimeout(()=>{timedOut=true;controller.abort();},REFRESH_TIMEOUT_MS);
try{
await request('/v1/inventory',controller.signal);
const requestedAt=performance.now(),requestedWallAt=Date.now(),s=await request('/v1/status',controller.signal);
if(timedOut)throw Error('Refresh timed out');
if(sequence!==refreshSequence)return;
lastStatus=s;receivedAt=requestedAt;receivedWallAt=requestedWallAt;lastClock=null;clockFailed=false;refreshFailed=false;
render();element('error').textContent=(s.inventory?.warnings||[]).join('\n');
element('status').textContent=renderedFresh?'Inventory refreshed. Fresh observation.':'Inventory refreshed. Availability is stale or unavailable.';
}catch(e){
if(sequence!==refreshSequence)return;
refreshFailed=true;render();element('connection').textContent='Connection unavailable';
element('status').textContent='Refresh failed. Availability is unavailable.';
element('error').textContent=timedOut?'Refresh timed out after 120 seconds. Check the local daemon and try again.':e.message||'Refresh failed. Check the local daemon and try again.';
}finally{clearTimeout(timeout);busy(false);if(document.hasFocus()&&document.activeElement===document.body&&['token','unlock','refresh'].some(id=>element(id)===focusTarget))focusTarget.focus();}
}
setInterval(()=>{if(lastStatus&&renderedFresh&&!fresh()){render();element('status').textContent=refreshing?'Refreshing inventory. The last observation is stale or unavailable.':'Inventory is stale or unavailable. Refresh to check current availability.';}},1000);
element('token-form').onsubmit=e=>{e.preventDefault();if(refreshing)return;credential=element('token').value;element('token').value='';refresh();};element('refresh').onclick=refresh;
</script></html>'''
