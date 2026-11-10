"""Local dashboard. The bearer token stays only in this page's memory."""

HTML = r'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nodus · Local GPUs</title><style>
body{margin:0;background:#f3f5f7;color:#16233b;font:15px system-ui,sans-serif}main{max-width:1100px;margin:48px auto;padding:0 24px}
header{display:flex;justify-content:space-between;align-items:center}h1{font-size:32px;margin:8px 0}small,.muted{color:#5c6b80}
section{background:white;border:1px solid #dce2ea;border-radius:12px;padding:24px;margin:24px 0}input,button,select{font:inherit;padding:10px;border:1px solid #aeb9ca;border-radius:6px}
button{background:#1e4e9d;color:white;cursor:pointer}.table-wrap{overflow-x:auto}table{min-width:650px;width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px 8px;border-bottom:1px solid #e4e8ee;font-size:13px}
code{font-size:12px;overflow-wrap:anywhere}.error{color:#a12020;white-space:pre-wrap}label{display:block;margin:8px 0}#summary{display:flex;gap:30px}.metric strong{display:block;font-size:28px}
@media(max-width:600px){main{margin:24px auto;padding:0 16px}section{padding:16px}header{display:block}#summary{flex-wrap:wrap;gap:20px}.metric strong{font-size:24px}input{box-sizing:border-box;width:100%;max-width:100%}}
</style><main><header><div><small>NODUS · LOCAL CONTROL</small><h1>Your GPU resources</h1><p class="muted">Local management works without a platform account.</p></div><span id="connection">Locked</span></header>
<section id="login"><label>Local API token <input id="token" type="password" autocomplete="off" size="48"></label><button id="unlock">Unlock local view</button><p class="muted">Use the local token file printed by the daemon. The token is kept in memory until this page closes.</p></section>
<section><div id="summary"><div class="metric"><strong id="gpus">—</strong>Physical GPUs</div><div class="metric"><strong id="leases">—</strong>Held allocations</div><div class="metric"><strong id="external">—</strong>Capacity participation</div></div><p id="freshness" class="muted">No inventory read.</p><button id="refresh">Refresh inventory</button></section>
<section><h2>Inventory</h2><p class="muted">Busy hardware is not automatically available for external work. Unsupported allocation modes stay disabled.</p><div class="table-wrap"><table><thead><tr><th>Resource</th><th>Kind</th><th>Memory</th><th>GPU utilization</th><th>Modes</th><th>Observed state</th></tr></thead><tbody id="resources"></tbody></table></div></section>
<section><h2>Allocations</h2><p class="muted">Reserved, draining and quarantined resources remain held. A release appears only after cleanup verification.</p><div class="table-wrap"><table><thead><tr><th>Lease / generation</th><th>Owner</th><th>Resources</th><th>State</th><th>Expires</th></tr></thead><tbody id="allocations"></tbody></table></div></section>
<p class="muted">Hardware qualification has not been completed for this development build. Detailed allocation and lifecycle actions are available through the CLI/API.</p><p id="error" class="error"></p></main>
<script>
let credential='';
const element=id=>document.getElementById(id);
async function request(path){const r=await fetch(path,{headers:{Authorization:'Bearer '+credential}});const data=await r.json();if(!r.ok)throw Error(data.error?.message||'Request failed');return data;}
function cell(row,value){const td=document.createElement('td');td.textContent=String(value);row.append(td);}
async function refresh(){if(!credential)return;try{await request('/v1/inventory');const s=await request('/v1/status');const inv=s.inventory;const rs=inv?.resources||[];
element('resources').replaceChildren();for(const x of rs){const tr=document.createElement('tr');for(const v of [x.id,x.kind,x.memory_bytes?(x.memory_bytes/1073741824).toFixed(1)+' GiB':'Driver-defined',x.details?.utilization_gpu||'Not reported',(x.modes||[]).join(', ')||'Observe only',!x.healthy?'Unknown / unhealthy':x.busy?'Activity detected':'No activity observed'])cell(tr,v);element('resources').append(tr);}
element('allocations').replaceChildren();for(const x of s.leases){const tr=document.createElement('tr');for(const v of [x.id+' / '+x.generation,x.owner,x.resources.join(', '),x.state,new Date(x.expires_at*1000).toLocaleString()])cell(tr,v);element('allocations').append(tr);}
element('gpus').textContent=rs.filter(x=>x.kind==='gpu').length;element('leases').textContent=s.leases.filter(x=>x.state!=='released').length;element('external').textContent=s.bridge_policy?.enabled&&s.bridge_policy.expires_at>Date.now()/1000?'Enabled by policy':'Disabled';element('freshness').textContent=inv?'Observed '+new Date(inv.observed_at*1000).toLocaleString(): 'No inventory';element('connection').textContent='Local connection';element('error').textContent=(inv?.warnings||[]).join('\n');}catch(e){element('error').textContent=e.message;}}
element('unlock').onclick=()=>{credential=element('token').value;element('token').value='';refresh();};element('refresh').onclick=refresh;
</script></html>'''
