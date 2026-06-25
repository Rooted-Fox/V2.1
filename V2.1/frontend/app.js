/* VulnIQ — frontend application v2 */

const CAT = {
  "A01:broken_access_control":{code:"A01",label:"Broken access control"},
  "A02:security_misconfiguration":{code:"A02",label:"Security misconfiguration"},
  "A03:software_supply_chain_failures":{code:"A03",label:"Supply chain"},
  "A04:cryptographic_failures":{code:"A04",label:"Cryptographic failures"},
  "A05:injection":{code:"A05",label:"Injection"},
  "A06:insecure_design":{code:"A06",label:"Insecure design"},
  "A07:authentication_failures":{code:"A07",label:"Authentication failures"},
  "A08:software_data_integrity_failures":{code:"A08",label:"Integrity failures"},
  "A09:logging_alerting_failures":{code:"A09",label:"Logging & alerting"},
  "A10:mishandling_exceptional_conditions":{code:"A10",label:"Exceptional conditions"},
};

const HIST_VULNS=[
  {name:"Buffer Overflow",year:1988,category:"Memory Corruption",refs:"Morris Worm"},
  {name:"SQL Injection",year:1998,category:"Injection",refs:"First documented 1998"},
  {name:"Cross-Site Scripting",year:1999,category:"Injection",refs:"CERT advisory 2000"},
  {name:"Path Traversal",year:1999,category:"Access Control",refs:"CVE-1999-0061"},
  {name:"Command Injection",year:1994,category:"Injection",refs:"Sendmail exploit"},
  {name:"CSRF",year:2001,category:"Auth & Session",refs:"Zeller & Felten 2001"},
  {name:"XXE",year:2002,category:"Injection",refs:"OWASP 2002"},
  {name:"IDOR / BOLA",year:2001,category:"Access Control",refs:"OWASP documented"},
  {name:"Insecure Deserialization",year:2015,category:"Integrity",refs:"Apache Commons"},
  {name:"SSRF",year:2012,category:"Access Control",refs:"OWASP 2012"},
  {name:"Clickjacking",year:2008,category:"Misconfiguration",refs:"Ha & Hansen 2008"},
  {name:"Heartbleed",year:2012,category:"Cryptographic",refs:"CVE-2014-0160"},
  {name:"Log4Shell",year:2021,category:"Supply Chain",refs:"CVE-2021-44228"},
  {name:"Privilege Escalation",year:1988,category:"Access Control",refs:"UNIX setuid bugs"},
  {name:"Weak TLS/SSL",year:1994,category:"Cryptographic",refs:"SSLv2 (1994)"},
];

async function api(path,opts={}){
  const r=await fetch(`/api${path}`,{headers:{"Content-Type":"application/json"},...opts});
  if(!r.ok){const b=await r.json().catch(()=>({}));throw new Error(b.detail||`Error ${r.status}`);}
  return r.status===204?null:r.json();
}
function esc(v){const d=document.createElement("div");d.textContent=v==null?"":v;return d.innerHTML;}
function showToast(msg){const t=document.getElementById("toast");t.textContent=msg;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2600);}

/* ── tabs ── */
let currentTab="dashboard";
function switchTab(name){
  currentTab=name;
  document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("active",t.dataset.tab===name));
  document.querySelectorAll(".panel").forEach(p=>{const a=p.id===`panel-${name}`;p.classList.toggle("active",a);p.hidden=!a;});
  if(name==="dashboard")loadDashboard();
  if(name==="scans"){loadScanJobs();loadSchedules();}
  if(name==="findings")loadFindingsTab();
  if(name==="remediation")loadRemediation();
  if(name==="settings")loadSettings();
}
document.querySelectorAll(".tab").forEach(t=>t.addEventListener("click",()=>switchTab(t.dataset.tab)));

/* ── app selector ── */
let selectedApp="";
async function populateAppSelectors(){
  const apps=await api("/apps");
  ["appSelectDashboard","appFilterEnum","appFilterEval","appFilterRemediation"].forEach(id=>{
    const sel=document.getElementById(id);if(!sel)return;
    const cur=sel.value;
    sel.innerHTML='<option value="">All applications</option>'+apps.map(a=>`<option value="${esc(a)}">${esc(a)}</option>`).join("");
    sel.value=apps.includes(cur)?cur:"";
  });
}
document.getElementById("appSelectDashboard").addEventListener("change",e=>{selectedApp=e.target.value;loadDashboard();});

/* ── dashboard ── */
let dashView="technical",sevChart=null,remChart=null;
function setDashView(v){
  dashView=v;
  document.getElementById("dashTechnical").hidden=(v!=="technical");
  document.getElementById("dashExecutive").hidden=(v!=="executive");
  document.getElementById("btnTechnical").classList.toggle("active",v==="technical");
  document.getElementById("btnExecutive").classList.toggle("active",v==="executive");
  if(v==="executive")renderExecutive();
}

async function loadDashboard(){
  await populateAppSelectors();
  document.getElementById("appSelectDashboard").value=selectedApp;
  const qs=selectedApp?`?app_name=${encodeURIComponent(selectedApp)}`:"";
  const [sev,chains,findings]=await Promise.all([api(`/summary/severity${qs}`),api(`/chains${qs}`),api(`/findings${qs}`)]);
  renderMetrics(sev);renderPriorityPatch(findings);renderChains(chains);renderHistoricalTable(findings);
  if(dashView==="executive")renderExecutive();
  document.getElementById("btnDashPdf").dataset.url=`/api/report/html${qs}&dashboard=${dashView}`;
}

function renderMetrics(sev){
  document.getElementById("metricGrid").innerHTML=[
    {label:"Critical",value:sev.critical||0,cls:"critical"},
    {label:"High",value:sev.high||0,cls:"high"},
    {label:"Medium",value:sev.medium||0,cls:"medium"},
    {label:"Low",value:sev.low||0,cls:"low"},
  ].map(i=>`<div class="metric-card"><p class="metric-label">${i.label}</p><p class="metric-value ${i.cls}">${i.value}</p></div>`).join("");
}

function renderPriorityPatch(findings){
  const sorted=[...findings].filter(f=>f.remediation_status==="open")
    .sort((a,b)=>(b.cvss_score||0)-(a.cvss_score||0)).slice(0,6);
  const list=document.getElementById("priorityPatchList");
  if(!sorted.length){list.innerHTML='<div class="empty-state"><p>No open findings yet.</p></div>';return;}
  list.innerHTML=sorted.map(f=>`<div class="priority-item ${f.severity}">
    <p class="priority-item-title">${esc(f.vulnerability_name||f.rationale||"Finding")}</p>
    <p class="priority-item-meta">CVSS ${f.cvss_score||"—"} · ${esc(f.cwe_id||"")} · ${esc(f.url||"n/a")}${f.exploitable?'<span class="badge high" style="margin-left:6px;">Exploitable</span>':""}</p>
  </div>`).join("");
}

function renderChains(chains){
  document.getElementById("chainCount").textContent=chains.length;
  document.getElementById("chainsList").innerHTML=!chains.length?
    '<p class="hint">No attack chains yet.</p>':
    chains.slice(0,4).map(c=>`<div class="chain-card">
      <p class="chain-title">${esc(c.chain_name)}</p>
      <div class="chain-meta"><span>Risk ${c.risk_score}/10</span><span>${esc(c.exploitation_difficulty)}</span></div>
    </div>`).join("");
}

function renderHistoricalTable(findings){
  const counts={};
  findings.forEach(f=>{
    const name=f.vulnerability_name||"";
    HIST_VULNS.forEach(hv=>{if(name.toLowerCase().includes(hv.name.split(" ")[0].toLowerCase()))counts[hv.name]=(counts[hv.name]||0)+1;});
  });
  document.getElementById("histVulnTable").innerHTML=`<table class="hist-table">
    <thead><tr><th>Vulnerability</th><th>First known</th><th>Category</th><th>Found in scans</th><th>Reference</th></tr></thead>
    <tbody>${HIST_VULNS.map(hv=>`<tr><td>${esc(hv.name)}</td><td><span class="year-badge">${hv.year}</span></td><td>${esc(hv.category)}</td><td>${counts[hv.name]||0}</td><td style="font-size:11px;color:var(--text-tertiary);">${esc(hv.refs)}</td></tr>`).join("")}</tbody>
  </table>`;
}

async function renderExecutive(){
  const qs=selectedApp?`?app_name=${encodeURIComponent(selectedApp)}`:"";
  const [sev,rem,chains]=await Promise.all([api(`/summary/severity${qs}`),api(`/summary/remediation${qs}`),api(`/chains${qs}`)]);
  const total=Object.values(sev).reduce((a,b)=>a+b,0);
  const riskLevel=(sev.critical||0)>0?"CRITICAL":(sev.high||0)>0?"HIGH":(sev.medium||0)>0?"MEDIUM":"LOW";
  const riskColor={"CRITICAL":"var(--critical)","HIGH":"var(--high)","MEDIUM":"var(--medium)","LOW":"var(--confirmed)"}[riskLevel];
  document.getElementById("execSummary").innerHTML=[
    {val:total,lbl:"Total findings"},
    {val:`<span style="color:${riskColor}">${riskLevel}</span>`,lbl:"Overall risk"},
    {val:chains.length,lbl:"Attack chains"},
    {val:rem.remediated||0,lbl:"Remediated"},
    {val:rem.open||0,lbl:"Open"},
  ].map(i=>`<div class="exec-card"><p class="exec-card-val">${i.val}</p><p class="exec-card-lbl">${i.lbl}</p></div>`).join("");
  const ctx1=document.getElementById("chartSeverity");
  if(sevChart)sevChart.destroy();
  sevChart=new Chart(ctx1,{type:"doughnut",data:{labels:["Critical","High","Medium","Low"],datasets:[{data:[sev.critical||0,sev.high||0,sev.medium||0,sev.low||0],backgroundColor:["#f85149","#ffa657","#e3b341","#6e7eff"],borderWidth:0}]},options:{plugins:{legend:{position:"bottom",labels:{color:"#8b949e"}}},cutout:"60%"}});
  const ctx2=document.getElementById("chartRemediation");
  if(remChart)remChart.destroy();
  remChart=new Chart(ctx2,{type:"bar",data:{labels:["Open","In Progress","Review","Remediated","Reopened"],datasets:[{data:[rem.open||0,rem.in_progress||0,rem.ready_for_validation||0,rem.remediated||0,rem.reopened||0],backgroundColor:["#f85149","#ffa657","#e3b341","#3fb950","#ffa657"],borderRadius:4}]},options:{plugins:{legend:{display:false}},scales:{x:{ticks:{color:"#8b949e"}},y:{ticks:{color:"#8b949e"},beginAtZero:true}}}});
  document.getElementById("execPosture").innerHTML=`<div class="exec-posture">
    <div class="posture-item"><p class="posture-label">Critical unpatched</p><p class="posture-value" style="color:var(--critical)">${sev.critical||0}</p></div>
    <div class="posture-item"><p class="posture-label">Attack chains</p><p class="posture-value">${chains.length}</p></div>
    <div class="posture-item"><p class="posture-label">Remediated</p><p class="posture-value" style="color:var(--confirmed)">${rem.remediated||0}</p></div>
    <div class="posture-item"><p class="posture-label">Remediation rate</p><p class="posture-value" style="color:var(--confirmed)">${total>0?Math.round(((rem.remediated||0)/total)*100):0}%</p></div>
  </div>`;
}

/* ── SCANS TAB — parallel independent scans ── */
let urlRows=[];
let jobPollHandle=null;

function addUrlRow(){
  const list=document.getElementById("urlRowList");
  const idx=urlRows.length;
  urlRows.push({url:"",name:"",reachable:null});
  const row=document.createElement("div");
  row.className="url-row";row.dataset.idx=idx;
  row.innerHTML=`
    <span class="url-status-dot" id="dot-${idx}" title="Not checked"></span>
    <input type="text" class="url-input" id="url-${idx}" placeholder="https://your-app.com" oninput="onUrlInput(${idx},this.value)" autocomplete="off">
    <input type="text" class="name-input" id="name-${idx}" placeholder="App name (optional)" autocomplete="off">
    <button class="btn-ghost btn-sm" onclick="checkUrlReachability(${idx})">Check</button>
    <button class="btn-primary btn-sm" onclick="startSingleScan(${idx})" id="scan-btn-${idx}">Scan</button>
    <button class="btn-ghost btn-sm" onclick="removeUrlRow(${idx})" style="color:var(--text-tertiary)">✕</button>`;
  list.appendChild(row);
}

function removeUrlRow(idx){
  const row=document.querySelector(`.url-row[data-idx="${idx}"]`);
  if(row)row.remove();
}

function onUrlInput(idx,val){
  if(!urlRows[idx]) urlRows[idx]={};
  urlRows[idx].url=val;
  urlRows[idx].reachable=null;
  setDot(idx,null);
}

function setDot(idx,state){
  const dot=document.getElementById(`dot-${idx}`);
  if(!dot)return;
  dot.className="url-status-dot "+(state===true?"green":state===false?"red":"grey");
  dot.title=state===true?"Reachable":state===false?"Not reachable":"Not checked";
}

async function checkUrlReachability(idx){
  const urlEl=document.getElementById(`url-${idx}`);
  if(!urlEl||!urlEl.value.trim())return;
  setDot(idx,null);
  try{
    const result=await api("/url/check",{method:"POST",body:JSON.stringify({target_url:urlEl.value.trim()})});
    setDot(idx,result.reachable);
    if(result.reachable&&result.final_url!==urlEl.value.trim()){
      showToast(`Redirects to: ${result.final_url}`);
    }
  }catch(e){setDot(idx,false);}
}

async function startSingleScan(idx){
  const urlEl=document.getElementById(`url-${idx}`);
  const nameEl=document.getElementById(`name-${idx}`);
  if(!urlEl||!urlEl.value.trim()){showToast("Enter a URL first");return;}
  const btn=document.getElementById(`scan-btn-${idx}`);
  if(btn)btn.disabled=true;
  try{
    const result=await api("/scan/single",{method:"POST",body:JSON.stringify({
      target_url:urlEl.value.trim(),
      app_name:nameEl?.value.trim()||null
    })});
    showToast(`Scan started — job ${result.job_id}`);
    setDot(idx,true);
    if(!jobPollHandle)jobPollHandle=setInterval(loadScanJobs,2000);
  }catch(e){
    showToast(e.message);
    if(btn)btn.disabled=false;
  }
}

async function loadScanJobs(){
  const jobs=await api("/scan/jobs");
  const list=document.getElementById("activeJobsList");
  if(!jobs.length){list.innerHTML='<p class="hint">No scan jobs yet. Add a target above and click Scan.</p>';return;}

  const running=jobs.filter(j=>j.status==="running"||j.status==="queued");
  const done=jobs.filter(j=>j.status==="complete"||j.status==="failed");

  // Stop polling if nothing running
  if(!running.length&&jobPollHandle){clearInterval(jobPollHandle);jobPollHandle=null;}

  list.innerHTML=[...running,...done].map(j=>`
    <div class="job-card ${j.status}">
      <div class="job-header">
        <div>
          <p class="job-title">${esc(j.app_name||j.target_url)}</p>
          <p class="job-meta">${esc(j.target_url)} &middot; ${j.status.toUpperCase()} &middot; ${j.raw_count||0} found</p>
        </div>
        <span class="job-badge ${j.status}">${j.status}</span>
      </div>
      ${j.status==="running"||j.status==="queued"?`
        <div class="progress-wrap" style="margin-top:8px;">
          <div class="progress-bar" style="width:${j.progress||0}%"></div>
        </div>
        <p class="progress-label">${j.progress||0}% — ${esc(j.status_message||"")}</p>`:
        j.last_error?`<p class="inline-error" style="margin-top:6px;">${esc(j.last_error)}</p>`:""}
    </div>`).join("");

  // Re-enable scan buttons for completed jobs
  jobs.filter(j=>j.status!=="running"&&j.status!=="queued").forEach(j=>{
    document.querySelectorAll(`[id^="scan-btn-"]`).forEach(btn=>{btn.disabled=false;});
  });

  // Refresh findings if any completed
  if(done.length&&currentTab==="findings")loadFindingsTab();
  if(done.length&&currentTab==="dashboard")loadDashboard();
}

/* ── FINDINGS TAB — Enumerated + Evaluated ── */
async function loadFindingsTab(){
  await populateAppSelectors();
  
  const activeTab=document.querySelector(".findings-subtab.active")?.dataset.sub||"enumerated";
  if(activeTab==="enumerated") loadEnumeratedFindings();
  else loadEvaluatedFindings();
}

document.querySelectorAll(".findings-subtab").forEach(btn=>{
  btn.addEventListener("click",()=>{
    document.querySelectorAll(".findings-subtab").forEach(b=>b.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("enumerated-pane").hidden=(btn.dataset.sub!=="enumerated");
    document.getElementById("evaluated-pane").hidden=(btn.dataset.sub!=="evaluated");
    if(btn.dataset.sub==="enumerated")loadEnumeratedFindings();
    else loadEvaluatedFindings();
  });
});

async function loadEnumeratedFindings(){
  const app=document.getElementById("appFilterEnum")?.value||"";
  const qs=app?`?app_name=${encodeURIComponent(app)}`:"";
  const data=await api(`/pending${qs}`);
  const list=document.getElementById("enumeratedList");
  const countEl=document.getElementById("enumCount");
  if(countEl)countEl.textContent=data.count||0;

  if(!data.count){
    list.innerHTML='<div class="empty-state"><p>No enumerated findings yet. Start a scan to discover vulnerabilities.</p></div>';
    return;
  }

  // Group by app_name
  const byApp={};
  (data.findings||[]).forEach(f=>{const a=f.app_name||"Unknown";if(!byApp[a])byApp[a]=[];byApp[a].push(f);});

  list.innerHTML=Object.entries(byApp).map(([appName,findings])=>`
    <div style="margin-bottom:20px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;padding:8px 12px;background:var(--surface-raised);border-radius:var(--radius);border-left:3px solid var(--accent);">
        <span style="font-size:13px;font-weight:600;color:var(--accent-text);">${esc(appName)}</span>
        <span class="badge-count">${findings.length} findings</span>
      </div>
      ${findings.map(f=>{
        const sev=(f.raw_severity||"info").toLowerCase().replace("informational","info");
        return `<div class="finding-row">
          <div class="finding-head" data-toggle>
            <div style="flex:1;min-width:0;">
              <p class="finding-title">${esc(f.title||"Security Finding")}</p>
              <p class="finding-meta">${esc(f.url||"n/a")}</p>
            </div>
            <span class="badge ${sev}">${sev}</span>
          </div>
          <div class="finding-body">
            <div class="finding-section"><p class="finding-section-label">Description</p><p class="finding-section-value">${esc(f.description||"—")}</p></div>
            <div class="finding-section"><p class="finding-section-label">Evidence</p><p class="finding-section-value">${esc(f.evidence||"—")}</p></div>
          </div>
        </div>`;
      }).join("")}
      ${findings.length>0?`<div style="margin-top:10px;display:flex;gap:8px;">
        <button class="btn-primary btn-sm" onclick="approveTriageForApp('${appName}')">Approve Opus analysis for ${esc(appName)}</button>
      </div>`:""}
    </div>`).join("");

  list.querySelectorAll("[data-toggle]").forEach(h=>h.addEventListener("click",()=>h.closest(".finding-row").classList.toggle("expanded")));
}

async function approveTriageForApp(appName){
  const [settings]=await Promise.all([api("/settings")]);
  if(!settings.ai_enabled){showToast("Enable AI integration in Settings first.");return;}
  try{
    await api("/triage",{method:"POST",body:JSON.stringify({app_name:appName||null})});
    showToast("Opus analysis started for "+appName);
    pollTriageStatus();
  }catch(e){showToast(e.message);}
}

let allEvaluated=[];
async function loadEvaluatedFindings(){
  await populateAppSelectors();
  const app=document.getElementById("appFilterEval")?.value||"";
  const qs=app?`?app_name=${encodeURIComponent(app)}`:"";
  allEvaluated=await api(`/findings${qs}`);
  renderEvaluatedFindings();
}

function renderEvaluatedFindings(){
  const sev=document.getElementById("severityFilterEval")?.value||"";
  const val=document.getElementById("validationFilterEval")?.value||"";
  const filtered=allEvaluated.filter(f=>(!sev||f.severity===sev)&&(!val||f.validation_status===val));
  const list=document.getElementById("evaluatedList");
  const countEl=document.getElementById("evalCount");
  if(countEl)countEl.textContent=filtered.length;
  if(!filtered.length){
    list.innerHTML=`<div class="empty-state"><p>${allEvaluated.length===0?"No evaluated findings yet. Approve Opus analysis after scanning.":"No findings match these filters."}</p></div>`;
    return;
  }
  list.innerHTML=filtered.map(f=>{
    const info=CAT[f.category]||{code:"",label:f.category};
    const vs=f.validation_status||"potential";
    return `<div class="finding-row" data-id="${f.id}">
      <div class="finding-head" data-toggle>
        <div style="flex:1;min-width:0;">
          <p class="finding-title">${esc(f.vulnerability_name||f.rationale||"Finding")}</p>
          <p class="finding-meta">${esc(info.code)} · ${esc(f.cwe_id||"")} · ${esc(f.url||"n/a")}</p>
        </div>
        <div class="finding-badges">
          <span class="badge ${f.severity}">${f.severity}</span>
          ${f.cvss_score?`<span class="cvss-badge">CVSS ${f.cvss_score}</span>`:""}
          <span class="badge ${vs}">${vs}</span>
        </div>
      </div>
      <div class="finding-body">
        <div class="analysis-grid">
          <div>
            <div class="finding-section"><p class="finding-section-label">Root cause</p><p class="finding-section-value">${esc(f.root_cause||"—")}</p></div>
            <div class="finding-section"><p class="finding-section-label">Technical impact</p><p class="finding-section-value">${esc(f.technical_impact||"—")}</p></div>
            <div class="finding-section"><p class="finding-section-label">Business impact</p><p class="finding-section-value">${esc(f.business_impact||"—")}</p></div>
          </div>
          <div>
            <div class="finding-section"><p class="finding-section-label">Attack scenario</p><p class="finding-section-value">${esc(f.attack_scenario||"—")}</p></div>
            <div class="finding-section"><p class="finding-section-label">Evidence of exploitation</p><p class="finding-section-value">${esc(f.evidence_summary||"—")}</p></div>
          </div>
        </div>
        <div class="finding-section"><p class="finding-section-label">Reproduction steps</p><pre>${esc(f.reproduction_steps||"—")}</pre></div>
        <div class="finding-section"><p class="finding-section-label">Recommendation to patch</p><p class="finding-section-value">${esc(f.remediation||"—")}</p></div>
        <div class="finding-section"><p class="finding-section-label">CVSS vector</p><div class="cvss-vector">${esc(f.cvss_vector||"N/A")}</div></div>
        <div class="finding-actions">
          <button class="btn-ghost" data-rem="in_progress">In progress</button>
          <button class="btn-ghost" data-rem="ready_for_validation">Ready for validation</button>
          <button class="btn-ghost" data-rem="remediated">Remediated</button>
          <button class="btn-ghost" data-rem="dismissed" style="color:var(--text-tertiary)">Dismiss</button>
        </div>
      </div>
    </div>`;
  }).join("");
  list.querySelectorAll("[data-toggle]").forEach(h=>h.addEventListener("click",()=>h.closest(".finding-row").classList.toggle("expanded")));
  list.querySelectorAll("[data-rem]").forEach(btn=>btn.addEventListener("click",async e=>{
    e.stopPropagation();
    const id=btn.closest(".finding-row").dataset.id;
    await api(`/findings/${id}/remediation`,{method:"PATCH",body:JSON.stringify({status:btn.dataset.rem})});
    showToast("Status updated");
    loadEvaluatedFindings();
    if(currentTab==="remediation")loadRemediation();
  }));
}

["appFilterEnum"].forEach(id=>document.getElementById(id)?.addEventListener("change",loadEnumeratedFindings));
["appFilterEval","severityFilterEval","validationFilterEval"].forEach(id=>document.getElementById(id)?.addEventListener("change",renderEvaluatedFindings));

/* ── triage polling ── */
let triagePoll=null;
async function pollTriageStatus(){
  const s=await api("/triage/status");
  if(s.running){
    if(!triagePoll)triagePoll=setInterval(pollTriageStatus,2500);
  } else {
    if(triagePoll){clearInterval(triagePoll);triagePoll=null;}
    if(s.last_error)showToast(s.last_error);
    else if(s.last_result)showToast(`Analysis done: ${s.last_result.triaged_count} findings, ${s.last_result.chain_count||0} chains`);
    if(currentTab==="findings")loadFindingsTab();
    if(currentTab==="dashboard")loadDashboard();
    if(currentTab==="remediation")loadRemediation();
  }
}

/* ── remediation ── */
async function loadRemediation(){
  await populateAppSelectors();
  document.getElementById("appFilterRemediation").value=selectedApp;
  const qs=selectedApp?`?app_name=${encodeURIComponent(selectedApp)}`:"";
  const [rem,findings]=await Promise.all([api(`/summary/remediation${qs}`),api(`/findings${qs}`)]);
  document.getElementById("remMetricGrid").innerHTML=[
    {label:"Open",value:rem.open||0,cls:"critical"},{label:"In progress",value:rem.in_progress||0,cls:"medium"},
    {label:"Pending review",value:rem.ready_for_validation||0,cls:"low"},{label:"Remediated",value:rem.remediated||0,cls:"confirmed"},
    {label:"Reopened",value:rem.reopened||0,cls:"high"},
  ].map(i=>`<div class="metric-card"><p class="metric-label">${i.label}</p><p class="metric-value ${i.cls}">${i.value}</p></div>`).join("");
  const cols=["open","in_progress","ready_for_validation","remediated","reopened"];
  const labels={open:"Open",in_progress:"In Progress",ready_for_validation:"Ready for Review",remediated:"Remediated",reopened:"Reopened"};
  document.getElementById("remColumns").innerHTML=cols.map(col=>{
    const items=findings.filter(f=>f.remediation_status===col);
    return `<div class="rem-column"><h3>${labels[col]} <span class="badge-count">${items.length}</span></h3>
      ${items.map(f=>`<div class="rem-item">
        <p class="rem-item-title">${esc((f.vulnerability_name||"Finding").substring(0,45))}</p>
        <p class="rem-item-meta"><span class="badge ${f.severity}" style="font-size:9px;">${f.severity}</span>${f.cvss_score?` CVSS ${f.cvss_score}`:""}</p>
      </div>`).join("")||`<p style="font-size:12px;color:var(--text-tertiary);">None</p>`}
    </div>`;
  }).join("");
}
document.getElementById("appFilterRemediation")?.addEventListener("change",e=>{selectedApp=e.target.value;loadRemediation();});

/* ── settings ── */
function applyProviderVisibility(p){
  document.getElementById("anthropicKeyField").hidden=(p==="azure_foundry");
  document.getElementById("azureEndpointField").hidden=(p!=="azure_foundry");
  document.getElementById("azureKeyField").hidden=(p!=="azure_foundry");
}
document.getElementById("providerSelect").addEventListener("change",e=>applyProviderVisibility(e.target.value));

async function loadSettings(){
  const s=await api("/settings");
  document.getElementById("providerSelect").value=s.provider;
  applyProviderVisibility(s.provider);
  document.getElementById("aiEnabledToggle").checked=!!s.ai_enabled;
  document.getElementById("skipInfoToggle").checked=!!s.skip_info_findings;
  document.getElementById("apiKeyStatus").textContent=s.anthropic_api_key_set?`Saved (${s.anthropic_api_key_masked})`:"Not set";
  document.getElementById("azureEndpointInput").value=s.azure_foundry_endpoint||"";
  document.getElementById("azureKeyStatus").textContent=s.azure_foundry_api_key_set?`Saved (${s.azure_foundry_api_key_masked})`:"Not set";
  document.getElementById("modelInput").value=s.agent_model||"";
  document.getElementById("zapUrlInput").value=s.zap_api_url||"";
  document.getElementById("zapKeyStatus").textContent=s.zap_api_key_set?"Saved":"Not set";
  document.getElementById("nvdKeyStatus").textContent=s.nvd_api_key_set?"Saved — 10x faster CVE scanning":"Not set";
  document.getElementById("slackStatus").textContent=s.slack_webhook_url_set?"Saved":"Not set";
  renderConfigChecklist(s);
  loadTokenUsage();
}

function renderConfigChecklist(s){
  const items=[
    {label:"ZAP running at configured URL",ok:!!s.zap_api_url,required:true},
    {label:"ZAP API key",ok:s.zap_api_key_set,required:false},
    {label:"Opus AI credentials",ok:s.provider==="azure_foundry"?s.azure_foundry_api_key_set:s.anthropic_api_key_set,required:false},
    {label:"AI integration enabled",ok:s.ai_enabled,required:false},
    {label:"NVD API key (faster CVE scan)",ok:s.nvd_api_key_set,required:false},
    {label:"Slack notifications",ok:s.slack_webhook_url_set,required:false},
  ];
  document.getElementById("configChecklist").innerHTML=items.map(i=>`<div class="config-item">
    <span class="config-dot ${i.ok?"ok":i.required?"missing":"optional"}"></span>
    <span>${i.label}</span>
    <span style="margin-left:auto;font-size:11px;color:${i.ok?"var(--confirmed)":i.required?"var(--critical)":"var(--text-tertiary)"};">${i.ok?"Configured":i.required?"Required":"Optional"}</span>
  </div>`).join("");
}

document.getElementById("settingsForm").addEventListener("submit",async e=>{
  e.preventDefault();
  await api("/settings",{method:"POST",body:JSON.stringify({
    provider:document.getElementById("providerSelect").value,
    ai_enabled:document.getElementById("aiEnabledToggle").checked,
    anthropic_api_key:document.getElementById("apiKeyInput").value||null,
    azure_foundry_endpoint:document.getElementById("azureEndpointInput").value||null,
    azure_foundry_api_key:document.getElementById("azureKeyInput").value||null,
    agent_model:document.getElementById("modelInput").value||null,
  })});
  document.getElementById("apiKeyInput").value="";
  document.getElementById("azureKeyInput").value="";
  showToast("AI settings saved");
  loadSettings();
});

document.getElementById("scannerSettingsForm").addEventListener("submit",async e=>{
  e.preventDefault();
  await api("/settings",{method:"POST",body:JSON.stringify({
    zap_api_url:document.getElementById("zapUrlInput").value||null,
    zap_api_key:document.getElementById("zapKeyInput").value||null,
    nvd_api_key:document.getElementById("nvdKeyInput").value||null,
    slack_webhook_url:document.getElementById("slackInput").value||null,
    skip_info_findings:document.getElementById("skipInfoToggle").checked,
  })});
  document.getElementById("zapKeyInput").value="";
  document.getElementById("nvdKeyInput").value="";
  document.getElementById("slackInput").value="";
  showToast("Scanner settings saved");
  loadSettings();
});

async function loadTokenUsage(){
  const d=await api("/tokens");
  document.getElementById("tokenLimitInput").value=d.limit||"";
  document.getElementById("tokenMetricGrid").innerHTML=[
    {label:"Tokens used",value:d.used,cls:""},{label:"Limit",value:d.limit||"Unlimited",cls:"accent"},
    {label:"Remaining",value:d.remaining===null?"—":d.remaining,cls:"confirmed"},
  ].map(i=>`<div class="metric-card"><p class="metric-label">${i.label}</p><p class="metric-value ${i.cls}">${i.value}</p></div>`).join("");
}
document.getElementById("saveTokenLimitButton").addEventListener("click",async()=>{
  const v=parseInt(document.getElementById("tokenLimitInput").value.trim()||"0",10);
  await api("/settings",{method:"POST",body:JSON.stringify({token_limit:isNaN(v)?0:v})});
  showToast("Token limit saved");loadTokenUsage();
});
document.getElementById("resetTokensButton").addEventListener("click",async()=>{
  if(!confirm("Reset token usage?"))return;
  await api("/tokens/reset",{method:"POST"});showToast("Usage reset");loadTokenUsage();
});

/* ── schedules ── */
async function loadSchedules(){
  const schedules=await api("/schedules");
  const el=document.getElementById("schedulesList");
  if(!schedules.length){el.innerHTML='<p class="hint">No scheduled assessments yet.</p>';return;}
  el.innerHTML=schedules.map(s=>`<div class="schedule-row">
    <div><p>${esc(s.app_name||s.target_url)}</p><p class="sub">${esc(s.cron)} · ${s.enabled?"Enabled":"Disabled"}</p></div>
    <div style="display:flex;gap:6px;">
      <button class="btn-ghost btn-sm" onclick="toggleSched('${s.id}',${!s.enabled})">${s.enabled?"Disable":"Enable"}</button>
      <button class="btn-ghost btn-sm" style="color:var(--critical)" onclick="deleteSched('${s.id}')">Delete</button>
    </div>
  </div>`).join("");
}
document.getElementById("scheduleForm").addEventListener("submit",async e=>{
  e.preventDefault();
  await api("/schedules",{method:"POST",body:JSON.stringify({
    target_url:document.getElementById("scheduleUrl").value.trim(),
    app_name:document.getElementById("scheduleAppName").value.trim()||null,
    cron:document.getElementById("scheduleCron").value.trim()||"0 2 * * *",
  })});
  showToast("Schedule added");loadSchedules();
});
async function deleteSched(id){if(!confirm("Delete?"))return;await api(`/schedules/${id}`,{method:"DELETE"});loadSchedules();}
async function toggleSched(id,en){await api(`/schedules/${id}`,{method:"PATCH",body:JSON.stringify({enabled:en})});loadSchedules();}

/* ── init ── */
addUrlRow();  // start with one URL row
loadDashboard();
