"use strict";

const RECORDED = document.documentElement.dataset.mode === "recorded";
const TOKEN = document.querySelector('meta[name="workbench-token"]')?.content || "";
const CATALOG = [
  {slug:"ledgerbridge",name:"LedgerBridge",category:"FINANCE OPERATIONS",description:"Reconcile rows once, expose exceptions, and hand each mismatch to a reviewer.",help:"Use a fresh public Treasury sample, or paste your own authorized ledger and bank rows. Local rows are processed in memory.",outcome:"Every returned row receives one status; missing sides, duplicates, and variances become a review queue.",boundary:"Public Treasury cash is not company books. A person must confirm ownership and the records before any posting.",source:"https://fiscaldata.treasury.gov/api-documentation/"},
  {slug:"marketbrief",name:"MarketBrief",category:"RESEARCH",description:"Turn a dated public GDP series into a compact, cited macro observation.",help:"Fetch the current World Bank U.S. GDP series. The result is descriptive context, not an investment recommendation.",outcome:"Compare the two most recent annual observations and inspect the full source history.",boundary:"An analyst must check release timing, alternative sources, and any company-specific question.",source:"https://data.worldbank.org/indicator/NY.GDP.MKTP.CD"},
  {slug:"chainwatch",name:"ChainWatch",category:"WATCH-ONLY REVIEW",description:"Check authorized address-rate observations for threshold breaches without a chain API.",help:"Paste observations you are allowed to review. No wallet key, signing path, chain request, or transfer is used.",outcome:"Rates are compared with a supplied baseline and short sample windows are marked uncertain.",boundary:"A person must verify address ownership, source windows, and any escalation. No public chain API is admitted here.",source:null},
  {slug:"backtestguard",name:"BacktestGuard",category:"RESEARCH INTEGRITY",description:"Inspect a chronology split and reveal future-information leakage before a model test.",help:"Choose a decision cutoff year, then inspect fresh World Bank observations on either side of it.",outcome:"The workbench shows which years belong after the cutoff and whether the split is structurally valid.",boundary:"Observation year is not release date. This does not establish a tradable strategy or completed backtest.",source:"https://data.worldbank.org/indicator/NY.GDP.MKTP.CD"},
  {slug:"replycraft",name:"ReplyCraft",category:"SUPPORT DRAFTING",description:"Read an official public notice and prepare a source-cited sample response for human editing.",help:"The public sample answers a question about an OPM proposed-rule comment date. There is no customer case.",outcome:"A cited draft appears in an editable review field; it is never sent.",boundary:"A support agent must verify the cited text and supply approved customer policy before real support use.",source:"https://www.govinfo.gov/"},
  {slug:"handoffhub",name:"HandoffHub",category:"KNOWLEDGE HANDOFF",description:"Extract a public rule excerpt and package it with a clear next action.",help:"Fetch the current official OPM rule metadata and its identity-matched GovInfo text.",outcome:"The handoff carries the exact public document, cited excerpt, and a reviewer action.",boundary:"A person must connect permission-scoped internal knowledge and a real owner before workplace use.",source:"https://www.govinfo.gov/"},
  {slug:"sentineldesk",name:"SentinelDesk",category:"SECURITY TRIAGE",description:"Group public exploited-vulnerability context into a review queue without touching assets.",help:"Fetch the current CISA Known Exploited Vulnerabilities catalog and inspect prioritized entries.",outcome:"The queue retains CVE identity, due dates, source links, and public-context limits.",boundary:"A security owner must map CVEs to authorized assets and decide the response. No containment is performed.",source:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
  {slug:"searchlift",name:"SearchLift",category:"CONTENT AUDIT",description:"Inspect the owned public portfolio page for bounded structural content issues.",help:"Read the selected public portfolio page and inspect title, headings, paragraphs, and workflow-name coverage.",outcome:"Issues and suggested review priorities appear with the exact inspected-page boundary.",boundary:"An editor must assess any changes. No ranking, traffic, or whole-site SEO result is inferred.",source:"https://cayleb-james2008.github.io/agentic-resume/"},
  {slug:"pipelinerelay",name:"PipelineRelay",category:"RESEARCH HANDOFF",description:"Check one public repository's identity and license before an authorized research handoff.",help:"Enter a public GitHub owner and repository. Only repository metadata is read.",outcome:"The result highlights identity, branch, license, timestamp, and the human verification task.",boundary:"A person must establish any account context and consent. This is not a lead or outreach tool.",source:"https://docs.github.com/en/rest/repos/repos#get-a-repository"},
  {slug:"onboardpath",name:"OnboardPath",category:"PUBLIC POLICY REVIEW",description:"Select an official OPM rule and inspect its text with employee-service limits visible.",help:"Enter a current Federal Register document number, or let the source select a recent rule.",outcome:"The selected document and sections appear with metadata and direct GovInfo provenance.",boundary:"A person must supply approved employer policy and authorized employee records before answering anyone.",source:"https://www.federalregister.gov/"}
];

const $ = (id) => document.getElementById(id);
const el = (tag, cls, value) => {const node=document.createElement(tag);if(cls)node.className=cls;if(value!==undefined)node.textContent=String(value);return node;};
let current = CATALOG[0];
let lastReceipt = null;

function appendText(parent, tag, cls, value){const node=el(tag,cls,value);parent.append(node);return node;}
function field(parent,id,label,type,value,help){
  const wrap=el("div","field");const lab=el("label",null,label);lab.htmlFor=id;wrap.append(lab);
  const control=el(type==="textarea"?"textarea":"input");control.id=id;if(type!=="textarea")control.type=type;if(value!==undefined)control.value=value;
  wrap.append(control);if(help)appendText(wrap,"small",null,help);parent.append(wrap);return control;
}
function check(parent,id,label){const wrap=el("div","check-field");const input=el("input");input.type="checkbox";input.id=id;const lab=el("label",null,label);lab.htmlFor=id;wrap.append(input,lab);parent.append(wrap);return input;}
function metric(parent,label,value){const box=el("div","metric");appendText(box,"span","metric__label",label);appendText(box,"strong","metric__value",value===undefined||value===null?"Unknown":value);parent.append(box);}
function section(parent,title){const box=el("section","result-section");appendText(box,"h4",null,title);parent.append(box);return box;}
function list(parent,items,render){const ul=el("ul","result-list");items.forEach(item=>{const li=el("li");render(li,item);ul.append(li);});parent.append(ul);return ul;}
function paragraphs(parent,text){if(Array.isArray(text))text.forEach(item=>appendText(parent,"p","result-copy",item));else if(text)appendText(parent,"p","result-copy",text);}
function safeLink(parent,label,url){try{const parsed=new URL(url);if(parsed.protocol!=="https:")return;const a=el("a",null,label);a.href=parsed.href;a.target="_blank";a.rel="noopener noreferrer";parent.append(a);}catch{}}
function mainResult(data){return data.task_result ?? data.result ?? {};}

function renderNav(){const nav=$("workflow-nav");nav.replaceChildren();CATALOG.forEach((item,i)=>{const button=el("button","nav-item");button.type="button";button.dataset.slug=item.slug;button.setAttribute("aria-label",`${i+1}. ${item.name}`);appendText(button,"span","nav-number",String(i+1).padStart(2,"0"));appendText(button,"span","nav-item__name",item.name);appendText(button,"span","nav-item__arrow","↗");button.addEventListener("click",()=>select(item.slug,true));nav.append(button);});}

function renderFields(item){const box=$("form-fields");box.replaceChildren();
  if(RECORDED){appendText(box,"p","result-copy","This is a dated, inspectable result from a prior local run. Use the repository's local workbench to fetch fresh public data or review your own authorized input.");$("run-button").textContent="Explore recorded result ↗";return;}
  if(item.slug==="ledgerbridge"){
    const wrap=el("div","field"),lab=el("label",null,"Input source");lab.htmlFor="input-mode";const select=el("select");select.id="input-mode";[["public","Fresh Treasury rows"],["user","My authorized CSV rows"]].forEach(([value,label])=>{const option=el("option",null,label);option.value=value;select.append(option);});wrap.append(lab,select);box.append(wrap);
    const csv=field(box,"input-csv","CSV rows","textarea","","Required columns: row_id,reference,side,amount_cents,owner. Include one ledger and one bank row per reference.");csv.placeholder="row_id,reference,side,amount_cents,owner\nA1,INV-01,ledger,2500,reviewer\nA2,INV-01,bank,2500,reviewer";const group=csv.parentElement;group.hidden=true;select.addEventListener("change",()=>{group.hidden=select.value!=="user";});
  }else if(item.slug==="chainwatch"){
    const csv=field(box,"input-csv","Watch observations (CSV)","textarea","","Columns: event_id,chain,address,rate_units_per_hour,baseline_units_per_hour,sample_hours,owner. EVM addresses only.");csv.placeholder="event_id,chain,address,rate_units_per_hour,baseline_units_per_hour,sample_hours,owner";
    field(box,"input-threshold","Alert multiple","number","3","Alert when observed rate is at least this multiple of baseline.").step="0.1";
    check(box,"input-authorized","I am authorized to review these observations. I understand this is a local, watch-only calculation.");
  }else if(item.slug==="backtestguard")field(box,"input-cutoff","Decision cutoff year","number","2020","The holdout begins after this year.");
  else if(item.slug==="pipelinerelay"){field(box,"input-owner","GitHub owner","text","pytest-dev");field(box,"input-repo","Repository","text","pytest");}
  else if(item.slug==="onboardpath")field(box,"input-document","Federal Register document number (optional)","text","","Example: 2026-19222. Blank selects a recent eligible rule.");
  else appendText(box,"p","micro","Uses the selected official public source. No private credentials or uploaded data are needed.");
}

function select(slug,updateHash=false){const item=CATALOG.find(x=>x.slug===slug)||CATALOG[0];current=item;lastReceipt=null;
  $("category").textContent=item.category;$("index").textContent=`${String(CATALOG.indexOf(item)+1).padStart(2,"0")} / 10`;
  $("signal").textContent=`${String(CATALOG.indexOf(item)+1).padStart(2,"0")} · ${item.category}`;
  $("title").textContent=item.name;$("description").textContent=item.description;$("input-help").textContent=RECORDED?"This dated snapshot records one bounded journey. Open the result to inspect its source, calculation or draft, and human handoff.":item.help;$("outcome").textContent=item.outcome;$("boundary").textContent=item.boundary;
  document.querySelectorAll(".nav-item").forEach(button=>{if(button.dataset.slug===item.slug)button.setAttribute("aria-current","page");else button.removeAttribute("aria-current");});
  renderFields(item);$("result-content").replaceChildren();const empty=el("div","empty-state");appendText(empty,"span",null,"↳");appendText(empty,"p",null,RECORDED?"Open the dated result to inspect the recorded evidence and human handoff.":"Choose an input and run this workflow. The cited result will appear here.");$("result-content").append(empty);setState(RECORDED?"READY TO EXPLORE":"READY TO RUN",null);$("result-actions").hidden=true;
  if(updateHash)history.replaceState(null,"",`#${item.slug}`);
}

function parseCsv(text,columns){
  if(!text.trim())throw new Error("Paste CSV observations first.");
  const records=[];let row=[],cell="",quoted=false;
  for(let i=0;i<text.length;i++){const ch=text[i];if(ch==='"'){if(quoted&&text[i+1]==='"'){cell+='"';i++;}else quoted=!quoted;}else if(ch===","&&!quoted){row.push(cell);cell="";}else if((ch==="\n"||ch==="\r")&&!quoted){if(ch==="\r"&&text[i+1]==="\n")i++;row.push(cell);if(row.some(x=>x.trim()))records.push(row.map(x=>x.trim()));row=[];cell="";}else cell+=ch;}
  if(quoted)throw new Error("A CSV quote is not closed.");row.push(cell);if(row.some(x=>x.trim()))records.push(row.map(x=>x.trim()));
  const header=records.shift();if(!header||header.join(",")!==columns.join(","))throw new Error(`CSV header must be: ${columns.join(",")}`);
  if(!records.length||records.length>200)throw new Error("Provide between 1 and 200 data rows.");
  return records.map((values,i)=>{if(values.length!==columns.length)throw new Error(`CSV row ${i+2} has the wrong number of columns.`);return Object.fromEntries(columns.map((key,index)=>[key,values[index]]));});
}
function payloadFor(item){const p={mode:"public"};
  if(item.slug==="ledgerbridge"&&$("input-mode").value==="user"){
    p.mode="user";p.rows=parseCsv($("input-csv").value,["row_id","reference","side","amount_cents","owner"]);
    p.rows.forEach(row=>{if(!/^\d+$/.test(row.amount_cents))throw new Error("Amounts must be whole, nonnegative cents.");row.amount_cents=Number(row.amount_cents);});
  }else if(item.slug==="chainwatch"){
    p.mode="user";p.authorized=$("input-authorized").checked;p.threshold=Number($("input-threshold").value);
    p.rows=parseCsv($("input-csv").value,["event_id","chain","address","rate_units_per_hour","baseline_units_per_hour","sample_hours","owner"]);
    p.rows.forEach(row=>["rate_units_per_hour","baseline_units_per_hour","sample_hours"].forEach(key=>{if(!/^\d+(\.\d+)?$/.test(row[key]))throw new Error(`${key} must be a nonnegative number.`);row[key]=Number(row[key]);}));
  }else if(item.slug==="backtestguard")p.cutoff_year=Number($("input-cutoff").value);
  else if(item.slug==="pipelinerelay"){p.owner=$("input-owner").value.trim();p.repo=$("input-repo").value.trim();}
  else if(item.slug==="onboardpath")p.document_number=$("input-document").value.trim();
  return p;
}

function setState(label,tone){const state=$("result-state");state.textContent=label;if(tone)state.dataset.tone=tone;else delete state.dataset.tone;}
function renderSpecific(root,item,data,result){
  const box=section(root,"The work");
  if(item.slug==="ledgerbridge"){
    metricBox(root,[["Rows accounted",result.accounted_row_count],["Rows received",result.input_row_count],["Review cues",(result.exceptions_for_human_review||result.owner_queue||[]).length]]);
    const exceptions=result.exceptions_for_human_review||result.owner_queue||[];
    if(exceptions.length)list(box,exceptions.slice(0,12),(li,x)=>{appendText(li,"strong",null,`${x.exception||x.reasons?.join(" + ")||"Review required"} · ${x.reference||x.as_of||"row"}`);appendText(li,"span",null,x.interpretation||`Reference ${x.reference}; variance ${x.variance_cents??"not calculated"} cents.`);if(x.source_ids)appendText(li,"span",null,` Source IDs: ${x.source_ids.join(", ")}.`);});
    else paragraphs(box,"Every submitted reference matched under the supplied row values. Confirm source completeness before using this result.");
  }else if(item.slug==="marketbrief"){
    const change=result.latest_nominal_change||{};metricBox(root,[["Observations",result.record_count],["Latest year",change.to_year],["Nominal change",change.change_percent?`${change.change_percent}%`:"Unknown"]]);
    paragraphs(box,`${change.from_year||"Earlier"} → ${change.to_year||"latest"} nominal U.S. GDP. This is annual public macro data, not company or market-price evidence.`);
    const rows=result.annual_observations||[];if(rows.length){const graph=document.createElementNS("http://www.w3.org/2000/svg","svg");graph.setAttribute("class","series");graph.setAttribute("viewBox","0 0 300 110");graph.setAttribute("role","img");graph.setAttribute("aria-label","Annual nominal GDP bars from the first through last returned year");const values=rows.map(r=>Number(r.gdp_current_usd));const max=Math.max(...values);values.forEach((v,i)=>{const bar=document.createElementNS("http://www.w3.org/2000/svg","rect");const h=Math.max(10,Math.round(v/max*95));bar.setAttribute("x",String(i*20+1));bar.setAttribute("y",String(110-h));bar.setAttribute("width","16");bar.setAttribute("height",String(h));bar.setAttribute("fill",i===values.length-1?"#bd4a31":"#1e4d65");graph.append(bar);});box.append(graph);}
  }else if(item.slug==="chainwatch"){
    const alerts=result.alerts||[];metricBox(root,[["Observations",(result.observations||[]).length],["Alerts",alerts.length],["Threshold",result.threshold_multiple?`${result.threshold_multiple}×`:"Unknown"]]);
    if(alerts.length)list(box,alerts,(li,x)=>{appendText(li,"strong",null,`${x.event_id} · ${x.rate_to_baseline}× baseline`);appendText(li,"span",null,`${x.reason}. Sample uncertainty: ${x.uncertainty}.`);});else paragraphs(box,"No row crossed the supplied threshold. Check baseline quality and observation coverage before concluding an address is quiet.");
  }else if(item.slug==="backtestguard"){
    const params=result.experiment_parameters||{},control=result.valid_chronological_control||{},leak=result.future_observation_leakage_probe||{};
    metricBox(root,[["GDP records",result.record_count],["Decision year",params.decision_cutoff_year],["Order check",control.passes_observation_year_order_only?"Pass":"Unverified"]]);
    paragraphs(box,result.label);const years=el("p","result-copy");appendText(years,"strong",null,"Holdout years: ");years.append(document.createTextNode((params.holdout_years||[]).join(", ")||"None"));box.append(years);paragraphs(box,leak.reason);
  }else if(item.slug==="replycraft"){
    metricBox(root,[["Document",result.document_id],["Customer case",result.customer_case?"Yes":"No"],["Send attempted",result.send_attempted?"Yes":"No"]]);
    paragraphs(box,result.question);const draft=el("textarea","draft-box");draft.value=result.draft||"";draft.setAttribute("aria-label","Editable draft for human review");box.append(draft);appendText(box,"p","micro","Editable here for review only. This workbench has no send action.");
  }else if(item.slug==="handoffhub"){
    metricBox(root,[["Document",result.document_id],["Source text",data.policy_text_status||"Unknown"],["Internal owner","Unverified"]]);paragraphs(box,result.answer);paragraphs(box,result.limitation);
  }else if(item.slug==="sentineldesk"){
    const queue=result.review_queue||[];metricBox(root,[["Catalog records",result.catalog_record_count],["Review queue",queue.length],["Org assets","Not connected"]]);
    const search=field(box,"cve-search","Find a CVE in the returned queue","search","","Filters the returned review queue only.");const listHost=el("div");box.append(listHost);
    const draw=()=>{listHost.replaceChildren();const filtered=queue.filter(x=>JSON.stringify(x).toLowerCase().includes(search.value.trim().toLowerCase()));if(!filtered.length){paragraphs(listHost,"No matching returned entry. Clear the search to inspect the queue.");return;}list(listHost,filtered.slice(0,20),(li,x)=>{appendText(li,"strong",null,`${x.source_id||x.cve_id||"CVE"} · due ${x.due_date||"unknown"}`);appendText(li,"span",null,(x.public_summary||"").slice(0,260));});};search.addEventListener("input",draw);draw();
  }else if(item.slug==="searchlift"){
    const coverage=result.name_coverage||{};metricBox(root,[["Pages reviewed",result.pages_reviewed],["Name coverage",coverage.count],["Issues",result.issue_count]]);
    paragraphs(box,coverage.coverage_note);const issues=result.issues||[];if(issues.length)list(box,issues,(li,x)=>appendText(li,"span",null,`${x.rule_id||"Issue"}: ${x.observed||x.reason||"Review"}`));else paragraphs(box,"No issue was found within the captured fields and parser limits. This is not an SEO performance result.");
  }else if(item.slug==="pipelinerelay"){
    const meta=result.metadata||{};metricBox(root,[["Repository",meta.full_name],["Reported license",meta.license_spdx_id],["Default branch",meta.default_branch]]);
    paragraphs(box,result.summary);list(box,result.review_checks||[],(li,x)=>{appendText(li,"strong",null,`${x.check||"Check"} · ${x.status||"Unknown"}`);appendText(li,"span",null,x.note||"");});paragraphs(box,result.human_verification_task);
  }else if(item.slug==="onboardpath"){
    const selected=result.selected_document||{};metricBox(root,[["Document",selected.document_number||"None selected"],["Text",data.policy_text_status||"Unknown"],["Employee records","Not loaded"]]);
    if(selected.text_excerpt)paragraphs(box,selected.text_excerpt);else paragraphs(box,"No matching current rule text was selected. Try a document number from the returned official list.");
    const sections=selected.sections||[];if(sections.length)list(box,sections.slice(0,6),(li,x)=>{appendText(li,"strong",null,x.section||x.name||"Section");appendText(li,"span",null,(x.review||x.excerpt||x.text||"").slice(0,260));});paragraphs(box,result.limitation);
  }
}
function metricBox(root,entries){const box=el("div","result-intro");entries.forEach(([label,value])=>metric(box,label,value));root.insertBefore(box,root.querySelector(".result-section"));}

function renderResult(data){lastReceipt=data;const host=$("result-content");host.replaceChildren();const result=mainResult(data);const sourceStatus=String(data.source_status||data.data_status||data.status||"UNVERIFIED");
  setState(sourceStatus.startsWith("VERIFIED")?"SOURCE VERIFIED":sourceStatus.startsWith("USER_SUPPLIED")?"USER INPUT · UNVERIFIED":"SOURCE UNVERIFIED",sourceStatus.startsWith("VERIFIED")?"good":"warn");
  if(RECORDED){const stamp=el("p","result-copy");stamp.textContent=`Recorded snapshot exported ${data.recorded_at_utc||"at an unknown time"}. This is not a fresh source request.`;host.append(stamp);}
  const intro=el("p","result-copy");intro.textContent=`Source: ${sourceStatus}. Full workflow: ${data.workflow_status||data.job_verdict||"UNVERIFIED"}. AI: ${data.ai_status||"NOT RUN"}.`;host.append(intro);
  if(result&&typeof result==="object"&&Object.keys(result).length)renderSpecific(host,current,data,result);else{const empty=section(host,"No result available");paragraphs(empty,data.reason||data.uncertainty||"The source did not return usable data. Check the selected input and retry.");}
  if(data.ai_output&&data.ai_proof){const area=section(host,"Cited local model contribution");paragraphs(area,data.ai_output);paragraphs(area,"A separate witness matched the model request and response. The cited sentence passed the app's citation check and a human source review; neither check establishes a complete enterprise job.");const proof=el("div","source-links");safeLink(proof,"Inspect the witness bundle ↗",data.ai_proof.proof_url);area.append(proof);}
  const handoff=data.handoff||data.human_handoff;if(handoff){const area=section(host,"Human review");paragraphs(area,handoff.next_action||handoff.context||"Review the cited evidence before acting.");}
  if(data.uncertainty){const area=section(host,"Limit and uncertainty");paragraphs(area,data.uncertainty);}
  const sources=section(host,"Source trail");const links=el("div","source-links");if(current.source&&!sourceStatus.startsWith("USER_SUPPLIED"))safeLink(links,"Source reference ↗",current.source);
  const evidence=Array.isArray(data.evidence)?data.evidence:[];const requestUrl=data.request_url||data.source_metadata?.request_url||data.source?.request_url; if(requestUrl)safeLink(links,"Exact source request ↗",requestUrl);const urls=[...new Set(evidence.map(x=>x&&x.source_url).filter(Boolean))].slice(0,3);urls.forEach((url,i)=>safeLink(links,`Evidence ${i+1} ↗`,url));if(!links.children.length)paragraphs(sources,"User-supplied rows only; no external source was queried.");else sources.append(links);
  const raw=el("details","raw-details");appendText(raw,"summary",null,"Inspect full JSON receipt");const pre=el("pre");raw.addEventListener("toggle",()=>{if(raw.open&&!pre.textContent)pre.textContent=JSON.stringify(data,null,2);});raw.append(pre);host.append(raw);
  $("result-actions").hidden=false;$("review-button").textContent="Mark locally reviewed";
  $("result-panel").scrollIntoView({behavior:window.matchMedia("(prefers-reduced-motion: reduce)").matches?"auto":"smooth",block:"start"});
}

async function submit(event){event.preventDefault();const item=current;let payload={};if(!RECORDED){try{payload=payloadFor(item);}catch(error){showError(error.message);return;}}
  const button=$("run-button");button.disabled=true;button.textContent=RECORDED?"Opening recorded receipt…":"Running source review…";setState("RUNNING", "loading");const host=$("result-content");host.replaceChildren();const loading=el("div","empty-state");appendText(loading,"span",null,"↗");appendText(loading,"p",null,RECORDED?"Opening the dated public receipt…":"Reading the selected source and checking its evidence boundary…");host.append(loading);$("result-actions").hidden=true;
  try{const response=RECORDED?await fetch(`receipts/${item.slug}.json`,{cache:"no-store"}):await fetch(`/api/run/${item.slug}`,{method:"POST",headers:{"Content-Type":"application/json","X-Workbench-Token":TOKEN},body:JSON.stringify(payload),cache:"no-store"});const data=await response.json();if(!response.ok)throw new Error(data.error||"The workflow could not run.");if(current===item)renderResult(data);}catch(error){if(current===item)showError(error.message||"The workflow failed. Retry with fresh input.");}finally{button.disabled=false;button.textContent=RECORDED?"Explore recorded result ↗":"Run review ↗";}
}
function showError(message){setState("NEEDS ATTENTION","warn");$("result-content").replaceChildren();const box=el("div","empty-state");appendText(box,"span",null,"!");appendText(box,"p",null,`${message} Correct the input or retry the source.`);$("result-content").append(box);$("result-actions").hidden=true;lastReceipt=null;}
function download(){if(!lastReceipt)return;const json=JSON.stringify(lastReceipt,null,2);const url=URL.createObjectURL(new Blob([json],{type:"application/json"}));const a=el("a");a.href=url;a.download=`${current.slug}-review-${new Date().toISOString().slice(0,10)}.json`;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function review(){if(!lastReceipt)return;$("review-button").textContent="Reviewed in this browser ✓";}

renderNav();select(location.hash.slice(1));window.addEventListener("hashchange",()=>select(location.hash.slice(1)));$("run-form").addEventListener("submit",submit);$("download-button").addEventListener("click",download);$("review-button").addEventListener("click",review);
