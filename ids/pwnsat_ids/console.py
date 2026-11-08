"""The web console.

Standard library only, one file, no package hunt: the sensor has to come up on
the instructor's laptop, on a student's Ubuntu VM and on a Raspberry Pi, and a
console that needs a build step is a console that is down while the room waits.

What it has to do, in the order it matters:

**Say what it is for.** On an empty screen "nothing is wrong" and "nothing is
watching" look the same. The rule inventory is on the page whether or not
anything has fired, and so are the two attacks in the syllabus this set cannot
catch.

**Show the evidence.** An alert that reads `declared 41, received 1` is a
claim. The octets that raised it, the board's own account of the frame, and the
time it arrived are what turn it into a finding somebody can write up.

**Carry the defence.** Every alert opens with what the sensor saw, why it
matters and how the fault is fixed. That is the house rule, and a student who
only gets the attack half leaves with half a skill.
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .knowledge import BLIND_SPOTS, inventory
from .rules import Detection

PAGE = r'''<!doctype html><html lang="en"><meta charset="utf-8">
<title>Space IDS</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{
 --tinta:#0A0A0A; --papel:#FFFFFF; --cota:#8A8A8A; --reticula:#E8E8E8;
 --ataque:#C25E00; --defensa:#0F6F68; --gris:#5A5A5A; --panel:#FAFAFA;
 --critica:#B3261E; --alta:#C25E00; --media:#5A5A5A; --viva:#0F6F68;
 --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
 --disp:"Space Grotesk",system-ui,-apple-system,sans-serif;
 --cuerpo:"IBM Plex Sans",-apple-system,system-ui,sans-serif;
}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){
 --tinta:#F2F2F2; --papel:#0A0A0A; --cota:#7E7E7E; --reticula:#232323;
 --gris:#9A9A9A; --panel:#121212;
 --ataque:#FF9F1C; --defensa:#35D6C8; --critica:#FF6B5E; --alta:#FF9F1C;
 --media:#9A9A9A; --viva:#35D6C8;
}}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--papel);color:var(--tinta);font:14px/1.55 var(--cuerpo);
 display:flex;flex-direction:column;overflow:hidden}
.k{font:500 9.5px/1 var(--mono);letter-spacing:.14em;color:var(--cota);text-transform:uppercase}
code,.mono{font-family:var(--mono)}

/* ---- masthead ---------------------------------------------------- */
header{padding:16px 20px 0;border-bottom:1px solid var(--reticula);flex:0 0 auto}
.title{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
h1{font:500 22px/1 var(--disp);margin:0;letter-spacing:-.01em}
.chain{font-family:var(--mono);font-size:11.5px;color:var(--gris)}
.chain b{color:var(--tinta);font-weight:500}
.live{margin-left:auto;display:flex;align-items:center;gap:7px;font:500 10px/1 var(--mono);
 letter-spacing:.14em;text-transform:uppercase;color:var(--viva)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--viva)}
.beat{animation:beat 2s infinite}
@keyframes beat{0%,100%{opacity:1}50%{opacity:.25}}
.paused .live{color:var(--gris)} .paused .dot{background:var(--gris);animation:none}
.purpose{margin:9px 0 0;max-width:72ch;color:var(--gris);font-size:13px}
.purpose b{color:var(--tinta);font-weight:500}

/* ---- claims + counters ------------------------------------------ */
.bar{display:flex;gap:0;flex-wrap:wrap;margin:13px -20px 0;padding:0 20px;
 border-top:1px solid var(--reticula)}
.cell{padding:9px 22px 10px 0;min-width:84px}
.v{font:500 17px/1.25 var(--disp);margin-top:3px}
.v.sm{font-size:13px;font-family:var(--mono);font-weight:400;word-break:break-all}
.claim{margin-left:auto;display:flex;gap:0}
.claim .cell{padding-left:22px;border-left:1px solid var(--reticula)}
.claim .v{font:500 12px/1.3 var(--cuerpo)}
.ok{color:var(--viva)} .warn{color:var(--alta)}

/* ---- tabs -------------------------------------------------------- */
nav{display:flex;gap:2px;margin:0 -20px;padding:0 20px;border-top:1px solid var(--reticula)}
nav button{background:none;border:0;border-bottom:2px solid transparent;cursor:pointer;
 font:500 10.5px/1 var(--mono);letter-spacing:.13em;text-transform:uppercase;
 color:var(--cota);padding:11px 13px 9px;margin-bottom:-1px}
nav button:hover{color:var(--tinta)}
nav button[aria-selected=true]{color:var(--tinta);border-bottom-color:var(--tinta)}
nav .count{color:var(--cota);font-weight:400}

/* ---- toolbar ----------------------------------------------------- */
.tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:10px 20px;
 border-bottom:1px solid var(--reticula);flex:0 0 auto;background:var(--panel)}
.sev{font:500 10px/1 var(--mono);letter-spacing:.09em;text-transform:uppercase;
 padding:5px 9px;border:1px solid currentColor;background:none;cursor:pointer;color:var(--gris)}
.sev b{font-weight:500;font-variant-numeric:tabular-nums}
.sev.critical{color:var(--critica)} .sev.high{color:var(--alta)} .sev.medium{color:var(--media)}
.sev[aria-pressed=true]{background:currentColor}
.sev[aria-pressed=true] span,.sev[aria-pressed=true] b{color:var(--papel)}
input[type=search],select{font:400 12px/1 var(--mono);padding:6px 8px;background:var(--papel);
 color:var(--tinta);border:1px solid var(--reticula);border-radius:0}
input[type=search]{min-width:190px}
.tools .right{margin-left:auto;display:flex;gap:8px;align-items:center}
.btn{font:500 10px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;padding:6px 10px;
 border:1px solid var(--reticula);background:var(--papel);color:var(--gris);cursor:pointer}
.btn:hover{color:var(--tinta);border-color:var(--cota)}
.btn[aria-pressed=true]{background:var(--tinta);color:var(--papel);border-color:var(--tinta)}

/* ---- timeline ---------------------------------------------------- */
.tlwrap{display:flex;align-items:center;gap:13px;padding:0 20px;flex:0 0 auto;
 border-bottom:1px solid var(--reticula)}
.tlwrap .k{flex:0 0 auto}
.tl{flex:1 1 auto;display:flex;align-items:flex-end;gap:1px;height:40px;padding:7px 0 8px}
.tl i{flex:1;min-width:1px;background:var(--reticula);height:2px;display:block}
.tl i.c{background:var(--critica)} .tl i.h{background:var(--alta)} .tl i.m{background:var(--media)}

/* ---- panes ------------------------------------------------------- */
/* The alert view is a flex child of the body and a flex column itself, or the
   panes collapse to their content and leave the page half empty whenever few
   rules have fired, which is most of the day. */
#view-alerts{flex:1 1 auto;display:flex;flex-direction:column;min-height:0}
#view-rules{min-height:0}
main{flex:1 1 auto;display:flex;min-height:0}
.list{flex:1 1 56%;overflow:auto;border-right:1px solid var(--reticula);min-width:0}
.detail{flex:1 1 44%;overflow:auto;min-width:0;background:var(--panel)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
thead th{position:sticky;top:0;z-index:2;text-align:left;background:var(--papel);
 border-bottom:1px solid var(--tinta);padding:7px 10px;
 font:500 9.5px/1 var(--mono);letter-spacing:.14em;color:var(--cota);text-transform:uppercase}
tbody tr{cursor:pointer;border-bottom:1px solid var(--reticula)}
tbody tr:hover{background:var(--panel)}
tbody tr[aria-selected=true]{background:var(--tinta)}
tbody tr[aria-selected=true] td,tbody tr[aria-selected=true] code{color:var(--papel)}
tbody tr[aria-selected=true] .pill{border-color:var(--papel);color:var(--papel)}
td{padding:7px 10px;vertical-align:top}
td.t{font-family:var(--mono);font-size:11px;color:var(--gris);white-space:nowrap}
td.r code{font-size:11.5px}
td.d{color:var(--gris)}
.pill{display:inline-block;font:500 9px/1 var(--mono);letter-spacing:.08em;text-transform:uppercase;
 padding:3px 5px;border:1px solid currentColor;white-space:nowrap}
.pill.critical{color:var(--critica)} .pill.high{color:var(--alta)} .pill.medium{color:var(--media)}
.arrow{font-family:var(--mono);font-size:10.5px;color:var(--cota);white-space:nowrap}
.fresh{animation:fresh 2.4s ease-out}
@keyframes fresh{from{background:var(--reticula)}to{background:transparent}}

/* ---- detail ------------------------------------------------------ */
.pad{padding:18px 20px 40px}
.dh{border-bottom:1px solid var(--reticula);padding-bottom:13px;margin-bottom:16px}
.dh h2{font:500 17px/1.25 var(--disp);margin:7px 0 3px}
.dh .rule{font-family:var(--mono);font-size:12px;color:var(--gris)}
.sec{margin:0 0 17px;padding-left:11px;border-left:2px solid var(--reticula)}
.sec.atk{border-left-color:var(--ataque)}
.sec.def{border-left-color:var(--defensa)}
.sec p{margin:5px 0 0;font-size:13px}
.sec .k{display:block;margin-bottom:0}
.grid{display:grid;grid-template-columns:auto 1fr;gap:2px 14px;margin-top:6px;
 font-family:var(--mono);font-size:11.5px}
.grid dt{color:var(--cota)} .grid dd{margin:0;word-break:break-all}
pre{font-family:var(--mono);font-size:11px;line-height:1.6;margin:7px 0 0;padding:10px;
 background:var(--papel);border:1px solid var(--reticula);overflow-x:auto;white-space:pre}
pre .hdr{color:var(--ataque);font-weight:500}
.prov{font-size:11.5px;color:var(--gris);border-top:1px solid var(--reticula);padding-top:12px}
.prov code{color:var(--tinta)}
.where{display:inline-block;margin-top:6px;font-family:var(--mono);font-size:11.5px;
 color:var(--defensa);border:1px solid currentColor;padding:3px 6px}

/* ---- inventory --------------------------------------------------- */
.inv{overflow:auto;flex:1 1 auto}
.inv .pad{max-width:none}
.lead{max-width:74ch;color:var(--gris);font-size:13px;margin:0 0 20px}
.lead b{color:var(--tinta);font-weight:500}
.rl{border-top:1px solid var(--reticula);padding:13px 0;display:grid;
 grid-template-columns:minmax(210px,1fr) 2.4fr;gap:4px 26px}
.rl:last-child{border-bottom:1px solid var(--reticula)}
.rl h3{font:500 13.5px/1.3 var(--disp);margin:5px 0 3px}
.rl .meta{font-family:var(--mono);font-size:10.5px;color:var(--cota);
 display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.rl .body p{margin:0 0 6px;font-size:12.5px}
.rl .body p:last-child{margin:0}
.rl .lbl{color:var(--cota);font:500 9px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;
 margin-right:6px}
.fired{color:var(--alta)} .quiet{color:var(--cota)}
.blind{margin-top:34px;border-top:2px solid var(--tinta);padding-top:16px}
h2.sh{font:500 15px/1.2 var(--disp);margin:0 0 5px}
.empty{padding:60px 22px;text-align:center;color:var(--gris);font-size:13px}
.empty b{display:block;font:500 15px/1.3 var(--disp);color:var(--tinta);margin-bottom:6px}
.hide{display:none!important}
@media(max-width:900px){
 main{flex-direction:column}
 .list{flex:0 0 auto;max-height:45vh;border-right:0;border-bottom:1px solid var(--tinta)}
 .detail{flex:1 1 auto}
 .rl{grid-template-columns:1fr;gap:9px}
 .claim{margin-left:0;width:100%;border-top:1px solid var(--reticula)}
 .claim .cell:first-child{padding-left:0;border-left:0}
}
</style>

<header id="hdr">
 <div class="title">
  <h1>Space IDS</h1>
  <span class="chain">FlatSat &rarr; <b>sensor</b> &rarr; PWNSAT-C3</span>
  <span class="live"><span class="dot beat"></span><span id="livetxt">live</span></span>
 </div>
 <p class="purpose">Every frame between the board and the ground console crosses this
 process, in <b>both directions</b>, and is classified before it is passed on unchanged.
 Detect-only: the attack lands, and you watch it land.</p>
 <div class="bar">
  <div class="cell"><div class="k">Mode</div><div class="v" id="mode">&mdash;</div></div>
  <div class="cell"><div class="k">Board</div><div class="v sm" id="board">&mdash;</div></div>
  <div class="cell"><div class="k">Uptime</div><div class="v" id="up">&mdash;</div></div>
  <div class="cell"><div class="k">C3 links</div><div class="v" id="clients">0</div></div>
  <div class="cell"><div class="k">Telemetry</div><div class="v" id="tm">0</div></div>
  <div class="cell"><div class="k">Commands</div><div class="v" id="tc">0</div></div>
  <div class="cell"><div class="k">Board events</div><div class="v" id="ev">0</div></div>
  <div class="claim">
   <div class="cell"><div class="k">Clean traffic raises nothing</div>
    <div class="v" id="claim1">&mdash;</div></div>
   <div class="cell"><div class="k">Identifiers say where they come from</div>
    <div class="v" id="claim2">&mdash;</div></div>
  </div>
 </div>
 <nav>
  <button id="tab-alerts" aria-selected="true">Alerts <span class="count" id="nal">0</span></button>
  <button id="tab-rules" aria-selected="false">What this sensor watches for <span class="count" id="nru">0</span></button>
 </nav>
</header>

<div id="view-alerts">
<div class="tools">
 <button class="sev critical" id="f-critical" aria-pressed="false"><span>critical</span> <b>0</b></button>
 <button class="sev high" id="f-high" aria-pressed="false"><span>high</span> <b>0</b></button>
 <button class="sev medium" id="f-medium" aria-pressed="false"><span>medium</span> <b>0</b></button>
 <select id="f-dir">
  <option value="">both directions</option>
  <option value="up">uplink — what the operator sent</option>
  <option value="down">downlink — what the board said</option>
 </select>
 <select id="f-rule"><option value="">every rule</option></select>
 <input type="search" id="f-q" placeholder="filter text, APID, identifier">
 <div class="right">
  <button class="btn" id="pause" aria-pressed="false">Pause</button>
  <button class="btn" id="clear">Clear filters</button>
 </div>
</div>
<div class="tlwrap"><span class="k">Last 90 s</span><div class="tl" id="tl"></div></div>
<main>
 <div class="list">
  <table><thead><tr>
   <th style="width:68px">Time</th><th style="width:78px">Severity</th>
   <th style="width:40px">Dir</th><th style="width:172px">Rule</th><th>What fired</th>
  </tr></thead><tbody id="rows"></tbody></table>
  <p class="empty" id="empty"><b>Nothing has fired.</b>
   Clean traffic raises nothing, which is the property this set is built around
   and the one that is easiest to lose. The rules are armed, and the second tab
   lists every one of them.</p>
 </div>
 <div class="detail" id="detail"><div class="pad"><p class="empty" style="padding:40px 0">
  Select an alert to see the frame that raised it, why it matters and how the fault is fixed.
 </p></div></div>
</main>
</div>

<div id="view-rules" class="inv hide"><div class="pad">
 <p class="lead">These are every rule in the set, armed right now, whether or not anything
 has fired. <b>An empty alert list means one of two things</b>: nothing is wrong, or
 nothing is watching. They look identical on a blank screen, so the inventory stays on the
 page permanently. Each rule answers an attack that is run in this course, and each
 one has a capture that proves it fires.</p>
 <div id="rulelist"></div>
 <div class="blind">
  <h2 class="sh">What this sensor does not catch</h2>
  <p class="lead">Two attacks on the syllabus produce no usable detection. They are on the page
  rather than left out: a detection set that lists only its wins teaches students to trust
  a quiet screen.</p>
  <div id="blindlist"></div>
 </div>
</div></div>

<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
/* The prose names fields, files and flags in backticks. Escape first, then let
   those read as code: `payload_total - 2` is not a sentence, and setting it as
   one is how a technical explanation stops being readable. */
const fmt=s=>esc(s).replace(/`([^`]+)`/g,'<code>$1</code>');
const SEV=['critical','high','medium'];
const S={alerts:[],since:0,rules:{},inv:[],sel:null,paused:false,tab:'alerts',
         f:{sev:new Set(),dir:'',rule:'',q:''},started:0,frames:0};

/* ---------- boot: the inventory, fetched once ---------- */
async function boot(){
 const r=await (await fetch('api/rules')).json();
 S.inv=r.rules; r.rules.forEach(x=>S.rules[x.rule]=x);
 $('nru').textContent=r.rules.length;
 $('rulelist').innerHTML=r.rules.map(x=>`<div class="rl" data-rule="${esc(x.rule)}">
   <div><div class="meta"><span class="pill ${x.severity}">${esc(x.severity)}</span>
     <span>${x.ids.map(esc).join(' / ')}${x.taxonomy==='local'?'*':''}</span></div>
    <h3>${esc(x.label)}</h3>
    <div class="meta"><code>${esc(x.rule)}</code></div>
    <div class="meta" style="margin-top:5px"><span class="quiet" data-fired="${esc(x.rule)}">not fired yet</span></div>
    ${x.lab?`<div class="meta" style="margin-top:5px">${esc(x.lab)}</div>`:''}</div>
   <div class="body">
    <p><span class="lbl">Fires on</span>${fmt(x.means)}</p>
    <p><span class="lbl">Why</span>${fmt(x.why)}</p>
    <p><span class="lbl" style="color:var(--defensa)">Fix</span>${fmt(x.fix)}
     ${x.where?`<span class="where">${esc(x.where)}</span>`:''}</p>
   </div></div>`).join('');
 $('blindlist').innerHTML=r.blind_spots.map(b=>`<div class="rl">
   <div><div class="meta"><span class="pill medium">no detection</span></div>
    <h3>${esc(b.attack)}</h3><div class="meta">${esc(b.lab)}</div></div>
   <div class="body"><p><span class="lbl">Why nothing fires</span>${fmt(b.why)}</p>
    <p><span class="lbl" style="color:var(--defensa)">What covers it instead</span>${fmt(b.fix)}</p>
   </div></div>`).join('');
 const sel=$('f-rule');
 r.rules.forEach(x=>{const o=document.createElement('option');o.value=x.rule;o.textContent=x.rule;sel.appendChild(o);});
}

/* ---------- poll ---------- */
async function tick(){
 try{
  const s=await (await fetch('api/state?since='+S.since)).json();
  S.since=s.cursor; S.started=s.started;
  S.frames=s.tm+s.tc+s.events;
  $('mode').textContent=s.mode; $('board').textContent=s.board;
  $('clients').textContent=s.clients; $('tm').textContent=s.tm;
  $('tc').textContent=s.tc; $('ev').textContent=s.events;
  for(const sv of SEV) $('f-'+sv).querySelector('b').textContent=s.counts[sv]||0;
  $('nal').textContent=s.total;
  const live=S.frames>0;
  $('claim1').innerHTML = s.total===0
   ? (live?'<span class="ok">holding</span>':'<span class="quiet">no traffic yet</span>')
   : `<span class="warn">${s.total}</span> on ${S.frames} frames`;
  $('claim2').innerHTML=`<span>${s.n_sparta} SPARTA</span> &middot; <span>${s.n_local} ours</span>`;
  if(s.alerts.length){
   const first = S.alerts.length===0;
   s.alerts.forEach(a=>{a._new=true;S.alerts.push(a);});
   if(S.alerts.length>2000) S.alerts.splice(0,S.alerts.length-2000);
   render();
   // Open on the newest alert the first time something arrives, so nobody has
   // to discover that the rows are clickable.
   if(first) select(S.alerts[S.alerts.length-1].n);
  }
  $('up').textContent=hms(Date.now()/1000-s.started);
 }catch(e){ $('livetxt').textContent='sensor unreachable'; document.body.classList.add('paused'); return; }
 document.body.classList.toggle('paused',S.paused);
 $('livetxt').textContent=S.paused?'paused':'live';
}
const hms=t=>{t=Math.max(0,Math.floor(t));
 return String(Math.floor(t/3600)).padStart(2,'0')+':'+String(Math.floor(t/60)%60).padStart(2,'0')+':'+String(t%60).padStart(2,'0');};
const clock=ts=>{const d=new Date(ts*1000);
 return String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0')+':'+String(d.getSeconds()).padStart(2,'0');};

/* ---------- list ---------- */
function visible(){
 const f=S.f, q=f.q.toLowerCase();
 return S.alerts.filter(a=>{
  if(f.sev.size && !f.sev.has(a.severity)) return false;
  if(f.dir && a.direction!==f.dir) return false;
  if(f.rule && a.rule!==f.rule) return false;
  if(q && !(a.rule+' '+a.detail+' '+a.id+' '+a.label+' '+JSON.stringify(a.evidence||{})).toLowerCase().includes(q)) return false;
  return true;
 });
}
const ARROW={up:'&uarr; up',down:'&darr; down',capture:'&mdash;'};
function render(){
 const v=visible().slice().reverse();
 $('empty').style.display=v.length?'none':'block';
 $('rows').innerHTML=v.slice(0,400).map(a=>`<tr data-n="${a.n}" aria-selected="${S.sel===a.n}"
   class="${a._new?'fresh':''}">
   <td class="t">${clock(a.ts)}</td>
   <td><span class="pill ${a.severity}">${esc(a.severity)}</span></td>
   <td class="arrow">${ARROW[a.direction]||''}</td>
   <td class="r"><code>${esc(a.rule)}</code></td>
   <td class="d">${esc(a.detail)}</td></tr>`).join('');
 S.alerts.forEach(a=>a._new=false);
 // the inventory marks what has fired
 const by={}; S.alerts.forEach(a=>by[a.rule]=(by[a.rule]||0)+1);
 document.querySelectorAll('[data-fired]').forEach(el=>{
  const n=by[el.dataset.fired]||0;
  el.className=n?'fired':'quiet';
  el.textContent=n?(n+(n===1?' alert this run':' alerts this run')):'not fired yet';
 });
 drawTimeline();
}

/* ---------- timeline: 90 one-second buckets ---------- */
function drawTimeline(){
 const N=90, now=Date.now()/1000, b=new Array(N).fill(0);
 const rank={medium:1,high:2,critical:3};
 S.alerts.forEach(a=>{const i=N-1-Math.floor(now-a.ts); if(i>=0&&i<N) b[i]=Math.max(b[i],rank[a.severity]||1);});
 const cls=['','m','h','c'];
 $('tl').innerHTML=b.map(x=>`<i class="${cls[x]}" style="height:${x?8+x*9:2}px"></i>`).join('');
}

/* ---------- detail ---------- */
function hexdump(hex){
 const trunc=hex.endsWith('...'); if(trunc) hex=hex.slice(0,-3);
 const by=[]; for(let i=0;i<hex.length;i+=2) by.push(parseInt(hex.substr(i,2),16));
 if(!by.length) return '';
 const out=[];
 for(let i=0;i<by.length;i+=16){
  const c=by.slice(i,i+16);
  const cells=c.map((x,j)=>{const h=x.toString(16).padStart(2,'0');
    return (i+j)<6?`<span class="hdr">${h}</span>`:h;});
  while(cells.length<16) cells.push('  ');
  const txt=c.map(x=>(x>=32&&x<127)?esc(String.fromCharCode(x)):'.').join('');
  out.push(i.toString(16).padStart(4,'0')+'  '+cells.join(' ')+'  |'+txt+'|');
 }
 if(trunc) out.push('      ... truncated; the sensor keeps the first 48 octets with the alert');
 return out.join('\n');
}
function select(n){
 S.sel=n; const a=S.alerts.find(x=>x.n===n); if(!a) return;
 const k=S.rules[a.rule]||{};
 const ev=a.evidence||{};
 const rows=Object.keys(ev).map(key=>
   `<dt>${esc(key)}</dt><dd>${esc(typeof ev[key]==='boolean'?(ev[key]?'yes':'no'):ev[key])}</dd>`).join('');
 const dump=hexdump(a.raw||'');
 $('detail').innerHTML=`<div class="pad">
  <div class="dh">
   <span class="pill ${a.severity}">${esc(a.severity)}</span>
   <h2>${esc(a.label)}</h2>
   <div class="rule"><code>${esc(a.rule)}</code> &middot; frame ${a.frame}
    &middot; ${esc(a.direction==='up'?'uplink, sent by the operator':a.direction==='down'?'downlink, from the board':'capture')}
    &middot; ${clock(a.ts)}</div>
  </div>

  <div class="sec atk"><span class="k">What the sensor saw</span>
   <p>${fmt(a.detail)}.${k.means?' '+fmt(k.means):''}</p>
   ${rows?`<dl class="grid">${rows}</dl>`:''}
  </div>

  ${dump?`<div class="sec"><span class="k">The frame that raised it</span>
   <pre>${dump}</pre>
   <p style="font-size:11.5px;color:var(--gris);margin-top:7px">The first six octets, in
   amber, are the CCSDS primary header: version, type, secondary-header flag and APID,
   then sequence flags and count, then DATA LENGTH, which is octets minus one.</p></div>`
  :`<div class="sec"><span class="k">The frame that raised it</span>
   <p style="color:var(--gris)">This alert came from the board's own event channel
   (APID 0x20), which reports facts about a frame and carries no payload bytes. The table
   above is everything the board said about it.</p></div>`}

  ${k.why?`<div class="sec atk"><span class="k">Why it matters</span><p>${fmt(k.why)}</p></div>`:''}
  ${k.fix?`<div class="sec def"><span class="k">How the fault is fixed</span><p>${fmt(k.fix)}</p>
   ${k.where?`<span class="where">${esc(k.where)}</span>`:''}</div>`:''}

  <div class="prov">
   <code>${esc(a.id)}</code> &middot; ${esc(k.label||a.label)}.
   ${a.taxonomy==='SPARTA'
     ? 'A SPARTA technique identifier. The identifier is SPARTA’s; mapping this observation to it is this project’s analysis, not an Aerospace Corporation classification.'
     : 'No SPARTA technique describes this one, so the identifier is this project’s own and is marked as such.'}
   ${k.lab?`<br><br>Lab ${esc(k.lab)}`:''}
  </div>
 </div>`;
 document.querySelectorAll('#rows tr').forEach(tr=>tr.setAttribute('aria-selected',tr.dataset.n==n));
}

/* ---------- wiring ---------- */
$('rows').addEventListener('click',e=>{const tr=e.target.closest('tr'); if(tr) select(+tr.dataset.n);});
SEV.forEach(sv=>$('f-'+sv).addEventListener('click',()=>{
 const b=$('f-'+sv), on=b.getAttribute('aria-pressed')==='true';
 b.setAttribute('aria-pressed',!on); on?S.f.sev.delete(sv):S.f.sev.add(sv); render();}));
$('f-dir').addEventListener('change',e=>{S.f.dir=e.target.value;render();});
$('f-rule').addEventListener('change',e=>{S.f.rule=e.target.value;render();});
$('f-q').addEventListener('input',e=>{S.f.q=e.target.value;render();});
$('clear').addEventListener('click',()=>{
 S.f={sev:new Set(),dir:'',rule:'',q:''};
 SEV.forEach(sv=>$('f-'+sv).setAttribute('aria-pressed','false'));
 $('f-dir').value='';$('f-rule').value='';$('f-q').value='';render();});
$('pause').addEventListener('click',()=>{
 S.paused=!S.paused; $('pause').setAttribute('aria-pressed',S.paused);
 $('pause').textContent=S.paused?'Resume':'Pause';});
function tab(which){
 S.tab=which;
 $('tab-alerts').setAttribute('aria-selected',which==='alerts');
 $('tab-rules').setAttribute('aria-selected',which==='rules');
 $('view-alerts').classList.toggle('hide',which!=='alerts');
 $('view-rules').classList.toggle('hide',which!=='rules');
}
$('tab-alerts').addEventListener('click',()=>tab('alerts'));
$('tab-rules').addEventListener('click',()=>tab('rules'));

boot().then(()=>{tick(); setInterval(()=>{if(!S.paused) tick();},1000); setInterval(drawTimeline,1000);});
</script>
</html>'''


class ConsoleState:
    """What the page reads. Alerts are numbered so the browser can ask for
    only what it has not seen: a ten-attack pass produces a few hundred, and
    re-sending all of them every second turns a localhost poll into a packet
    capture."""

    def __init__(self, keep: int = 2000):
        self.alerts: deque[dict] = deque(maxlen=keep)
        self.sensor = None
        self.board_name = "—"
        self.started = time.time()
        self._n = 0
        self._counts = {"critical": 0, "high": 0, "medium": 0}
        self._taxonomy = {"SPARTA": 0, "local": 0}
        self._lock = threading.Lock()

    def add(self, d: Detection) -> None:
        with self._lock:
            row = d.as_dict()
            self._n += 1
            row["n"] = self._n
            self.alerts.append(row)
            self._counts[d.severity] = self._counts.get(d.severity, 0) + 1
            self._taxonomy[d.taxonomy] = self._taxonomy.get(d.taxonomy, 0) + 1

    def snapshot(self, since: int = 0) -> dict:
        with self._lock:
            s = self.sensor
            new = [a for a in self.alerts if a["n"] > since] if since else list(self.alerts)
            return {
                "mode": s.mode if s else "—",
                "board": self.board_name,
                "clients": s.downstream.client_count if s else 0,
                "tm": s.stats.tm_frames if s else 0,
                "tc": s.stats.tc_frames if s else 0,
                "events": s.stats.events if s else 0,
                "dropped": s.stats.dropped if s else 0,
                "started": self.started,
                "cursor": self._n,
                "total": self._n,
                "counts": dict(self._counts),
                "n_sparta": self._taxonomy.get("SPARTA", 0),
                "n_local": self._taxonomy.get("local", 0),
                "alerts": new,
            }


def serve(state: ConsoleState, host: str = "127.0.0.1", port: int = 5011):
    rules_body = json.dumps({"rules": inventory(), "blind_spots": BLIND_SPOTS}).encode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):      # quiet; the sensor owns stdout
            pass

        def do_GET(self):
            u = urlparse(self.path)
            path = u.path.rstrip("/")
            if path.endswith("api/state"):
                since = parse_qs(u.query).get("since", ["0"])[0]
                try:
                    since_n = int(since)
                except ValueError:
                    since_n = 0
                body = json.dumps(state.snapshot(since_n)).encode()
                ctype = "application/json"
            elif path.endswith("api/rules"):
                body, ctype = rules_body, "application/json"
            else:
                body = PAGE.encode()
                ctype = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    class Server(ThreadingHTTPServer):
        # Without this, each request handler is a non-daemon thread and the
        # process refuses to exit after Ctrl-C.
        daemon_threads = True
        allow_reuse_address = True

    srv = Server((host, port), Handler)
    threading.Thread(target=srv.serve_forever, name="ids-console", daemon=True).start()
    return srv
