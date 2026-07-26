#!/usr/bin/env python3
"""gen_interactive.py — build interactive_v2.html with the authoritative JSON EMBEDDED.

Directive §23: the interactive page must not contain hand-written sample arrays. Every value it
plots is read from the embedded copy of authoritative_results.json, which is itself computed from
the four shipped pcaps.
"""
import argparse
import json
import os

PAGE = """<title>DNP3 timing normalizer — Defense 2, live inline (corrected)</title>
<style>
  :root{
    --ground:#F5F6F8;--panel:#fff;--panel2:#EDF0F4;--ink:#16202b;--muted:#5c6b7a;--rule:#d5dce5;
    --accent:#1e5f9e;--hold:#b87514;--norm:#1f7a6b;--bad:#a8324a;
    --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    --serif:"Iowan Old Style",Georgia,"Times New Roman",serif;}
  @media (prefers-color-scheme:dark){:root{--ground:#0f141a;--panel:#161d25;--panel2:#1d2630;
    --ink:#e4eaf1;--muted:#8b9aaa;--rule:#26313d;--accent:#5aa6e8;--hold:#e0a448;--norm:#4fbfa9;--bad:#e0697f;}}
  :root[data-theme="dark"]{--ground:#0f141a;--panel:#161d25;--panel2:#1d2630;--ink:#e4eaf1;
    --muted:#8b9aaa;--rule:#26313d;--accent:#5aa6e8;--hold:#e0a448;--norm:#4fbfa9;--bad:#e0697f;}
  :root[data-theme="light"]{--ground:#F5F6F8;--panel:#fff;--panel2:#EDF0F4;--ink:#16202b;
    --muted:#5c6b7a;--rule:#d5dce5;--accent:#1e5f9e;--hold:#b87514;--norm:#1f7a6b;--bad:#a8324a;}
  *{box-sizing:border-box}
  body{background:var(--ground);color:var(--ink);font-family:var(--serif);line-height:1.6;margin:0}
  .wrap{max-width:74ch;margin:0 auto;padding:0 1.3rem 4rem}
  h1,h2,.lbl,code,table,button,select{font-family:var(--mono)}
  h1{font-size:clamp(1.5rem,4vw,2.2rem);line-height:1.15;letter-spacing:-.02em;margin:0 0 .5rem}
  h2{font-size:1.1rem;margin:2.2rem 0 .5rem}
  .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:.15em;color:var(--muted);display:block;margin-bottom:.5rem}
  header{border-bottom:1px solid var(--rule);padding:2.5rem 0 1.5rem;margin-bottom:1.5rem}
  .thesis{color:var(--muted);max-width:58ch}
  .panel{background:var(--panel);border:1px solid var(--rule);border-radius:3px;padding:1.1rem;margin:1.3rem 0}
  canvas{display:block;width:100%;height:auto}
  .ctl{display:flex;gap:1rem;align-items:center;flex-wrap:wrap;margin-bottom:.8rem}
  select,button{background:var(--panel2);color:var(--ink);border:1px solid var(--rule);
    border-radius:2px;padding:.35rem .7rem;font-size:.8rem;cursor:pointer}
  .readout{font-family:var(--mono);font-size:.8rem;display:flex;gap:1.2rem;flex-wrap:wrap;margin-top:.7rem}
  .readout b{font-weight:650}
  .ok{color:var(--norm)}.warn{color:var(--hold)}.bad{color:var(--bad)}
  table{border-collapse:collapse;width:100%;font-size:.78rem;font-variant-numeric:tabular-nums}
  th,td{text-align:right;padding:.35rem .5rem;border-bottom:1px solid var(--rule);white-space:nowrap}
  th:first-child,td:first-child{text-align:left}
  thead th{font-size:.66rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
  .scroll{overflow-x:auto}
  .note{border-left:2px solid var(--accent);padding-left:1rem;color:var(--muted);margin:1.2rem 0}
  .note.warn{border-left-color:var(--bad)}
  footer{border-top:1px solid var(--rule);margin-top:3rem;padding-top:1rem;font-family:var(--mono);
    font-size:.72rem;color:var(--muted)}
</style>

<div class="wrap">
<header>
  <span class="lbl">Tofino-1 &middot; Defense 2 &middot; physical SEL-751 &middot; corrected</span>
  <h1>Holding the DNP3 response until an ACK-relative deadline</h1>
  <p class="thesis">Every number on this page is read from the embedded
  <code>authoritative_results.json</code>, which is computed from the four shipped pcaps. Nothing is
  typed in by hand.</p>
</header>

<h2>1. The two campaigns, both shipped</h2>
<div class="panel">
  <div class="ctl">
    <label class="lbl" style="margin:0">campaign</label>
    <select id="camp"><option value="A">A</option><option value="B">B</option></select>
    <label class="lbl" style="margin:0">variant</label>
    <select id="variant">
      <option value="all_state">all-state (includes the connection-cold first transaction)</option>
      <option value="steady_state">steady-state (cold transaction excluded)</option>
    </select>
  </div>
  <canvas id="cv" width="900" height="210" role="img"
    aria-label="Native and protected CLRT observations for the selected campaign"></canvas>
  <div class="readout">
    <span>native sd <b id="ns"></b></span>
    <span>protected sd <b id="ps"></b></span>
    <span>ratio <b id="rt"></b></span>
    <span id="coldnote" class="warn"></span>
  </div>
</div>
<div class="note">Both variants are reported. The all-state variance is strongly influenced by the
first transaction of each capture; the steady-state distribution also shows substantial
normalization. Neither is "the" corrected result.</div>

<h2>2. Entropy depends on the observer's resolution</h2>
<div class="panel">
  <div class="ctl">
    <label class="lbl" style="margin:0">bin width</label>
    <select id="res"></select>
    <span class="readout"><span>bins half-open [lo, hi), origin 0.0 ms</span></span>
  </div>
  <div class="scroll"><table id="enttab"><thead><tr>
    <th>campaign</th><th>treatment</th><th>occupied bins</th><th>entropy (bits)</th><th>n</th>
  </tr></thead><tbody></tbody></table></div>
</div>
<div class="note warn">At 1&nbsp;ms bins campaign B protected occupies one bin and measures
0&nbsp;bits, while campaign A protected occupies two and does not &mdash; its minimum falls on the
other side of the bin edge. An unqualified "entropy is zero" is therefore not a supportable claim
about this defense.</div>

<h2>3. What the implementation does</h2>
<div class="panel" style="font-family:var(--mono);font-size:.8rem;line-height:1.9">
  1. READ forwarded to the relay<br>
  2. relay's pure TCP ACK <b>forwarded immediately</b>, arrival stamped<br>
  3. deadline armed at <code>t_ack + G</code><br>
  4. relay's DNP3 RESPONSE <b>held queue-resident</b> on a low-priority TM queue (dp8)<br>
  5. high-priority <b>blocker reservoir</b> denies that queue service &mdash; blockers loop, the response does not<br>
  6. blockers compare now vs deadline and terminate once past it<br>
  7. queue becomes eligible, the original response leaves
</div>
<div class="note">The blockers are <b>seeded by the host</b> and then circulate internally. The
release decision is data-plane controlled, with no controller action in the transaction fast path.
This is not a claim of fully internal blocker generation.</div>

<h2>4. Limits</h2>
<div class="note warn">One SEL-751, read-only DNP3 only. CLRT-magnitude channel only. No anonymity
claim: ACK mode, response size and TCP-stack characteristics are untouched. No size-obfuscation
claim. Live byte identity is not independently proven &mdash; the relay leg cannot be tapped, so the
same frame cannot be compared before and after holding.</div>

<footer id="foot"></footer>
</div>

<script id="authoritative" type="application/json">__JSON__</script>
<script>
(function(){
  "use strict";
  var D = JSON.parse(document.getElementById("authoritative").textContent);
  var css = function(n){ return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); };
  function ser(c,t){ return D.series.filter(function(s){return s.campaign===c&&s.treatment===t;})[0]; }
  function cmp(c){ return D.comparisons.filter(function(x){return x.campaign===c;})[0]; }

  function draw(){
    var c=document.getElementById("camp").value, v=document.getElementById("variant").value;
    var cv=document.getElementById("cv"), r=cv.getBoundingClientRect(), dpr=window.devicePixelRatio||1;
    cv.width=Math.max(320,Math.round(r.width*dpr)); cv.height=Math.round(210*dpr);
    var x=cv.getContext("2d"); x.setTransform(dpr,0,0,dpr,0,0);
    var W=cv.width/dpr,H=cv.height/dpr,pad=40,base=H-34,maxMs=40;
    x.clearRect(0,0,W,H);
    var X=function(ms){return pad+(ms/maxMs)*(W-pad-16);};
    x.strokeStyle=css("--rule"); x.beginPath(); x.moveTo(pad,base+.5); x.lineTo(W-12,base+.5); x.stroke();
    x.font="11px "+css("--mono"); x.fillStyle=css("--muted"); x.textAlign="center";
    for(var t=0;t<=maxMs;t+=10) x.fillText(t+(t===maxMs?" ms":""),X(t),base+16);
    [["native",1,css("--accent")],["protected",0,css("--norm")]].forEach(function(row){
      var s=ser(c,row[0]); if(!s) return;
      var vals=s.clrt_values_all_state_ms.slice(v==="steady_state"?1:0);
      var y=base-30-row[1]*52;
      x.fillStyle=css("--muted"); x.textAlign="left"; x.font="11px "+css("--mono");
      x.fillText(row[0]+"  n="+vals.length,pad,y-16);
      vals.forEach(function(val,i){
        var isCold=(v!=="steady_state" && i===0 && row[0]==="native");
        x.beginPath(); x.arc(X(val),y,6,0,Math.PI*2);
        x.fillStyle=isCold?css("--bad"):row[2]; x.globalAlpha=isCold?.95:.6; x.fill(); x.globalAlpha=1;
      });
    });
    var k=cmp(c)[v];
    document.getElementById("ns").textContent=k.native_sd_pop.toFixed(3)+" ms";
    document.getElementById("ps").textContent=k.protected_sd_pop.toFixed(3)+" ms";
    document.getElementById("rt").textContent=k.sd_ratio.toFixed(1)+"x";
    var cold=ser(c,"native").connection_cold_transaction.clrt_ms;
    document.getElementById("coldnote").textContent =
      (v==="all_state") ? ("includes the connection-cold first transaction, "+cold.toFixed(3)+" ms")
                        : ("connection-cold transaction ("+cold.toFixed(3)+" ms) excluded");
  }

  function fillRes(){
    var sel=document.getElementById("res");
    ser("A","native").all_state.entropy.forEach(function(e){
      var o=document.createElement("option");
      o.value=String(e.bin_width_ms);
      o.textContent=(e.bin_width_ms>=1? e.bin_width_ms+" ms" : Math.round(e.bin_width_ms*1000)+" \\u00b5s");
      sel.appendChild(o);
    });
    sel.value="1";
  }
  function drawEnt(){
    var w=parseFloat(document.getElementById("res").value);
    var tb=document.querySelector("#enttab tbody"); tb.innerHTML="";
    D.series.forEach(function(s){
      var e=s.all_state.entropy.filter(function(z){return z.bin_width_ms===w;})[0];
      var tr=document.createElement("tr");
      tr.innerHTML="<td>"+s.campaign+"</td><td>"+s.treatment+"</td><td>"+e.occupied_bins+
                   "</td><td>"+e.entropy_bits.toFixed(4)+"</td><td>"+e.n+"</td>";
      tb.appendChild(tr);
    });
  }
  function foot(){
    document.getElementById("foot").textContent =
      "CLRT = " + D.clrt_definition + "  |  primary source: " + D.clrt_primary_source +
      "  |  DNP3 link addresses: master " + D.dnp3_link_addresses.master +
      ", outstation " + D.dnp3_link_addresses.outstation;
  }
  function init(){
    fillRes(); drawEnt(); draw(); foot();
    document.getElementById("camp").addEventListener("change",draw);
    document.getElementById("variant").addEventListener("change",draw);
    document.getElementById("res").addEventListener("change",drawEnt);
    var rt; window.addEventListener("resize",function(){clearTimeout(rt);rt=setTimeout(draw,120);});
    new MutationObserver(draw).observe(document.documentElement,{attributes:true,attributeFilter:["data-theme"]});
    if(window.matchMedia){var mq=window.matchMedia("(prefers-color-scheme: dark)");
      if(mq.addEventListener) mq.addEventListener("change",draw);}
  }
  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded",init); else init();
})();
</script>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    data = json.load(open(a.json))
    # keep the page small: drop the per-bin histograms, keep everything the page reads
    for s in data["series"]:
        for var in ("all_state", "steady_state"):
            for e in s[var]["entropy"]:
                e.pop("bins", None)
    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    open(a.out, "w").write(PAGE.replace("__JSON__", blob))
    print("wrote %s (%d bytes)" % (a.out, os.path.getsize(a.out)))


if __name__ == "__main__":
    main()
