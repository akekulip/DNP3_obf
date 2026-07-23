#!/usr/bin/env python3
"""Assemble the holistic project report HTML with base64-embedded plots."""
import base64, os

EXP = "/home/philip/Projects/DNP3/research/physical_sel751/clrt_300poll_20260723T152242"
PLOTS = {
    "hist": f"{EXP}/plots/clrt_histogram.png",
    "ecdf": f"{EXP}/plots/clrt_ecdf.png",
    "box":  f"{EXP}/plots/clrt_box_violin.png",
    "ts":   f"{EXP}/plots/clrt_timeseries.png",
    "acf":  f"{EXP}/validation/plots/acf_all_series.png",
    "roll": f"{EXP}/validation/plots/clrt_rolling.png",
    "trend":f"{EXP}/validation/plots/clrt_trend.png",
}
def datauri(p):
    return "data:image/png;base64," + base64.b64encode(open(p, "rb").read()).decode()
IMG = {k: datauri(v) for k, v in PLOTS.items()}

HTML = r"""<title>DNP3 Traffic Obfuscation on a Programmable Switch — an End-to-End Account</title>
<style>
:root{
  --paper:#f6f4ee; --panel:#fffdf8; --panel2:#efece3; --ink:#1c2321; --ink-soft:#4c5854; --ink-faint:#7c8783;
  --line:#ddd8cc; --line-strong:#c7c1b2; --accent:#0e7c86; --accent-ink:#0a5960; --accent-soft:#dcecee;
  --gold:#9a7b1f; --done:#2c8a58; --caution:#b0761c; --gate:#b0432c; --gate-soft:#f3ddd6;
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,"Times New Roman",serif;
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){:root{
  --paper:#0f1413; --panel:#151d1c; --panel2:#101817; --ink:#e9efec; --ink-soft:#9fb0ab; --ink-faint:#6d7c78;
  --line:#26312e; --line-strong:#37433f; --accent:#37bcc6; --accent-ink:#7fd6dd; --accent-soft:#0f2f31;
  --gold:#cca544; --done:#43b878; --caution:#d6a441; --gate:#db6b50; --gate-soft:#2c1712;
}}
:root[data-theme="light"]{--paper:#f6f4ee;--panel:#fffdf8;--panel2:#efece3;--ink:#1c2321;--ink-soft:#4c5854;--ink-faint:#7c8783;--line:#ddd8cc;--line-strong:#c7c1b2;--accent:#0e7c86;--accent-ink:#0a5960;--accent-soft:#dcecee;--gold:#9a7b1f;--done:#2c8a58;--caution:#b0761c;--gate:#b0432c;--gate-soft:#f3ddd6;}
:root[data-theme="dark"]{--paper:#0f1413;--panel:#151d1c;--panel2:#101817;--ink:#e9efec;--ink-soft:#9fb0ab;--ink-faint:#6d7c78;--line:#26312e;--line-strong:#37433f;--accent:#37bcc6;--accent-ink:#7fd6dd;--accent-soft:#0f2f31;--gold:#cca544;--done:#43b878;--caution:#d6a441;--gate:#db6b50;--gate-soft:#2c1712;}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);line-height:1.62;font-size:16.5px;-webkit-font-smoothing:antialiased}
.wrap{max-width:900px;margin:0 auto;padding:44px 22px 90px}
h1,h2,h3,h4{font-family:var(--serif);line-height:1.18;letter-spacing:-.01em;text-wrap:balance}
h1{font-size:clamp(28px,4.6vw,42px);margin:0 0 8px;font-weight:700}
h2{font-size:clamp(22px,3.2vw,29px);margin:56px 0 6px;padding-top:18px;border-top:2px solid var(--ink)}
h2 .num{color:var(--accent-ink);font-family:var(--mono);font-size:.62em;font-weight:600;margin-right:.5em}
h3{font-size:20px;margin:30px 0 6px;color:var(--ink)}
h4{font-size:16.5px;margin:22px 0 4px;font-family:var(--sans);font-weight:700}
p{margin:12px 0}
a{color:var(--accent-ink);text-decoration:underline;text-underline-offset:2px}
.lede{font-size:19px;color:var(--ink-soft);font-family:var(--serif)}
.byline{font-family:var(--mono);font-size:12.5px;color:var(--ink-faint);letter-spacing:.04em;margin:14px 0 0}
code{font-family:var(--mono);font-size:.86em;background:var(--panel2);padding:1px 5px;border-radius:4px;border:1px solid var(--line)}
.mono{font-family:var(--mono)}
strong{font-weight:700}
em{color:var(--ink)}
ul,ol{margin:12px 0;padding-left:24px}
li{margin:6px 0}
.small{font-size:14px;color:var(--ink-soft)}
sup.cite{font-family:var(--mono);font-size:11px;color:var(--accent-ink);font-weight:600}
sup.cite a{text-decoration:none}

.toc{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 22px;margin:28px 0}
.toc h4{margin:0 0 8px;font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-faint)}
.toc ol{columns:2;column-gap:34px;margin:0;padding-left:18px;font-size:14.5px}
@media(max-width:620px){.toc ol{columns:1}}

.callout{border-left:3px solid var(--accent);background:linear-gradient(90deg,var(--accent-soft),transparent 82%);
  padding:12px 16px;border-radius:0 10px 10px 0;margin:18px 0}
.callout.ex{border-left-color:var(--gold);background:linear-gradient(90deg,color-mix(in srgb,var(--gold) 16%,transparent),transparent 82%)}
.callout.warn{border-left-color:var(--gate);background:linear-gradient(90deg,var(--gate-soft),transparent 82%)}
.callout .lab{font-family:var(--mono);font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;font-weight:700;color:var(--accent-ink);display:block;margin-bottom:4px}
.callout.ex .lab{color:var(--gold)} .callout.warn .lab{color:var(--gate)}
.callout p{margin:6px 0} .callout p:first-of-type{margin-top:0} .callout p:last-child{margin-bottom:0}

figure{margin:26px 0;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 16px 8px;overflow:hidden}
figure img{width:100%;height:auto;border-radius:6px;display:block;background:#fff}
figcaption{font-size:13.5px;color:var(--ink-soft);margin:10px 2px 6px;line-height:1.5}
figcaption b{color:var(--ink)}
.figtag{font-family:var(--mono);font-size:11px;color:var(--accent-ink);font-weight:700}

pre.mermaid{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin:22px 0;overflow-x:auto;text-align:center}

.tbl{overflow-x:auto;margin:18px 0}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:8px 11px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-family:var(--mono);font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--ink-soft);font-weight:700;border-bottom:1.5px solid var(--line-strong)}
td.n,th.n{font-variant-numeric:tabular-nums;font-family:var(--mono);white-space:nowrap}
.pill{display:inline-block;font-family:var(--mono);font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:999px;white-space:nowrap}
.pill.done{background:color-mix(in srgb,var(--done) 18%,transparent);color:var(--done)}
.pill.part{background:color-mix(in srgb,var(--caution) 18%,transparent);color:var(--caution)}
.pill.no{background:var(--gate-soft);color:var(--gate)}

.filemap{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px 15px;margin:16px 0;font-family:var(--mono);font-size:12.5px;line-height:1.85}
.filemap b{color:var(--accent-ink)}
.refs{font-size:14px}
.refs li{margin:10px 0}
.refs .v{color:var(--ink-soft)}
hr.soft{border:none;border-top:1px solid var(--line);margin:34px 0}
.kbd{font-family:var(--mono);font-size:.85em;background:var(--panel2);border:1px solid var(--line-strong);border-bottom-width:2px;border-radius:4px;padding:1px 5px}
</style>

<div class="wrap">
<h1>DNP3 traffic obfuscation on a programmable switch</h1>
<p class="lede">An end-to-end account — the problem, the platform, everything we built and measured, the
challenges we hit, what we proved, and what remains open. Written to be read cold: nothing is assumed.</p>
<p class="byline">Research log &middot; DNP3 / Case-A timing &amp; size obfuscation &middot; branch research/caseA-ditto-queue &middot; 2026-07-23</p>

<div class="callout"><span class="lab">How to read this</span>
<p>Sections 1–3 are background — what the problem is and why, explained from scratch with examples.
Sections 4–7 are what we actually did and measured, with the figures. Section 8 is the honest list of
things that went wrong and what they taught us. Sections 9–10 place the work in the research literature
and state the limits. Blue call-outs are context; gold call-outs are worked examples you can follow
byte-by-byte; red call-outs are honest caveats or things that failed. Superscripts like <sup class="cite">[1]</sup>
point to the reference list; <code>monospace paths</code> point to real files in the repository.</p></div>

<div class="toc"><h4>Contents</h4>
<ol>
<li><a href="#s1">The problem: fingerprinting a relay by its timing</a></li>
<li><a href="#s2">The idea: obfuscate in the network</a></li>
<li><a href="#s3">The testbed</a></li>
<li><a href="#s4">Thread A — the size axis, proven on silicon</a></li>
<li><a href="#s5">Thread B — bringing the physical relay online</a></li>
<li><a href="#s6">The 300-poll CLRT experiment</a></li>
<li><a href="#s7">The validation pass</a></li>
<li><a href="#s8">Challenges &amp; lessons</a></li>
<li><a href="#s9">Where this sits in the literature</a></li>
<li><a href="#s10">Limitations &amp; what's next</a></li>
</ol></div>

<h2 id="s1"><span class="num">01</span> The problem: fingerprinting a relay by its timing</h2>

<p><strong>DNP3</strong> (Distributed Network Protocol 3, standardized as IEEE 1815<sup class="cite">[1]</sup>) is one
of the main languages that electric utilities use to talk to the equipment in substations. A control
center runs a <em>master</em>; out in the field sits an <em>outstation</em> — here, a
<strong>SEL-751 feeder protection relay</strong>, a real piece of hardware that protects a power line and
reports measurements. The master <em>polls</em>; the outstation <em>responds</em>. That is the whole
conversation: "tell me your status," "here it is."</p>

<div class="callout ex"><span class="lab">Example — one DNP3 poll in plain terms</span>
<p>The master sends a <strong>Class-0 read</strong>: "send me all your current static data." The relay
answers with a response carrying, in our case, <strong>69 data points</strong> (breaker states, analog
measurements, etc.). Over TCP this is: master &rarr; <code>READ</code> request, relay &rarr; a bare TCP
acknowledgement, then relay &rarr; the DNP3 <code>RESPONSE</code>. Nothing is encrypted — DNP3 as
deployed here has no confidentiality — so anyone who can see the wire sees the bytes and, crucially,
<em>the timing</em>.</p></div>

<h3>The threat: passive device fingerprinting</h3>
<p>An attacker who can passively observe substation traffic wants to know <em>what device</em> is at each
address, without ever sending a packet — reconnaissance for a later attack. Formby, Srinivasan, Leonard,
Rogers &amp; Beyah showed at NDSS 2016<sup class="cite">[2]</sup> that industrial devices can be
fingerprinted by a physical timing signature they cannot easily hide: the
<strong>Cross-Layer Response Time (CLRT)</strong> — the gap between the low-level acknowledgement of a
request and the actual application response. Different relays, running different firmware on different
hardware, take characteristically different amounts of time to think. That timing is a fingerprint.</p>

<pre class="mermaid">
sequenceDiagram
  autonumber
  participant M as Master (link addr 1)
  participant R as SEL-751 outstation (link addr 0)
  M->>R: DNP3 READ, Class-0  (t = 0)
  R-->>M: pure TCP ACK        (+0.9 ms)
  Note over R: relay assembles the response
  R->>M: DNP3 RESPONSE, 69 points (+6.1 ms after the ACK)
  Note over M,R: CLRT = time from the pure ACK to the response
</pre>

<div class="callout"><span class="lab">The key definitions, once</span>
<p><strong>Separate ACK (our "Case A"):</strong> the relay first sends a bare TCP acknowledgement (no DNP3
payload), and only later sends the DNP3 response. The gap between them is the CLRT. The SEL-751 does
this. <strong>Combined ACK (Case B):</strong> other devices (an AB1400, an ION7550) piggy-back the
acknowledgement onto the response — there is no standalone ACK, so no CLRT to measure. Case A is the
whole game here because it is the case that <em>leaks</em> a CLRT fingerprint.</p></div>

<p>There are actually <strong>two</strong> passive leakage channels, and this project attacks both:</p>
<ul>
<li><strong>Timing</strong> — the CLRT (and the surrounding inter-packet gaps). This is the Formby
fingerprint.</li>
<li><strong>Size</strong> — how big responses are and how they are segmented. A device that always answers
with a 134-byte frame looks different from one that answers with 37 bytes.</li>
</ul>

<h2 id="s2"><span class="num">02</span> The idea: obfuscate in the network</h2>

<p>The defence is to make the outstation's traffic <em>look the same regardless of which device it is</em>
— normalize the size, and normalize/reshape the timing — <strong>without changing the relay, the master,
or the DNP3 bytes' meaning.</strong> The natural place to do that is a device in the middle: a
<strong>programmable switch</strong>.</p>

<h3>What a programmable switch is (P4 and Tofino), plainly</h3>
<p>An ordinary switch has fixed behaviour baked into silicon. A <strong>programmable</strong> switch lets
you write the packet-processing logic yourself, in a language called <strong>P4</strong><sup class="cite">[3]</sup>,
and compile it onto a high-speed chip. The chip we use is an <strong>Intel Tofino-1</strong>, whose
architecture (a reconfigurable match-action pipeline, "RMT") came from Bosshart et&nbsp;al.<sup class="cite">[4]</sup>.
The catch: this hardware processes packets at terabit rates by being <em>extremely</em> restricted — a
fixed number of pipeline stages, no loops, no floating point, tiny per-packet state. Getting a
"hold this packet for 13 milliseconds" behaviour out of a chip designed to never hold anything is the
central engineering tension of the project.</p>

<div class="callout"><span class="lab">The inspiration: <em>Ditto</em></span>
<p>Meier, Lenders &amp; Vanbever's <em>Ditto</em> (NDSS 2022)<sup class="cite">[5]</sup> showed that a
programmable switch can obfuscate WAN traffic <strong>at line rate</strong> by padding packets to fixed
sizes and releasing them on a deterministic schedule, so an observer sees a device-independent pattern
instead of the real sizes and timings. Our project adapts that idea to DNP3 in a substation: pad the
<em>size</em>, and reshape the <em>timing</em>, of a protection relay's responses. Ditto is the
methodological ancestor of the "queue/traffic-manager scheduling" direction we pursue.</p></div>

<p>Within Case A there are two timing defences, and they are complementary:</p>
<div class="tbl"><table>
<tr><th>Defence</th><th>Mechanism</th><th>Goal</th></tr>
<tr><td><strong>Defence 1 — delay the ACK</strong></td><td>Hold the pure TCP ACK; let the response go near its natural time</td><td>Shrink the ACK&rarr;response gap so the CLRT fingerprint collapses</td></tr>
<tr><td><strong>Defence 2 — delay the response</strong></td><td>Forward the ACK normally; release the response on a chosen schedule</td><td>Force the CLRT to a device-independent target, hiding the relay's native processing time</td></tr>
</table></div>

<p>Both were previously demonstrated on the Tofino via a "recirculation-hold" mechanism (bouncing a packet
through the pipeline to burn time) and are treated as a <strong>frozen feasibility baseline</strong>. The
work in this report is the <em>next</em> layer: proving the size axis on real silicon, and — the bulk of
what follows — replacing captured-file replay with the <strong>physical relay</strong> so that every
timing number is measured against real hardware.</p>

<h2 id="s3"><span class="num">03</span> The testbed</h2>

<p>Four machines and one relay, on a lab bench:</p>
<pre class="mermaid">
flowchart LR
  subgraph LAB["lab / management net 10.10.54.0/24 (unmanaged TP-Link switch)"]
    VIS["Vision<br/>DNP3 master<br/>10.10.54.19"]
    HULK["Hulk<br/>traffic host<br/>10.10.54.158"]
    GAM["gambit<br/>dev / analysis<br/>10.10.54.133"]
    TOF["Tofino-1<br/>programmable switch<br/>mgmt 10.10.54.15"]
  end
  REL["SEL-751 relay<br/>192.168.10.7<br/>(separate-ACK, Case A)"]
  VIS -- "25G to Tofino dp8/dp9" --- TOF
  HULK -- "25G to Tofino" --- TOF
  VIS == "eno1 + temp 192.168.10.1" ==> REL
  REL == "DNP3/TCP :20000" ==> VIS
</pre>

<p><strong>Vision</strong> runs the DNP3 master (it has a working <code>pydnp3</code> stack).
<strong>Hulk</strong> drives high-rate traffic into the Tofino. <strong>gambit</strong> is the dev box
where analysis runs. The <strong>Tofino-1</strong> is the programmable switch. The
<strong>physical SEL-751</strong> is the real relay we finally connected. A hard rule governs everything:
<strong>the switch is shared and any change to it is gated on explicit human authorization</strong>, and
the relay is only ever <em>read</em>, never controlled or reconfigured by us.</p>

<h2 id="s4"><span class="num">04</span> Thread A — the size axis, proven on silicon</h2>

<p>Before the relay work, we proved the <strong>size</strong> half of the obfuscation on the actual Tofino.
The mechanism (Level-1): take a corpus of real DNP3 frame sizes and <strong>pad every one of them to a
single 128-byte state</strong>, on-chip, in the dataplane.</p>

<pre class="mermaid">
flowchart LR
  IN["frame in<br/>size in {60..120} B"] --> CL["classify by<br/>declared size class"]
  CL --> MAP["map to one<br/>target state = 128 B"]
  MAP --> PAD["prepend pad header<br/>(power-of-2 set)"]
  PAD --> Q["one real queue<br/>(qid = 1)"]
  Q --> OUT["frame out<br/>= 128 B, always"]
</pre>

<p>On live Tofino-1 silicon, across three reproducible runs of 150 frames each: every output was exactly
128&nbsp;bytes, with <strong>zero loss and zero reordering</strong>. The information the size channel gave
away — measured as <em>mutual information</em>, in bits, between a frame's size and the device that sent
it — went from <strong>0.91 bits to 0.00 bits</strong>. In plain terms: before, a frame's length told you
something about which device sent it; after, it tells you nothing, because every frame is the same
length.</p>

<div class="callout warn"><span class="lab">Honest scope of Thread A</span>
<p>This was a <strong>Level-1</strong> result: the switch classified frames by a <em>declared</em> size
tag we attached, not by parsing live DNP3/TCP, and it addressed only the size channel on a small
three-flow corpus. It is a genuine on-silicon proof that the padding mechanism works with no loss or
reordering — not a claim that a full inline DNP3 defence is finished. Details and evidence live under
<code>research/tofino_dcrn_feasibility/p4/queue_microbench/autonomous_run_20260722/</code>
(tag <code>queue-trace-level1-hw-pass</code>).</p></div>

<h2 id="s5"><span class="num">05</span> Thread B — bringing the physical relay online</h2>

<p>Everything above used captured traffic replayed from files. The advisor's direction was to stop relying
on replay and <strong>connect the physical SEL-751</strong>, first through the ordinary lab switch (with
the Tofino <em>not</em> inline yet), just to establish a real, measured baseline. This turned into a
multi-stage debugging story worth telling in full, because each stage taught something.</p>

<h3>Challenge 1 — the relay was invisible</h3>
<p>We plugged the relay into the lab switch and it simply did not appear. From Vision we ran an ARP scan of
the whole <code>10.10.54.0/24</code> subnet and a 30-second passive capture: <strong>zero</strong> packets
from any Schweitzer device. The reason is mundane but important: an <strong>un-polled DNP3 relay is
silent</strong> — it does not announce itself, it only answers when spoken to. You cannot discover it
passively; you must know its IP.</p>

<h3>Challenge 2 — a wrong theory, corrected by evidence</h3>
<p>Because the capture showed 802.1Q VLAN tags, I initially suspected the relay's switch port was on a
different VLAN. Then the physical photos showed the switch is a <strong>TP-Link TL-SG1024S — an
unmanaged switch with no VLANs at all</strong>. The tags were just other devices' traffic passing
through. The VLAN theory was wrong; I retracted it. (This is a recurring theme: every theory got checked
against evidence, and the wrong ones were dropped, not defended.)</p>

<h3>Challenge 3 — the smoking gun: an accept-then-hang-up</h3>
<p>The relay's real address turned out to be <code>192.168.10.7</code> on its own subnet. With Vision given
a matching address, ping worked and TCP port 20000 opened — but every DNP3 session <strong>died
instantly</strong>. The packet capture showed the pattern, repeated ~430 times:</p>

<pre class="mermaid">
sequenceDiagram
  participant V as Vision (192.168.10.100)
  participant R as SEL-751 (192.168.10.7)
  V->>R: TCP SYN
  R-->>V: SYN-ACK
  V->>R: ACK  (handshake complete)
  R-->>V: FIN  (relay closes it — median 1.9 ms later, zero DNP3 bytes)
  Note over V,R: opendnp3 immediately reconnects → 55 sessions/second
</pre>

<p>The relay accepted the TCP handshake and then closed the connection itself before any DNP3 was
exchanged. The cause, once we read the relay's configuration, was a <strong>DNP3 master-IP allowlist</strong>:
the relay setting <code>DNPIP1 := 192.168.10.1</code> means it only talks DNP3 to a master at
<code>192.168.10.1</code>. Vision was at <code>.100</code>. Not on the list &rarr; accepted then dropped.</p>

<div class="callout warn"><span class="lab">Honest disclosure — I hammered the relay by accident</span>
<p>The DNP3 library (<code>opendnp3</code>) defaults to auto-reconnecting when a channel drops. Because the
relay closed every session instantly, the library reconnected <strong>~55 times per second for ~8
seconds — 434 TCP sessions</strong>. I intended one session; the retry loop produced hundreds. The
mitigating fact, verified in the capture: <strong>zero DNP3 application bytes were ever sent</strong>
across all of them — no read, no control, no write — so no protocol-level safety rule was violated. The
lesson went straight into the fix: the next probe used a <em>no-retry</em> transport (a one-hour minimum
reconnect interval), so a drop cannot trigger a reconnection. This is documented in
<code>research/physical_sel751/SEL751_DIRECT_CONNECTIVITY_REPORT.md</code>.</p></div>

<h3>Challenge 4 — the DNP3 library's dangerous defaults</h3>
<p>Talking to a live protection relay read-only is not just "don't send a control command." The
<code>opendnp3</code> master, left on defaults, will <em>automatically</em>: send an
<code>ENABLE_UNSOLICITED</code> request, send a <code>DISABLE_UNSOLICITED</code> request at startup, and —
most dangerously — <strong>send a WRITE to clear the relay's "device restart" flag</strong>. A WRITE to a
protection relay is exactly what a read-only experiment must never do. So the probe pins every automatic
behaviour off: no startup poll, no unsolicited management, no time-sync, and
<code>ignoreRestartIIN = True</code> so the restart flag is never cleared. The verified-safe probe is
<code>research/physical_sel751/native_class0_probe.py</code>.</p>

<h3>The payoff — a clean native transaction</h3>
<p>With Vision at <code>.1</code>, outstation address <code>0</code> (its real configured value — not the
<code>10</code> from the old captures), and the no-retry probe, the relay answered on the first try. One
TCP session, one Class-0 read &rarr; <strong>a separate pure ACK</strong> &rarr; a 134-byte response
carrying 69 points. <strong>Case A confirmed on the physical device</strong>, with a first-transaction
CLRT of 6.12&nbsp;ms.</p>

<h2 id="s6"><span class="num">06</span> The 300-poll CLRT experiment</h2>

<p>One transaction is an anecdote, not a distribution. The authorized experiment: <strong>300 sequential
Class-0 reads over one persistent TCP session</strong>, one request outstanding at a time, a one-second
pause after each response, <strong>no retries, no reconnects</strong>, read-only, with hard stop
conditions (any reset, timeout, unexpected function, or protocol error ends it immediately). It ran ~5
minutes and completed all 300 with no stop condition, one TCP session, zero resets, zero retransmissions.
The probe is <code>clrt_300poll_&hellip;/clrt_experiment.py</code>; the raw evidence and a SHA-256 manifest
are in that directory.</p>

<div class="callout ex"><span class="lab">Worked example — what "CLRT" is, in numbers</span>
<p>For each poll we timestamp three wire events: the request leaving Vision, the relay's bare TCP ACK, and
the relay's DNP3 response. Then
<code>request&rarr;ACK = 0.9 ms</code>, <code>CLRT = ACK&rarr;response = 6.1 ms</code>,
<code>request&rarr;response = 7.0 ms</code> for that first poll. The CLRT — the middle number — is the
Formby fingerprint. We compute it 300 times and study the <em>distribution</em>.</p></div>

<figure>
<img alt="CLRT histogram, n=300" src="%%hist%%">
<figcaption><span class="figtag">Figure 1.</span> <b>Distribution of the CLRT over 300 polls.</b> Most
responses cluster tightly around ~1.9&nbsp;ms, with a right-hand tail out to ~15.6&nbsp;ms. A histogram
just counts how many polls fell in each 0.5&nbsp;ms bin. The long thin tail is the reason the
<em>mean</em> (2.98&nbsp;ms) sits above the <em>median</em> (1.90&nbsp;ms): a handful of slow responses
drag the average up.</figcaption>
</figure>

<figure>
<img alt="CLRT empirical CDF" src="%%ecdf%%">
<figcaption><span class="figtag">Figure 2.</span> <b>Empirical CDF of the CLRT.</b> Read it as: "what
fraction of polls had a CLRT at or below <em>x</em>?" The curve rises almost vertically near 1.9&nbsp;ms
(most polls are there) and then crawls rightward through the slow tail. Half the mass is below the median
(1.90&nbsp;ms); 90% is below ~6.0&nbsp;ms (the p90); 95% below ~7.4&nbsp;ms.</figcaption>
</figure>

<figure>
<img alt="CLRT box and violin plot" src="%%box%%">
<figcaption><span class="figtag">Figure 3.</span> <b>Box-and-violin view.</b> The violin's width shows
where the data pile up (a fat lobe at ~1.9&nbsp;ms); the box marks the 25th–75th percentiles
(1.73–3.06&nbsp;ms) with the median line inside; the points above are the slow-tail outliers. Same data
as Figures 1–2, drawn to make the skew and the tail obvious at a glance.</figcaption>
</figure>

<div class="tbl"><table>
<tr><th>CLRT statistic (n=300)</th><th class="n">value (ms)</th><th>plain meaning</th></tr>
<tr><td>median</td><td class="n">1.899</td><td>the typical response time</td></tr>
<tr><td>mean</td><td class="n">2.983</td><td>the average, pulled up by the tail</td></tr>
<tr><td>std dev</td><td class="n">2.273</td><td>spread around the mean</td></tr>
<tr><td>p90 / p95</td><td class="n">5.99 / 7.43</td><td>9-in-10 / 19-in-20 are faster than this</td></tr>
<tr><td>min / max</td><td class="n">0.905 / 15.649</td><td>fastest / slowest single poll</td></tr>
</table></div>

<h3>The bug that hid inside the framing</h3>
<p>The first analysis pass mis-counted the transactions by one. The cause is a nice illustration of DNP3
framing: <strong>every</strong> DNP3 frame — including pure link-layer housekeeping frames that carry no
application data — begins with the two magic bytes <code>0x05 0x64</code>. When a fresh TCP session opens,
the relay and master exchange a link-status handshake (two such frames) before any real read. My parser
counted the master's link-status frame as if it were a request, shifting every poll's data by one. The
fix was to require an actual application layer (a link length field greater than 5) and the correct
application function code before treating a frame as a request or response. After the fix: exactly 300
requests, 300 responses, none missing.</p>

<h2 id="s7"><span class="num">07</span> The validation pass</h2>

<p>A distribution is only as trustworthy as the assumptions behind its summary statistics. The validation
pass — run entirely on the already-committed evidence, changing no raw data — stress-tested four things.</p>

<h3>7.1 &nbsp; Decoding what the relay actually said (the IIN field)</h3>
<p>Every DNP3 response carries two "Internal Indication" bytes — status flags from the outstation. Ours
read <code>0x80 0x00</code> on all 300 responses. The report had rendered this as "0x8000," which is
<em>endian-ambiguous</em>: is the set bit in the first byte or the second?</p>

<div class="callout ex"><span class="lab">Worked example — reading the IIN bits</span>
<p>On the wire the first byte is <strong>IIN1 = <code>0x80</code></strong> = binary <code>1000&nbsp;0000</code>
= only bit&nbsp;7 set. In DNP3, IIN1 bit&nbsp;7 is <strong>DEVICE_RESTART</strong>. The second byte is
<strong>IIN2 = <code>0x00</code></strong> = no bits, and critically none of IIN2's bits are <em>error</em>
bits. So the relay is saying, on every response: "I restarted at some point, and I have no error." The
restart flag stays lit because a normal master would clear it with a WRITE — and we deliberately never
write. The corrected, unambiguous notation used everywhere now is <code>IIN1=0x80, IIN2=0x00</code>.
Reproducible via <code>validation/validate_iin.py</code>.</p></div>

<h3>7.2 &nbsp; Are the samples independent? (They are not.)</h3>
<p>Every statistic that follows — confidence intervals especially — silently assumes the 300 CLRT values
are <em>independent</em> draws. We tested that with an <strong>autocorrelation</strong> analysis: does a
slow poll tend to be followed by another slow poll?</p>

<figure>
<img alt="Autocorrelation of the three latency series" src="%%acf%%">
<figcaption><span class="figtag">Figure 4.</span> <b>Autocorrelation (ACF) at lags 1–10 for all three
timing series.</b> Each bar asks: "how correlated is a value with the value <em>k</em> polls earlier?" The
red dashed lines are the 95% "no real correlation" band (&plusmn;0.113). For the <strong>CLRT (middle
panel)</strong>, the lag-1 bar is 0.35 and <em>every</em> bar 1–10 pokes above the band — strong,
persistent positive correlation. In plain terms: slow responses come in <em>bursts</em>, not at random.
The Ljung–Box test (a formal test for "any autocorrelation at all") returns <code>p ≈ 0</code>,
overwhelmingly rejecting independence.</figcaption>
</figure>

<figure>
<img alt="CLRT rolling median and p95" src="%%roll%%">
<figcaption><span class="figtag">Figure 5.</span> <b>Rolling median and rolling p95 (window = 25 polls).</b>
The median (teal) is flat across the run — the typical response time doesn't drift. But the p95 (red) rises
and falls, and is highest in the first ~50 polls: the <em>tail</em> is bursty and slightly heavier early
on. This is the same clustering the ACF detected, seen in the time domain.</figcaption>
</figure>

<figure>
<img alt="CLRT vs poll number with linear trend" src="%%trend%%">
<figcaption><span class="figtag">Figure 6.</span> <b>CLRT versus poll number, with a fitted straight
line.</b> The line is essentially flat (slope ≈ 6&times;10<sup>-4</sup> ms per poll, <code>p = 0.69</code>,
r² ≈ 0.0005): there is <strong>no drift or warm-up trend</strong> over the five minutes. The dependence is
short-range clustering, not a slow ramp. Note the seven clusters of high points — the bursts.</figcaption>
</figure>

<h3>7.3 &nbsp; Fixing the confidence intervals (bootstrap)</h3>
<div class="callout"><span class="lab">What a bootstrap is, in one paragraph</span>
<p>A <strong>bootstrap</strong> estimates how uncertain a statistic is by resampling the data itself: draw
300 values (with replacement) from your 300, recompute the median, repeat 10,000 times, and look at the
spread of those medians. The middle 95% of that spread is a 95% confidence interval — <em>without</em>
assuming the data follow any particular distribution. Its catch: the ordinary bootstrap assumes the
observations are <strong>independent</strong>. We just showed ours are not.</p></div>

<p>Because the CLRT is autocorrelated, the ordinary ("IID") bootstrap treats bursty, correlated data as if
it carried more independent information than it really does, so its intervals come out <strong>too
narrow</strong>. The fix is a <strong>moving-block bootstrap</strong>: resample <em>contiguous blocks</em>
of consecutive polls instead of individual polls, so each block keeps its internal correlation. The point
estimates don't change; the honest intervals widen:</p>

<div class="tbl"><table>
<tr><th>CLRT statistic</th><th>IID bootstrap 95% CI</th><th>moving-block (L=7)</th><th>moving-block (L=30)</th></tr>
<tr><td>mean</td><td class="n">[2.73, 3.25]</td><td class="n">[2.59, 3.40]</td><td class="n">[2.36, 3.65]</td></tr>
<tr><td>median</td><td class="n">[1.82, 1.93]</td><td class="n">[1.79, 2.06]</td><td class="n">[1.78, 2.29]</td></tr>
</table></div>

<p>The median interval roughly <strong>doubles-to-triples</strong> under the correct method. The lesson,
stated plainly in the reports: <em>the originally-quoted CIs were anti-conservative; the moving-block
intervals supersede them for any uncertainty statement.</em> Full write-up:
<code>validation/TEMPORAL_DEPENDENCE_ANALYSIS.md</code>.</p>

<h3>7.4 &nbsp; The historical "~13 ms" mystery</h3>
<p>Prior project documents and the advisor's notes cite a native SEL-751 CLRT of <strong>~13 ms</strong>,
from earlier captured traces. Our live median is <strong>1.9 ms</strong> — a 7&times; difference for the
same device and the same measurement. That gap had to be explained, not brushed aside.</p>

<p>Recomputing directly from the original trace (<code>Traffic Trace/SEL751.pcap</code>) reproduced the old
number <em>exactly</em>: median 12.90&nbsp;ms over 299 transactions, and it genuinely is the ACK&rarr;response
CLRT. Then the decisive test — split it by request type:</p>

<div class="tbl"><table>
<tr><th>dataset</th><th>request</th><th class="n">n</th><th class="n">resp bytes</th><th class="n">CLRT median (ms)</th><th class="n">req&rarr;ACK median (ms)</th></tr>
<tr><td>historical</td><td>DIRECT_OPERATE</td><td class="n">200</td><td class="n">37</td><td class="n">12.84</td><td class="n">3.67</td></tr>
<tr><td>historical</td><td>READ</td><td class="n">99</td><td class="n">54</td><td class="n">13.18</td><td class="n">3.83</td></tr>
<tr><td><b>live 300-poll</b></td><td>READ (Class-0)</td><td class="n">300</td><td class="n">134</td><td class="n"><b>1.90</b></td><td class="n"><b>0.56</b></td></tr>
</table></div>

<p>This kills the obvious hypothesis. The historical <em>READ-only</em> CLRT (13.18&nbsp;ms) is essentially
the same as its control CLRT (12.84&nbsp;ms), so the gap is <strong>not</strong> caused by the historical
traffic being control-heavy. Instead, the whole historical environment was uniformly ~7&times; slower —
in <em>both</em> the req&rarr;ACK (3.7 vs 0.56&nbsp;ms) <em>and</em> the CLRT — which points to a systematic
difference (network path, capture point, relay firmware/config/load, or a different setup entirely), not a
per-request effect.</p>

<div class="callout warn"><span class="lab">A tempting inference I checked and retracted</span>
<p>I briefly suspected the historical <code>10.0.0.1</code> was a <em>simulator</em>, because its packets
carried IP TTL 64 (a Linux signature) rather than 255. Then I checked the live physical relay's own TCP
packets in the committed capture — they are <strong>also TTL 64</strong> (its ping replies are 255, but its
TCP is 64). So TTL does <em>not</em> distinguish the two, and the simulator inference was wrong. I struck
it. What honestly remains: the ~13&nbsp;ms is a real CLRT from a different, undocumented capture context;
the 1.9&nbsp;ms is the physical relay's CLRT in the current direct setup; and <strong>the cause of the
offset is undetermined from the available evidence.</strong> The two numbers should not be compared
head-to-head. Full analysis: <code>validation/HISTORICAL_13MS_RECONCILIATION.md</code>.</p></div>

<h2 id="s8"><span class="num">08</span> Challenges &amp; lessons</h2>
<div class="tbl"><table>
<tr><th>Challenge</th><th>What it actually was</th><th>Lesson / fix</th></tr>
<tr><td>Relay invisible on the wire</td><td>An un-polled DNP3 relay is silent; no gratuitous ARP</td><td>Discovery needs the IP; passive scanning cannot find it</td></tr>
<tr><td>"Different VLAN" theory</td><td>Switch is unmanaged (no VLANs); tags were other traffic</td><td>Check theories against the hardware; retract when wrong</td></tr>
<tr><td>Accept-then-hang-up</td><td>Relay master-IP allowlist (<code>DNPIP1</code>) excluded us</td><td>Read the device config; match the master IP</td></tr>
<tr><td>Accidental 434-session storm</td><td>opendnp3 auto-retry vs. a relay that closes instantly</td><td>Use a no-retry transport for controlled single sessions</td></tr>
<tr><td>Library's unsafe defaults</td><td>Auto WRITE to clear restart-IIN; auto unsolicited mgmt</td><td>Pin every automatic behaviour off for a read-only probe</td></tr>
<tr><td>Off-by-one in analysis</td><td>Link-layer frames also start <code>0x0564</code></td><td>Require an app layer + correct function code before counting</td></tr>
<tr><td>Over-narrow confidence intervals</td><td>CLRT is autocorrelated; IID bootstrap invalid</td><td>Moving-block bootstrap; report both, prefer the block CI</td></tr>
<tr><td>~13 ms vs 1.9 ms</td><td>Not request-type; a ~7&times; systematic environment offset</td><td>Reproduce, split, and state honestly what's undetermined</td></tr>
</table></div>

<h2 id="s9"><span class="num">09</span> Where this sits in the literature</h2>
<p>The project lives at the intersection of three research lines. <strong>ICS device fingerprinting</strong>
is the threat: Formby et&nbsp;al.<sup class="cite">[2]</sup> established the CLRT as a hard-to-hide physical
fingerprint of control-system devices — the exact signal our timing defences target, and the exact number
(the CLRT) this report measures on a real relay. <strong>Traffic-analysis defences</strong> are the
method: the website-fingerprinting community learned, painfully, that naive padding and simple timing
tricks are defeated by better classifiers — Dyer et&nbsp;al.'s "Peek-a-Boo"<sup class="cite">[6]</sup>
showed coarse countermeasures fail; principled defences like Wright et&nbsp;al.'s traffic
morphing<sup class="cite">[7]</sup>, Cai et&nbsp;al.'s Tamaraw<sup class="cite">[8]</sup>, and Juárez
et&nbsp;al.'s WTF-PAD<sup class="cite">[9]</sup> shape both size and timing with explicit cost/robustness
trade-offs. That literature is <em>why</em> we insist on measuring information leakage (mutual
information, classifier accuracy) rather than eyeballing "it looks obfuscated." <strong>Programmable
dataplanes</strong> are the platform: P4<sup class="cite">[3]</sup> and the RMT architecture<sup class="cite">[4]</sup>
behind Tofino make line-rate, in-network shaping possible, and Ditto<sup class="cite">[5]</sup> is the
direct precedent for doing size+timing obfuscation on such a switch. Our specific contribution is to bring
this to a <strong>non-cooperative, real DNP3 protection relay</strong>, and to hold ourselves to
measured, statistically-honest results at every step.</p>

<h2 id="s10"><span class="num">10</span> Limitations &amp; what's next</h2>
<ul>
<li><strong>Size axis:</strong> proven on silicon but at <em>Level-1</em> (declared size class, not live
DNP3 parsing), single small corpus. <span class="pill done">proven, scoped</span></li>
<li><strong>Timing axis:</strong> the two Case-A defences exist as a frozen recirculation-based
feasibility baseline; the queue/traffic-manager version inspired by Ditto is designed, not yet built.
<span class="pill part">partial</span></li>
<li><strong>Physical relay:</strong> reachable, Case A confirmed, CLRT distribution measured and validated.
But: one relay, one configuration, one 1&nbsp;Hz session, 300 samples, read-only Class-0 only; no strong
tail (p99) claim; CLRT is load-sensitive and load was uncontrolled. <span class="pill done">measured</span></li>
<li><strong>Inline defence:</strong> the Tofino has <em>not</em> yet been placed between the master and the
physical relay — that is gated on explicit authorization and is the natural next step (a "shadow mode"
that parses live DNP3 and measures without modifying, before any active padding/holding).
<span class="pill no">not yet</span></li>
<li><strong>The ~13 ms offset</strong> between the historical traces and the live relay is
<em>undetermined</em>; resolving it needs the original capture's provenance and a controlled A/B on the
same physical relay.</li>
</ul>

<hr class="soft">
<h3>Appendix A — file &amp; evidence map</h3>
<div class="filemap">
<b>Physical relay (Thread B) —</b> research/physical_sel751/<br>
&nbsp;&nbsp;SEL751_DIRECT_CONNECTIVITY_REPORT.md &nbsp;— the connectivity saga + native baseline<br>
&nbsp;&nbsp;native_class0_probe.py &nbsp;— the verified-safe single-poll probe<br>
&nbsp;&nbsp;evidence/native_class0_v2.pcap &nbsp;— the first clean transaction<br>
&nbsp;&nbsp;clrt_300poll_20260723T152242/ &nbsp;— the 300-poll experiment<br>
&nbsp;&nbsp;&nbsp;&nbsp;clrt_experiment.py, analyze_clrt.py, per_poll.csv, summary.{csv,json}<br>
&nbsp;&nbsp;&nbsp;&nbsp;CLRT_EXPERIMENT_REPORT.md, plots/, evidence/, SHA256SUMS.txt<br>
&nbsp;&nbsp;&nbsp;&nbsp;validation/ &nbsp;— IIN_DECODE, TEMPORAL_DEPENDENCE, HISTORICAL_13MS reports + scripts + plots<br>
<b>Size axis (Thread A) —</b> research/tofino_dcrn_feasibility/p4/queue_microbench/<br>
&nbsp;&nbsp;autonomous_run_20260722/ &nbsp;— HARDWARE_RESULT.md, evidence (tag queue-trace-level1-hw-pass)<br>
<b>Timing defences (frozen baseline) —</b> research/tofino_dcrn_feasibility/p4/ack_delay/<br>
&nbsp;&nbsp;dcrn_defense1/2.p4, ACK_DELAY_*.md, evidence/clrt_baseline.py<br>
<b>Original device traces —</b> Traffic Trace/SEL751.pcap (and AB1400, ION7550)<br>
<b>Direction / meeting —</b> meeting.md, meeting_direction.md (Dr. Lin)
</div>

<h3>Appendix B — references</h3>
<ol class="refs">
<li>IEEE Standards Association. <em>IEEE Std 1815-2012 — IEEE Standard for Electric Power Systems
Communications — Distributed Network Protocol (DNP3).</em> <span class="v">IEEE, 2012.</span> — the DNP3
protocol standard.</li>
<li>D. Formby, P. Srinivasan, A. M. Leonard, J. D. Rogers, and R. Beyah. "Who's in Control of Your Control
System? Device Fingerprinting for Cyber-Physical Systems." <span class="v">Network and Distributed System
Security Symposium (NDSS), 2016.</span> — introduces Cross-Layer Response Time (CLRT) fingerprinting; the
threat our timing defences target. <span class="small">(Verified via Semantic Scholar.)</span></li>
<li>P. Bosshart, D. Daly, G. Gibb, M. Izzard, N. McKeown, J. Rexford, C. Schlesinger, D. Talayco,
A. Vahdat, G. Varghese, and D. Walker. "P4: Programming Protocol-Independent Packet Processors."
<span class="v">ACM SIGCOMM Computer Communication Review, 44(3), 2014.</span> — the P4 language.
<span class="small">(Verified; Semantic Scholar lists the 2013 preprint / CCR record.)</span></li>
<li>P. Bosshart, G. Gibb, H.-S. Kim, G. Varghese, N. McKeown, M. Izzard, F. Mujica, and M. Horowitz.
"Forwarding Metamorphosis: Fast Programmable Match-Action Processing in Hardware for SDN."
<span class="v">ACM SIGCOMM, 2013.</span> — the RMT architecture behind Tofino. <span class="small">(Verified.)</span></li>
<li>R. Meier, V. Lenders, and L. Vanbever. "Ditto: WAN Traffic Obfuscation at Line Rate."
<span class="v">NDSS, 2022.</span> — in-network size+timing obfuscation on a programmable switch; the
methodological precedent. <span class="small">(Verified.)</span></li>
<li>K. P. Dyer, S. E. Coull, T. Ristenpart, and T. Shrimpton. "Peek-a-Boo, I Still See You: Why Efficient
Traffic Analysis Countermeasures Fail." <span class="v">IEEE Symposium on Security and Privacy, 2012.</span>
— why naive padding/timing defences are defeated; motivates measuring leakage. <span class="small">(Verified.)</span></li>
<li>C. V. Wright, S. E. Coull, and F. Monrose. "Traffic Morphing: An Efficient Defense Against Statistical
Traffic Analysis." <span class="v">NDSS, 2009.</span> — shaping one traffic distribution to look like
another. <span class="small">(Well-established; not re-verified this session — Semantic Scholar was rate-limited.)</span></li>
<li>X. Cai, R. Nithyanand, T. Wang, R. Johnson, and I. Goldberg. "A Systematic Approach to Developing and
Evaluating Website Fingerprinting Defenses" (Tamaraw). <span class="v">ACM CCS, 2014.</span> — provably-bounded
size+timing padding. <span class="small">(Verified.)</span></li>
<li>M. Juárez, M. Imani, M. Perry, C. Díaz, and M. Wright. "Toward an Efficient Website Fingerprinting
Defense" (WTF-PAD). <span class="v">ESORICS, 2016.</span> — adaptive padding to break timing features.
<span class="small">(Verified; Semantic Scholar lists the 2015 preprint.)</span></li>
</ol>
<p class="small" style="margin-top:22px">Prepared with AI assistance (Claude Code). Every measured number
in this report traces to a committed evidence file with a SHA-256 manifest; every cited paper was checked
for existence against Semantic Scholar except where noted. Diagrams rendered with Mermaid; plots generated
by the analysis scripts named above.</p>
</div>
"""

out = HTML
for k, uri in IMG.items():
    out = out.replace("%%" + k + "%%", uri)
dest = "/home/philip/Projects/DNP3/research/physical_sel751/PROJECT_HOLISTIC_REPORT.artifact.html"
open(dest, "w").write(out)
print("wrote", dest, "bytes", len(out))
