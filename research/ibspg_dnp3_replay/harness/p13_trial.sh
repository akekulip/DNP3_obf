#!/bin/bash
# p13_trial.sh — one Part 13 real-DNP3 replay trial. Prints a machine-readable RESULT line.
#
# build plan locally -> stage -> reset -> measure the Vision/Hulk clock skew -> read counters
# (before) -> start captures -> fire BOTH injectors against a shared start epoch -> wait ->
# stop captures, fetch pcaps -> read counters (after) -> verify locally on the DELTAS.
#
# WHAT IS NEW HERE vs part12_trial.sh: injection is TWO-SIDED. Real DNP3 has no synthetic role
# byte, so ibspg_dnp3.p4 takes direction from the ingress port and the frames must physically
# arrive on the right one:
#       READ (master -> outstation, dir 0)     VISION -> dp9
#       pure ACK, RESPONSE (dir 1)             HULK   -> dp11
#       blocker tokens (0x88C1)                HULK   -> dp11 (forced ROLE_BLOCK in the parser)
# An ssh round trip per frame would put tens of milliseconds of jitter into an interval measured
# in microseconds, so instead a small injector is staged on EACH host and both are handed the
# SAME absolute --start-epoch; each then runs its own schedule off its own monotonic clock. The
# ACK -> RESPONSE interval under test is generated entirely by Hulk, so it carries NO cross-host
# clock error; the only cross-host requirement is that the READ leads, and that is covered by a
# 20 ms lead plus the pre-flight skew gate below.
#
# NOTHING RUNS AT SOURCE TIME. Every remote step is inside the ordered body, and DRYRUN=1 prints
# each remote command instead of executing it, so this script can be reviewed end to end without
# touching the switch, Hulk or Vision. Run it for real only under explicit authorization.
#
# Env (all optional):
#   MODE      bypass | hold_ack | hold_resp        (default hold_resp)
#             bypass    = no reservoir, nothing held: the no-hold baseline
#             hold_resp = the reservoir holds the RESPONSE until t_ack + G
#             hold_ack  = NEGATIVE CONTROL. ibspg_dnp3.p4 has no ACK-hold branch; this proves
#                         the ACK is never held and is wired for a future P4 that holds it.
#   K         blocker reservoir depth                (default 64; the Part 9 working depth)
#   G_MS      guard interval G in milliseconds       (default 25, the compiled G_DEFAULT_NS)
#   NTXN      transactions to replay, 0 = all 30     (default 30)
#   RUNID     names the artifacts                    (default p13)
#   BUDGET TXN_PERIOD_MS TOK_LEAD_MS ACK_LEAD_MS RESP_DELAY_MS START_LEAD_S TAIL_MS TOL_MS
#   CAPHOST   vision | hulk | both                   (default both)
#   CONFIG=1  also run the one-time static TM/port config   (default 0)
#   STAGE=1   scp the injector/reader to the hosts first    (default 0)
#   DRYRUN=1  print remote commands, execute nothing        (default 0)
#
# Prints: RESULT mode=.. k=.. g_ms=.. ntxn=.. skew_ms=.. arm=.. aarm=.. abyp=.. benq=.. bloop=..
#         tdl=.. ttmo=.. tstale=.. renq=.. rrel=.. byp0=.. byp1=.. clrt_med_ms=.. clrt_p95_ms=..
#         clrt_spread_ms=.. cap=LIVE|DEAD verify=PASS|FAIL|INCONCLUSIVE_CAPTURE
set -u
source ~/.lab_env 2>/dev/null

SSHO="-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR"
SW=decps@10.10.54.81; HULK=decps@10.10.54.158; VIS=decps@10.10.54.19
HIF=${HIF:-enp59s0f0np0}; VIF=${VIF:-enp59s0f0np0}
E='export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install; export PATH=$SDE_INSTALL/bin:$PATH; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH; export PYTHONPATH=$(echo $SDE_INSTALL/lib/python*/site-packages):$(echo $SDE_INSTALL/lib/python*/site-packages/tofino):$PYTHONPATH'

HARNESS=/home/philip/Projects/DNP3-part13/research/ibspg_dnp3_replay/harness
REPLAY=/home/philip/Projects/DNP3-part13/research/ibspg_dnp3_replay
INJECT=$HARNESS/p13_inject.py
VERIFY=$HARNESS/p13_verify.py
READER=$HARNESS/p13_read.py
# committed separately (Part 13 control-plane guard-interval setter); reused as-is, never forked
GUARD=${GUARD:-$HARNESS/p13_guard.py}
# The Part 11 control plane is name-parameterized and is REUSED AS-IS, never forked.
SETUP=${SETUP:-/home/decps/part11/ibspg_paired_setup.py}
SWDIR=${SWDIR:-/home/decps/p13}
HOSTDIR=${HOSTDIR:-/home/decps/p13}
OUT=${OUT:-/home/philip/Projects/DNP3-part13/research/ibspg_dnp3_replay/evidence}
RPY=${RESEARCH_PYTHON:-python3}
PROG=${PROG:-ibspg_dnp3}

MODE=${MODE:-hold_resp}; K=${K:-64}; G_MS=${G_MS:-25}; NTXN=${NTXN:-30}; RUNID=${RUNID:-p13}
BUDGET=${BUDGET:-2000000}
TXN_PERIOD_MS=${TXN_PERIOD_MS:-250}
TOK_LEAD_MS=${TOK_LEAD_MS:-20}
ACK_LEAD_MS=${ACK_LEAD_MS:-70}
RESP_DELAY_MS=${RESP_DELAY_MS:-2}
START_LEAD_S=${START_LEAD_S:-4}
TAIL_MS=${TAIL_MS:-1500}
TOL_MS=${TOL_MS:-5}
CAPHOST=${CAPHOST:-both}
CONFIG=${CONFIG:-0}; STAGE=${STAGE:-0}; DRYRUN=${DRYRUN:-0}

G_NS=$(awk "BEGIN{printf \"%d\", $G_MS * 1000000}")

REGS="reg_gen,reg_active,reg_deadline,reg_ts_first_block,reg_ts_ack_arm,reg_ts_block_term,reg_ts_first_resp_release"
# ctr_bypass is TWO entries: [0] forwarded transparently, [1] dropped for a bad ingress port.
CTRS="ctr_arm,ctr_block_enq,ctr_block_loop,ctr_block_term_deadline,ctr_block_term_timeout,ctr_block_term_stale,ctr_ack_arm,ctr_ack_bypass,ctr_resp_enq,ctr_resp_release,ctr_bypass:0,ctr_bypass:1"
# The frozen Part 11 setup script clears counter INDEX 0 only, so ctr_bypass:1 would survive a
# reset. Nothing here depends on the reset succeeding: every assertion uses an after-before delta.
RESET_CTRS="ctr_arm,ctr_block_enq,ctr_block_loop,ctr_block_term_deadline,ctr_block_term_timeout,ctr_block_term_stale,ctr_ack_arm,ctr_ack_bypass,ctr_resp_enq,ctr_resp_release,ctr_bypass"

mkdir -p "$OUT" 2>/dev/null
PLAN=$OUT/${RUNID}.plan.json
VPCAP=$OUT/${RUNID}.vision.pcap
HPCAP=$OUT/${RUNID}.hulk.pcap
BJSON=$OUT/${RUNID}.before.json
AJSON=$OUT/${RUNID}.after.json
VJSON=$OUT/${RUNID}.verify.json
INJV=$OUT/${RUNID}.inject.vision.json
INJH=$OUT/${RUNID}.inject.hulk.json

# ---- remote helpers: every one of these is a no-op under DRYRUN=1 ----------
# The DRYRUN trace goes to a log as well as stderr, because several steps redirect stderr away
# to keep a real run's output down to the RESULT line.
DRYLOG=""
[ "$DRYRUN" = "1" ] && DRYLOG=$(mktemp /tmp/p13_dryrun.XXXXXX)
_dry() {
  echo "$1" >&2
  [ -n "$DRYLOG" ] && echo "$1" >> "$DRYLOG"
  return 0
}
sw() {          # run on the switch, under the SDE environment
  local cmd="$*"
  if [ "$DRYRUN" = "1" ]; then _dry "DRYRUN sw   : $cmd"; return 0; fi
  sshpass -e ssh $SSHO $SW "bash -lc '$E; $cmd'"
}
hulk_sudo() {   # run on Hulk as root (raw AF_PACKET inject and capture both need it)
  local cmd="$*"
  if [ "$DRYRUN" = "1" ]; then _dry "DRYRUN hulk : sudo $cmd"; return 0; fi
  sshpass -e ssh $SSHO $HULK "echo '$SSHPASS' | sudo -S -p '' bash -c '$cmd'"
}
vis_sudo() {    # run on Vision as root
  local cmd="$*"
  if [ "$DRYRUN" = "1" ]; then _dry "DRYRUN vis  : sudo $cmd"; return 0; fi
  sshpass -e ssh $SSHO $VIS "echo '$SSHPASS' | sudo -S -p '' bash -c '$cmd'"
}
host_plain() {  # unprivileged remote read (the clock probe)
  local who="$1"; shift
  local cmd="$*"
  if [ "$DRYRUN" = "1" ]; then _dry "DRYRUN $who: $cmd"; return 0; fi
  sshpass -e ssh $SSHO "$who" "$cmd"
}

# ---- 0. build the plan LOCALLY (offline, unprivileged, always runs) --------
# Done even under DRYRUN, on purpose: the plan is the reviewable artifact that says exactly
# which frame each host sends and when.
NTXN_ARG=""; [ "$NTXN" != "0" ] && NTXN_ARG="--ntxn $NTXN"
PLANOUT=$($RPY $INJECT --build-plan --selftest --mode $MODE --k $K --budget $BUDGET $NTXN_ARG \
  --txn-period-ms $TXN_PERIOD_MS --tok-lead-ms $TOK_LEAD_MS --ack-lead-ms $ACK_LEAD_MS \
  --resp-delay-ms $RESP_DELAY_MS --runid $RUNID --spec $REPLAY/replay_spec_sel751.json \
  --frames $REPLAY/replay_frames_sel751.json --out $PLAN 2>&1)
PLANRC=$?
echo "$PLANOUT" | sed 's/^/LOCAL plan: /' >&2
if [ "$PLANRC" != "0" ]; then
  echo "RESULT mode=$MODE k=$K g_ms=$G_MS ntxn=$NTXN verify=FAIL plan=ERR msg=$(echo "$PLANOUT" | tr '\n' ' ' | cut -c1-200)"
  exit 1
fi
DUR_MS=$($RPY -c "import json;print(int(json.load(open('$PLAN'))['schedule']['duration_ms']))")
# the EFFECTIVE reservoir depth: bypass mode forces it to 0 whatever K asked for
K_EFF=$($RPY -c "import json;print(json.load(open('$PLAN'))['k'])")
WAIT_MS=$(awk "BEGIN{printf \"%d\", $DUR_MS + $G_MS + $TAIL_MS}")

# ---- 1. optional staging --------------------------------------------------
# The injector imports nothing but the standard library at run time, so each host needs exactly
# two files: the script and the plan.
if [ "$STAGE" = "1" ]; then
  if [ "$DRYRUN" = "1" ]; then
    _dry "DRYRUN stage: ssh $VIS  mkdir -p $HOSTDIR"
    _dry "DRYRUN stage: scp $INJECT $PLAN -> $VIS:$HOSTDIR/"
    _dry "DRYRUN stage: ssh $HULK mkdir -p $HOSTDIR"
    _dry "DRYRUN stage: scp $INJECT $PLAN -> $HULK:$HOSTDIR/"
    _dry "DRYRUN stage: ssh $SW   mkdir -p $SWDIR"
    _dry "DRYRUN stage: scp $READER $GUARD -> $SW:$SWDIR/"
    _dry "DRYRUN stage: (control plane already on the switch at $SETUP; reused as-is, never forked)"
  else
    host_plain $VIS "mkdir -p $HOSTDIR" >/dev/null 2>&1
    sshpass -e scp $SSHO $INJECT $PLAN $VIS:$HOSTDIR/ >/dev/null 2>&1
    host_plain $HULK "mkdir -p $HOSTDIR" >/dev/null 2>&1
    sshpass -e scp $SSHO $INJECT $PLAN $HULK:$HOSTDIR/ >/dev/null 2>&1
    sw "mkdir -p $SWDIR" >/dev/null 2>&1
    sshpass -e scp $SSHO $READER $SW:$SWDIR/ >/dev/null 2>&1
    [ -f "$GUARD" ] && sshpass -e scp $SSHO $GUARD $SW:$SWDIR/ >/dev/null 2>&1
  fi
else
  # even without staging the plan changes per trial, so it always has to be pushed
  if [ "$DRYRUN" = "1" ]; then
    _dry "DRYRUN stage: scp $PLAN -> $VIS:$HOSTDIR/ (plan is per-trial, always pushed)"
    _dry "DRYRUN stage: scp $PLAN -> $HULK:$HOSTDIR/ (plan is per-trial, always pushed)"
  else
    sshpass -e scp $SSHO $PLAN $VIS:$HOSTDIR/ >/dev/null 2>&1
    sshpass -e scp $SSHO $PLAN $HULK:$HOSTDIR/ >/dev/null 2>&1
  fi
fi
PLAN_R=$HOSTDIR/$(basename $PLAN)

# ---- 2. optional one-time static config (2 strict-priority levels) --------
# Part 13 needs only Q_BLOCK qid7 HIGH > Q_RESP qid1 LOW, so the Part 11 setup runs WITHOUT
# --paired. A leftover Q_ACK qid5 level is harmless: ibspg_dnp3.p4 never uses qid5.
if [ "$CONFIG" = "1" ]; then
  sw "python3 $SETUP --prog $PROG --config --qb 7 --qh 1 --host-ports 9,11 --port-l 8 --pg-l 2"
fi

# ---- 2b. set the guard interval G on the chip ----------------------------
# WITHOUT THIS STEP G_MS IS ONLY AN EXPECTATION. A real pure TCP ACK has nowhere to carry G, so
# ibspg_dnp3.p4 takes it from tbl_guard's default action parameter, whose compile-time value is
# G_DEFAULT_NS = 25 ms. Setting G_MS here and NOT writing it would silently measure against 25 ms
# whatever G_MS said. p13_guard.py writes it and reads it back — a write that is not verified is
# not a configuration.
if [ -f "$GUARD" ]; then
  GOUT=$(sw "python3 $SWDIR/$(basename $GUARD) --prog $PROG --set-g-ms $G_MS 2>&1 | grep P13GUARD" 2>&1)
  [ "$DRYRUN" = "1" ] || echo "$GOUT" | sed 's/^/LOCAL guard: /' >&2
else
  echo "LOCAL guard: WARNING — $GUARD not found; G was NOT written to the chip, so the trial "\
       "measures against the compiled default (25 ms) regardless of G_MS=$G_MS." >&2
fi

# ---- 3. per-trial reset (control plane may reset and read, never release) --
sw "python3 $SETUP --prog $PROG --reset --regs $REGS --counters $RESET_CTRS" >/dev/null 2>&1

# ---- 4. pre-flight: how far apart are the Vision and Hulk clocks? ---------
# Ordering survives any skew smaller than TOK_LEAD_MS. Measure it rather than assume it: each
# host's clock is sampled between two local stamps, which bounds the estimate by half the RTT.
SKEW_MS="na"; SKEW_BOUND_MS="na"
if [ "$DRYRUN" = "1" ]; then
  _dry "DRYRUN vis  : date +%s.%N            (clock probe, bounded by RTT/2)"
  _dry "DRYRUN hulk : date +%s.%N            (clock probe, bounded by RTT/2)"
  _dry "DRYRUN local: FAIL THE TRIAL if |skew| + bound >= TOK_LEAD_MS ($TOK_LEAD_MS ms)"
else
  probe() {   # echo "<offset_s> <bound_s>" for one host
    local who="$1" t1 t2 rt
    t1=$($RPY -c "import time;print(repr(time.time()))")
    rt=$(host_plain "$who" "date +%s.%N" 2>/dev/null | tr -d '\r')
    t2=$($RPY -c "import time;print(repr(time.time()))")
    $RPY -c "
t1=$t1; t2=$t2
try: rt=float('$rt')
except Exception: print('nan nan'); raise SystemExit
print('%r %r' % (rt-(t1+t2)/2.0, (t2-t1)/2.0))"
  }
  VP=$(probe $VIS); HP=$(probe $HULK)
  read -r VOFF VBND <<<"$VP"; read -r HOFF HBND <<<"$HP"
  SK=$($RPY -c "
import math
try:
    v,vb,h,hb=float('$VOFF'),float('$VBND'),float('$HOFF'),float('$HBND')
except Exception:
    print('na na'); raise SystemExit
if any(math.isnan(x) for x in (v,vb,h,hb)): print('na na'); raise SystemExit
print('%.3f %.3f' % ((h-v)*1000.0, (vb+hb)*1000.0))")
  read -r SKEW_MS SKEW_BOUND_MS <<<"$SK"
  if [ "$SKEW_MS" != "na" ]; then
    BAD=$($RPY -c "print(1 if abs($SKEW_MS)+$SKEW_BOUND_MS >= $TOK_LEAD_MS else 0)")
    if [ "$BAD" = "1" ]; then
      echo "RESULT mode=$MODE k=$K g_ms=$G_MS ntxn=$NTXN skew_ms=$SKEW_MS skew_bound_ms=$SKEW_BOUND_MS verify=FAIL reason=clock_skew_exceeds_tok_lead"
      exit 1
    fi
  fi
fi

# ---- 5. baseline counter read (deltas make the reset non-load-bearing) ----
B=$(sw "python3 $SWDIR/p13_read.py --prog $PROG --g-ns $G_NS --regs $REGS --counters $CTRS --tag before 2>&1 | grep P13READ" 2>&1)
[ "$DRYRUN" != "1" ] && echo "$B" > $BJSON

# ---- 6. start the captures ------------------------------------------------
# INBOUND ONLY (-Q in). Vision has to inject its READ and capture on the SAME interface; a
# packet socket would otherwise also record Vision's own outbound frames as if they had been
# received. -Q in is the direction filter that removes exactly that, and the injector's TX
# socket and tcpdump's RX ring are independent kernel objects, so they do not exclude each other.
# The filter deliberately KEEPS ethertype 0x88C1: filtering blocker tokens out here would make
# the verifier's isolation check vacuous — absence of evidence, not evidence of absence.
CAPFILTER="(tcp port 20000) or (ether proto 0x88c1)"
if [ "$CAPHOST" = "vision" ] || [ "$CAPHOST" = "both" ]; then
  vis_sudo "rm -f /tmp/p13_v.pcap; nohup tcpdump -i $VIF -Q in -w /tmp/p13_v.pcap -s 512 -U \"$CAPFILTER\" >/dev/null 2>&1 & true" >/dev/null 2>&1
fi
if [ "$CAPHOST" = "hulk" ] || [ "$CAPHOST" = "both" ]; then
  hulk_sudo "rm -f /tmp/p13_h.pcap; nohup tcpdump -i $HIF -Q in -w /tmp/p13_h.pcap -s 512 -U \"$CAPFILTER\" >/dev/null 2>&1 & true" >/dev/null 2>&1
fi
[ "$DRYRUN" = "1" ] || sleep 1.5

# ---- 7. fire BOTH injectors against ONE shared absolute start epoch -------
# Each host sleeps until this CLOCK_REALTIME instant on its own clock, then plays its own side
# of the schedule from its own monotonic clock. The two ssh calls run in parallel; the start
# lead absorbs their launch latency.
START=$($RPY -c "import time;print(repr(time.time() + $START_LEAD_S))")
if [ "$DRYRUN" = "1" ]; then
  _dry "DRYRUN local: START=\$(python3 -c 'import time;print(time.time() + $START_LEAD_S)')   # shared absolute epoch"
  _dry "DRYRUN vis  : python3 $HOSTDIR/p13_inject.py --side vision --plan $PLAN_R --iface $VIF --start-epoch \$START   [background, parallel with Hulk]"
  _dry "DRYRUN hulk : python3 $HOSTDIR/p13_inject.py --side hulk   --plan $PLAN_R --iface $HIF --start-epoch \$START   [background, parallel with Vision]"
  _dry "DRYRUN local: wait for both injectors (schedule is ${DUR_MS} ms long)"
else
  ( vis_sudo "python3 $HOSTDIR/p13_inject.py --side vision --plan $PLAN_R --iface $VIF --start-epoch $START" > $INJV 2>&1 ) &
  VPID=$!
  ( hulk_sudo "python3 $HOSTDIR/p13_inject.py --side hulk --plan $PLAN_R --iface $HIF --start-epoch $START" > $INJH 2>&1 ) &
  HPID=$!
  wait $VPID; VRC=$?
  wait $HPID; HRC=$?
fi

# ---- 8. wait out the last hold -------------------------------------------
[ "$DRYRUN" = "1" ] || $RPY -c "import time; time.sleep($TAIL_MS/1000.0)"

# ---- 9. stop the captures and fetch them ---------------------------------
if [ "$CAPHOST" = "vision" ] || [ "$CAPHOST" = "both" ]; then
  vis_sudo "pkill tcpdump 2>/dev/null; sleep 0.4" >/dev/null 2>&1
  [ "$DRYRUN" = "1" ] && _dry "DRYRUN scp  : $VIS:/tmp/p13_v.pcap -> $VPCAP" \
                      || sshpass -e scp $SSHO $VIS:/tmp/p13_v.pcap $VPCAP >/dev/null 2>&1
fi
if [ "$CAPHOST" = "hulk" ] || [ "$CAPHOST" = "both" ]; then
  hulk_sudo "pkill tcpdump 2>/dev/null; sleep 0.4" >/dev/null 2>&1
  [ "$DRYRUN" = "1" ] && _dry "DRYRUN scp  : $HULK:/tmp/p13_h.pcap -> $HPCAP" \
                      || sshpass -e scp $SSHO $HULK:/tmp/p13_h.pcap $HPCAP >/dev/null 2>&1
fi

# ---- 10. read the on-chip evidence (after) -------------------------------
A=$(sw "python3 $SWDIR/p13_read.py --prog $PROG --g-ns $G_NS --regs $REGS --counters $CTRS --tag after 2>&1 | grep P13READ" 2>&1)
[ "$DRYRUN" != "1" ] && echo "$A" > $AJSON

# ---- 11. verify locally on the deltas ------------------------------------
verify="SKIP"
if [ "$DRYRUN" != "1" ]; then
  HARG=""; [ -s "$HPCAP" ] && HARG="--hulk-pcap $HPCAP"
  $RPY $VERIFY --plan $PLAN --vision-pcap $VPCAP $HARG \
      --before-json $BJSON --after-json $AJSON --mode $MODE --g-ns $G_NS \
      --tol-ms $TOL_MS --json $VJSON >/dev/null 2>&1
  verify=$($RPY -c "
import json
try:
    print(json.load(open('$VJSON'))['verdict'])
except Exception:
    print('FAIL')")
fi

# ---- 12. the single RESULT line ------------------------------------------
if [ "$DRYRUN" = "1" ]; then
  echo "--- DRYRUN: the remote commands this trial WOULD run, in order ---"
  [ -n "$DRYLOG" ] && { cat "$DRYLOG"; rm -f "$DRYLOG"; }
  echo "RESULT mode=$MODE k=$K_EFF g_ms=$G_MS ntxn=$NTXN wait_ms=$WAIT_MS DRYRUN=1 (nothing executed remotely; plan built locally at $PLAN)"
  exit 0
fi
$RPY -c "
import json
try:
    v = json.load(open('$VJSON'))
except Exception:
    v = {'counter_deltas': {}, 'clrt': {}, 'capture': {}, 'verdict': 'FAIL'}
d = v.get('counter_deltas', {}); c = v.get('clrt', {}); cap = v.get('capture', {})
def g(k):
    x = d.get(k)
    return 'na' if x is None else x
def q(k):
    x = c.get(k)
    return 'na' if x is None else x
print('RESULT mode=$MODE k=$K_EFF g_ms=$G_MS ntxn=$NTXN skew_ms=$SKEW_MS '
      'arm=%s aarm=%s abyp=%s benq=%s bloop=%s tdl=%s ttmo=%s tstale=%s renq=%s rrel=%s '
      'byp0=%s byp1=%s clrt_med_ms=%s clrt_p95_ms=%s clrt_spread_ms=%s cap=%s verify=%s' % (
    g('ctr_arm'), g('ctr_ack_arm'), g('ctr_ack_bypass'), g('ctr_block_enq'), g('ctr_block_loop'),
    g('ctr_block_term_deadline'), g('ctr_block_term_timeout'), g('ctr_block_term_stale'),
    g('ctr_resp_enq'), g('ctr_resp_release'), g('ctr_bypass:0'), g('ctr_bypass:1'),
    q('median_ms'), q('p95_ms'), q('spread_ms'),
    'LIVE' if cap.get('live') else 'DEAD', v.get('verdict', 'FAIL')))
"
