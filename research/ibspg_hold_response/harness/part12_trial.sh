#!/bin/bash
# part12_trial.sh — one Part 12 HOLD_RESPONSE trial. Prints a machine-readable RESULT line.
#
# reset -> Vision capture -> inject scenario on Hulk (ARM, K blockers, ACK carrying G, RESPONSE)
# -> wait -> stop capture -> read registers/counters on the switch -> verify byte-identity,
#    ACK-before-response, the observed ACK->response interval vs G, and the negative-scenario
#    counter signature.
#
# THE ACK IS NEVER HELD in Part 12. Only the RESPONSE is held (Q_RESP qid1), and the release is
# caused ONLY by the data-plane deadline (t_ack + G) or by blocker budget exhaustion. There is no
# drain packet and no drain register — nothing injected can release the response.
#
# NOTHING RUNS AT SOURCE TIME. Every remote step is inside the ordered body below, and DRYRUN=1
# prints each remote command instead of executing it, so this script can be reviewed end to end
# without touching the switch, Hulk, or Vision. Run it for real only under explicit authorization.
#
# Env (all optional):
#   K            blocker reservoir size                       (default 64; K=0 = forwarding gate)
#   G_MS         guard interval G in milliseconds              (default 20)
#   SCENARIO     normal|stale-ack|unrelated-ack|no-ack         (default normal)
#   RESP_DELAY_MS  ACK -> RESPONSE spacing at the injector     (default 2; keep well under G_MS)
#   RUNID        trial id; names the pcap/json artifacts       (default p12)
#   NACK NRESP BUDGET GEN PAD ARM_SETTLE_MS WAIT_MS TOL_NS
#   CONFIG=1     also run the one-time static TM/port config   (default 0)
#   STAGE=1      scp the gen/read scripts to Hulk/switch first (default 0)
#   DRYRUN=1     print remote commands, execute nothing        (default 0)
#
# Prints: RESULT scenario=.. k=.. g_ms=.. nack=.. nresp=.. arm=.. aarm=.. abyp=.. benq=.. bloop=..
#         tdl=.. ttmo=.. tstale=.. renq=.. rrel=.. g_obs_ns=.. dl_err_ns=.. tail_ns=..
#         order_ts=OK|BAD verify=PASS|FAIL abr=true|false
set -u
source ~/.lab_env 2>/dev/null

SSHO="-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR"
SW=decps@10.10.54.81; HULK=decps@10.10.54.158; VIS=decps@10.10.54.19
HIF=enp59s0f0np0; VIF=enp59s0f0np0; VMAC=3cfdfecc5dc0; SNEUTRAL=02000000000a
E='export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install; export PATH=$SDE_INSTALL/bin:$PATH; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH; export PYTHONPATH=$(echo $SDE_INSTALL/lib/python*/site-packages):$(echo $SDE_INSTALL/lib/python*/site-packages/tofino):$PYTHONPATH'

HARNESS=/home/philip/Projects/DNP3/research/ibspg_hold_response/harness
VERIFY=$HARNESS/ibspg_p12_verify.py
# The Part 11 control plane is name-parameterized and is REUSED AS-IS (never forked).
SETUP_LOCAL=/home/philip/Projects/DNP3/research/ibspg_paired/control/ibspg_paired_setup.py
SETUP=${SETUP:-/home/decps/part11/ibspg_paired_setup.py}
SWDIR=${SWDIR:-/home/decps/part12}
HULK_GEN=${HULK_GEN:-/home/decps/ibspg_p12_gen.py}
OUT=${OUT:-/home/philip/Projects/DNP3/research/ibspg_hold_response/evidence}
RPY=${RESEARCH_PYTHON:-python3}
PROG=${PROG:-ibspg_hold_response}

K=${K:-64}; G_MS=${G_MS:-20}; SCENARIO=${SCENARIO:-normal}; RESP_DELAY_MS=${RESP_DELAY_MS:-2}
NACK=${NACK:-1}; NRESP=${NRESP:-1}; BUDGET=${BUDGET:-2000000}; GEN=${GEN:-7}; PAD=${PAD:-60}
ARM_SETTLE_MS=${ARM_SETTLE_MS:-50}; RUNID=${RUNID:-p12}; TOL_NS=${TOL_NS:-1000000}
CONFIG=${CONFIG:-0}; STAGE=${STAGE:-0}; DRYRUN=${DRYRUN:-0}

# default wait: a deadline release lands at ~G; a fail-open release waits out the pass budget
if [ "$SCENARIO" = "normal" ]; then
  WAIT_MS=${WAIT_MS:-$(awk "BEGIN{printf \"%d\", $G_MS + 1500}")}
else
  WAIT_MS=${WAIT_MS:-8000}
fi
G_NS=$(awk "BEGIN{printf \"%d\", $G_MS * 1000000}")

REGS="reg_gen,reg_active,reg_deadline,reg_ts_first_block,reg_ts_ack_arm,reg_ts_block_term,reg_ts_first_resp_release"
CTRS="ctr_arm,ctr_block_enq,ctr_block_loop,ctr_block_term_deadline,ctr_block_term_timeout,ctr_block_term_stale,ctr_ack_arm,ctr_ack_bypass,ctr_resp_enq,ctr_resp_release,ctr_nonibspg"

mkdir -p "$OUT" 2>/dev/null
PCAP=$OUT/${RUNID}.pcap
RJSON=$OUT/${RUNID}.read.json
VJSON=$OUT/${RUNID}.verify.json

# ---- remote helpers: every one of these is a no-op under DRYRUN=1 ----------
# The DRYRUN trace is written to a log as well as stderr, because several steps
# below redirect stderr away to keep a real run's output down to the RESULT line.
DRYLOG=""
[ "$DRYRUN" = "1" ] && DRYLOG=$(mktemp /tmp/p12_dryrun.XXXXXX)
_dry() {
  echo "$1" >&2
  [ -n "$DRYLOG" ] && echo "$1" >> "$DRYLOG"
  return 0
}
sw() {   # run on the switch, under the SDE environment
  local cmd="$*"
  if [ "$DRYRUN" = "1" ]; then _dry "DRYRUN sw   : $cmd"; return 0; fi
  sshpass -e ssh $SSHO $SW "bash -lc '$E; $cmd'"
}
hulk_sudo() {   # run on Hulk as root (raw AF_PACKET inject needs it)
  local cmd="$*"
  if [ "$DRYRUN" = "1" ]; then _dry "DRYRUN hulk : sudo $cmd"; return 0; fi
  sshpass -e ssh $SSHO $HULK "echo '$SSHPASS' | sudo -S -p '' $cmd"
}
vis_sudo() {    # run on Vision as root (capture)
  local cmd="$*"
  if [ "$DRYRUN" = "1" ]; then _dry "DRYRUN vis  : sudo $cmd"; return 0; fi
  sshpass -e ssh $SSHO $VIS "echo '$SSHPASS' | sudo -S -p '' bash -c '$cmd'"
}

# ---- 0. optional staging --------------------------------------------------
if [ "$STAGE" = "1" ]; then
  if [ "$DRYRUN" = "1" ]; then
    _dry "DRYRUN stage: scp $HARNESS/ibspg_p12_gen.py -> $HULK:$HULK_GEN"
    _dry "DRYRUN stage: scp $HARNESS/ibspg_p12_read.py -> $SW:$SWDIR/"
    _dry "DRYRUN stage: (setup script already on the switch at $SETUP; local copy $SETUP_LOCAL)"
  else
    sshpass -e scp $SSHO $HARNESS/ibspg_p12_gen.py $HULK:$HULK_GEN >/dev/null 2>&1
    sw "mkdir -p $SWDIR" >/dev/null 2>&1
    sshpass -e scp $SSHO $HARNESS/ibspg_p12_read.py $SW:$SWDIR/ >/dev/null 2>&1
  fi
fi

# ---- 1. optional one-time static config (2 strict-priority levels) --------
# Part 12 needs only Q_BLOCK qid7 HIGH > Q_RESP qid1 LOW, so the Part 11 setup script runs
# WITHOUT --paired. A leftover Q_ACK qid5 level from Part 11 is harmless: qid5 is never used.
if [ "$CONFIG" = "1" ]; then
  sw "python3 $SETUP --prog $PROG --config --qb 7 --qh 1 --host-ports 9,11 --port-l 8 --pg-l 2"
fi

# ---- 2. per-trial reset (control plane may reset + read, never release) ---
sw "python3 $SETUP --prog $PROG --reset --regs $REGS --counters $CTRS" >/dev/null 2>&1

# ---- 3. start the Vision-side capture ------------------------------------
# BOTH ethertypes: 0x88c0 = ACK + RESPONSE (the frames under test), 0x88c1 = blocker token.
# The tokens must never reach a host port, and filtering them out here would make the
# verifier's b2_no_blocker_escape check vacuous — absence of evidence, not evidence of absence.
vis_sudo "rm -f /tmp/p12.pcap; nohup tcpdump -i $VIF -Q in -w /tmp/p12.pcap -s 256 \"ether proto 0x88c0 or ether proto 0x88c1\" >/dev/null 2>&1 & true" >/dev/null 2>&1
[ "$DRYRUN" = "1" ] || sleep 1.2

# ---- 4. inject the whole scenario in ONE process on Hulk -----------------
GENOUT=$(hulk_sudo "python3 $HULK_GEN --iface $HIF --scenario $SCENARIO --k $K --budget $BUDGET \
  --g-ns $G_NS --gen $GEN --slot 0 --nack $NACK --nresp $NRESP --resp-id-start 1 \
  --resp-delay-ms $RESP_DELAY_MS --arm-settle-ms $ARM_SETTLE_MS --pad-to $PAD \
  --dst-mac $VMAC --src-mac $SNEUTRAL --runid $RUNID" 2>&1)
GENRC=$?
SPEC=$(echo "$GENOUT" | sed -n 's/.*"spec": *"\([^"]*\)".*/\1/p' | head -1)

# ---- 5. wait out the hold ------------------------------------------------
# normal: the deadline fires at ~G. negatives: the response is released only when
# every blocker has burned its pass BUDGET, so BUDGET and WAIT_MS must be
# calibrated together on the first real run (an unexhausted budget looks like a
# missing release, not a slow one).
[ "$DRYRUN" = "1" ] || $RPY -c "import time; time.sleep($WAIT_MS/1000.0)"

# ---- 6. stop the capture and fetch it ------------------------------------
vis_sudo "pkill tcpdump 2>/dev/null; sleep 0.4" >/dev/null 2>&1
if [ "$DRYRUN" != "1" ]; then
  sshpass -e scp $SSHO $VIS:/tmp/p12.pcap $PCAP >/dev/null 2>&1
fi

# ---- 7. read the on-chip evidence ----------------------------------------
J=$(sw "python3 $SWDIR/ibspg_p12_read.py --prog $PROG --g-ns $G_NS --regs $REGS --counters $CTRS 2>&1 | grep P12READ" 2>&1)
if [ "$DRYRUN" != "1" ]; then echo "$J" > $RJSON; fi

# ---- 8. verify locally ---------------------------------------------------
verify="SKIP"; abr="na"
if [ "$DRYRUN" != "1" ] && [ -n "$SPEC" ] && [ -s "$PCAP" ]; then
  VZ=$($RPY $VERIFY --released $PCAP --reader-json $RJSON --spec "$SPEC" \
       --scenario $SCENARIO --k $K --tol-ns $TOL_NS --json $VJSON 2>&1)
  verify=$(echo "$VZ" | grep -oE '"verdict": "[A-Z]+"' | grep -oE '(PASS|FAIL)' | head -1)
  abr=$(echo "$VZ" | grep -oE '"ack_before_resp": (true|false)' | grep -oE '(true|false)' | head -1)
fi
[ -z "$verify" ] && verify="FAIL"
[ -z "$abr" ] && abr="na"

# ---- 9. the single RESULT line -------------------------------------------
if [ "$DRYRUN" = "1" ]; then
  echo "--- DRYRUN: the remote commands this trial WOULD run, in order ---"
  [ -n "$DRYLOG" ] && { cat "$DRYLOG"; rm -f "$DRYLOG"; }
  echo "RESULT scenario=$SCENARIO k=$K g_ms=$G_MS nack=$NACK nresp=$NRESP DRYRUN=1 (nothing executed)"
  exit 0
fi
if [ "$GENRC" != "0" ] || [ -z "$SPEC" ]; then
  echo "RESULT scenario=$SCENARIO k=$K g_ms=$G_MS verify=FAIL gen=ERR rc=$GENRC msg=$(echo "$GENOUT" | tr '\n' ' ' | cut -c1-160)"
  exit 1
fi
echo "$J" | sed 's/^P12READ //' | $RPY -c "
import sys, json
d = json.loads(sys.stdin.read()); c = d['counters']; r = d['registers']; g = d['derived']
def gi(x):
    v = r.get(x) or 0
    return v if isinstance(v, int) else 0
def gn(x):
    v = g.get(x)
    return v if isinstance(v, int) else 0
ta = gi('reg_ts_ack_arm'); tr = gi('reg_ts_first_resp_release')
# NA = no qualifying ACK ever armed the deadline, which is the EXPECTED state for the
# stale-ack / unrelated-ack / no-ack scenarios — not an ordering failure.
if not ta:
    order = 'NA'
elif not tr:
    order = 'OK'
else:
    order = 'OK' if (((tr - ta) & 0xFFFFFFFF) < (1 << 31)) else 'BAD'
print('RESULT scenario=$SCENARIO k=$K g_ms=$G_MS nack=$NACK nresp=$NRESP '
      'arm=%s aarm=%s abyp=%s benq=%s bloop=%s tdl=%s ttmo=%s tstale=%s renq=%s rrel=%s '
      'g_obs_ns=%d dl_err_ns=%d tail_ns=%d order_ts=%s verify=$verify abr=$abr' % (
    c.get('ctr_arm'), c.get('ctr_ack_arm'), c.get('ctr_ack_bypass'), c.get('ctr_block_enq'),
    c.get('ctr_block_loop'), c.get('ctr_block_term_deadline'), c.get('ctr_block_term_timeout'),
    c.get('ctr_block_term_stale'), c.get('ctr_resp_enq'), c.get('ctr_resp_release'),
    gn('g_observed_ns'), gn('deadline_error_ns'), gn('release_tail_ns'), order))
"
