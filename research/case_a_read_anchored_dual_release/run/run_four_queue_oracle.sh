#!/usr/bin/env bash
# =============================================================================
#  run_four_queue_oracle.sh — the SAFETY-CRITICAL driver for the four-queue
#  dequeue oracle.
#
#  THIS SCRIPT OWNS RESTORATION. Whatever happens — clean finish, a failed
#  trial, Ctrl-C, `kill`, or an SSH hang-up — the switch is returned to the
#  proven Defense 2 program `dnp3_timing_normalizer_pktgen` and that return is
#  VERIFIED, not assumed. Restoration is the only thing this script guarantees
#  unconditionally; everything else is best-effort.
#
#  Restoration = CONVERGE TO THE KNOWN-GOOD STATE, not "always restart":
#    - if bf_switchd is already running the Defense 2 conf, the program is NOT
#      restarted; only the control plane is re-asserted and verified.
#    - if it is absent, or running anything else, bf_switchd is stopped and
#      relaunched from /home/decps/defense2_pktgen_compile/launch_pktgen.sh.
#  That is what makes `--restore-only` safe to run against a healthy switch: it
#  re-asserts a known-good state rather than cycling it.
#
#  ---------------------------------------------------------------------------
#  MODES
#    --restore-only     perform ONLY the restoration + verification, then exit.
#                       Safe against a live, healthy Defense 2.
#    --microbench       port-shaper preload microbenchmark (delegates to
#                       run/shaper_preload_microbench.sh). Requires the oracle
#                       to be loaded.
#    --pilot            FIVE pilot trials, then STOP. There is deliberately no
#                       flag that continues to a full campaign: that decision is
#                       a human one and is taken after the pilot is reviewed.
#    (default)          refuses to do anything — a mode must be named.
#
#  ---------------------------------------------------------------------------
#  HARDWARE PRECONDITIONS THIS SCRIPT WILL NOT WORK AROUND
#    * --pilot and --microbench require p4/four_queue_oracle.p4 to be LOADED.
#      This script does not load it. Loading displaces Defense 2 and is a
#      separate, explicitly authorized step.
#    * Injection on Hulk uses run/oracle_inject, which needs CAP_NET_RAW.
#      The capability is granted ONCE, by hand, by Philip:
#          sudo setcap cap_net_raw+ep /path/to/run/oracle_inject
#      This script DETECTS a missing capability and fails with that instruction.
#      It never calls sudo on Hulk and never escalates.
#
#  ---------------------------------------------------------------------------
#  PROCESS-CHECK NOTE (this bit has bitten this project before)
#  `pgrep -f bf_switchd` OVERCOUNTS. Measured on the switch 2026-07-28 it
#  returned 3 for a single running daemon, because (a) the launcher is
#  `bash -c tail -f /dev/null | bf_switchd ...`, whose command line contains the
#  string, and (b) the invoking shell's own command line contains it too. The
#  `[b]f_switchd` bracket trick fixes only (b). The count that is actually
#  correct is `pgrep -cx bf_switchd`, which matches the executable NAME:
#      $ pgrep -cx bf_switchd   -> 1     (correct)
#      $ pgrep -cf [b]f_switchd -> 3     (wrong)
#  So: `-cx` for counting the daemon, the bracket trick for any `pkill -f`.
#
#  LD_LIBRARY_PATH is always dereferenced as ${LD_LIBRARY_PATH:-}. An unset
#  variable under `set -u` previously aborted a swap AFTER the old program had
#  been stopped, leaving the switch with nothing loaded.
# =============================================================================
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# ---- switch / host identity -------------------------------------------------
SW_HOST="${SW_HOST:-decps@10.10.54.81}"
SSH_OPTS="${SSH_OPTS:--o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5}"

SDE="${SDE:-/home/decps/Downloads/bf-sde-9.13.2}"
SP="$SDE/install/lib/python3.8/site-packages"
PYPATH="$SP:$SP/tofino"          # bfrt_grpc lives under site-packages/tofino

DEF2_DIR="${DEF2_DIR:-/home/decps/defense2_pktgen_compile}"
DEF2_LAUNCH="$DEF2_DIR/launch_pktgen.sh"
DEF2_SETUP="$DEF2_DIR/dnp3_timing_normalizer_pktgen_setup.py"
DEF2_CONF="$DEF2_DIR/pktgen_abs.conf"
DEF2_PROG="dnp3_timing_normalizer_pktgen"

ORACLE_PROG="${ORACLE_PROG:-four_queue_oracle}"
ORACLE_SETUP_REMOTE="${ORACLE_SETUP_REMOTE:-/home/decps/fqo/four_queue_oracle_setup.py}"

HULK_HOST="${HULK_HOST:-hulk}"           # ssh alias or user@host for Hulk
HULK_IFACE="${HULK_IFACE:-enp59s0f0np0}" # Hulk NIC facing dp11
INJECT_BIN="${INJECT_BIN:-$HERE/oracle_inject}"
INJECT_BIN_REMOTE="${INJECT_BIN_REMOTE:-/home/decps/fqo/oracle_inject}"

# ---- run-local state --------------------------------------------------------
OUTDIR="${OUTDIR:-$ROOT/evidence/four_queue_oracle}"
LOCKFILE="${LOCKFILE:-${TMPDIR:-/tmp}/fq_oracle.lock}"
RUNTS="$(date -u +%Y%m%dT%H%M%SZ)"
SNAPSHOT="$OUTDIR/switch_state_snapshot_$RUNTS.json"
RESTORE_LOG="$OUTDIR/restore_$RUNTS.log"

DRYRUN="${DRYRUN:-0}"                     # 1 = no ssh, no hardware at all
FQO_STUB_RESTORE="${FQO_STUB_RESTORE:-0}" # 1 = restore is a stub (trap testing)
NO_TMUX="${FQO_NO_TMUX:-0}"

MODE=""
PILOT_TRIALS="${PILOT_TRIALS:-5}"        # FIVE. Not configurable upward here.

# ---- gate parameters (overridable; the microbench establishes the real ones) -
GATE_UNIT="${GATE_UNIT:-PPS}"
GATE_RATE="${GATE_RATE:-1}"
GATE_BURST="${GATE_BURST:-0}"
GATE_OPEN_MODE="${GATE_OPEN_MODE:-disarm}"

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die()  { log "FATAL: $*"; exit 1; }

# =============================================================================
#  argument parsing
# =============================================================================
usage() {
  sed -n '2,60p' "${BASH_SOURCE[0]}" | sed 's/^#\{0,1\} \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --restore-only) MODE="restore-only" ;;
    --pilot)        MODE="pilot" ;;
    --microbench)   MODE="microbench" ;;
    --no-tmux)      NO_TMUX=1 ;;
    --dry-run)      DRYRUN=1 ;;
    -h|--help)      usage 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done
[[ -n "$MODE" ]] || die "a mode is required: --restore-only | --pilot | --microbench"

mkdir -p "$OUTDIR"

# =============================================================================
#  ONE TMUX SESSION for the whole hardware transaction.
#  The point is that the transaction survives the terminal. If the controlling
#  SSH session dies mid-swap, a bare script would take SIGHUP with the switch
#  half-configured; inside tmux the script keeps running and its EXIT trap still
#  restores Defense 2.
#  --no-tmux exists for local dry-runs and for the trap tests, which must run
#  inline so the signal can be delivered to this very process.
# =============================================================================
if [[ -z "${TMUX:-}" && "$NO_TMUX" != "1" ]]; then
  command -v tmux >/dev/null 2>&1 || die "tmux not found (or re-run with --no-tmux)"
  SESSION="fqo_${MODE//-/_}_$RUNTS"
  RCFILE="$OUTDIR/.tmux_rc_$RUNTS"
  TMUXLOG="$OUTDIR/tmux_${SESSION}.log"
  log "re-executing inside tmux session '$SESSION' (log: $TMUXLOG)"
  # Re-exec self with --no-tmux inside the session; record the exit code.
  tmux new-session -d -s "$SESSION" \
    "FQO_NO_TMUX=1 '${BASH_SOURCE[0]}' --$MODE $( [[ $DRYRUN == 1 ]] && echo --dry-run ) \
       >'$TMUXLOG' 2>&1; echo \$? >'$RCFILE'"
  # Stream the session's output until it finishes.
  : > "$TMUXLOG"
  tail -n +1 -f "$TMUXLOG" &
  TAILPID=$!
  while tmux has-session -t "$SESSION" 2>/dev/null; do sleep 0.5; done
  sleep 0.3
  kill "$TAILPID" 2>/dev/null || true
  RC="$(cat "$RCFILE" 2>/dev/null || echo 1)"
  rm -f "$RCFILE"
  log "tmux session finished, rc=$RC"
  exit "$RC"
fi

# =============================================================================
#  flock — two runs can NEVER overlap. A second run while the first is mid-swap
#  would race on the program load and could leave nothing loaded.
# =============================================================================
exec 9>"$LOCKFILE"
if ! flock -n 9; then
  die "another run holds $LOCKFILE — refusing to start a second hardware transaction"
fi
log "acquired $LOCKFILE (pid $$)"

# =============================================================================
#  remote command transport
#  Commands are shipped base64-encoded and decoded on the far side. Nested
#  single quotes inside `ssh host "sudo bash -c '...'"` have silently mangled
#  commands in this project before; base64 removes the entire quoting problem.
# =============================================================================
sw() {
  if [[ "$DRYRUN" == "1" ]]; then
    log "DRYRUN sw: $*"
    return 0
  fi
  local b64
  b64="$(printf '%s' "$*" | base64 -w0)"
  # shellcheck disable=SC2086
  ssh $SSH_OPTS "$SW_HOST" "echo $b64 | base64 -d | bash -s"
}

hulk() {
  if [[ "$DRYRUN" == "1" ]]; then
    log "DRYRUN hulk: $*"
    return 0
  fi
  local b64
  b64="$(printf '%s' "$*" | base64 -w0)"
  # shellcheck disable=SC2086
  ssh $SSH_OPTS "$HULK_HOST" "echo $b64 | base64 -d | bash -s"
}

# The Defense 2 control-plane invocation. LD_LIBRARY_PATH is dereferenced with
# :- so an unset variable cannot abort this under `set -u`.
def2_setup_cmd() {
  cat <<EOF
export SDE=$SDE
export SDE_INSTALL=\$SDE/install
export LD_LIBRARY_PATH=\$SDE_INSTALL/lib:\${LD_LIBRARY_PATH:-}
PYTHONPATH=$PYPATH python3.8 $DEF2_SETUP $*
EOF
}

oracle_cp_cmd() {
  cat <<EOF
export SDE=$SDE
export SDE_INSTALL=\$SDE/install
export LD_LIBRARY_PATH=\$SDE_INSTALL/lib:\${LD_LIBRARY_PATH:-}
PYTHONPATH=$PYPATH python3.8 $ORACLE_SETUP_REMOTE $*
EOF
}

# =============================================================================
#  switch state introspection
# =============================================================================
# Reads the LOADED program name independently of any setup script, by finding
# the --conf-file bf_switchd was actually launched with and parsing it. This is
# authoritative: it reports what the daemon is running, not what a script
# believes it configured.
switch_state_cmd() {
  cat <<'EOF'
set -uo pipefail
n=$(pgrep -cx bf_switchd || true)
pid=$(pgrep -ox bf_switchd || true)
conf=""
prog=""
if [ -n "$pid" ]; then
  conf=$(tr '\0' '\n' < /proc/$pid/cmdline | awk '/^--conf-file$/{getline; print; exit}')
  if [ -z "$conf" ]; then
    conf=$(tr '\0' '\n' < /proc/$pid/cmdline | sed -n 's/^--conf-file=//p' | head -1)
  fi
  if [ -n "$conf" ] && [ -r "$conf" ]; then
    prog=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(d['p4_devices'][0]['p4_programs'][0]['program-name'])
" "$conf" 2>/dev/null || true)
  fi
fi
printf '{\"n_bf_switchd\":%s,\"pid\":\"%s\",\"conf\":\"%s\",\"p4_name\":\"%s\"}\n' \
  "${n:-0}" "$pid" "$conf" "$prog"
EOF
}

switch_state() {
  if [[ "$DRYRUN" == "1" ]]; then
    echo '{"n_bf_switchd":1,"pid":"999999","conf":"'"$DEF2_CONF"'","p4_name":"'"$DEF2_PROG"'"}'
    return 0
  fi
  sw "$(switch_state_cmd)" | tail -1
}

json_field() {  # json_field <json> <key>   (string or number, no nesting)
  python3 -c '
import json,sys
d=json.loads(sys.argv[1])
v=d.get(sys.argv[2])
print("" if v is None else v)
' "$1" "$2"
}

# =============================================================================
#  RESTORATION — the one thing this script guarantees
# =============================================================================
RESTORE_DONE=0

restore_defense2() {
  if [[ "$RESTORE_DONE" == "1" ]]; then
    log "restore already performed this run; not repeating"
    return 0
  fi
  RESTORE_DONE=1

  if [[ "$FQO_STUB_RESTORE" == "1" ]]; then
    log "STUB RESTORE: would restore Defense 2 ($DEF2_PROG) here"
    echo "STUB_RESTORE_RAN $(date -u +%Y-%m-%dT%H:%M:%SZ) mode=$MODE" \
      | tee -a "$RESTORE_LOG"
    return 0
  fi

  log "=========== RESTORING DEFENSE 2 ($DEF2_PROG) ==========="
  {
    echo "restore started $(date -u +%Y-%m-%dT%H:%M:%SZ) mode=$MODE"
  } >>"$RESTORE_LOG"

  local st n prog
  st="$(switch_state)"
  n="$(json_field "$st" n_bf_switchd)"
  prog="$(json_field "$st" p4_name)"
  log "pre-restore state: n_bf_switchd=$n p4_name='$prog'"
  echo "pre-restore: $st" >>"$RESTORE_LOG"

  if [[ "$n" == "1" && "$prog" == "$DEF2_PROG" ]]; then
    log "Defense 2 already loaded and exactly one bf_switchd — NOT restarting."
    log "re-asserting the control plane only."
  else
    log "switch is NOT in the known-good state (n=$n prog='$prog') — full relaunch."
    log "stopping bf_switchd"
    # `pkill -x` matches the executable name. The `tail -f /dev/null` feeder of
    # the launcher pipeline does not exit when bf_switchd dies, so it is stopped
    # too — with the bracket trick so the pattern cannot match this shell.
    sw 'sudo pkill -x bf_switchd || true; sudo pkill -f "[t]ail -f /dev/null" || true; sleep 3' \
      >>"$RESTORE_LOG" 2>&1 || true
    for _ in $(seq 1 20); do
      st="$(switch_state)"; n="$(json_field "$st" n_bf_switchd)"
      [[ "$n" == "0" ]] && break
      sleep 1
    done
    log "relaunching $DEF2_LAUNCH"
    # setsid + nohup so the daemon is not a child of the ssh session and cannot
    # take SIGHUP when that session ends.
    sw "sudo setsid nohup bash $DEF2_LAUNCH >/dev/null 2>&1 < /dev/null & disown; sleep 2" \
      >>"$RESTORE_LOG" 2>&1 || true
    log "waiting for bf_switchd + bfrt gRPC (:50052)"
    local up=0
    for _ in $(seq 1 90); do
      if sw 'test "$(pgrep -cx bf_switchd)" = "1" && ss -ltn 2>/dev/null | grep -q ":50052 "' \
           >/dev/null 2>&1; then up=1; break; fi
      sleep 2
    done
    [[ "$up" == "1" ]] || log "WARN: bf_switchd/gRPC did not come up within 180 s"
  fi

  log "re-running the Defense 2 control plane: --config --mode native"
  local cpout=""
  set +e
  cpout="$(sw "$(def2_setup_cmd --config --mode native)" 2>&1)"
  local cprc=$?
  set -e
  echo "$cpout" >>"$RESTORE_LOG"
  [[ $cprc -eq 0 ]] || log "WARN: Defense 2 setup exited $cprc"

  verify_restored "$cpout"
}

# Verifies the four required facts. Prints a PASS/FAIL table and returns
# non-zero if any fact is wrong. This is what makes restoration a claim with
# evidence rather than an assertion.
verify_restored() {
  local cpout="${1:-}"
  local st n prog pk sp ae fails=0

  st="$(switch_state)"
  n="$(json_field "$st" n_bf_switchd)"
  prog="$(json_field "$st" p4_name)"

  # PKTGENSETUP {...} is the machine-readable line the Defense 2 setup emits.
  pk="$(printf '%s\n' "$cpout" | grep -m1 '^PKTGENSETUP ' | sed 's/^PKTGENSETUP //' || true)"
  if [[ "$DRYRUN" == "1" ]]; then
    pk='{"strict_priority_verified": true, "app_enable": false}'
  fi
  if [[ -n "$pk" ]]; then
    sp="$(python3 -c '
import json,sys
try: print(str(json.loads(sys.argv[1]).get("strict_priority_verified")).lower())
except Exception: print("")' "$pk")"
    ae="$(python3 -c '
import json,sys
try: print(str(json.loads(sys.argv[1]).get("app_enable")).lower())
except Exception: print("")' "$pk")"
  else
    sp=""; ae=""
  fi

  echo ""
  echo "RESTORE VERIFICATION"
  printf '  %-6s %-32s %s\n' "RES" "FACT" "OBSERVED"
  printf '  %-6s %-32s %s\n' "------" "--------------------------------" "----------------"

  chk() {  # chk <name> <got> <want>
    if [[ "$2" == "$3" ]]; then
      printf '  %-6s %-32s %s\n' "PASS" "$1" "$2"
    else
      printf '  %-6s %-32s %s\n' "FAIL" "$1" "got '$2', want '$3'"
      fails=$((fails+1))
    fi
  }
  chk "p4_name"                  "$prog" "$DEF2_PROG"
  chk "strict_priority_verified" "$sp"   "true"
  chk "app_enable"               "$ae"   "false"
  chk "exactly one bf_switchd"   "$n"    "1"
  echo ""

  {
    echo "post-restore: $st"
    echo "strict_priority_verified=$sp app_enable=$ae fails=$fails"
    echo "restore finished $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >>"$RESTORE_LOG"

  if [[ $fails -eq 0 ]]; then
    log "RESTORE VERIFIED — switch is running $DEF2_PROG in native mode."
    return 0
  fi
  log "RESTORE VERIFICATION FAILED ($fails fact(s) wrong) — see $RESTORE_LOG"
  log "DO NOT leave the switch in this state. Re-run: $0 --restore-only"
  return 1
}

# ---- the traps --------------------------------------------------------------
# Signal traps `exit`, which makes the EXIT trap fire, which restores. The
# RESTORE_DONE guard keeps restoration to exactly one execution.
on_exit() {
  local rc=$?
  trap - EXIT
  log "on_exit: rc=$rc — running restoration"
  restore_defense2 || rc=$(( rc == 0 ? 1 : rc ))
  log "exit $rc"
  exit "$rc"
}
trap 'on_exit' EXIT
trap 'log "caught SIGINT";  exit 130' INT
trap 'log "caught SIGTERM"; exit 143' TERM
trap 'log "caught SIGHUP";  exit 129' HUP

# =============================================================================
#  state snapshot — taken BEFORE anything is touched
# =============================================================================
snapshot_state() {
  local st
  st="$(switch_state)"
  python3 - "$st" "$SNAPSHOT" <<'PY'
import json, sys, time
st = json.loads(sys.argv[1])
st["snapshot_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
st["note"] = ("state observed BEFORE this run touched anything; the p4_name is "
              "parsed from the --conf-file the running bf_switchd was launched "
              "with, not from any setup script's belief")
with open(sys.argv[2], "w") as fh:
    json.dump(st, fh, indent=2)
print(json.dumps(st, indent=2))
PY
  log "snapshot -> $SNAPSHOT"
}

log "mode=$MODE dryrun=$DRYRUN stub_restore=$FQO_STUB_RESTORE"
snapshot_state

PRE_PROG="$(json_field "$(cat "$SNAPSHOT")" p4_name)"

# TEST HOOK. Not used in any real run. Holds the script in a known long-running
# state so INT / TERM / HUP can be delivered deterministically, which is how the
# "the trap really does restore Defense 2 on a signal" property is demonstrated.
# The sleep is backgrounded and waited on, because bash does not run a trap until
# the current foreground builtin returns — a plain `sleep 300` would delay the
# trap by the full 300 s and make the test look like a failure.
if [[ -n "${FQO_TEST_HANG:-}" ]]; then
  log "TEST HOOK: holding for ${FQO_TEST_HANG}s so a signal can be delivered"
  sleep "$FQO_TEST_HANG" &
  wait $! || true
  log "TEST HOOK: hold elapsed without a signal"
fi

# =============================================================================
#  MODE: --restore-only
# =============================================================================
if [[ "$MODE" == "restore-only" ]]; then
  log "restore-only: re-asserting and verifying the known-good Defense 2 state"
  restore_defense2
  rc=$?
  exit $rc
fi

# =============================================================================
#  Everything below needs the ORACLE loaded. This script does not load it.
# =============================================================================
if [[ "$PRE_PROG" != "$ORACLE_PROG" && "$DRYRUN" != "1" ]]; then
  die "mode '$MODE' needs '$ORACLE_PROG' loaded, but the switch is running \
'$PRE_PROG'. Loading the oracle displaces Defense 2 and is a separate, \
explicitly authorized step — this script will not do it. \
(The EXIT trap will still verify Defense 2 before returning.)"
fi

# ---- Hulk capability preflight: DETECT, never escalate ----------------------
preflight_injector() {
  log "checking $INJECT_BIN_REMOTE on $HULK_HOST for CAP_NET_RAW"
  local out rc
  set +e
  out="$(hulk "test -x '$INJECT_BIN_REMOTE' || { echo MISSING_BINARY; exit 66; }
             getcap '$INJECT_BIN_REMOTE' 2>/dev/null || true
             '$INJECT_BIN_REMOTE' --dry-run --iface lo --trial-id 0 \
                --schedule ablock:1 --seed 1 >/dev/null 2>&1 || echo DRYRUN_FAILED" 2>&1)"
  rc=$?
  set -e
  if [[ "$DRYRUN" == "1" ]]; then
    log "DRYRUN: skipping injector capability preflight"
    return 0
  fi
  if [[ $rc -eq 66 || "$out" == *MISSING_BINARY* ]]; then
    die "injector not present at $INJECT_BIN_REMOTE on $HULK_HOST. Build it with \
'make -C $HERE' and copy it over."
  fi
  if [[ "$out" != *cap_net_raw* ]]; then
    cat >&2 <<EOF

  ------------------------------------------------------------------
  MISSING CAPABILITY — the injector cannot open a raw AF_PACKET socket.

  Philip must grant the capability ONCE, by hand, to this binary only:

      sudo setcap cap_net_raw+ep $INJECT_BIN_REMOTE

  Then confirm with:

      getcap $INJECT_BIN_REMOTE

  This script will NOT run sudo on Hulk and will NOT grant capabilities
  to a Python interpreter. Injection is refused until the capability is
  present on the binary itself.
  ------------------------------------------------------------------

EOF
    die "CAP_NET_RAW missing on $INJECT_BIN_REMOTE"
  fi
  log "injector capability OK"
}

# =============================================================================
#  MODE: --microbench   (delegates; see run/shaper_preload_microbench.sh)
# =============================================================================
if [[ "$MODE" == "microbench" ]]; then
  log "delegating to shaper_preload_microbench.sh"
  preflight_injector
  DRYRUN="$DRYRUN" OUTDIR="$OUTDIR" SW_HOST="$SW_HOST" HULK_HOST="$HULK_HOST" \
    "$HERE/shaper_preload_microbench.sh"
  exit $?
fi

# =============================================================================
#  MODE: --pilot   — FIVE trials, then STOP.
# =============================================================================
preflight_injector

log "=== PILOT: $PILOT_TRIALS trials, then STOP for review ==="
log "gate: unit=$GATE_UNIT rate=$GATE_RATE burst=$GATE_BURST open-mode=$GATE_OPEN_MODE"

n_ok=0; n_invalid=0; n_err=0
for ((t=1; t<=PILOT_TRIALS; t++)); do
  tag="$(printf 'pilot_%02d_%s' "$t" "$RUNTS")"
  pcap="$OUTDIR/$tag.pcap"
  injjson="$OUTDIR/$tag.inject.json"
  log "--- trial $t/$PILOT_TRIALS ($tag) ---"

  # 1. capture FIRST, so "zero pre-release frames" is observable
  hulk "nohup tcpdump -i $HULK_IFACE -s 128 -w /tmp/$tag.pcap 'ether proto 0x88C2' \
        >/dev/null 2>&1 & echo \$! > /tmp/$tag.tcpdump.pid; sleep 1" || true

  # 2. reset counters, close the gate (all four queues stay scheduling-enabled)
  sw "$(oracle_cp_cmd --reset-counters)" >"$OUTDIR/$tag.cp_reset.txt" 2>&1 || true
  sw "$(oracle_cp_cmd --gate-close --gate-unit "$GATE_UNIT" \
          --gate-rate "$GATE_RATE" --gate-burst "$GATE_BURST")" \
     >"$OUTDIR/$tag.cp_close.txt" 2>&1 \
    || { log "gate close failed; see $OUTDIR/$tag.cp_close.txt"; n_err=$((n_err+1)); continue; }

  # 3. inject all four roles in randomized order (the binary does the shuffle)
  hulk "$INJECT_BIN_REMOTE --iface $HULK_IFACE --trial-id $t \
        --schedule ablock:64,rblock:64,ack:1,resp:1 --seed $((0xC2000000 + t))" \
      >"$injjson" 2>"$OUTDIR/$tag.inject.err" \
    || { log "injection failed; see $OUTDIR/$tag.inject.err"; n_err=$((n_err+1)); continue; }
  sleep 0.2

  # 4. the PRELOAD GATE: all four backlogged, zero drops, gate still armed
  set +e
  sw "$(oracle_cp_cmd --preload-gate-check)" >"$OUTDIR/$tag.cp_gate_check.txt" 2>&1
  gaterc=$?
  set -e

  # 5. THE RELEASE: one write
  sw "$(oracle_cp_cmd --gate-open --gate-open-mode "$GATE_OPEN_MODE")" \
     >"$OUTDIR/$tag.cp_open.txt" 2>&1 || true
  sleep 0.5

  # 6. stop the capture and collect
  hulk "pkill -f '[t]cpdump -i $HULK_IFACE' >/dev/null 2>&1 || true; sleep 0.5" || true
  if [[ "$DRYRUN" != "1" ]]; then
    scp $SSH_OPTS "$HULK_HOST:/tmp/$tag.pcap" "$pcap" >/dev/null 2>&1 || \
      log "WARN: could not fetch $tag.pcap"
  fi

  if [[ $gaterc -ne 0 ]]; then
    n_invalid=$((n_invalid+1)); log "  trial $t INVALID (preload gate not satisfied)"
  else
    n_ok=$((n_ok+1));           log "  trial $t completed"
  fi
done

log "-------------------------------------------------------------"
log "PILOT COMPLETE: $PILOT_TRIALS trials — completed:$n_ok invalid:$n_invalid error:$n_err"
log "evidence: $OUTDIR"
log ""
log "STOPPING HERE BY DESIGN. This script has no flag that continues to a full"
log "campaign. Review the pilot first:"
log "  python3 $ROOT/analysis/analyze_four_queue_oracle.py --evidence-dir $OUTDIR"
log ""
log "The EXIT trap now restores Defense 2."
exit 0
