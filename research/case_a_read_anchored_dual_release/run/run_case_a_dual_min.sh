#!/usr/bin/env bash
# =============================================================================
#  run_case_a_dual_min.sh — driver for the MINIMAL SYNTHETIC DUAL-RELEASE GATE.
#
#  ---------------------------------------------------------------------------
#  RESTORATION IS NOT REIMPLEMENTED HERE.
#
#  The EXIT / INT / TERM / HUP trap calls
#
#      run/run_four_queue_oracle.sh --restore-only --no-tmux
#
#  which is the PROVEN restore path: converge-to-known-good (it does NOT cycle a
#  healthy switch), then verify five facts — p4_name, strict_priority_verified,
#  app_enable, exactly one bf_switchd, dp8 shaping restored. That path has
#  worked repeatedly including from a real failure. Nothing about it is copied,
#  edited, or re-derived here, and run_four_queue_oracle.sh is NOT modified: the
#  four-queue dequeue oracle is CLOSED (reports/FOUR_QUEUE_ORACLE_CLOSED.md) and
#  this script neither loads it, runs it, nor changes it.
#
#  Two mechanical details make the delegation work:
#    * the child is given its OWN lockfile. This script holds the shared
#      hardware lock for the whole run; if the child tried to take the same one
#      its `flock -n` would fail and restoration would not happen.
#    * the child is invoked with --no-tmux so it runs inline in this process
#      tree and its output is captured, rather than detaching into a session
#      this script would then have to wait on.
#
#  ---------------------------------------------------------------------------
#  MODES
#    --restore-only     perform ONLY the restoration + verification, then exit.
#                       Safe against a live, healthy Defense 2.
#    --run              EXACTLY FIVE normal synthetic transactions, then STOP.
#                       There is deliberately no flag that continues past five:
#                       the next step is a human decision taken after the five
#                       are reviewed.
#    --early-response   THREE runs of the early-response safety test. NOT run by
#                       --run, and not run automatically by anything.
#    --late-ack         THREE runs of the late-ack safety test. Likewise.
#    (default)          refuses to do anything — a mode must be named.
#
#  THE SAFETY TESTS ARE SEPARATE MODES ON PURPOSE. They are not five-plus-two:
#  each drives a different generator spacing and a different event role map, and
#  bundling them into the normal run would mean a single "the gate works"
#  verdict covering three different experiments.
#
#  ---------------------------------------------------------------------------
#  HARDWARE PRECONDITION THIS SCRIPT WILL NOT WORK AROUND
#  Every mode except --restore-only requires p4/case_a_dual_min.p4 to be LOADED.
#  This script does not load it. Loading displaces Defense 2 and is a separate,
#  explicitly authorized step.
#
#  No Hulk, no injector, no capture, no sudo on any host: every packet is
#  generated inside the chip and every result is read out of registers and
#  counters. dp9, dp11 and dp64 are never configured.
#
#  ---------------------------------------------------------------------------
#  PROCESS-CHECK NOTE (this has bitten this project before)
#  `pgrep -f bf_switchd` OVERCOUNTS — measured 3 for a single running daemon,
#  because the launcher command line contains the string and so does the
#  invoking shell's. Count with `pgrep -cx bf_switchd`, which matches the
#  executable NAME; use the [b]racket trick only for `pkill -f`. This script
#  does not count bf_switchd itself — the delegated restore does — but the note
#  stays here so the rule is not rediscovered.
#
#  LD_LIBRARY_PATH is always dereferenced as ${LD_LIBRARY_PATH:-}: an unset
#  variable under `set -u` previously aborted a swap AFTER the old program had
#  been stopped, leaving the switch with nothing loaded.
# =============================================================================
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# ---- switch identity --------------------------------------------------------
SW_HOST="${SW_HOST:-decps@10.10.54.81}"
SSH_OPTS="${SSH_OPTS:--o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5}"

SDE="${SDE:-/home/decps/Downloads/bf-sde-9.13.2}"
SP="$SDE/install/lib/python3.8/site-packages"
PYPATH="$SP:$SP/tofino"          # bfrt_grpc lives under site-packages/tofino

PROG="${PROG:-case_a_dual_min}"
CP_REMOTE="${CP_REMOTE:-/home/decps/cadm/case_a_dual_min_setup.py}"

# the proven restore, delegated to verbatim
RESTORE_RUNNER="$HERE/run_four_queue_oracle.sh"

# ---- run-local state --------------------------------------------------------
OUTDIR="${OUTDIR:-$ROOT/evidence/dual_min}"
LOCKFILE="${LOCKFILE:-${TMPDIR:-/tmp}/case_a_dual_min.lock}"
RUNTS="$(date -u +%Y%m%dT%H%M%SZ)"

DRYRUN="${DRYRUN:-0}"                 # 1 = no ssh, no hardware at all
NO_TMUX="${CADM_NO_TMUX:-0}"

MODE=""
N_NORMAL=5      # FIVE. Not configurable upward here.
N_SAFETY=3      # THREE each. Likewise.

# A/R and budgets are pass-through so a sweep needs no edit to this file.
A_MS="${A_MS:-3}"
R_MS="${R_MS:-13}"
BUDGET_A="${BUDGET_A:-20000}"
BUDGET_R="${BUDGET_R:-80000}"

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die()  { log "FATAL: $*"; exit 1; }

usage() {
  sed -n '2,60p' "${BASH_SOURCE[0]}" | sed 's/^#\{0,1\} \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --restore-only)   MODE="restore-only" ;;
    --run)            MODE="run" ;;
    --early-response) MODE="early-response" ;;
    --late-ack)       MODE="late-ack" ;;
    --no-tmux)        NO_TMUX=1 ;;
    --dry-run)        DRYRUN=1 ;;
    -h|--help)        usage 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done
[[ -n "$MODE" ]] || die "a mode is required: --restore-only | --run | \
--early-response | --late-ack"

mkdir -p "$OUTDIR"
[[ -x "$RESTORE_RUNNER" || -f "$RESTORE_RUNNER" ]] \
  || die "the proven restore runner is missing: $RESTORE_RUNNER"

# =============================================================================
#  ONE TMUX SESSION for the whole hardware transaction, so it survives the
#  terminal: if the controlling SSH session dies mid-run, a bare script would
#  take SIGHUP with the switch half-configured; inside tmux the script keeps
#  running and its EXIT trap still restores Defense 2. --no-tmux exists for
#  local dry-runs and for trap tests, which must run inline so a signal can be
#  delivered to this very process.
# =============================================================================
if [[ -z "${TMUX:-}" && "$NO_TMUX" != "1" ]]; then
  command -v tmux >/dev/null 2>&1 || die "tmux not found (or re-run with --no-tmux)"
  SESSION="cadm_${MODE//-/_}_$RUNTS"
  RCFILE="$OUTDIR/.tmux_rc_$RUNTS"
  TMUXLOG="$OUTDIR/tmux_${SESSION}.log"
  log "re-executing inside tmux session '$SESSION' (log: $TMUXLOG)"
  tmux new-session -d -s "$SESSION" \
    "CADM_NO_TMUX=1 '${BASH_SOURCE[0]}' --$MODE $( [[ $DRYRUN == 1 ]] && echo --dry-run ) \
       >'$TMUXLOG' 2>&1; echo \$? >'$RCFILE'"
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
#  flock — two runs can NEVER overlap.
# =============================================================================
exec 9>"$LOCKFILE"
if ! flock -n 9; then
  die "another run holds $LOCKFILE — refusing to start a second hardware transaction"
fi
log "acquired $LOCKFILE (pid $$)"

# =============================================================================
#  remote command transport. Commands are shipped base64-encoded and decoded on
#  the far side: nested single quotes inside `ssh host "bash -c '...'"` have
#  silently mangled commands in this project before, and base64 removes the
#  entire quoting problem. Carried from run/run_four_queue_oracle.sh:223.
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

cp_cmd() {
  cat <<EOF
export SDE=$SDE
export SDE_INSTALL=\$SDE/install
export LD_LIBRARY_PATH=\$SDE_INSTALL/lib:\${LD_LIBRARY_PATH:-}
PYTHONPATH=$PYPATH python3.8 $CP_REMOTE $*
EOF
}

# Reads the LOADED program name independently of any setup script, by finding
# the --conf-file bf_switchd was actually launched with and parsing it. This is
# authoritative: it reports what the daemon is running, not what a script
# believes it configured. Carried from run/run_four_queue_oracle.sh:285.
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
    echo '{"n_bf_switchd":1,"pid":"999999","conf":"/dryrun.conf","p4_name":"'"$PROG"'"}'
    return 0
  fi
  sw "$(switch_state_cmd)" | tail -1
}

json_field() {  # json_field <json> <key>
  python3 -c '
import json,sys
d=json.loads(sys.argv[1])
v=d.get(sys.argv[2])
print("" if v is None else v)
' "$1" "$2"
}

# =============================================================================
#  RESTORATION — delegated, not reimplemented. See the file header.
# =============================================================================
RESTORE_DONE=0

restore_defense2() {
  if [[ "$RESTORE_DONE" == "1" ]]; then
    log "restore already performed this run; not repeating"
    return 0
  fi
  RESTORE_DONE=1
  log "=========== RESTORING via $RESTORE_RUNNER --restore-only ==========="
  local rc=0
  # A private lockfile for the child: this process already holds the shared
  # hardware lock, and the child's own `flock -n` would otherwise fail and skip
  # the restore entirely.
  LOCKFILE="${TMPDIR:-/tmp}/cadm_child_restore_$$.lock" \
  OUTDIR="$OUTDIR" \
    bash "$RESTORE_RUNNER" --restore-only --no-tmux \
      $( [[ "$DRYRUN" == "1" ]] && echo --dry-run ) || rc=$?
  rm -f "${TMPDIR:-/tmp}/cadm_child_restore_$$.lock"
  if [[ $rc -eq 0 ]]; then
    log "RESTORE VERIFIED by the proven runner."
  else
    log "RESTORE VERIFICATION FAILED (rc=$rc)."
    log "DO NOT leave the switch in this state. Re-run: $RESTORE_RUNNER --restore-only"
  fi
  return $rc
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

log "mode=$MODE dryrun=$DRYRUN prog=$PROG"

# TEST HOOK. Not used in any real run. Holds the script in a known long-running
# state so INT / TERM / HUP can be delivered deterministically. The sleep is
# backgrounded and waited on, because bash does not run a trap until the current
# foreground builtin returns.
if [[ -n "${CADM_TEST_HANG:-}" ]]; then
  log "TEST HOOK: holding for ${CADM_TEST_HANG}s so a signal can be delivered"
  sleep "$CADM_TEST_HANG" &
  wait $! || true
  log "TEST HOOK: hold elapsed without a signal"
fi

if [[ "$MODE" == "restore-only" ]]; then
  log "restore-only: delegating to the proven runner"
  restore_defense2
  exit $?
fi

# =============================================================================
#  Everything below needs case_a_dual_min LOADED. This script does not load it.
# =============================================================================
PRE_STATE="$(switch_state)"
PRE_PROG="$(json_field "$PRE_STATE" p4_name)"
echo "$PRE_STATE" > "$OUTDIR/switch_state_snapshot_$RUNTS.json"
log "pre-run switch state: $PRE_STATE"

if [[ "$PRE_PROG" != "$PROG" && "$DRYRUN" != "1" ]]; then
  die "mode '$MODE' needs '$PROG' loaded, but the switch is running '$PRE_PROG'. \
Loading it displaces Defense 2 and is a separate, explicitly authorized step — \
this script will not do it. (The EXIT trap will still verify Defense 2 before \
returning.)"
fi

case "$MODE" in
  run)            SCENARIO="normal";         N_TXN=$N_NORMAL ;;
  early-response) SCENARIO="early-response"; N_TXN=$N_SAFETY ;;
  late-ack)       SCENARIO="late-ack";       N_TXN=$N_SAFETY ;;
  *) die "unreachable mode $MODE" ;;
esac

RUN_OUT="$OUTDIR/${MODE}_$RUNTS"
mkdir -p "$RUN_OUT"
log "=== $MODE: $N_TXN transaction(s), scenario=$SCENARIO, then STOP ==="
log "A=$A_MS ms  R=$R_MS ms  budgets $BUDGET_A / $BUDGET_R"
log "evidence: $RUN_OUT"

# One-time configuration: dp8 loopback + five queues, mirror session, parser
# value_set, both generator apps and both buffer templates, guard, event map.
log "--- one-time --config ---"
sw "$(cp_cmd --config --prog "$PROG" --scenario "$SCENARIO" \
        --a-ms "$A_MS" --r-ms "$R_MS" \
        --budget-a "$BUDGET_A" --budget-r "$BUDGET_R")" \
   >"$RUN_OUT/config.txt" 2>&1 \
  || log "WARN: --config reported failures; see $RUN_OUT/config.txt"

# Preflight cleanup. Every transaction REFUSES to start on a dirty switch, so
# without this the first one would refuse whenever the switch was left dirty by
# anything earlier. This is the ONLY place cleanup runs outside a transaction;
# between transactions it is the transaction's own `finally` that does it.
log "--- preflight cleanup + clean assertion ---"
sw "$(cp_cmd --cleanup --assert-clean --prog "$PROG")" \
   >"$RUN_OUT/preflight_clean.txt" 2>&1 \
  || log "WARN: preflight cleanup reported failures; see $RUN_OUT/preflight_clean.txt"

ok=0; err=0
for ((i = 1; i <= N_TXN; i++)); do
  # The generation ADVANCES every transaction, within the 0xC0..0xCF domain the
  # P4's tbl_txn_active ternary recognises. That is what makes "no stale
  # generation affects the next transaction" testable rather than assumed: a
  # token left over from transaction i-1 carries a generation the analyzer can
  # name, and the generation-bound ACK commitment refuses it.
  GEN=$(printf '0x%02X' $(( 0xC0 + ((i - 1) % 16) )))
  log "--- transaction $i/$N_TXN  scenario=$SCENARIO gen=$GEN ---"
  rjson="/tmp/cadm_${MODE}_${i}_${RUNTS}.json"
  ljson="$RUN_OUT/txn_$(printf '%02d' "$i").json"

  # The WHOLE transaction runs in ONE remote process: assert clean, program the
  # scenario, arm, wait on the token account, read, clean up. Keeping it in one
  # process means the arm and the read are local gRPC calls rather than ones
  # that have to cross an SSH hop.
  set +e
  sw "$(cp_cmd --txn --prog "$PROG" --scenario "$SCENARIO" --gen "$GEN" \
          --txn-index "$i" --a-ms "$A_MS" --r-ms "$R_MS" \
          --budget-a "$BUDGET_A" --budget-r "$BUDGET_R" --out "$rjson")" \
     >"$RUN_OUT/txn_$(printf '%02d' "$i").log" 2>&1
  trc=$?
  set -e

  if [[ "$DRYRUN" != "1" ]]; then
    # shellcheck disable=SC2086
    scp $SSH_OPTS "$SW_HOST:$rjson" "$ljson" >/dev/null 2>&1 \
      || log "WARN: could not fetch $rjson"
    sw "rm -f $rjson" >/dev/null 2>&1 || true
  fi

  if [[ $trc -eq 0 ]]; then
    ok=$((ok + 1)); log "  transaction $i completed with no failed checks"
  else
    err=$((err + 1)); log "  transaction $i reported failures (rc=$trc)"
  fi
done

{
  echo "mode=$MODE scenario=$SCENARIO n=$N_TXN a_ms=$A_MS r_ms=$R_MS"
  echo "budget_a=$BUDGET_A budget_r=$BUDGET_R"
  echo "clean=$ok with_failures=$err"
  echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$RUN_OUT/config.summary"

log "-------------------------------------------------------------"
log "$MODE COMPLETE: $N_TXN transaction(s) — clean:$ok with-failures:$err"
log "evidence: $RUN_OUT"
log ""
log "STOPPING HERE BY DESIGN. Review before anything else runs:"
log "  python3 $ROOT/analysis/analyze_case_a_dual_min.py --evidence-dir $RUN_OUT"
log ""
if [[ "$MODE" == "run" ]]; then
  log "The two SAFETY TESTS are separate modes and were NOT run:"
  log "  $0 --early-response      (3 runs)"
  log "  $0 --late-ack            (3 runs)"
  log ""
fi
log "The EXIT trap now restores Defense 2 via the proven runner."
exit 0
