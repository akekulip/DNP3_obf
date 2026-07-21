#!/usr/bin/env bash
# run_matrix.sh — QUEUE_MICROBENCH_PLAN §4 test matrix as concrete host/switch commands.
#
# This is a REFERENCE DRIVER, not a cross-host orchestrator. Each cell lists the three sites:
#   [SWITCH]  decps@10.10.54.15 : queue_microbench_setup.py (bring-up / mode / mech)  -- GATED
#   [VISION]  master/observe    : mb_capture.sh <iface> <out.pcap> <secs>
#   [HULK]    generator          : mb_gen.py --iface <dp9-iface> ...
# then parse anywhere:  mb_parse.py --pcap <out.pcap> --tau-ms <T> --pattern <P...>
#
# Run each cell against BOTH mechanisms (--mech pktgen | shaper) and BOTH modes where noted.
# Fill in the interface names for your rig. NOTHING here touches the switch until the review
# gate (hardware_authorized) is cleared; the [SWITCH] lines are the approved-run recipe.
#
# Env you set once per rig:
: "${DP9_IFACE:=enp1s0f0}"          # HULK NIC facing dp9
: "${DP8_IFACE:=enp59s0f0np0}"      # VISION NIC facing dp8
: "${SW:=decps@10.10.54.15}"        # switch (key-based ssh)
: "${TAU_MS:=10}"                   # metronome slot period
: "${OUT:=runs}"                    # output dir for pcaps
mkdir -p "$OUT"

cat <<'PLAN'
================= QUEUE_MICROBENCH_PLAN §4 MATRIX (commands per cell) =================
Legend:  [SWITCH]=gated bring-up  [VISION]=capture  [HULK]=generate  [PARSE]=offline

--- a. Sparse first-packet (the DNP3 case): one lone marked packet ---
  final/pktgen:
   [SWITCH] python3.8 queue_microbench_setup.py --mode final --mech pktgen --tau-ms $TAU_MS
   [VISION] sudo ./mb_capture.sh $DP8_IFACE $OUT/a_final_pktgen.pcap 15
   [HULK]   sudo python3 mb_gen.py --iface $DP9_IFACE --dports 20001 --count 1
   [PARSE]  python3 mb_parse.py --pcap $OUT/a_final_pktgen.pcap --tau-ms $TAU_MS --pattern S1 S2
  Repeat with --mech shaper (expect starvation per GridCloak B1 if R<~1200 pps).
  -> metrics: first-packet jitter, is the lone frame padded to its state & released on a slot.

--- b. Empty vs backlogged queue (the crux for a sparse flow) ---
  (i) empty:      [HULK] send 1 frame (as in a).
  (ii) backlogged:[HULK] sudo python3 mb_gen.py --iface $DP9_IFACE --dports 20001 20002 --count 500 --interval-ms 0.5
  -> metrics: does the scheduler emit the size-state on an empty queue (metronome: tick=chaff cover)
     or does round-robin SKIP the empty state (the Ditto/GridCloak empty-slot problem)?

--- c. Chaff / metronome requirement ---
  metronome-only (no host traffic): [HULK] send nothing; [VISION] capture 20 s.
  -> metrics: does the size-state pattern hold on a silent flow via chaff ticks alone?
     Compare frames: chaff!=0 means chaff was REQUIRED to keep the pattern (informs claim scope §4).

--- d. Background-load sensitivity (idle/low/mod/high) ---
  For LOAD in 0 / 200 / 2000 / 20000 pps  (interval-ms = 1000/LOAD):
   [HULK-bg]  sudo python3 mb_gen.py --iface $DP9_IFACE --dports 30000 --count <LOAD*20> --interval-ms <1000/LOAD> &
   [HULK]     sudo python3 mb_gen.py --iface $DP9_IFACE --dports 20001 20002 --count 200 --interval-ms $TAU_MS
  -> metrics: delay/jitter/loss/reorder + size-state conformity under each background level.

--- e. Release jitter (distribution of realized-vs-target release time) ---
  [HULK] sudo python3 mb_gen.py --iface $DP9_IFACE --dports 20001 --count 500 --interval-ms $TAU_MS
  -> metrics: mb_parse cadence block: within-tol fraction + |jitter| p50/p90/p99/max.

--- f. Packet ordering (ACK-before-response; size-state order; no held-frame reorder) ---
  [HULK] sudo python3 mb_gen.py --iface $DP9_IFACE --dports 20001 20002 --count 400 --interval-ms $TAU_MS
  -> metrics: mb_parse ordering (seq inversions=0 target) + size-state run-length vs P.

--- g. Loss (0-drop target in the sparse DNP3 regime) ---
  [HULK] sudo python3 mb_gen.py --iface $DP9_IFACE --dports 20001 --count 1000 --interval-ms $TAU_MS
  -> metrics: mb_parse loss block: missing / loss_frac over real seq (target 0).

--- h. Comparison vs the frozen recirc baseline (dcrn_defense*) ---
  Run the SAME arrival patterns against the recirc-hold program (dcrn_defense1/2, its own setup)
  and compare mean/median/std/p50/p90/p99/worst delay, load sensitivity, loss, reorder, resource
  cost (stages/SRAM) and complexity. Do NOT declare the queue better before this is complete.

Arrival patterns to sweep (per cell where relevant): 1 isolated · 1/20 ms · 1/10 ms · 1/2 ms ·
  bursts of 4 · mixed S1/S2.   Background: none · low · moderate · high.
=====================================================================================
PLAN
echo
echo "Set DP9_IFACE / DP8_IFACE / TAU_MS for your rig, then run the per-cell [HULK]/[VISION]/[PARSE]"
echo "lines by hand across hosts. [SWITCH] lines are GATED on review authorization."
