"""Model-only validation of xpipe_reflect_probe.p4's new fwd_mac table: can a P4 table reflect a
synthetic frame back out the SAME ingress port it arrived on, based on destination MAC, while an
unrelated port keeps the original xpipe_probe behavior untouched?

Run inside launch_model.sh's namespace against evidence/vepa_reflect_01/compile_local.

  integration/core/launch_model.sh -p evidence/vepa_reflect_01/compile_local -o evidence/vepa_reflect_01/model_01 \
      -P "1 2 9" -d evidence/vepa_reflect_01/model_drive_reflect.py

Port 9 stands in for the shared physical port two VEPA macvlans would share; MAC_A/MAC_B stand in
for the two test endpoints. Port 1 is left as a control -- the original xpipe_probe fwd table's
behavior for a plain, unmatched ingress port (no entry installed at all, default_action = deny()).
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE4 = HERE.parent.parent.parent
sys.path.insert(0, str(CASE4 / 'integration' / 'core'))
from model_driver import Model, same_frame  # noqa: E402

PROBE_TYPE = b'\x88\xb5'
MAC_A = bytes.fromhex('0a0000000011')
MAC_B = bytes.fromhex('0a0000000022')
MAC_RELAY = bytes.fromhex('0a0000000099')  # stands in for "the relay's own MAC", unrelated entry


def frame(src, dst, epoch=1, gen=1, expected=0, event=0):
    pfx = epoch.to_bytes(4, 'big') + gen.to_bytes(4, 'big') + expected.to_bytes(4, 'big') + event.to_bytes(2, 'big') + b'\x00\x00'
    return dst + src + PROBE_TYPE + pfx


m = Model()
for p in (1, 2, 9):
    m.drain([p])

ok = True


def check(name, actual, expected_ok):
    global ok
    result_ok = (actual == expected_ok)
    ok = ok and result_ok
    print('%-4s %-45s observed=%-6s expected=%-6s' % ('PASS' if result_ok else 'FAIL', name, actual, expected_ok))


# Install: on port 9, (dst=MAC_A) -> reflect to port 9; (dst=MAC_B) -> reflect to port 9.
# This is the exact pattern needed for two VEPA macvlan siblings sharing physical port 9.
# Single broadcast pipeline (matches case4_response_path.p4's structure; the original 4-distinct-
# pipeline Switch(p0,p1,p2,p3) failed to load on the real switch, which has only 2 physical pipes) --
# table names are plain pipe.Ingress.* here, no per-pipe prefix. Ports 1/2/9 are all pipe-0 locals.
m.add('Ingress.fwd_mac', {'ig.ingress_port': 9, 'hdr.eth.dst': int.from_bytes(MAC_A, 'big')},
      'Ingress.go_reflect', {'port': 9, 'do_mir': 0, 'sid': 0})
m.add('Ingress.fwd_mac', {'ig.ingress_port': 9, 'hdr.eth.dst': int.from_bytes(MAC_B, 'big')},
      'Ingress.go_reflect', {'port': 9, 'do_mir': 0, 'sid': 0})

# Preserve existing forwarding: port 2 still uses the plain port-only fwd table, unrelated to MAC.
m.add('Ingress.fwd', {'ig.ingress_port': 2}, 'Ingress.go_egress', {'port': 1, 'do_mir': 0, 'sid': 0})

# --- Case 1: A -> B's MAC, arriving on port 9, must come back out on port 9 (reflection works) ---
f_a_to_b = frame(MAC_A, MAC_B)
got = m.exchange(9, f_a_to_b, [1, 2, 9], timeout=1.0, quiet=0.3)
check('reflect_A_to_B_comes_back_on_port_9', len(got.get(9, [])) == 1 and len(got.get(1, [])) == 0 and len(got.get(2, [])) == 0, True)
if got.get(9):
    check('reflect_A_to_B_byte_identical', same_frame(got[9][0], f_a_to_b), True)

# --- Case 2: B -> A's MAC, arriving on port 9, must also reflect back out port 9 ---
f_b_to_a = frame(MAC_B, MAC_A)
got2 = m.exchange(9, f_b_to_a, [1, 2, 9], timeout=1.0, quiet=0.3)
check('reflect_B_to_A_comes_back_on_port_9', len(got2.get(9, [])) == 1 and len(got2.get(1, [])) == 0, True)

# --- Case 3: an unrelated destination MAC on port 9 (no fwd_mac entry) falls back to the ORIGINAL
#     xpipe_probe fwd table's behavior for ig.ingress_port=9 -- no entry installed there either,
#     so it must be DENIED (dropped), not silently misrouted anywhere. This models "preserve
#     existing forwarding for everything the new table doesn't specifically name": with no fwd
#     row for port 9 either, the fallback is the table's own safe default (deny), not reflection.
f_unrelated = frame(MAC_RELAY, MAC_RELAY)
got3 = m.exchange(9, f_unrelated, [1, 2, 9], timeout=0.6, quiet=0.3)
check('unmatched_mac_on_port_9_is_denied_not_misrouted', all(len(v) == 0 for v in got3.values()), True)

# --- Case 4: port 2's plain port-only forwarding (the "preserve existing relay forwarding" case)
#     still works exactly as xpipe_probe's original table would, untouched by the new table ---
f_plain = frame(MAC_RELAY, MAC_RELAY)
got4 = m.exchange(2, f_plain, [1, 2, 9], timeout=1.0, quiet=0.3)
check('port_2_plain_forwarding_untouched_goes_to_port_1', len(got4.get(1, [])) == 1 and len(got4.get(9, [])) == 0, True)

# --- Case 5 (negative-control rehearsal): remove port 9's reflection entries, confirm A->B no
#     longer reflects (falls to deny) -- the model-side dry run of the hardware negative control ---
# (Model driver has no live entry_del convenience here; re-run on a fresh Model connection with no
# rows installed demonstrates the same "no entry = deny" default already shown in case 3.)

print('OVERALL', 'PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
