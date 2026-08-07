# A4 — specification-to-implementation-to-evidence matrix

Program: `defense4/timing/p4/defense4_caseA.p4` (sha256 `1272679…`, the committed blob that
produced the loaded binary `0ec4e452…`). Spec: `defense4/TIMING_SPEC.md`. Columns: what the spec
requires | what the committed P4 implements (line cites) | what the compiler proves | what silicon
evidence proves so far | what remains unverified. Findings verified against the primary P4 source;
independent P4/DNP3 expert analyses corroborate the rows marked (agent-corroborated).

## Resolved architecture questions (the instruction's "resolve rather than hide" list)

| question | resolution (primary evidence) |
|---|---|
| "internal generation" vs DNP3 app-sequence | **It is the DNP3 application-control octet.** `meta.gen_in = hdr.dnp3_app.app_control`; `dnp3_app_h{app_control,func_code}` (P4:708); READ admitted only when `(app_control & 0xF0)==0xC0` (P4:1196,1202). No data-plane generation arithmetic — the master supplies the rolling app-seq. |
| 16-value reuse interval | **Confirmed = 16.** Generation domain is `0xC0..0xCF` (P4:457), plus `0x00`=INACTIVE. block.py enumerates C0..CF then repeats (block.py:24,61). A real rollover test = ≥17 consecutive protected READs on ONE connection, verifying poll #(k+16) cannot alias poll #k's stale token/RESPONSE. |
| mode latched per-txn or read per-packet | **Read per-packet** from `tbl_params` default action (`set_params` sets `meta.mode` P4:1861; keyless table P4:1864). A policy change takes effect on the next packet, so set-policy MUST be refused while a transaction is active (drives B1). |
| concurrent READ overwriting session trackers | **Guarded.** `tag_arm` compare-and-arm-once writes only from `v==TAG_INACTIVE` (P4:125-134); a duplicate/concurrent READ cannot re-arm or push the tag. To be stress-tested on silicon (D7). |
| combined ACK-bearing RESPONSE | **Reaches a bounded fail-open, not a clean bypass** (agent-corroborated). A data-bearing segment cannot be ROLE_ACK (needs zero payload); T_RESP arms only on a native separate ACK, which never comes for Case B, so the held RESPONSE drains on the budget at H≈30.8 ms. Clean bypass only under OFF/FAIL_OPEN. Moot for the Case-A SEL-751; a combined-response detector is PROPOSED in spec §10, NOT implemented. |
| protects only READ? | **Yes.** Only func 1 (READ) reaches `set_role_arm`→`tag_arm` (P4:291,304,1228-1233). |
| SELECT(3)/OPERATE(4)/DIRECT_OPERATE(5) | **Bypass transparently** via `default: accept`→ROLE_BYPASS; never arm; their func-129 response bypasses as `CF_RESP_BYPASS` when no txn is active. Test only against a software outstation; never physical SELECT/OPERATE. |
| both reservoirs established before the physical ACK? | **Relies on measured timing margin, not an explicit readiness guard** (to confirm with the P4 agent + D9). The READ seeds a 2K=128 burst; the reservoir must stand before the ~0.45 ms native READ→ACK. Silicon: bring-up txn2 shows qid7=43/qid5=64 standing, but establishment-vs-ACK timing is not directly measured yet (D9 runtime bottleneck). |
| FIN/RST + missing-event cleanup in the integrated source | Generation-qualified cleanup + budget fail-open present per spec §7; explicit FIN/RST path presence to be confirmed by the P4 agent and exercised in D3/D7. |

## Property matrix

| property | spec requires | P4 implements | compiler proves | silicon so far | unverified / differs |
|---|---|---|---|---|---|
| OFF bypass | forward ACK+RESP immediately, no arm | ROLE_BYPASS paths, pktgen disabled | places 12/12 | bring-up OFF n=1 clrt 1.82 ms native | native distribution needs n≥100 (D4 OFF) |
| D1 event release | ACK held until RESPONSE event or budget, not ordinary deadline | event/budget release, not ACK deadline (agent-corr.) | placed | **SUPPORTED**: 17 D1, clrt→0.03 ms, ACK held ~8 ms (blk_t2.pcap) — but all C0, no rollover | event-not-deadline release under a LATE response not yet forced (D4-D1) |
| D2 response deadline | RESP held to T_RESP=t_A+D_R | to_resp_hold qid4, tresp_arm_once on native ACK | placed | **NOT DEMONSTRATED**: D_R was 32.768 µs << ~2 ms native; RESP never held (qid4 wm=0) | needs D_R > native RESP for a substantial trial fraction (D4-D2, D5) |
| D3 ACK deadline | ACK held to T_A=t_A+D_A | default mode; to_hold qid6 | placed | **NOT YET RUN** in integrated program | run integrated D3 (D4-D3) |
| D4 dual deadline | ACK to T_A, RESP to T_RESP, ACK commits first | dual deadline | placed | **NOT DEMONSTRATED** as shaping (both 32.768 µs) | meaningful D_A/D_R, both-cause attribution (D4-D4) |
| configured FAIL_OPEN | true bypass, pktgen disabled | FAIL_OPEN ∉ pktgen-enabled | placed | bring-up n=1 bypass | fine as-is |
| runtime fail-open transition | bounded release on missing ACK/RESP/budget-zero | budget_zero→CD_BLOCK_TERM_TMO→CD_RELEASE_FAILOPEN | placed | **NOT INDUCED** | induce missing-ACK / missing-RESP / zero-budget (D3) |
| separate ACK (Case A) | CLRT defined; protect | ROLE_ACK requires zero-payload segment | placed | forwards real SEL-751 ACK/RESP | — |
| combined ACK-RESP (Case B) | bypass or bounded fail-open | bounded fail-open at H≈30.8 ms | placed | out of scope (SEL-751 is Case A) | detector PROPOSED not built |
| generation source + rollover | per-transaction generation | DNP3 app-control 0xC0..0xCF, 16 codes | placed | **rollover NOT exercised** (C0 only) | real ≥33-READ rollover, all modes (D2) |
| exact flow/transaction matching | port + 4-tuple + gen + seq gates | §8.1/§8.2 conjuncts (ingress_port==PORT_RELAY, gen match, EXP_ACK) | placed | matched real relay traffic | wrong-seq/wrong-ack/wrong-flow negatives (D7) |
| one-shot admission | 2K=128 split 64/64 by packet_id | packet_id[6] split to SLOT_ACK/SLOT_RESP | placed | txn2 admit=128; qid5=64, qid7=43(drains) | 64/64 per-reservoir inferred not directly counted (D7/B4) |
| duplicate READ/ACK/RESP | reject re-arm, suppress dup | arm-once; dup handling | placed | not exercised | inject dups (D7) |
| concurrent transactions | one active per domain | atomic {active,gen} guard | placed | not exercised | overlap test (D7) |
| missing ACK / missing RESP | bounded fail-open | budget watchdog | placed | not induced | D3 |
| FIN/RST cleanup | generation-qualified teardown | spec §7; presence TBC | placed | not exercised | confirm + test (D3/D7) |
| timestamp wrap | modular compare, half-range horizon | modular sign-bit mask, horizon<2^31 | placed | not exercised | wrap test (D7) |
| blocker isolation | 0x88C1 never escapes to master | forced ROLE_BLOCK + PORT_L confinement + drop (NOT deparser strip) | placed | 0 drops in short run; escape NOT independently checked (filter was host relay_ip) | full-Ethernet capture for 0x88C1 escape (B4/D6) |
| byte preservation | no field/CRC/length edit | only hdr.ib.seq (token's own) written; originals queue-resident | placed | responses delivered | byte-identity check vs golden (B4/D6) |
| supported DNP3 functions | define boundary | READ arms; SELECT/OPERATE bypass; func129 held/bypass | placed | READ on relay | SELECT/OPERATE on software outstation (D8) |
| resource / stage limits | ≤12 ingress | 12/12, CP 10, 12 SALU (caseA_9132_deployment_compile.txt) | **12/12 proven** on 9.13.2 | loaded + ran | raw placement artifacts + next-limit (D9) |

## Net position going into Part B/D

The audit resolves the architecture questions and confirms the mechanism is real for load/forward,
two-reservoir split, and D1 event-release. It also fixes the exact experiments still owed:
generation rollover, D2/D3/D4 deadline shaping with realized deadlines above native, induced
fail-open, negative/adversarial coverage, byte-identity and token-escape verification, and the
resource/runtime bottleneck characterization. These are Part D. (Rows citing "the P4 agent" will be
reconciled when that analysis returns; none of the Part-B/D work is blocked on it.)
