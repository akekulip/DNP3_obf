# papervizagent input specs — two methodology figures
# Run once OPENAI_API_KEY is a valid key. Verify EVERY technical label after generation
# (GPT-Image garbles exact tokens: qid IDs, dp ports, stage counts) and correct as needed.

## FIG-A — Tofino-1 pipeline WITH the Traffic Manager (TM) queues
Caption: "One Tofino-1 pipe: ingress parser and 12-stage MAU dispatch traffic into two Traffic-Manager
loopback scheduling domains, then egress to the relay."
Content (draw exactly, do not invent):
- Ingress: dp9 master (Vision) -> parser (DNP3/link-CRC) -> 12 MAU ingress stages with early
  packet-class dispatch (pclass) -> RRC | BOR | bypass (mutually exclusive) -> one meta.outcome ->
  one tbl_commit terminal -> one indexed outcome counter. Note "one pipe, <=12 ingress stages".
- Traffic Manager (TM): show it as the block holding the egress queues + strict-priority schedulers.
  Two independent internal-loopback scheduling domains (separate egress schedulers):
    * dp8 (RRC domain): strict-priority queues, high->low: qid7 ACK_BLOCK, qid6 ACK_HOLD,
      qid5 RESP_BLOCK, qid4 RESP_HOLD. (reservoir/hold queues; shaping OFF)
    * dp10 (BOR domain): qid3 OP_BLOCK, qid2 OP_HOLD.
  Show the strict-priority order (qid7 highest on dp8; qid3 highest on dp10) and that each domain
  is a distinct port with its own scheduler. Pktgen reservoirs feed the *_BLOCK queues.
- Ports: dp9 master ingress; dp64 relay egress (SEL-751 .7); dp68 internal pktgen/recirc + clone-mirror
  (NOT a host tap). dp8/dp10 are switch-internal loopbacks (not inline devices).

## FIG-B — RRC + BOR primitive mechanism
Caption: "The RRC size/CLRT primitive and the BOR bounded-OPERATE-release primitive."
Content (two linked panels; see RRC_BOR_PRIMITIVE.md for the authoritative description):
- RRC panel: relay response -> recirculate via dp8 loopback -> carve at DNP3 CRC block boundaries
  into [28,21] (byte-preserving, no CRC recompute) -> hold to fixed CLRT deadline -> master.
  dp8 ladder qid7 ACK_BLOCK > qid6 ACK_HOLD > qid5 RESP_BLOCK > qid4 RESP_HOLD.
- BOR panel: SELECT pre-seeds a BOR epoch (qid3 reservoir on dp10) -> OPERATE at T0 held in qid2 ->
  released once to relay at T0+J (J from secret codebook) -> ACK@T0+A, echo@T0+R anchored to T0,
  invariant to J (anti-subtraction). dp10 ladder qid3 OP_BLOCK > qid2 OP_HOLD.

## Generation record (2026-08-13)
Generated via papervizagent's DIAGRAM render path (OpenAI `gpt-image-2-2026-04-21`, 1536x1024,
quality high, opaque PNG; prompt = papervizagent DIAGRAM prompt_template wrapping the descs above).
API key supplied transiently via `OPENAI_API_KEY` env — never committed.
- FIG-A -> `figs/FIG-8_tofino_pipeline_pva.png`  (papervizagent rendition of the pipeline + TM queues)
- FIG-B -> `figs/FIG-10_rrc_bor_primitive_pva.png` (papervizagent rendition of the RRC/BOR primitive)
Label verification: every exact technical token (dp8/dp10/dp64/dp68/dp9, qid7..qid2, ACK_BLOCK/
ACK_HOLD/RESP_BLOCK/RESP_HOLD/OP_BLOCK/OP_HOLD, meta.outcome, tbl_commit, [28,21], T0+J/A/R,
echo-ACK=R-A, J in {2,6,12}) rendered CORRECTLY in both — no garbling. These raster renditions are
alternates; the vector exact-label masters remain `figs/FIG-8_tofino_pipeline.svg` and
`figs/FIG-10_rrc_bor_primitive.svg` (publication masters via `ieee-paper-figures`).
