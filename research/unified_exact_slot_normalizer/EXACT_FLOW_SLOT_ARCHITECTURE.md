# Exact flow-slot architecture (Part 2)

The static exact-match admission table that maps an admitted canonical DNP3 session to a compact `slot_id`,
control-plane-populated once at init, never in the fast path.

## Table: `flow_admission` (SRAM exact match, NOT TCAM)

```
table flow_admission {
    key = {
        meta.canon_master_ip  : exact;   // 32b
        meta.canon_out_ip     : exact;   // 32b
        meta.canon_master_port: exact;   // 16b  (DNP3 port is implicitly 20000; see below)
    }
    actions = { admit; bypass_unknown; }
    default_action = bypass_unknown;     // table MISS -> fail open
    size = FLOW_TABLE_SIZE;              // sized to configured sessions (e.g. 256/1024)
}
action admit(bit<SLOT_W> slot_id, bit<1> enabled, bit<2> policy_mode, bit<8> profile_id) {
    meta.slot_id = slot_id; meta.admitted = 1; meta.enabled = enabled;
    meta.policy_mode = policy_mode; meta.profile_id = profile_id;
}
action bypass_unknown() { meta.admitted = 0; classifier.count(EV_UNADMITTED_BYPASS); }
```

- **Key = 80 bits** (master IP, outstation IP, master TCP port). The DNP3 port (20000) is a **constant** the
  MAU already filters on before this table (only DNP3-flow frames reach admission), so it need not be a key
  field — implicit. If a deployment multiplexes several DNP3 services on one master, add the DNP3 port as a
  4th exact field (documented, +16b).
- **SRAM exact-match, no TCAM:** an 80-bit exact key is well within SRAM exact-match (hash-based match with
  the compiler's own collision handling inside the table — that is exact, not our state hashing). TCAM is
  used only if a wildcard/range field were required; none is. So `flow_admission` is 1 SRAM table stage.
- **Action data** = `slot_id` (SLOT_W bits, e.g. 8–12), `enabled`, `policy_mode` (0=BYPASS, 1=HOLD_ACK,
  2=HOLD_RESPONSE), `profile_id` (optional device/policy). Populated **once by the control plane at program
  init**; the control plane never touches matching/hold/release/cleanup in the fast path.

## Both directions → same `slot_id` (canonicalization vs paired entries)

**Canonicalization (chosen).** Before the table lookup, derive the canonical key from the physical
direction (`meta.dir`, already set from ingress port — dp9=dir0=master, dp11=dir1=outstation, GATE-1-proven):

```
if (meta.dir == 0) {  // master -> outstation (dst 20000)
    canon_master_ip = ip.src; canon_out_ip = ip.dst; canon_master_port = tcp.src_port;
} else {              // outstation -> master (src 20000)
    canon_master_ip = ip.dst; canon_out_ip = ip.src; canon_master_port = tcp.dst_port;
}
```

Both directions of one session resolve to the **same 80-bit canonical key → same table entry → same
`slot_id`**. This costs a few PHV moves gated on `dir` (one small MAU block, before the table) and uses **N**
table entries for N sessions.

**Paired entries (alternative).** Install two exact entries per session — one per literal 5-tuple direction
— both with the same `slot_id` action. No canonicalization logic, but **2N** entries and the control plane
must keep the pair consistent.

**Resource verdict:** canonicalization uses **half** the SRAM entries (N vs 2N) at the cost of one small
direction-gated PHV-move block that the pipeline already performs conceptually (the shadow/defenses already
canonicalize the flow-hash domain to `{client_ip, server_ip, client_port}`). For a static OT table this is a
minor stage cost and the cleaner, smaller design. **Choose canonicalization**; paired entries are the
fallback if the canonicalization block proves to cost a stage the budget can't spare (confirmed in Part 6).

## Unknown / unadmitted flows

Table miss → `bypass_unknown` → `meta.admitted=0`. The datapath then:
- forwards the frame **byte-identically** (the Phase-1 bump-in-the-wire path, incl. link-only → LINK_OTHER),
- allocates **no** timing state (no slot, no register touch),
- increments `EV_UNADMITTED_BYPASS` telemetry,
- never interferes with any admitted transaction.

This is the OT security property: only enumerated device sessions can arm timing state; an unknown or
hostile flow cannot allocate a slot, cannot collide with an admitted slot, and cannot trigger a release.

## Stage placement (estimate; confirmed in Part 6)

1. parser + prologue (dir, flags, payload_len, DNP3 parse — reused from the parser-hardened Phase-1).
2. canonicalization PHV block (dir-gated key select).
3. `flow_admission` exact-match table → `slot_id`, `policy_mode`, `admitted`.
4+. packed transaction-state register actions (Part 3), indexed by `slot_id`.

Because there is **no CRC flow-hash** and **no fingerprint-compare**, steps 2–3 are expected to cost about
the same as the frozen defense's `flow_hash` stage while removing the collision risk — leaving headroom the
hash design lacked (the Phase-2 generation-enforcement fit hypothesis).
