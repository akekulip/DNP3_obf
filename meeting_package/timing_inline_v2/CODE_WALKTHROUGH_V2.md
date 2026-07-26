# Code walkthrough (corrected)

References are to `p4/dnp3_timing_normalizer_inline.p4`, the source of the loaded binary. The running
binary was built from sha256 `fb3b10dad575bed4…`; this file now carries a corrected header comment
and hashes to `dd9b816aea99b6d2…`, differing from the as-loaded revision in comments only (code verified
byte-identical). This is **Defense 2**: the RESPONSE is held, the ACK is not.

## Ports

```p4
const PortId_t PORT_L      = 9w8;   // internal loopback, blocker ring          :132
const PortId_t PORT_VISION = 9w9;   // master side                              :133
const PortId_t PORT_HULK   = 9w11;  // outstation side, REPLAY injector         :134
const PortId_t PORT_RELAY  = 9w64;  // outstation side, LIVE relay leg (E1/33)  :139
```

All four are below 128, so all are in pipe 0. That matters because the registers are per-pipe.

**Known scope issue, stated rather than fixed here:** this single binary accepts *both* `PORT_HULK`
and `PORT_RELAY` as outstation ingress (parser select, `:302-306`). In live operation dp11 is not
part of the path, so it is an unused acceptance path. Separating the live and replay builds is
listed as future work; it is not something these measurements depend on.

## Direction, decided before any header is read

```p4
transition select(ig_intr_md.ingress_port) {          // :302
    PORT_L      : from_loopback;
    PORT_HULK   : from_outstation;
    PORT_RELAY  : from_outstation;
    PORT_VISION : from_master;
    default     : accept;      // port_ok stays 0 -> dropped in the MAU
}
```

Frames from an unexpected port die early:

```p4
if (meta.port_ok == 8w0) { ctr_bypass.count(8w1); drop_pkt(); }    // :699
```

## Blocker tokens cannot be spoofed onto a host port

```p4
state parse_token {                 // :337
    pkt.extract(hdr.ib);
    meta.role   = ROLE_BLOCK;       // FORCED regardless of ingress port
    meta.gen_in = hdr.ib.gen;
    transition accept;
}
```

Ethertype `0x88C1` is always `ROLE_BLOCK`. Note this is about *role*, not about visibility: the
shipped captures used a filter that excluded `0x88C1`, so external visibility is untested in them.

## ACK forwarded immediately; RESPONSE parked

```p4
/* ACK from the outstation: forward at once, and arm the deadline. */
reg_t_ack    = ig_intr_md.ingress_mac_tstamp;
reg_deadline = reg_t_ack + G;                   // deadline_arm_once, :472

/* RESPONSE from the outstation: do not forward. Park it. */
ig_tm_md.ucast_egress_port = PORT_L;            // :578  dp8 loopback
ig_tm_md.qid               = QID_RESP;          // :579  qid 1, max_priority 0 (LOW)

/* BLOCKER token, once per lap. */
ig_tm_md.ucast_egress_port = PORT_L;            // :573
ig_tm_md.qid               = QID_BLOCK;         // :574  qid 7, max_priority 7 (HIGH)
hdr.ib.seq = hdr.ib.seq - 32w1;                 // :801  fail-open budget
```

Forwarding the ACK immediately is deliberate: holding it as well would move the fingerprint into
the request-to-ACK interval rather than remove it.

Nothing rewrites the response. It is queued, then dequeued. Byte preservation follows from the
construction — which is not the same as having proven byte identity on the live wire, and that
proof is absent here.

## Release

The blockers evaluate the deadline themselves, once per lap, because P4 ingress cannot express
"release this queued packet at time T". Expiry is decided by a ternary match on the sign bit of
`(now - deadline)`: a bit-slice inside a gateway condition is rejected as "condition expression too
complex", and slicing a 32-bit arithmetic field breaks PHV allocation outright.

Each token also carries a pass budget (`:801`) as a fail-open watchdog. A response released that way
is **not** protected; its CLRT is the fail-open time. `ctr_release_deadline` and
`ctr_release_fail_open` distinguish the two.

## Seeding, stated accurately

The 64-token reservoir is **seeded by the host** and then circulates internally on dp8. There is no
controller action per transaction, and the release decision is entirely data-plane. An internal
seeding design exists and compiles, but it did not produce these measurements.
