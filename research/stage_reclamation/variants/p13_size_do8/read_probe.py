#!/usr/bin/env python3
"""Read the P13 egress size/length probe. RUN INSIDE bfrt_python (bfshell), on the switch.

    bfshell -b /path/to/read_probe.py
    # or paste the body into an interactive `bfshell` -> `bfrt_python` session

Prints, for the run so far:
  * every non-zero bin of eg_intr_md.pkt_length   -> the ACTUAL length convention
  * every non-zero bin of hdr.ipv4.total_len      -> what the egress parser saw
  * how many frames reached IPv4 / TCP in the egress parser
  * ctr_size_normalized vs ctr_size_failopen      -> whether the fix fired

Registers are read live. The two COUNTERS need an explicit SyncCounters first, which
this script does -- without it a P4 Counter reads back 0 on this SDE.

NOT RUN BY ME: this was written compile-only and has never been executed against a
switch. If a field name is rejected, `bfrt.p13_size_do8.pipe.Egress.reg_eg_pktlen.info()`
will print the accepted spelling; the bfrt names came from out_probe/bfrt.json and are:
    pipe.Egress.reg_eg_pktlen   data Egress.reg_eg_pktlen.f1   key $REGISTER_INDEX
    pipe.Egress.reg_eg_totlen   data Egress.reg_eg_totlen.f1
    pipe.Egress.reg_eg_ipv4_ok  data Egress.reg_eg_ipv4_ok.f1
    pipe.Egress.reg_eg_tcp_ok   data Egress.reg_eg_tcp_ok.f1
    pipe.Egress.ctr_size_normalized / ctr_size_failopen  data $COUNTER_SPEC_PKTS
"""

EG = bfrt.p13_size_do8.pipe.Egress          # noqa: F821  (bfrt is injected by bfshell)


def reg_val(table, field, index):
    """One register entry, summed across the per-ALU copies the SDE returns."""
    e = table.get(REGISTER_INDEX=index, from_hw=True, print_ents=False)
    v = e.data[field]
    return sum(v) if isinstance(v, list) else v


def histogram(table, field, name, n=512):
    print("\n%s -- non-zero bins (index = the observed value):" % name)
    any_hit = False
    for i in range(n):
        v = reg_val(table, field, i)
        if v:
            any_hit = True
            print("    value = %3d   count = %d" % (i, v))
    if not any_hit:
        print("    (all bins zero -- no frame reached this point in egress)")


histogram(EG.reg_eg_pktlen, "Egress.reg_eg_pktlen.f1", "eg_intr_md.pkt_length")
histogram(EG.reg_eg_totlen, "Egress.reg_eg_totlen.f1", "hdr.ipv4.total_len (egress)")

print("\nparser progress in egress:")
print("    frames with IPv4 valid : %d" % reg_val(EG.reg_eg_ipv4_ok,
                                                  "Egress.reg_eg_ipv4_ok.f1", 0))
print("    frames reaching TCP    : %d" % reg_val(EG.reg_eg_tcp_ok,
                                                  "Egress.reg_eg_tcp_ok.f1", 0))

for nm, tbl in (("ctr_size_normalized", EG.ctr_size_normalized),
                ("ctr_size_failopen", EG.ctr_size_failopen)):
    tbl.operations_execute("SyncCounters")
    e = tbl.get(COUNTER_INDEX=0, from_hw=True, print_ents=False)
    print("%-22s = %s" % (nm, e.data[b"$COUNTER_SPEC_PKTS"]))

print("""
HOW TO READ THIS
  Inject ONE frame of known wire length W (e.g. the 108 B data_offset=5 RESPONSE).
  * pkt_length histogram lights up at W        -> pkt_length IS the wire length
                            at W + 4           -> it includes the FCS
                            at W - 14          -> it is the IP length
                            anywhere else      -> that offset is the convention
  * total_len histogram must light up at 94 for that frame; if it does not, the
    egress parser is not seeing the IP header we think it is.
  * 'frames reaching TCP' must equal the number of injected TCP frames; if it is 0,
    the egress parser stops before parse_tcp and size_norm cannot match by design.
  * ctr_size_normalized must now be NON-ZERO. The P13 fix no longer reads pkt_length,
    so the histogram is diagnostic only -- it does not gate the fix.
""")
