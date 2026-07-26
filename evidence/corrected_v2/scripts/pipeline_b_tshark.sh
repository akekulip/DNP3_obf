#!/usr/bin/env bash
# Pipeline (b): independent CLRT extraction, tshark + awk only.
#
# Deliberately different from pipeline (a) in every dimension that could hide a
# shared bug:
#   * it TRUSTS the Wireshark DNP3 dissector (-d tcp.port==20000,dnp3) instead of
#     decoding DNP3 bytes itself;
#   * it uses RELATIVE TCP sequence numbers and tcp.nxtseq instead of raw
#     sequence numbers and seq+len arithmetic;
#   * it uses frame.time_relative instead of frame.time_epoch;
#   * it keys the pairing on the DNP3 APPLICATION SEQUENCE NUMBER rather than on
#     a positional scan through the packet list;
#   * it splits the TCP flags into individual boolean fields rather than parsing
#     a flags bitmask.
#
# Output (CSV to stdout):
#   app_seq,read_frame,read_nxtseq,ack_frame,ack_relack,resp_frame,clrt_ms,note
#
# Usage: pipeline_b_tshark.sh <pcap>

set -u
PCAP="${1:?usage: pipeline_b_tshark.sh <pcap>}"

tshark -r "$PCAP" \
    -d tcp.port==20000,dnp3 \
    -o tcp.relative_sequence_numbers:TRUE \
    -T fields -E separator='|' -E occurrence=f \
    -e frame.number \
    -e frame.time_relative \
    -e tcp.srcport \
    -e tcp.len \
    -e tcp.seq \
    -e tcp.ack \
    -e tcp.nxtseq \
    -e tcp.flags.syn \
    -e tcp.flags.fin \
    -e tcp.flags.reset \
    -e tcp.flags.ack \
    -e dnp3.al.func \
    -e dnp3.al.seq \
    -e dnp3.src \
    -e dnp3.dst \
2>/dev/null | awk -F'|' '
BEGIN {
    OFS = ","
    print "app_seq,read_frame,read_nxtseq,ack_frame,ack_relack,resp_frame,clrt_ms,note"
}
{
    fn = $1 + 0; t = $2 + 0; sport = $3 + 0; len = $4 + 0
    seq = $5 + 0; ack = $6 + 0; nxt = $7 + 0
    syn = ($8 == "True" || $8 == "1"); fin = ($9 == "True" || $9 == "1")
    rst = ($10 == "True" || $10 == "1"); ackf = ($11 == "True" || $11 == "1")
    func = $12; aseq = $13; dsrc = $14; ddst = $15

    from_outstation = (sport == 20000)

    # --- DNP3 READ from the master: anchor the transaction on its app sequence
    if (!from_outstation && func == "1") {
        s = aseq + 0
        if (s in read_frame) { note[s] = note[s] "app-seq " s " reused; " }
        read_frame[s] = fn
        read_nxt[s]   = (nxt > 0 ? nxt : seq + len)
        read_time[s]  = t
        order[++norder] = s
        next
    }

    # --- pure ACK from the outstation: match tcp.ack against a READ nxtseq
    if (from_outstation && len == 0 && !syn && !fin && !rst && ackf) {
        for (s in read_nxt) {
            if (read_nxt[s] == ack && !(s in ack_frame) && fn > read_frame[s]) {
                ack_frame[s] = fn; ack_time[s] = t; ack_relack[s] = ack
                break
            }
        }
        next
    }

    # --- DNP3 RESPONSE from the outstation: keyed on its own app sequence
    if (from_outstation && func == "129") {
        s = aseq + 0
        if (s in resp_frame) { note[s] = note[s] "duplicate RESPONSE for app-seq " s "; " }
        else { resp_frame[s] = fn; resp_time[s] = t }
        next
    }
}
END {
    for (i = 1; i <= norder; i++) {
        s = order[i]
        n = (s in note) ? note[s] : ""
        if (!(s in ack_frame)) { n = n "no qualifying ACK; " }
        if (!(s in resp_frame)) { n = n "no RESPONSE; " }
        if ((s in ack_frame) && (s in resp_frame)) {
            clrt = (resp_time[s] - ack_time[s]) * 1000.0
            if (resp_frame[s] < ack_frame[s]) n = n "RESPONSE precedes ACK; "
            printf "%d,%d,%d,%d,%d,%d,%.6f,%s\n", s, read_frame[s], read_nxt[s], \
                   ack_frame[s], ack_relack[s], resp_frame[s], clrt, n
        } else {
            printf "%d,%d,%d,,,,,%s\n", s, read_frame[s], read_nxt[s], n
        }
    }
}
'
