/* phase04b_dcrn_conformance.c -- unprivileged userspace harness exercising the SAME decision core
 * (phase04b_dcrn_common.h) the eBPF data plane uses. Reads decision commands on stdin and prints
 * results, so the Python oracle (phase04b_dcrn_policy.py) can compare bit-for-bit and prove the
 * eBPF <-> Python decision logic conforms -- WITHOUT loading BPF (corrective.md sec 4).
 *
 * Build:  clang -O2 -I . -o phase04b_dcrn_conformance phase04b_dcrn_conformance.c
 * Protocol (one command per line):
 *   TARGET   <mode> <seed> <counter> <lo_ns> <hi_ns> <fixed_ns> <dhigh_ns>  -> <target_ns>
 *   COVERS   <cum_ack> <expected>                                           -> <0|1>
 *   CLASSIFY <plen> <ack> <syn> <fin> <rst> <dnp3> <confirm> <covers>       -> <kind 0|1|2>
 *   RELEASE  <kind> <ready_ns> <deadline_ns> <is_sep> <guard_ns> <fifo>     -> <release_ns> <miss>
 */
#include <stdio.h>
#include <string.h>
#include "phase04b_dcrn_common.h"

int main(void)
{
    char line[256], cmd[32];
    while (fgets(line, sizeof line, stdin)) {
        if (sscanf(line, "%31s", cmd) != 1)
            continue;
        if (!strcmp(cmd, "TARGET")) {
            struct dcrn_config c;
            unsigned m;
            unsigned long long seed, counter, lo, hi, fx, dh;
            if (sscanf(line, "%*s %u %llu %llu %llu %llu %llu %llu",
                       &m, &seed, &counter, &lo, &hi, &fx, &dh) == 7) {
                c.mode = m; c.seed = seed; c.lo_ns = lo; c.hi_ns = hi;
                c.fixed_ns = fx; c.dhigh_ns = dh; c.fifo_reliable = 0; c.guard_ns = 0;
                printf("%llu\n", (unsigned long long)dcrn_select_target_ns(&c, counter));
            }
        } else if (!strcmp(cmd, "COVERS")) {
            unsigned long long a, e;
            if (sscanf(line, "%*s %llu %llu", &a, &e) == 2)
                printf("%d\n", dcrn_ack_covers((__u32)a, (__u32)e));
        } else if (!strcmp(cmd, "CLASSIFY")) {
            int plen, ack, syn, fin, rst, dnp3, confirm, covers;
            if (sscanf(line, "%*s %d %d %d %d %d %d %d %d",
                       &plen, &ack, &syn, &fin, &rst, &dnp3, &confirm, &covers) == 8)
                printf("%d\n", dcrn_classify_reverse(plen, ack, syn, fin, rst, dnp3, confirm, covers));
        } else if (!strcmp(cmd, "RELEASE")) {
            int kind, is_sep, fifo, miss = 0;
            unsigned long long ready, deadline, guard;
            if (sscanf(line, "%*s %d %llu %llu %d %llu %d",
                       &kind, &ready, &deadline, &is_sep, &guard, &fifo) == 6) {
                struct dcrn_config c;
                c.guard_ns = guard; c.fifo_reliable = fifo;
                unsigned long long rel = dcrn_release_ns(kind, ready, deadline, is_sep, &c, &miss);
                printf("%llu %d\n", rel, miss);
            }
        }
    }
    return 0;
}
