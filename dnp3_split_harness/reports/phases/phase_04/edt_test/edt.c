/* edt.c -- minimal tc-egress BPF program for the Phase 04 EDT load-and-release test.
 *
 * Sets each egress packet's earliest-departure-time to now + 30 ms; an `fq` root qdisc is
 * expected to hold the packet until then. Smallest program that exercises "a loaded BPF program
 * sets skb->tstamp AND fq enforces it" -- the behavioural check the feasibility report requires
 * before any DNP3 state machine is built. Forges nothing, edits no bytes.
 *
 * Build (needs the asm include path on Debian/Ubuntu):
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c edt.c -o edt.o
 *
 * Load + run (REQUIRES BPF-load privilege -- blocked non-sudo on this host because
 * kernel.unprivileged_bpf_disabled=2; see edt_load_release_test.md):
 *   tc qdisc add dev <if> clsact ; tc qdisc add dev <if> root fq
 *   tc filter add dev <if> egress bpf da obj edt.o sec tc
 *   # then capture and confirm packets depart ~30 ms late.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define DELAY_NS 30000000ULL   /* 30 ms */

SEC("tc")
int edt_egress(struct __sk_buff *skb)
{
    __u64 now = bpf_ktime_get_ns();
    skb->tstamp = now + DELAY_NS;
    return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
