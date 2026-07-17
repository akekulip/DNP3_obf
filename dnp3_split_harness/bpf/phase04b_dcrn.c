/* phase04b_dcrn.c -- DCRN dual-case tc/eBPF data plane (corrective.md sec 3-10).
 *
 * ONE object, TWO tc programs sharing three maps (config, counter, flows). Kept in one object
 * because the legacy iproute2 (ss200127) loader on this host has no BTF/bpftool and sharing maps
 * across two separate objects would need pinning; a single object shares maps natively. Attach:
 *   tc filter add dev <ifc> ingress bpf da obj phase04b_dcrn.o sec ingress
 *   tc filter add dev <ifc> egress  bpf da obj phase04b_dcrn.o sec egress
 *   tc qdisc  add dev <ifc> root fq                 # fq enforces the EDT (skb->tstamp)
 *
 * ingress: arm per-flow state for a payload-bearing master->outstation DNP3 READ request.
 * egress : classify the reverse pure ACK vs ACK-bearing RESPONSE and stamp skb->tstamp (EDT).
 * Decision logic lives entirely in phase04b_dcrn_common.h (shared with the userspace conformance
 * harness + mirrored by the Python oracle). Byte-preserving: only skb->tstamp is written.
 *
 * Build (no -g, to avoid the old-iproute2 .BTF rejection; matches ack_edt.c):
 *   clang -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
 *         -c phase04b_dcrn.c -o phase04b_dcrn.o
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define __BPF__ 1
#include "phase04b_dcrn_common.h"

/* legacy iproute2 map definition (no BTF required) */
struct bpf_elf_map {
    __u32 type; __u32 size_key; __u32 size_value; __u32 max_elem;
    __u32 flags; __u32 id; __u32 pinning;
};

/* Compile-time configuration (overridable with -D at build time). Built as a stack struct from plain
 * immediates -- NOT a const global -- so the legacy no-BTF iproute2 loader needs no .rodata map or
 * bpftool to populate config. The prepare script compiles a fixed and a bounded variant. */
#ifndef DCRN_MODE_CFG
#define DCRN_MODE_CFG   DCRN_MODE_FIXED
#endif
#ifndef DCRN_FIXED_NS
#define DCRN_FIXED_NS   32390000ULL      /* 32.39 ms, from calibration */
#endif
#ifndef DCRN_LO_NS
#define DCRN_LO_NS      32390000ULL
#endif
#ifndef DCRN_HI_NS
#define DCRN_HI_NS      42390000ULL
#endif
#ifndef DCRN_SEED_CFG
#define DCRN_SEED_CFG   20260717ULL
#endif
#ifndef DCRN_GUARD_NS
#define DCRN_GUARD_NS   200000ULL        /* provisional 0.2 ms guard; re-calibrate (sec 8) */
#endif
#ifndef DCRN_FIFO_CFG
#define DCRN_FIFO_CFG   0
#endif
#ifndef DCRN_DHIGH_NS
#define DCRN_DHIGH_NS   151000000ULL     /* RTO-safe ceiling (211-60 ms) */
#endif

static __always_inline struct dcrn_config cfg(void)
{
    struct dcrn_config c = {};
    c.mode = DCRN_MODE_CFG; c.fifo_reliable = DCRN_FIFO_CFG; c.fixed_ns = DCRN_FIXED_NS;
    c.lo_ns = DCRN_LO_NS; c.hi_ns = DCRN_HI_NS; c.seed = DCRN_SEED_CFG;
    c.guard_ns = DCRN_GUARD_NS; c.dhigh_ns = DCRN_DHIGH_NS;
    return c;
}

struct bpf_elf_map SEC("maps") dcrn_ctr = {
    .type = BPF_MAP_TYPE_ARRAY, .size_key = sizeof(__u32),
    .size_value = sizeof(__u64), .max_elem = 1, .pinning = 2,
};
struct bpf_elf_map SEC("maps") dcrn_flows = {
    .type = BPF_MAP_TYPE_LRU_HASH, .size_key = sizeof(__u64),
    .size_value = sizeof(struct dcrn_flow), .max_elem = 4096, .pinning = 2,
};

struct hdrs {
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u8 *payload;
    int payload_len;
};

static __always_inline int parse(struct __sk_buff *skb, struct hdrs *h)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return 0;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return 0;
    if (ip->protocol != IPPROTO_TCP) return 0;
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip)) return 0;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end) return 0;
    __u32 doff = tcp->doff * 4;
    if (doff < sizeof(*tcp)) return 0;
    __u32 tot = bpf_ntohs(ip->tot_len);
    h->ip = ip; h->tcp = tcp;
    h->payload = (__u8 *)tcp + doff;
    h->payload_len = (int)tot - (int)ihl - (int)doff;
    return 1;
}

/* master-side flow key (network-order addr<<16 | network-order port); identical for a flow at
 * ingress (master=source) and egress (master=dest). */
static __always_inline __u64 key_master(__u32 maddr, __u16 mport)
{
    return ((__u64)maddr << 16) | (__u64)mport;
}

/* Is this ingress packet a payload-bearing master->outstation DNP3 READ request? Reads the DNP3
 * start bytes (0x0564) and the application function code at payload offset 12 with bounds checks. */
static __always_inline int is_read_request(struct __sk_buff *skb, struct hdrs *h)
{
    if (bpf_ntohs(h->tcp->dest) != DCRN_DNP3_PORT || h->payload_len < 13)
        return 0;
    /* The DNP3 payload is often NOT in the linear region on the tc-ingress path, so direct
     * data..data_end access fails. bpf_skb_load_bytes reads across the (possibly paged) skb. */
    __u32 off = (__u32)((long)h->payload - (long)(void *)(long)skb->data);
    __u8 b[13];
    if (bpf_skb_load_bytes(skb, off, b, sizeof(b)) < 0)
        return 0;
    if (b[0] != 0x05 || b[1] != 0x64)
        return 0;                                 /* not DNP3 */
    if (b[12] != DCRN_READ_FC)
        return 0;                                 /* only routine READ arms (allowlist) */
    return 1;
}

SEC("ingress")
int dcrn_ingress(struct __sk_buff *skb)
{
    struct hdrs h;
    if (!parse(skb, &h))
        return TC_ACT_OK;
    if (!is_read_request(skb, &h))
        return TC_ACT_OK;                         /* handshake / non-READ / control -> not armed */

    struct dcrn_config cc = cfg();
    struct dcrn_config *c = &cc;
    if (c->mode == DCRN_MODE_NATIVE)
        return TC_ACT_OK;

    __u32 zero = 0;
    __u64 *ctr = bpf_map_lookup_elem(&dcrn_ctr, &zero);
    __u64 counter = 0;
    if (ctr) {                    /* plain read+write: clang-10 BPF cannot use XADD's return value,
                                     and a class-independent counter needs no strict cross-CPU atomicity */
        counter = *ctr;
        *ctr = counter + 1;
    }

    __u64 target = dcrn_select_target_ns(c, counter);
    if (!dcrn_target_safe(c, target))
        return TC_ACT_OK;                         /* FAIL OPEN: unsafe target -> native */

    __u64 now = bpf_ktime_get_ns();
    __u64 key = key_master(h.ip->saddr, h.tcp->source);
    struct dcrn_flow f = {};
    f.req_arrival_ns = now;
    f.deadline_ns = now + target;
    f.expected_ack = bpf_ntohl(h.tcp->seq) + (__u32)h.payload_len;
    f.armed = 1;
    bpf_map_update_elem(&dcrn_flows, &key, &f, BPF_ANY);
    return TC_ACT_OK;
}

SEC("egress")
int dcrn_egress(struct __sk_buff *skb)
{
    struct hdrs h;
    if (!parse(skb, &h))
        return TC_ACT_OK;
    if (bpf_ntohs(h.tcp->source) != DCRN_DNP3_PORT)
        return TC_ACT_OK;                         /* only outstation->master reverse packets */

    __u64 key = key_master(h.ip->daddr, h.tcp->dest);
    struct dcrn_flow *f = bpf_map_lookup_elem(&dcrn_flows, &key);
    if (!f || !f->armed) {
        return TC_ACT_OK;
    }
    /* NOTE: an earlier response_seen guard here bypassed trailing ACKs, but on a persistent polling
     * connection it also bypassed every transaction after the first (the per-request re-arm did not
     * reliably clear it before the next response egressed). Removed: each response is scheduled; the
     * READ-only + covers checks already exclude the trailing client-ACK/CONFIRM path. */

    struct dcrn_config cc = cfg();
    struct dcrn_config *c = &cc;
    if (c->mode == DCRN_MODE_NATIVE)
        return TC_ACT_OK;

    int covers = dcrn_ack_covers(bpf_ntohl(h.tcp->ack_seq), f->expected_ack);
    /* DNP3 CONFIRM detection on the reverse response would need a payload-offset read; the first
     * executable version treats any covering payload-bearing response as the RESPONSE and leaves
     * CONFIRM handling to the userspace allowlist (READ-only) -- see sec 12 realism table. */
    int kind = dcrn_classify_reverse(h.payload_len, h.tcp->ack, h.tcp->syn, h.tcp->fin, h.tcp->rst,
                                     1 /*dnp3_present assumed on port 20000*/, 0 /*not confirm here*/, covers);
    if (kind == DCRN_KIND_BYPASS)
        return TC_ACT_OK;

    int is_separate;
    if (kind == DCRN_KIND_PURE_ACK) {
        f->pure_ack_seen = 1;
        is_separate = 1;
    } else {
        is_separate = f->pure_ack_seen ? 1 : 0;   /* separate iff a pure ACK preceded the response */
        f->response_seen = 1;
    }

    int miss = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 rel = dcrn_release_ns(kind, now, f->deadline_ns, is_separate, c, &miss);
    skb->tstamp = rel;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
