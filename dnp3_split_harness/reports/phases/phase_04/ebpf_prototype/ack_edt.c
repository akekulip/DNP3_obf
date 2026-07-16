/* ack_edt.c -- Phase 04 eBPF EDT mechanism (narrowed §8a scope; loopback prototype).
 *
 * Independently schedules an EXISTING separate pure TCP ACK and the DNP3 response to per-flow
 * earliest-departure-times, byte-preservingly and WITHOUT forging anything (it only stamps a
 * departure time on packets that already exist). An `fq` root qdisc enforces the stamps.
 *
 * LOOPBACK SIMPLIFICATION: on `lo` BOTH directions traverse the SAME egress path, so one egress
 * program does the whole job -- it records the request as the request egresses, and schedules the
 * reverse ACK/response as they egress. A real inline (bridge / Tofino) deployment needs the
 * tc-INGRESS(record request)+EGRESS(schedule) split described in ack_control_feasibility.md §8a;
 * this program is the host-local proof of mechanism, not the bridge version.
 *
 * Policy (gap-normalization, separate-mode only):
 *   pure ACK  -> release at request_arrival + ACK_TARGET_NS   (20 ms)
 *   response  -> release at request_arrival + RESP_TARGET_NS   (40 ms)
 *   invariant ack_release < response_release holds by construction (20 < 40 ms).
 *   FAIL OPEN: a reverse packet with no recorded request (unknown / combined-mode) is left native.
 *
 * Build (no -g, to avoid the old-iproute2 .BTF rejection):
 *   clang -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c ack_edt.c -o ack_edt.o
 * Load (needs CAP_BPF -- run under sudo; see run_prototype.sh):
 *   tc qdisc add dev lo root fq ; tc qdisc add dev lo clsact
 *   tc filter add dev lo egress bpf da obj ack_edt.o sec tc
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SERVER_PORT    20000
#define ACK_TARGET_NS  20000000ULL   /* request -> pure ACK  = 20 ms */
#define RESP_TARGET_NS 40000000ULL   /* request -> response  = 40 ms */

struct flow_state {
    __u64 req_arrival_ns;
};

/* iproute2 (ss200127) legacy map definition -- does not require BTF. */
struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};

struct bpf_elf_map SEC("maps") flows = {
    .type      = BPF_MAP_TYPE_LRU_HASH,
    .size_key  = sizeof(__u64),
    .size_value = sizeof(struct flow_state),
    .max_elem  = 1024,
};

/* Parse eth+ip+tcp with bounds checks. Returns 1 on a TCP/IPv4 packet, filling the fields;
 * payload_len = IP total - IP header - TCP header (0 => pure ACK). */
static __always_inline int parse(struct __sk_buff *skb, __u32 *saddr, __u32 *daddr,
                                 __u16 *sport, __u16 *dport, int *payload_len)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    if (ip->protocol != IPPROTO_TCP)
        return 0;
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return 0;

    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end)
        return 0;
    __u32 doff = tcp->doff * 4;
    if (doff < sizeof(*tcp))
        return 0;

    __u32 tot = bpf_ntohs(ip->tot_len);
    *payload_len = (int)tot - (int)ihl - (int)doff;
    *saddr = ip->saddr;
    *daddr = ip->daddr;
    *sport = bpf_ntohs(tcp->source);
    *dport = bpf_ntohs(tcp->dest);
    return 1;
}

SEC("tc")
int ack_edt(struct __sk_buff *skb)
{
    __u32 saddr, daddr;
    __u16 sport, dport;
    int plen;

    if (!parse(skb, &saddr, &daddr, &sport, &dport, &plen))
        return TC_ACT_OK;

    /* Request egressing (master -> server, has payload): record its arrival, keyed by master side. */
    if (dport == SERVER_PORT && plen > 0) {
        __u64 key = ((__u64)saddr << 16) | sport;
        struct flow_state st = { .req_arrival_ns = bpf_ktime_get_ns() };
        bpf_map_update_elem(&flows, &key, &st, BPF_ANY);
        return TC_ACT_OK;
    }

    /* Reverse packet egressing (server -> master): schedule its EDT release. */
    if (sport == SERVER_PORT) {
        __u64 key = ((__u64)daddr << 16) | dport;   /* master side is the destination */
        struct flow_state *st = bpf_map_lookup_elem(&flows, &key);
        if (!st)
            return TC_ACT_OK;                         /* FAIL OPEN: unknown / combined-mode */
        __u64 target = st->req_arrival_ns +
                       (plen == 0 ? ACK_TARGET_NS : RESP_TARGET_NS);
        skb->tstamp = target;                         /* EDT; fq enforces. No byte edited. */
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
