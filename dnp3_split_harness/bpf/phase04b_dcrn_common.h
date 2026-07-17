/* phase04b_dcrn_common.h -- DCRN shared decision core (corrective.md sec 3-10).
 *
 * Pure, integer-only decision logic shared by BOTH the tc/eBPF data plane
 * (phase04b_dcrn_ingress.c, phase04b_dcrn_egress.c) AND an unprivileged userspace conformance
 * harness (phase04b_dcrn_conformance.c). The Python reference policy (phase04b_dcrn_policy.py)
 * mirrors these exact functions, so eBPF <-> Python conformance is verifiable WITHOUT loading BPF.
 *
 * No floats (verifier-safe). No packet parsing here -- callers pass already-parsed integer fields,
 * so the same decision functions run in-kernel and in userspace. Times are nanoseconds.
 *
 * Terminology is strict (sec 1): a "pure TCP ACK" is a zero-payload ACK covering the request; an
 * "ACK-bearing DNP3 RESPONSE" is a payload-bearing outstation response covering the request. A DNP3
 * RESPONSE is never an "application ACK".
 */
#ifndef PHASE04B_DCRN_COMMON_H
#define PHASE04B_DCRN_COMMON_H

#ifdef __BPF__
/* in BPF objects the standard int types arrive via the BPF headers the .c already includes */
#else
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#endif

#define DCRN_DNP3_PORT     20000
#define DCRN_READ_FC       1        /* routine solicited READ request  */
#define DCRN_RESPONSE_FC   129      /* DNP3 RESPONSE                    */
#define DCRN_CONFIRM_FC    0        /* DNP3 application CONFIRM         */

/* target modes */
#define DCRN_MODE_NATIVE   0
#define DCRN_MODE_FIXED    1
#define DCRN_MODE_BOUNDED  2

/* reverse-packet decision kinds */
#define DCRN_KIND_BYPASS   0
#define DCRN_KIND_PURE_ACK 1
#define DCRN_KIND_RESPONSE 2

/* configuration pushed by the loader (single map entry, index 0). */
struct dcrn_config {
    __u32 mode;            /* DCRN_MODE_*                                        */
    __u32 fifo_reliable;   /* 1 => equal-deadline FIFO proven; guard delta = 0   */
    __u64 fixed_ns;        /* P1 target                                          */
    __u64 lo_ns;           /* P2 lower bound                                     */
    __u64 hi_ns;           /* P2 upper bound                                     */
    __u64 seed;            /* deterministic experiment seed                      */
    __u64 guard_ns;        /* common ACK-before-response guard delta (separate)  */
    __u64 dhigh_ns;        /* RTO-safe ceiling: target must be < dhigh_ns        */
};

/* per-flow transaction state, armed at request ingress. */
struct dcrn_flow {
    __u64 req_arrival_ns;
    __u64 deadline_ns;     /* req_arrival_ns + target                            */
    __u32 expected_ack;    /* request_seq + request_len (cumulative ack cover)   */
    __u32 armed;           /* 1 once a READ request armed this flow              */
    __u32 pure_ack_seen;
    __u32 response_seen;
};

/* splitmix64 -- deterministic, seedable, portable; identical in C and Python. */
static __always_inline __u64 dcrn_splitmix64(__u64 x)
{
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

/* Class-independent target selection: depends ONLY on (mode, seed, counter) + config bounds.
 * NEVER on device, size, native ACK mode, or native timing. Returns nanoseconds. */
static __always_inline __u64 dcrn_select_target_ns(const struct dcrn_config *c, __u64 counter)
{
    if (c->mode == DCRN_MODE_NATIVE)
        return 0;
    if (c->mode == DCRN_MODE_FIXED)
        return c->fixed_ns;
    /* BOUNDED: uniform-ish in [lo,hi] from a seeded hash of the transaction counter. */
    {
        __u64 span = (c->hi_ns > c->lo_ns) ? (c->hi_ns - c->lo_ns + 1) : 1;
        __u64 h = dcrn_splitmix64(c->seed ^ (counter * 0x9E3779B97F4A7C15ULL));
        return c->lo_ns + (h % span);
    }
}

/* True if the target is within the RTO-safe window. */
static __always_inline int dcrn_target_safe(const struct dcrn_config *c, __u64 target_ns)
{
    return target_ns < c->dhigh_ns;
}

/* Wrap-aware cumulative-ACK coverage in 32-bit sequence space. */
static __always_inline int dcrn_ack_covers(__u32 cum_ack, __u32 expected)
{
    return (__u32)(cum_ack - expected) < 0x80000000U;
}

/* Reverse-packet kind from already-parsed fields + coverage flag. Returns DCRN_KIND_*.
 * This is the DATA-PLANE-implementable core; richer TCP-state bypasses (dup-ACK, SACK,
 * keepalive, CONFIRM, concurrent) are handled by the caller/userspace/post-capture per sec 12. */
static __always_inline int dcrn_classify_reverse(int payload_len, int ack, int syn, int fin, int rst,
                                                 int dnp3_present, int dnp3_is_confirm, int covers)
{
    if (payload_len > 0) {
        if (!dnp3_present || !covers)
            return DCRN_KIND_BYPASS;
        if (dnp3_is_confirm)
            return DCRN_KIND_BYPASS;     /* ACK-bearing CONFIRM, not a solicited RESPONSE */
        return DCRN_KIND_RESPONSE;
    }
    if (!(ack && !syn && !fin && !rst))
        return DCRN_KIND_BYPASS;
    if (!covers)
        return DCRN_KIND_BYPASS;         /* an ACK that does not cover the armed request */
    return DCRN_KIND_PURE_ACK;
}

/* Absolute release time for a classified packet. Never earlier than ready (can't send before the
 * bytes exist); never drops. Separate response gets +guard unless equal-deadline FIFO is proven.
 * Sets *deadline_miss = 1 when the packet is already later than its target (passed immediately). */
static __always_inline __u64 dcrn_release_ns(int kind, __u64 ready_ns, __u64 deadline_ns,
                                             int is_separate, const struct dcrn_config *c,
                                             int *deadline_miss)
{
    __u64 target = deadline_ns;
    if (kind == DCRN_KIND_RESPONSE && is_separate && !c->fifo_reliable)
        target = deadline_ns + c->guard_ns;
    if (ready_ns > target) {
        if (deadline_miss) *deadline_miss = 1;
        return ready_ns;
    }
    if (deadline_miss) *deadline_miss = 0;
    return target;
}

#endif /* PHASE04B_DCRN_COMMON_H */
