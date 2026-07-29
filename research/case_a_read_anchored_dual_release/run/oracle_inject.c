/* ============================================================================
 * oracle_inject.c — compiled AF_PACKET raw-frame injector for the four-queue
 * dequeue oracle (research/case_a_read_anchored_dual_release).
 *
 * WHY A C INJECTOR. The Python injector (run/four_queue_oracle.py) pays a
 * per-frame interpreter cost between send() calls, which widens the injection
 * burst and makes "was the queue actually non-empty when the release fired?"
 * harder to argue. This program does the same thing with a fixed, tiny
 * per-frame cost: build 64 bytes into a stack buffer, send(), optionally
 * nanosleep().
 *
 * WIRE FORMAT — must match, byte for byte:
 *   p4/four_queue_oracle.p4                 header oracle_h / ethernet_h
 *   run/four_queue_oracle.py                build_frame()
 *   analysis/analyze_four_queue_oracle.py   OFF_* constants / parse_oracle_frame()
 * The _Static_assert block below pins every offset at COMPILE time, so a future
 * edit that reorders or repads the struct cannot silently produce frames the
 * analyzer misreads.
 *
 * 64-byte frame, all multi-byte fields big-endian, no VLAN:
 *   0..5 dst MAC | 6..11 src MAC | 12..13 ethertype 0x88C2 | 14..15 trial_id
 *   16 role | 17..18 per_role_seq | 19..20 global_inj_seq | 21 pass | 22..63 pad
 *
 * The `pass` byte is 0 as injected; the switch's ingress sets it to 1 on the
 * loopback pass, so a captured frame with pass == 0 proves a short-circuit that
 * never traversed the queues.
 *
 * SCOPE. This program injects on ONE interface and does nothing else: no
 * control plane, no capture, no queue configuration. It never learns a port
 * number, so it cannot address dp9 (Vision) or dp64 (the SEL-751 leg).
 *
 * Exit codes: 0 success | 1 argument or send failure | 77 missing CAP_NET_RAW.
 * stdout carries exactly one JSON object (or, with --emit-hex, one hex line).
 * Every log line goes to stderr.
 * ==========================================================================*/
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ wire format */
#define ETHERTYPE_ORACLE 0x88C2u   /* .p4 const bit<16> ETHERTYPE_ORACLE          */
#define FRAME_LEN        64        /* .py FRAME_LEN / .analysis ORACLE_FRAME_LEN  */

#define ROLE_ABLOCK      1u        /* .p4 const bit<8> ROLE_ABLOCK                */
#define ROLE_HELD_ACK    2u        /* .p4 const bit<8> ROLE_HELD_ACK              */
#define ROLE_RBLOCK      3u        /* .p4 const bit<8> ROLE_RBLOCK                */
#define ROLE_HELD_RESP   4u        /* .p4 const bit<8> ROLE_HELD_RESP             */
#define N_ROLES          4

#define DEFAULT_DST_MAC "02:00:00:00:C2:01"
#define DEFAULT_SRC_MAC "02:00:00:00:C2:02"

/* Exit codes. 77 is deliberately distinct so a driver script can tell "you
 * forgot setcap" apart from "the injection failed". */
#define EXIT_ARG_OR_SEND 1
#define EXIT_NO_CAP      77

/* The on-the-wire header, packed. Nothing here may be reordered or widened
 * without updating the P4 parser and the analyzer offsets in the same commit. */
struct oracle_hdr {
    uint8_t  dst[6];          /* off  0 */
    uint8_t  src[6];          /* off  6 */
    uint16_t etype;           /* off 12, BE */
    uint16_t trial_id;        /* off 14, BE */
    uint8_t  role;            /* off 16 */
    uint16_t per_role_seq;    /* off 17, BE */
    uint16_t global_inj_seq;  /* off 19, BE */
    uint8_t  pass;            /* off 21 */
} __attribute__((packed));

/* Layout proof, checked by the compiler. The right-hand values are the
 * analyzer's OFF_* constants verbatim (analysis/analyze_four_queue_oracle.py). */
_Static_assert(sizeof(struct oracle_hdr) == 22, "oracle header must be exactly 22 bytes");
_Static_assert(FRAME_LEN == 64, "oracle frame must be exactly 64 bytes");
_Static_assert(offsetof(struct oracle_hdr, dst)            ==  0, "OFF_DST_MAC");
_Static_assert(offsetof(struct oracle_hdr, src)            ==  6, "OFF_SRC_MAC");
_Static_assert(offsetof(struct oracle_hdr, etype)          == 12, "OFF_ETHERTYPE");
_Static_assert(offsetof(struct oracle_hdr, trial_id)       == 14, "OFF_TRIAL_ID");
_Static_assert(offsetof(struct oracle_hdr, role)           == 16, "OFF_ROLE");
_Static_assert(offsetof(struct oracle_hdr, per_role_seq)   == 17, "OFF_PER_ROLE_SEQ");
_Static_assert(offsetof(struct oracle_hdr, global_inj_seq) == 19, "OFF_GLOBAL_INJ_SEQ");
_Static_assert(offsetof(struct oracle_hdr, pass)           == 21, "OFF_PASS");

/* ------------------------------------------------------------------ logging (stderr) */
static const char *PROG = "oracle_inject";

static void logmsg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", PROG);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* ------------------------------------------------------------------ roles */
static const char *role_name(unsigned role)
{
    switch (role) {
    case ROLE_ABLOCK:    return "ABLOCK";
    case ROLE_HELD_ACK:  return "HELD_ACK";
    case ROLE_RBLOCK:    return "RBLOCK";
    case ROLE_HELD_RESP: return "HELD_RESP";
    default:             return "UNKNOWN";
    }
}

/* Case-insensitive role name, the documented aliases, or a bare number 1..4.
 * Returns 0 on failure (0 is not a valid role: the P4 table drops it). */
static unsigned role_from_str(const char *s)
{
    static const struct { const char *name; unsigned role; } tbl[] = {
        { "ablock",    ROLE_ABLOCK    },
        { "ack",       ROLE_HELD_ACK  },
        { "held_ack",  ROLE_HELD_ACK  },
        { "rblock",    ROLE_RBLOCK    },
        { "resp",      ROLE_HELD_RESP },
        { "held_resp", ROLE_HELD_RESP },
    };
    size_t i;

    if (s == NULL || *s == '\0')
        return 0;

    for (i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        if (strcasecmp(s, tbl[i].name) == 0)
            return tbl[i].role;
    }
    if (s[1] == '\0' && s[0] >= '1' && s[0] <= '4')
        return (unsigned)(s[0] - '0');
    return 0;
}

/* ------------------------------------------------------------------ PRNG
 * splitmix64 (Steele/Lea/Flood, "Fast Splittable Pseudorandom Number
 * Generators", OOPSLA 2014) — the exact reference constants. It is used here
 * INSTEAD of libc rand()/random() so that the shuffle is a property of the seed
 * alone: identical seed -> identical injection order on any host, any libc, any
 * compiler. That reproducibility is load-bearing, because the analyzer's
 * "observed order is not the injection order" argument cites the seed.
 *
 * state <- state + 0x9E3779B97F4A7C15
 * z <- state; z ^= z>>30; z *= 0xBF58476D1CE4E5B9; z ^= z>>27;
 *      z *= 0x94D049BB133111EB; z ^= z>>31; return z
 */
static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Uniform in [0, bound) with NO modulo bias: reject the short tail of the 64-bit
 * range that would otherwise make the low residues more likely.
 * threshold = 2^64 mod bound, computed as (0 - bound) % bound on uint64_t. */
static uint64_t rand_below(uint64_t *state, uint64_t bound)
{
    uint64_t threshold = (0ULL - bound) % bound;
    for (;;) {
        uint64_t r = splitmix64(state);
        if (r >= threshold)
            return r % bound;
    }
}

/* ------------------------------------------------------------------ plan */
struct plan_item {
    unsigned role;
    unsigned per_role_seq;
    unsigned global_inj_seq;
    int      sent;
};

/* ------------------------------------------------------------------ helpers */
/* Strict "aa:bb:cc:dd:ee:ff" (or '-' separated): exactly six 1..2-digit hex
 * octets, exactly five separators, nothing else. Loose parsing here would let a
 * typo'd MAC through and the frames would go somewhere unintended. */
static int parse_mac(const char *s, uint8_t out[6])
{
    int i;

    for (i = 0; i < 6; i++) {
        char *end = NULL;
        unsigned long v;

        if (!isxdigit((unsigned char)*s))
            return -1;
        errno = 0;
        v = strtoul(s, &end, 16);
        if (errno != 0 || end == s || (end - s) > 2 || v > 0xFFUL)
            return -1;
        out[i] = (uint8_t)v;
        s = end;
        if (i < 5) {
            if (*s != ':' && *s != '-')
                return -1;
            s++;
        }
    }
    return (*s == '\0') ? 0 : -1;
}

/* strtoul with the checks people forget: no empty string, no trailing junk,
 * no negatives, explicit range. */
static int parse_u32(const char *s, unsigned long max, unsigned long *out)
{
    char *end = NULL;
    unsigned long v;

    if (s == NULL || *s == '\0' || *s == '-')
        return -1;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v > max)
        return -1;
    *out = v;
    return 0;
}

/* --schedule ablock:64,rblock:64,ack:1,resp:1 -> counts[role]. A repeated role
 * is an error rather than a silent sum: it is far more likely a typo than an
 * intent, and a mis-sized reservoir invalidates the trial. */
static int parse_schedule(const char *spec, unsigned long counts[N_ROLES + 1])
{
    char *buf = strdup(spec);
    char *save = NULL, *tok;
    int rc = 0;

    if (buf == NULL) {
        logmsg("out of memory parsing --schedule");
        return -1;
    }
    for (tok = strtok_r(buf, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
        char *colon = strchr(tok, ':');
        unsigned long n;
        unsigned role;

        if (colon == NULL) {
            logmsg("--schedule item '%s' is not ROLE:COUNT", tok);
            rc = -1;
            break;
        }
        *colon = '\0';
        role = role_from_str(tok);
        if (role == 0) {
            logmsg("--schedule: unknown role '%s' (ablock|ack|held_ack|rblock|resp|held_resp|1..4)", tok);
            rc = -1;
            break;
        }
        if (parse_u32(colon + 1, 65535UL, &n) != 0) {
            logmsg("--schedule: bad count '%s' for role %s (0..65535)", colon + 1, role_name(role));
            rc = -1;
            break;
        }
        if (counts[role] != 0) {
            logmsg("--schedule: role %s appears more than once", role_name(role));
            rc = -1;
            break;
        }
        counts[role] = n;
    }
    free(buf);
    return rc;
}

/* --only-roles ack,resp -> mask[role] = 1 */
static int parse_role_set(const char *spec, int mask[N_ROLES + 1])
{
    char *buf = strdup(spec);
    char *save = NULL, *tok;
    int rc = 0;

    if (buf == NULL) {
        logmsg("out of memory parsing --only-roles");
        return -1;
    }
    for (tok = strtok_r(buf, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
        unsigned role = role_from_str(tok);
        if (role == 0) {
            logmsg("--only-roles: unknown role '%s'", tok);
            rc = -1;
            break;
        }
        mask[role] = 1;
    }
    free(buf);
    return rc;
}

static void build_frame(unsigned char buf[FRAME_LEN],
                        const uint8_t dst[6], const uint8_t src[6],
                        unsigned trial_id, const struct plan_item *it)
{
    struct oracle_hdr h;

    memset(&h, 0, sizeof h);
    memcpy(h.dst, dst, 6);
    memcpy(h.src, src, 6);
    h.etype          = htons((uint16_t)ETHERTYPE_ORACLE);
    h.trial_id       = htons((uint16_t)trial_id);
    h.role           = (uint8_t)it->role;
    h.per_role_seq   = htons((uint16_t)it->per_role_seq);
    h.global_inj_seq = htons((uint16_t)it->global_inj_seq);
    h.pass           = 0;                 /* the switch sets this to 1 */

    memset(buf, 0, FRAME_LEN);            /* the 42-byte pad */
    memcpy(buf, &h, sizeof h);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_us(unsigned long us)
{
    struct timespec req, rem;

    if (us == 0)
        return;
    req.tv_sec  = (time_t)(us / 1000000UL);
    req.tv_nsec = (long)((us % 1000000UL) * 1000UL);
    while (nanosleep(&req, &rem) != 0 && errno == EINTR)
        req = rem;
}

/* Absolute path of this binary, so the setcap hint is copy-pasteable. */
static void self_path(char *out, size_t outlen)
{
    ssize_t n = readlink("/proc/self/exe", out, outlen - 1);
    if (n <= 0) {
        snprintf(out, outlen, "./%s", PROG);
        return;
    }
    out[n] = '\0';
}

/* ------------------------------------------------------------------ JSON (hand-rolled)
 * Deliberately no JSON library: this binary must build on the lab hosts with
 * nothing but a C compiler. */
static void json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f);  break;
        case '\r': fputs("\\r", f);  break;
        case '\t': fputs("\\t", f);  break;
        default:
            if (c < 0x20)
                fprintf(f, "\\u%04x", c);
            else
                fputc((char)c, f);
        }
    }
    fputc('"', f);
}

static void emit_json(const struct plan_item *plan, size_t n_planned,
                      const unsigned long counts[N_ROLES + 1],
                      const int only_mask[N_ROLES + 1], int have_only,
                      unsigned trial_id, unsigned long seed, const char *iface,
                      int dry_run, size_t n_sent,
                      uint64_t t_first, uint64_t t_last)
{
    static const unsigned order[N_ROLES] = {
        ROLE_ABLOCK, ROLE_HELD_ACK, ROLE_RBLOCK, ROLE_HELD_RESP
    };
    size_t i;
    int j, first;

    printf("{\n");
    printf("  \"trial_id\": %u,\n", trial_id);
    printf("  \"seed\": %lu,\n", seed);
    printf("  \"iface\": ");
    json_str(stdout, iface);
    printf(",\n");
    printf("  \"frame_len\": %d,\n", FRAME_LEN);
    printf("  \"ethertype\": \"0x%04x\",\n", ETHERTYPE_ORACLE);
    printf("  \"dry_run\": %s,\n", dry_run ? "true" : "false");

    printf("  \"schedule\": {");
    for (j = 0; j < N_ROLES; j++) {
        printf("%s", j ? ", " : "");
        json_str(stdout, role_name(order[j]));
        printf(": %lu", counts[order[j]]);
    }
    printf("},\n");

    printf("  \"only_roles\": ");
    if (!have_only) {
        printf("null,\n");
    } else {
        printf("[");
        first = 1;
        for (j = 0; j < N_ROLES; j++) {
            if (!only_mask[order[j]])
                continue;
            printf("%s", first ? "" : ", ");
            json_str(stdout, role_name(order[j]));
            first = 0;
        }
        printf("],\n");
    }

    printf("  \"n_planned\": %zu,\n", n_planned);
    printf("  \"n_sent\": %zu,\n", n_sent);
    printf("  \"t_first_send_unix_ns\": %" PRIu64 ",\n", t_first);
    printf("  \"t_last_send_unix_ns\": %" PRIu64 ",\n", t_last);

    printf("  \"injection_sequence\": [\n");
    for (i = 0; i < n_planned; i++) {
        printf("    {\"global_inj_seq\": %u, \"role\": %u, \"role_name\": ",
               plan[i].global_inj_seq, plan[i].role);
        json_str(stdout, role_name(plan[i].role));
        printf(", \"per_role_seq\": %u, \"sent\": %s}%s\n",
               plan[i].per_role_seq, plan[i].sent ? "true" : "false",
               (i + 1 < n_planned) ? "," : "");
    }
    printf("  ]\n");
    printf("}\n");
}

/* ------------------------------------------------------------------ socket */
static int open_raw_socket(const char *iface)
{
    struct sockaddr_ll sll;
    unsigned ifindex;
    int fd;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        if (errno == EPERM || errno == EACCES) {
            char path[4096];
            self_path(path, sizeof path);
            logmsg("cannot open an AF_PACKET raw socket on '%s': %s", iface, strerror(errno));
            logmsg("this binary needs the CAP_NET_RAW capability and does not have it.");
            logmsg("grant it ONCE, on this host, with exactly:");
            fprintf(stderr, "\n    sudo setcap cap_net_raw+ep %s\n\n", path);
            logmsg("do NOT work around this by running the injector under sudo: the oracle");
            logmsg("driver runs unprivileged, sudo would change the environment under the");
            logmsg("measurement and leave root-owned evidence files behind. Grant CAP_NET_RAW");
            logmsg("to the binary and re-run the same command as the same user.");
            logmsg("(a rebuild replaces the file and drops the capability — re-run setcap after 'make')");
            return -EXIT_NO_CAP;
        }
        logmsg("socket(AF_PACKET, SOCK_RAW): %s", strerror(errno));
        return -EXIT_ARG_OR_SEND;
    }

    ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        logmsg("if_nametoindex('%s'): %s", iface, strerror(errno));
        close(fd);
        return -EXIT_ARG_OR_SEND;
    }

    memset(&sll, 0, sizeof sll);
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof sll) != 0) {
        logmsg("bind(%s, ifindex %u): %s", iface, ifindex, strerror(errno));
        close(fd);
        return -EXIT_ARG_OR_SEND;
    }
    return fd;
}

/* ------------------------------------------------------------------ usage */
static void usage(FILE *f)
{
    fprintf(f,
"Usage: %s --iface NAME --trial-id N --schedule SPEC --seed N [options]\n"
"\n"
"Inject 64-byte oracle frames (ethertype 0x88C2) in a seed-reproducible random\n"
"order. One JSON record describing the injection is written to stdout; all\n"
"logging goes to stderr.\n"
"\n"
"Required:\n"
"  --iface NAME        interface to inject on (e.g. enp59s0f0np0)\n"
"  --trial-id N        trial id carried in every frame, 0..65535\n"
"  --schedule SPEC     comma-separated ROLE:COUNT, e.g.\n"
"                      ablock:64,rblock:64,ack:1,resp:1\n"
"  --seed N            seed for the injection-order shuffle (splitmix64)\n"
"\n"
"Optional:\n"
"  --dst-mac MAC       default %s\n"
"  --src-mac MAC       default %s\n"
"  --gap-us N          inter-frame gap in microseconds (default 0)\n"
"  --only-roles SPEC   send ONLY these roles, but keep the full plan's\n"
"                      global_inj_seq numbering (for late injection)\n"
"  --dry-run           build the plan, print the JSON, send nothing, exit 0\n"
"  --help              this text\n"
"\n"
"Roles: ablock | ack (held_ack) | rblock | resp (held_resp) | 1..4, case-insensitive.\n"
"Exit: 0 ok | %d argument or send failure | %d missing CAP_NET_RAW.\n",
            PROG, DEFAULT_DST_MAC, DEFAULT_SRC_MAC, EXIT_ARG_OR_SEND, EXIT_NO_CAP);
}

/* ------------------------------------------------------------------ main */
int main(int argc, char **argv)
{
    static const struct option opts[] = {
        { "iface",      required_argument, NULL, 'i' },
        { "trial-id",   required_argument, NULL, 't' },
        { "schedule",   required_argument, NULL, 's' },
        { "seed",       required_argument, NULL, 'S' },
        { "dst-mac",    required_argument, NULL, 'd' },
        { "src-mac",    required_argument, NULL, 'r' },
        { "gap-us",     required_argument, NULL, 'g' },
        { "only-roles", required_argument, NULL, 'o' },
        { "dry-run",    no_argument,       NULL, 'n' },
        { "emit-hex",   no_argument,       NULL, 'x' },
        { "help",       no_argument,       NULL, 'h' },
        { NULL,         0,                 NULL,  0  }
    };
    static const unsigned role_order[N_ROLES] = {
        ROLE_ABLOCK, ROLE_HELD_ACK, ROLE_RBLOCK, ROLE_HELD_RESP
    };

    const char *iface = NULL, *schedule = NULL, *only_roles = NULL;
    const char *dst_mac_s = DEFAULT_DST_MAC, *src_mac_s = DEFAULT_SRC_MAC;
    unsigned long trial_id = 0, seed = 0, gap_us = 0;
    int have_trial = 0, have_seed = 0, dry_run = 0, emit_hex = 0;
    unsigned long counts[N_ROLES + 1];
    int only_mask[N_ROLES + 1];
    uint8_t dst_mac[6], src_mac[6];
    struct plan_item *plan = NULL;
    size_t n_planned = 0, n_sent = 0, idx = 0;
    uint64_t t_first = 0, t_last = 0, rng_state;
    unsigned char frame[FRAME_LEN];
    int fd = -1, c, j;
    size_t i;

    memset(counts, 0, sizeof counts);
    memset(only_mask, 0, sizeof only_mask);

    while ((c = getopt_long(argc, argv, "i:t:s:S:d:r:g:o:nxh", opts, NULL)) != -1) {
        switch (c) {
        case 'i': iface = optarg; break;
        case 't':
            if (parse_u32(optarg, 65535UL, &trial_id) != 0) {
                logmsg("--trial-id must be 0..65535, got '%s'", optarg);
                return EXIT_ARG_OR_SEND;
            }
            have_trial = 1;
            break;
        case 's': schedule = optarg; break;
        case 'S':
            if (parse_u32(optarg, 4294967295UL, &seed) != 0) {
                logmsg("--seed must be 0..4294967295, got '%s'", optarg);
                return EXIT_ARG_OR_SEND;
            }
            have_seed = 1;
            break;
        case 'd': dst_mac_s = optarg; break;
        case 'r': src_mac_s = optarg; break;
        case 'g':
            if (parse_u32(optarg, 3600000000UL, &gap_us) != 0) {
                logmsg("--gap-us must be 0..3600000000, got '%s'", optarg);
                return EXIT_ARG_OR_SEND;
            }
            break;
        case 'o': only_roles = optarg; break;
        case 'n': dry_run = 1; break;
        case 'x': emit_hex = 1; break;
        case 'h': usage(stdout); return 0;
        default:  usage(stderr); return EXIT_ARG_OR_SEND;
        }
    }
    if (optind != argc) {
        logmsg("unexpected positional argument '%s'", argv[optind]);
        usage(stderr);
        return EXIT_ARG_OR_SEND;
    }
    if (iface == NULL || !have_trial || schedule == NULL || !have_seed) {
        logmsg("--iface, --trial-id, --schedule and --seed are all required");
        usage(stderr);
        return EXIT_ARG_OR_SEND;
    }
    if (parse_mac(dst_mac_s, dst_mac) != 0) {
        logmsg("bad --dst-mac '%s'", dst_mac_s);
        return EXIT_ARG_OR_SEND;
    }
    if (parse_mac(src_mac_s, src_mac) != 0) {
        logmsg("bad --src-mac '%s'", src_mac_s);
        return EXIT_ARG_OR_SEND;
    }
    if (parse_schedule(schedule, counts) != 0)
        return EXIT_ARG_OR_SEND;
    if (only_roles != NULL && parse_role_set(only_roles, only_mask) != 0)
        return EXIT_ARG_OR_SEND;

    for (j = 0; j < N_ROLES; j++)
        n_planned += counts[role_order[j]];
    if (n_planned == 0) {
        logmsg("--schedule '%s' plans zero frames", schedule);
        return EXIT_ARG_OR_SEND;
    }
    if (n_planned > 65535) {
        /* global_inj_seq is a uint16 on the wire; overflowing it would make two
         * frames indistinguishable to the analyzer. */
        logmsg("--schedule plans %zu frames; global_inj_seq is 16-bit, max 65535", n_planned);
        return EXIT_ARG_OR_SEND;
    }

    plan = calloc(n_planned, sizeof *plan);
    if (plan == NULL) {
        logmsg("out of memory for %zu plan items", n_planned);
        return EXIT_ARG_OR_SEND;
    }

    /* 1. build the plan: COUNT items per role, per_role_seq 0..COUNT-1 ... */
    for (j = 0; j < N_ROLES; j++) {
        unsigned long k;
        for (k = 0; k < counts[role_order[j]]; k++) {
            plan[idx].role         = role_order[j];
            plan[idx].per_role_seq = (unsigned)k;
            idx++;
        }
    }

    /* ... then shuffle (Fisher-Yates, splitmix64, unbiased bound). Randomizing
     * the injection order is load-bearing: if the observed dequeue order were
     * the injection order, priority would explain nothing. */
    rng_state = (uint64_t)seed;
    for (i = n_planned; i > 1; i--) {
        size_t k = (size_t)rand_below(&rng_state, (uint64_t)i);
        struct plan_item tmp = plan[i - 1];
        plan[i - 1] = plan[k];
        plan[k] = tmp;
    }
    for (i = 0; i < n_planned; i++)
        plan[i].global_inj_seq = (unsigned)i;

    /* --emit-hex: layout proof path. Prints the FIRST planned frame (the one
     * with global_inj_seq 0) as hex on stdout and sends nothing, so the frame
     * can be fed straight to the analyzer's parse_oracle_frame(). */
    if (emit_hex) {
        build_frame(frame, dst_mac, src_mac, (unsigned)trial_id, &plan[0]);
        for (i = 0; i < FRAME_LEN; i++)
            printf("%02x", frame[i]);
        printf("\n");
        free(plan);
        return 0;
    }

    /* 2. socket */
    if (!dry_run) {
        fd = open_raw_socket(iface);
        if (fd < 0) {
            int rc = -fd;
            free(plan);
            return rc;
        }
    }

    /* 3. send. A short write or an error on ANY frame is fatal: a partially
     * injected reservoir is not a smaller valid trial, it is an unknown one. */
    for (i = 0; i < n_planned; i++) {
        if (only_roles != NULL && !only_mask[plan[i].role])
            continue;   /* planned and reported, but not sent */
        if (dry_run)
            continue;

        build_frame(frame, dst_mac, src_mac, (unsigned)trial_id, &plan[i]);
        {
            ssize_t w = send(fd, frame, FRAME_LEN, 0);
            uint64_t t = now_ns();

            if (w < 0) {
                logmsg("send() failed at global_inj_seq %u (role %s, per_role_seq %u): %s",
                       plan[i].global_inj_seq, role_name(plan[i].role),
                       plan[i].per_role_seq, strerror(errno));
                logmsg("%zu of %zu planned frames were sent before the failure; the trial is void",
                       n_sent, n_planned);
                close(fd);
                free(plan);
                return EXIT_ARG_OR_SEND;
            }
            if (w != (ssize_t)FRAME_LEN) {
                logmsg("short write at global_inj_seq %u: %zd of %d bytes",
                       plan[i].global_inj_seq, w, FRAME_LEN);
                logmsg("%zu of %zu planned frames were sent before the failure; the trial is void",
                       n_sent, n_planned);
                close(fd);
                free(plan);
                return EXIT_ARG_OR_SEND;
            }
            if (n_sent == 0)
                t_first = t;
            t_last = t;
            plan[i].sent = 1;
            n_sent++;
        }
        sleep_us(gap_us);
    }

    if (fd >= 0)
        close(fd);

    logmsg("trial %lu: planned %zu, sent %zu on %s (seed %lu%s)",
           trial_id, n_planned, n_sent, iface, seed, dry_run ? ", DRY RUN" : "");

    /* 4. the one JSON object on stdout */
    emit_json(plan, n_planned, counts, only_mask, only_roles != NULL,
              (unsigned)trial_id, seed, iface, dry_run, n_sent, t_first, t_last);

    free(plan);
    return 0;
}
