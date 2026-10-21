# P4 placement findings: READ prefix for the frozen policy (range 49 → 141)

All compiles use bf-p4c 9.13.1 on gambit via `case4_architecture/build.py`. Each finding is about the specific construction that was compiled; none of them is a claim that every implementation is impossible.

## Attempts that put the 92-octet prefix in E (pipe-0 egress), all FAILED

| attempt | source sha | change | result |
|---|---|---|---|
| m12p_a01 | cb2e077e | first policy build: prefix in E with an 88-bit block-0 tail constant and a 512-bit constant remainder; C3 per-image `classify_rev`; C5 rows; window-zero; retained block-1/tail CRC verdicts | `--Werror=overlimit`: constants wider than 64 bits; PHV allocation not successful |
| m12p_a02 | f1c15af9 | constants split into fields of 64 bits or fewer | PHV allocation not successful |
| m12p_a03 | 2587c893 | dead re-encode checksum branch removed (it held `ra`/`ca`/`rbh`/`rc`/`cb`); `@pa_mutually_exclusive` between the READ prefix headers and the SBO reframing headers | PHV allocation not successful |
| m12p_a04 | 538d2223 | the constant remainder's TCP-checksum contribution folded into `m.len_delta` instead of listed | PHV allocation not successful: the same 18 field slices unallocated (`m.epoch_diff`, `m.owner_diff`, … in N's ingress; E's 1-bit `@pa_solitary` flags) |

Scratch bisect on the a02 and a04 sources (`scratchpad/bisect_a02`, `bisect_a04`):

- **A–D:** removing any single one of {C3 key, the 64-octet remainder, the retained CRC verdicts, C5 rows + window-zero} still failed.
- **E:** removing all four compiled.
- **G1:** the remainder alone failed.
- **G2–G4:** the remainder plus any one of the other three failed.
- **F:** the committed 49→73 range build compiles.
- **Z** (remainder as zero constants) and **Y** (E parses only block 0) still failed, with 23 and 24 slices left.

**Measured cause.** In the placing 49→73 build, pipe 0 (N ingress plus E egress) uses 86–90% of its PHV containers:

- 16-bit containers 96–100%;
- 32-bit containers 100%;
- 8-bit containers 58–66%.

Pipe 1 (T ingress plus an empty egress) uses 24% (`F/compile_local/out/p{0,1}/logs/phv_allocation_summary_*.log`). Adding 92 octets of new egress headers to pipe 0 exhausts its containers.

## Construction moved to pipe-1 egress (attempt m12p_b01 onward)

Every READ response that N admits leaves N through `emit_tev` to `n_READ_HANDOFF_PORT` = `t_T_IN` = 180, a pipe-1 port. It therefore traverses pipe-1 egress exactly once on the N→T handoff. T's held returns use port 182, which the padder does not touch.

The padder `transform_read_prefix_p1` replaces T's empty egress. It acts only on a packet that matches all of the following:

- egress port 180, `tev` kind 11 stage 0;
- IPv4 length 89 and TCP without options;
- a range READ response frame (LEN 0x26) whose block-0 CRC verifies and whose profile matches.

On such a packet it inserts the derived prefix and rewrites block 0. It recomputes the IP checksum and updates the TCP checksum incrementally (parser residual plus folded constant). T parses the `tev` and forwards the frame opaquely.

E (`transform_read_prepadded_e`) then:

- recognises the pre-padded frame by its prefix headers;
- uses native length = `ip.len` − 40 − 92;
- commits the 141-octet wire image through the unchanged per-shape mapper;
- no longer inserts or rewrites READ bytes.

The cost is that pipe-1 egress now does work it did not do before, one pass per READ response. No traversal is added, because the handoff pass already existed. Results of b01 onward are recorded in STATUS.md.
