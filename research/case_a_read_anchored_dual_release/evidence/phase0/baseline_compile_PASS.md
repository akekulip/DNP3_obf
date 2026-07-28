# Phase 0 gate 1 — preserved baseline still compiles

Date: 2026-07-28. Local, non-destructive: bf-p4c only, no switch, no bf_switchd.

Command:
```
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH bf-p4c --target tofino --arch tna -g \
  -o <outdir> research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4
```

Compiler: p4c 9.13.1 (SHA e558d01) — matches the recorded baseline SDE.
Source sha256: 812a56facd842dc7e96d631faffead9d88ca9753ac4d19f11f0b9bd809ffc7db

## Result: PASS — no drift from the recorded baseline

```
Table allocation done 1 time(s), state = INITIAL
Number of stages in table allocation: 10
  Number of stages for ingress table allocation: 10
  Number of stages for egress table allocation: 0
Critical path length through the table dependency graph: 8
Number of tables allocated: 70
```

| Metric | Recorded baseline | This compile | Match |
|---|---|---|---|
| errors | 0 | 0 | yes |
| warnings | 3 | 3 | yes |
| ingress stages | 10 | 10 | yes |
| egress stages | 0 | 0 | yes |
| critical path | 8 | 8 | yes |
| tables allocated | 70 | 70 | yes |

The three warnings are the known benign set: the struct-wide uninitialised-out-param
TNA notice, and two min_parse_depth_accept_loop unroll notices.
