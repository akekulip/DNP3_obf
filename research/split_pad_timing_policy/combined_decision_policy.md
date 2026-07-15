# Combined Decision Policy — Split × Pad × Timing

_The synthesis deliverable (spec §8/§9/§10): the decision tree, the per-transaction-class policy
matrix, the target-profile architecture, and the runtime engine. Draws on Agents A/C/D (mechanism
limits), E (engine), H (safety), F/G (platform), I (evaluation). Research/design only. A candidate
to TEST, not a proven policy. Evidence tags as elsewhere._

## 1. The governing facts that force the policy
1. **CROB count leaks on both size (R²=0.9999) and timing (R²≈0.99, n=1/N).** [M]
2. **Timing is closeable now** (class-independent normalization). **Size is not** (split preserves
   total bytes; no byte-preserving DNP3 padding exists; only a future tunnel/endpoint phase closes
   it). [M][S][I]
3. **Split relocates the size leak** from byte-size to packet-count and can create a beacon; it must
   be paced (to survive the wire) and paired with timing normalization. [M][I]
4. **Control traffic is both the lowest-privacy-value class** (infrequent/bursty → few CROB samples)
   **and the highest-safety-cost to touch**, while the **monitoring/read plane is the highest-value
   leak surface** (continuous polling) and the safest to shape. So bypass-control + shape-monitoring
   is dominant on *both* objectives. [I, Agent H]
5. **Safety dominates privacy; fail open.** DNP3 fields reveal operation *type*, never physical
   *criticality* → an operator allowlist is required. [S][I]

## 2. Decision tree
```
classify(request, response) -> {class, size, is_control, criticality(from allowlist), fragments}

if class is CRITICAL / PROTECTION / UNSUPPORTED / UNKNOWN:        -> BYPASS (release unchanged, now)
if is_control and not allowlisted_for_shaping:                    -> BYPASS (default-deny controls)
if effective_RTO_margin uncertain OR queue over limit OR
   ordering at risk OR deadline already missed:                  -> BYPASS (fail-open)

choose target_profile(class)         # class-independent target; never keyed on the secret

# SHAPE axis (size): split only helps large responses; never hides total bytes
if response is large and multi-frame:
    SPLIT at B1 (CRC-boundary), decoy-/target-matched granularity, PACED
if response smaller than profile target:
    if approved padding available:   apply it            # currently: none in-phase
    else:                            record RESIDUAL size leakage   # the honest path today

# TIMING axis
choose class-independent target release time (uniform-within-budget / size-decorrelation / decoy)
candidate_release = max(response_ready, request_time + target)
enforce: candidate_release <= operational_deadline
         candidate_release <= measured_RTO_safety_deadline (fraction of MEASURED RTO)
         per-flow FIFO order preserved; per-hop gap < RTO; cumulative < poll deadline
         held-packet / queue limits preserved
if any constraint fails:  release immediately + record policy bypass
else:                     release per {first-response deadline, inter-chunk gaps, completion deadline}
```

## 3. Policy matrix by transaction class
| Class | Split | Pad | Timing | Notes |
|---|---|---|---|---|
| Integrity / Class-0 READ (large) | **Yes** (B1, paced, decoy-matched) | future tunnel only | **Yes** (first-response + inter-chunk gap) | Primary target; high-value continuous leak; near-zero safety risk |
| Event READ | Yes, tighter timing | future | Yes, tight bound | Never suppress the CONFIRM (flushes event buffer) |
| Small status response | No (few chunks) | future | Yes | Splitting adds no size benefit |
| Multi-fragment response | Yes, within fragments | future | One completion deadline; CONFIRM verbatim | Do not merge/reorder across CONFIRM |
| SELECT response | Optional (small) | **none (residual size leak)** | Tight N-independent deadline, allowlist | Carries CROB-count leak on size — unclosable now |
| OPERATE response | Optional | none | Tight, allowlist; **bypass if critical** | Command latency + safety dominate |
| DIRECT_OPERATE / _NR | `_NR` has no response | none | Consequence-gated | Bypass if flagged critical |
| Application CONFIRM (M→O) | **No** | No | **No** — leave verbatim | Never suppress/synthesize |
| Unsolicited response | Off by default | none | Minimal if enabled | Alarm-driven → treat as urgent |
| Critical control / protection | **BYPASS entirely** | — | — | Safety > privacy; never delay |

## 4. Target-profile architecture (§9)
A profile is a **public, class-independent** shaping target — it must NOT be selected using a secret
variable that would itself leak (checkable as `I(policy_choice; secret | class) ≈ 0`, Agent I). Fields:
profile ID; applicable DNP3 classes; safety class; target packet-size pattern; target packet-count
range; split-boundary policy (B1, granularity distribution); padding mechanism permitted (currently
none in-phase → "record residual"); timing target distribution; first-response deadline; inter-chunk-
gap distribution; complete-transaction deadline; **TCP-RTO safety fraction (of the MEASURED RTO)**;
max queue occupancy; max concurrent held packets; deadline-miss action; bypass conditions; reproducible
seed; telemetry requirements. **Scope of profiles:** per-transaction-class + per-criticality-class is
the recommended granularity; a **per-device** or single global profile is discouraged (a lone shaped
device is a beacon — profiles should define **anonymity groups** shaped to a *common* target, ideally
fleet-wide or decoy-device-based). Learned-from-empirical profiles are allowed only if the learned
target is class-independent.

## 5. Combination rule (the candidate to TEST — not a conclusion)
- **Large routine (read) response:** split (B1, paced, decoy-matched) + first-response timing
  normalization + inter-chunk-gap normalization. *Residual: total-byte volume still visible.*
- **Small routine response:** timing normalization only; padding only when a future approved
  mechanism exists.
- **Noncritical SELECT/OPERATE:** tight N-independent timing normalization under the allowlist; split
  optional; **no invalid-index padding**; *residual: CROB-count size leak (unclosable now)*.
- **Critical control / urgent event:** bypass or extremely restricted shaping.
- **Silence:** requires future cover traffic; delay and splitting cannot hide the absence of packets.

## 6. Runtime engine (Agent E)
Application-layer, inside the replay/split server (it generates its bytes → schedules `send()`
directly; no live packet to intercept, so kernel/eBPF/DPDK shapers don't apply). **Per-flow FIFO
deque** release queue (never a global deadline min-heap — that would reorder within a flow and break
the no-reorder rule); a small cross-flow heap only across flow heads (F≈1). Synchronous
monotonic-deadline `sleep` (Python 3.8 on the target host: `time.monotonic_ns` present, ms precision
ample; `random.Random` for seeds, dependency-free); asyncio `call_at` only if concurrency ever exceeds
1. No busy-wait, no thread-per-packet. Watchdog = fraction of **measured** RTO. Full telemetry
(requested/actual delay, deadline miss, release reason, residual size leak). Fail-open catalogue,
config schema, complexity, and unit/integration/PCAP test plan are in `software_design.md`.

## 7. Failure handling
Fail **open** on every doubt (= grid-fail-safe): uncertain RTO margin, queue over limit, ordering
risk, unsupported class, missed deadline → release unchanged immediately and record a policy bypass.
The bypass **rate** is itself an exported privacy metric (frequent bypass = a leak channel). Never
suppress/synthesize a CONFIRM; never delay a control the allowlist can't prove non-critical; never
present a bypass as a shaped success.

_Plain language: figure out what kind of message it is; if it's a control or anything risky, send it
untouched right now. For a big routine read, chop it up (paced, varied) and release the pieces on a
shared clock. For small control replies, normalize the timing but accept that the size still leaks —
and log that leak honestly. Never make a real command wait, and if anything is uncertain, just send it
through._
