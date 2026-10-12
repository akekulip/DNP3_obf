This isolated candidate derives N/E/T from the unchanged `response_only` and
`read_queue_timing.p4` sources. The frozen `mirror_fix_01` baseline remains the
comparison and rollback target. `compose.py` emits the same two physical pipes
and program name, with explicit build port-map metadata.

N permits a same-tuple reconnect after both FINs and their qualified ACKs, or a
qualified RST. It requires genuine Work phase 4 before a close admission, again
before its FIN/RST owner CAS, and before a new SYN. It never forces Work free.
The full old owner remains the CAS expectation. Closing pure ACKs use the
existing expected-phase Work lifecycle. A close qualified on pass zero carries
its intended owner phase in the existing private origin word; that word holds
the normalization epoch on other packet kinds.

On reuse, the new client ISN plus one must advance at least two bytes beyond the
previous native client frontier within the forward TCP halfspace. The server
must satisfy the corresponding condition before FIRST_SYNACK arms E. Initial
ISNs are unrestricted. Modular wrap is supported; overlap, a halfspace jump,
and the identical previous client ISN fail closed. An indistinguishable segment
with identical bytes and sequence coordinates cannot be attributed to a prior
connection. Exact current pending handshake retries preserve the mapping;
established stale SYNACKs are rejected.

A pending SYN can abort through server RST|ACK with SEQ 0 and ACK equal to the
current client ISN plus one, or a qualified current master reset. This includes
recovery after a rejected ambiguous server ISN. There is no timeout-based forced
retirement. Lost producers and exhausted generations remain closed to reuse.

The private 16-byte envelope carries full epoch, immutable original wire ACK,
auxiliary data, opcode, stage, and reserved zero. N work returns additionally
carry an eight-byte origin. E captures the untouched wire ACK on N's private
normalization opcode before translating the packet. N preserves that captured
value throughout Work. Normalization only reads mapping/accounting/image state;
N's qualified return
authorizes accounting commitment. E accepts an increasing bounded OPEN before
FIRST_SYNACK and arms only the first such SYNACK of the pending epoch. T receives
CLOSE/OPEN through the existing handoff. All wire departures strip private data.

E's epoch register stores the bounded epoch in bits 30:0 and its atomic
FIRST_SYNACK latch in bit 31. An armed epoch 3 therefore reads as `0x80000003`;
decode `epoch = raw & 0x7fffffff` and `first_seen = raw >> 31`. N and T store
the bare epoch. OPEN must advance the decoded E epoch and clears its latch;
duplicate FIRST fails before any transport/image arm write.

E classifies the reverse ACK offset and TCP window directly. Each negative
offset within the fixed 58-byte image has an exact zero/open window partition;
the original window clamp and outcome counting follow that decision. Two pure
endpoint preparations reuse existing metadata before the shared image-end
access. Accounting and image authorities retain their original qualifications.

T holds the full epoch in the original's existing ladder budget word. It drops
old held originals under ON and OFF, fences tokens with nonreused generations,
and rejects old RESET without changing the current epoch, quarantine, anchors,
or allocator. CLOSE first obtains an exact epoch-XOR result from the current
epoch bank; its quarantine SALU writes only when that result is zero and the
packet epoch is nonzero. Each allocator, anchor, child-seen and ACK-commit bank
has one exclusive access table. Current-owner policy OFF still flushes held originals. Timer and
held paths use parser-initialized event-kind metadata instead of invalid tev
header bits. Old-epoch drops have a distinct outcome counter at index 14.

N connection generations never wrap their 16-bit owner tag. N's full allocator
and N/E/T epochs are bounded below 0x7fffffff. T transaction generations allocate
at most 0xfffe; 0xffff is an exhausted sentinel and is never a usable timer tag.
Reinitializing these authorities requires a deliberate cold deployment; there
is no CPU rearm or register-clear recovery path.

Generate a hardware-map checkpoint and compile offline:

```sh
python compose.py evidence/incremental_NN/response_only.p4 \
  --relay-port 9 --n-ack-return 48 --t-in 180 --hb-return 181 --held-return 182
python ../../../build.py evidence/incremental_NN/response_only.p4 \
  evidence/incremental_NN/compile_local
python -m unittest discover -s tests -v
```

Use the repository `build.py` at `case4_architecture/build.py` if invoking from
another directory. Checkpoints are immutable once compilation begins. Each
manifest records source/compiler hashes, command, log hash, and actual result.
No checkpoint with a failed full compile is deployable. Mirror selection must
also pass the retained compiled-BFA guard. Switch artifacts require the parent's
installed SDK 9.13.2 compile and guarded activation; local SDK 9.13.1 results are
offline evidence only.

After a full compile, run `model_drive_rearm.py` using `integration/core/launch_model.sh`
with `PORT_MAP` pointing at that checkpoint's `.inputs.json`, its compiled output
as `-p`, a new evidence directory as `-o`, and `-P "9 48 68 180 181 182 196"` for the
hardware map. This launcher uses a private user/network/PID namespace. The driver
reuses baseline transport, reflector, and padding helpers, and performs no
register writes. Compiled model results establish functional behavior, not host
CLRT precision or ASIC timing.

Checkpoint `evidence/incremental_55` compiled under SDK 9.13.1 with N/E/T using
12 stages each and passed the compiled mirror guard. Its private compiled model
passed 80/80 lifecycle/isolation checks, then 382/382 checks including every
reverse image-byte window boundary and exact pending handshake retries.
`full_composite_qualification.json` binds the source, inputs, binaries, authority
register inventory, resource reports, mirror guard, and model report hashes.
Installed SDK and silicon qualification remain separate requirements.

Source tests execute generated parser/control/register actions through the
existing interpreter. The candidate adapter evaluates identity hashes exactly;
the E-to-N source lap uses an independent TCP-checksum oracle because the
interpreter does not execute E's deparser checksum externs. Queue/mirror/pktgen
scheduling retains `queue_sim.py`'s documented assumptions. These tests are not
compiler, model, physical queue, or receiver timing evidence.

Rejected old external frames may advance N's diagnostic allocation counter or
claim/release a free Work generation. They must preserve N owner/client/server/
epoch and all E/T authority banks. Rejected old private Work returns preserve
the full N state as well. These distinctions belong in state-snapshot gates.

The candidate installer wrapper loads only candidate CP rows into the retained
installer's explicit CP dependency. `cp.py` imports the unchanged baseline CP
file directly and adds qualified reverse-accounting rows at the relay departure.
All other hardware tools remain on their existing baseline profile.
