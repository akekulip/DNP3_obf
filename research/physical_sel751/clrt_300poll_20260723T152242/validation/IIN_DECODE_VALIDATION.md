# IIN_DECODE_VALIDATION.md — decode of the DNP3 Internal Indications reported as "0x8000"

**Task 1.** Working only from the committed pcap
`evidence/clrt_300poll_20260723T152242.pcap`. Script: `validate/…` (extraction inlined; reproducible).

## Raw IIN bytes and wire order
Every DNP3 **RESPONSE** (application function code `0x81` = 129) carries a 2-octet Internal Indications
field immediately after the function code. In the response frame's TCP payload:
- **offset 13 = IIN octet 1 (IIN1)** — transmitted **first** on the wire → value **`0x80`**
- **offset 14 = IIN octet 2 (IIN2)** — transmitted **second** on the wire → value **`0x00`**

So the on-wire order is **IIN1 first (`0x80`), then IIN2 (`0x00`)**.

## Named bits asserted
- **IIN1 = `0x80` → only bit 7 set → `IIN1.7 = DEVICE_RESTART`.**
- **IIN2 = `0x00` → no bits set** (in particular, **no request-error bits**: FUNC_NOT_SUPPORTED,
  OBJECT_UNKNOWN, PARAMETER_ERROR, EVENT_BUFFER_OVERFLOW are all clear).

The relay reports **DEVICE_RESTART** on every response. This is expected and benign here: the master
was configured `ignoreRestartIIN=True` (read-only experiment), so it never sent the WRITE(g80v1) that
would clear the restart bit — therefore the bit persists on all responses. `IINField.HasRequestError()`
was **False** on all 300, i.e. no protocol error.

## How the analyzer constructs the value (and why "0x8000" is ambiguous)
`analyze_clrt.py::dnp3()` sets `iin_lsb = pl[13]` (= IIN1 = `0x80`) and `iin_msb = pl[14]`
(= IIN2 = `0x00`). This matches opendnp3's `IINField.LSB`/`.MSB` convention (LSB = IIN1, MSB = IIN2).
The report then rendered the pair as **"0x8000"**, i.e. `(IIN1 << 8) | IIN2`. That is **endian-ambiguous**:
the *same* bytes render as **`0x0080`** under `(IIN2 << 8) | IIN1`. A reader cannot tell from "0x8000"
whether DEVICE_RESTART lives in IIN1 or IIN2.

**Unambiguous representation (adopted):** `IIN1=0x80 (DEVICE_RESTART), IIN2=0x00`. The reports are
corrected to state this instead of the bare "0x8000".

## Same IIN in all 300 responses?
**Yes.** Independent extraction from the pcap over all response frames:
`distinct (IIN1_wire, IIN2_wire) = {(0x80, 0x00): 300}` — **300/300 identical**. No response carried any
other IIN state and none set a request-error bit.

## Verdict
The value is **DEVICE_RESTART (IIN1.7) set, everything else clear**, identical across all 300 responses,
consistent with a read-only session that deliberately never clears the restart bit. The "0x8000"
notation is replaced by the explicit `IIN1=0x80 / IIN2=0x00` form in `CLRT_EXPERIMENT_REPORT.md` and the
main connectivity report.
