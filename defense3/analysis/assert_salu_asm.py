#!/usr/bin/env python3
"""
assert_salu_asm.py — fail the build when the compiled SALU assembly is wrong, even
though bf-p4c reported success.

WHY THIS EXISTS. Two silent miscompiles have now been found in this program's stateful
ALUs, both accepted by bf-p4c with no error and no warning:

  1. a predicate comparing against a LARGE CONSTANT (`v == 0xFF`) did not fire on
     silicon, so a conditional state write never committed while the SALU's return
     value kept working;
  2. a sign test written as `v < 8w0` on a bit<8> register lowered to `lss.u lo, lo` —
     an UNSIGNED less-than-zero, which is NEVER TRUE. The explicit cast
     `(int<8>)v < 8s0` lowers to `lss.s`.

Neither is detectable from the compiler's exit status, and the second is not detectable
from the P4 source by eye. So the ASSEMBLY is the artifact under test.

    python3 analysis/assert_salu_asm.py <build-dir> [...]

Exit 0 only if every assertion holds.
"""

import glob
import os
import re
import sys

# (SALU action, must contain, must NOT contain, why it is load-bearing)
REQUIRED = [
    ("tag_retire_if_unmarked_0", [r"\blss\.s\b"], [r"\blss\.u\b"],
     "E1's Gate 4C repair: retire the transaction on ACK commitment ONLY when the tag "
     "is in 0xC0..0xCF. An unsigned compare is never true, so the repair would "
     "silently not exist and a missing RESPONSE would still strand the generation."),
    ("tag_read_or_mark_0", [r"\blss\.s\b"], [r"\blss\.u\b"],
     "E1's one-shot early-RESPONSE marker. An unsigned compare is never true, so the "
     "tag would never be marked, the ACK would retire while a RESPONSE was still "
     "queued, and that RESPONSE's release would then clear a NEW generation."),
    ("tag_arm_0", [r"\bequ lo, lo\b"], [r"equ lo, lo, -\d\d+"],
     "the F02 repair: the idle test must compare against ZERO. A large immediate here "
     "is the original defect — the arm write never commits while ARM_FRESH still "
     "fires."),
]

# SALU actions that must write the inactive marker or the marker delta at all
MUST_EXIST = ["tag_arm_0", "tag_rmw_0", "tag_read_or_mark_0",
              "tag_retire_if_unmarked_0"]

# the 0xB0 blocker-live decode entry, matched in the compiled match table
BLOCKER_0XB0 = re.compile(r"0xb0", re.I)


def salu_actions(bfa_text):
    """{action_name: [instruction, ...]} for every stateful action in the .bfa."""
    out, cur = {}, None
    for line in bfa_text.splitlines():
        st = line.strip()
        m = re.match(r"^(\w+_\d+):$", st)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            continue
        if cur is not None and st.startswith("- "):
            out[cur].append(st[2:])
        elif st and not st.startswith("-") and not st.endswith(":"):
            pass
    return out


def check(build_dir, require_r2=False):
    """Accepts EITHER a compiler output directory (<dir>/pipe/*.bfa) OR a bare .bfa
    file. The second form matters: artifacts/assembly/ archives the assembly for each
    build precisely so the §7 evidence stays checkable after the ~15 MB build trees
    are gone. Archived evidence that cannot be re-verified is not evidence."""
    if os.path.isfile(build_dir) and build_dir.endswith(".bfa"):
        bfa = [build_dir]
    else:
        bfa = glob.glob(os.path.join(build_dir, "pipe", "*.bfa"))
    if not bfa:
        print("  FAIL  no .bfa found at %s" % build_dir)
        return 1
    text = open(bfa[0]).read()
    acts = salu_actions(text)
    bad = 0

    for name in MUST_EXIST:
        if name not in acts:
            print("  FAIL  %-28s ABSENT from the assembly" % name)
            bad += 1

    for name, musts, must_nots, why in REQUIRED:
        body = " ; ".join(acts.get(name, []))
        if name not in acts:
            continue                      # already reported by MUST_EXIST
        for pat in musts:
            if not re.search(pat, body):
                print("  FAIL  %-28s missing /%s/" % (name, pat))
                print("        emitted: %s" % body)
                print("        WHY: %s" % why)
                bad += 1
        for pat in must_nots:
            if re.search(pat, body):
                print("  FAIL  %-28s CONTAINS FORBIDDEN /%s/" % (name, pat))
                print("        emitted: %s" % body)
                print("        WHY: %s" % why)
                bad += 1
        if not bad:
            print("  PASS  %-28s %s" % (name, body))

    # the marker must be an ADD of the delta, and the retirement an absolute write
    mark = " ; ".join(acts.get("tag_read_or_mark_0", []))
    if "add" not in mark:
        print("  FAIL  tag_read_or_mark_0 has no add: the marker cannot be applied")
        print("        emitted: %s" % mark)
        bad += 1
    else:
        print("  PASS  %-28s marker add present" % "tag_read_or_mark_0")

    # ---- R2: the fail-open note must be a REAL second predicate on tag_arm -------
    # Only checked when the build carries R2, so the assertion is silent on builds
    # that do not. The failure mode it guards is the one this project has already been
    # bitten by twice: a predicate that compiles, reads plausibly, and is never true.
    arm = " ; ".join(acts.get("tag_arm_0", []))
    r2_present = ("cmphi" in arm or "phv_hi" in arm)
    if require_r2 and not r2_present:
        # CORRECTIONS.md §6.2: on a build that is SUPPOSED to be the final R2 program, a
        # silent no-R2 pass is a false PASS. --require-r2 makes the absence a failure.
        print("  FAIL  tag_arm_0 has NO R2 note predicate, but --require-r2 was set")
        print("        WHY: this .bfa is not the final R1+R2+R3 build. Point the checker at")
        print("             the repaired assembly (artifacts/final/*.bfa).")
        print("        emitted: %s" % arm)
        bad += 1
    if r2_present:
        ok = True
        if not re.search(r"equ\s+lo,\s*lo\b", arm):
            print("  FAIL  tag_arm_0 lost its compare-against-ZERO (the idle test)")
            print("        emitted: %s" % arm); ok = False; bad += 1
        if not re.search(r"equ\s+hi,\s*lo,\s*-?phv_hi", arm):
            print("  FAIL  tag_arm_0 has no compare against the NOTE operand")
            print("        WHY: R2 arms over a failed-open generation only if reg_tag")
            print("             equals the note. Without this comparison the arm either")
            print("             never fires or fires unconditionally.")
            print("        emitted: %s" % arm); ok = False; bad += 1
        if not re.search(r"alu_a\s*\(\s*cmplo\s*\|\s*cmphi\s*\)", arm):
            print("  FAIL  tag_arm_0's write is not predicated on BOTH comparisons")
            print("        WHY: it must be (cmplo | cmphi) -- idle OR the note. A write")
            print("             predicated on one of them silently drops half the rule.")
            print("        emitted: %s" % arm); ok = False; bad += 1
        if ok:
            print("  PASS  %-28s R2 note predicate: %s" % ("tag_arm_0", arm))

    # the 0xB0 blocker-live decode entry must survive into the compiled table
    if not BLOCKER_0XB0.search(text):
        print("  FAIL  the 0xB0 blocker-live decode entry is absent from the assembly:")
        print("        without it every circulating token reads STALE the instant an")
        print("        early RESPONSE marks the tag, and the reservoir collapses "
              "before D.")
        bad += 1
    else:
        print("  PASS  %-28s 0xB0 blocker-live decode entry present" % "tbl_state_decode")
    return bad


def main(argv):
    # --require-r2: fail if the assembly is not the final R1+R2+R3 build (CORRECTIONS §6.2).
    require_r2 = "--require-r2" in argv
    argv = [a for a in argv if a != "--require-r2"]
    # Default target: prefer the FINAL repaired assembly over the archived ORIGINAL builds,
    # so a no-argument run does not silently pass on a pre-repair .bfa.
    if argv:
        dirs = argv
    else:
        dirs = sorted(glob.glob("artifacts/final/*.bfa")) or \
               sorted(glob.glob("artifacts/final/**/*.bfa", recursive=True))
        if not dirs:
            dirs = sorted(glob.glob("artifacts/assembly/*.bfa"))
            if dirs:
                print("WARNING: artifacts/final/ has no .bfa; falling back to the ARCHIVED "
                      "ORIGINAL assemblies. Pass the final repaired .bfa explicitly, or run "
                      "with --require-r2 to fail on a non-R2 build (CORRECTIONS.md §6.2).",
                      file=sys.stderr)
    dirs = [d for d in dirs if os.path.isdir(d)
            or (os.path.isfile(d) and d.endswith(".bfa"))]
    if not dirs:
        print("no build directories given or found", file=sys.stderr)
        return 2
    total = 0
    for d in dirs:
        print("=" * 74)
        print("SALU ASSEMBLY ASSERTIONS — %s%s" % (d, "  [--require-r2]" if require_r2 else ""))
        print("=" * 74)
        total += check(d, require_r2=require_r2)
    print("-" * 74)
    print("%d failure(s)" % total)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
