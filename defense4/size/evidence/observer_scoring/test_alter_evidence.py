#!/usr/bin/env python3
"""GATE D — prove the scorer output is DERIVED FROM the committed evidence files.

For each observer we take a baseline metric from score() on the committed files, then ALTER one
evidence file (a copy in a temp dir — the committed files are never touched) and assert the metric
moves in the EXPECTED direction. A hard-coded scorer could not react to these edits; an
evidence-driven one must. No git, no hardware, no absolute home paths.
"""
import copy
import json
import os
import sys
import tempfile

import observer_scoring as obs
import serializer as S

HERE = os.path.dirname(os.path.abspath(__file__))


def _write(tmp, name, doc):
    path = os.path.join(tmp, name)
    with open(path, "w") as f:
        json.dump(doc, f)
    return path


def alter_o_count_read_target(tmp):
    """O_count: break READ convergence by changing P2's padded target size -> normalized True->False."""
    doc = json.load(open(obs.DEF["read_vectors"]))
    for v in doc["vectors"]:
        if v["kind"] == "read_b2_target" and v["profile"] == "P2":
            v["app_bytes"] += 5             # claim P2 padded to a DIFFERENT size than P1
            v["response_hex"] += " 01 00 00 00 00"
    p = _write(tmp, "read_vectors.json", doc)
    base = obs.score()["O_count"]["read_target_normalized"]
    alt = obs.score({"read_vectors": p})["O_count"]["read_target_normalized"]
    return ("O_count", "READ target normalized (P2 size +5B)", base, alt, True, False)


def alter_o_parse_struct_cover(tmp):
    """O_parse_struct: relabel the cover frame's link address to an ENDPOINT so the address filter
    no longer strips it -> the bounded-negative recovery breaks (holds True->False)."""
    doc = json.load(open(obs.DEF["cover"]))
    fh = doc["frames_hex"]
    # cover link dest is 0x0032 (bytes ...C4 32 00...). Rewrite to 0x000A (=10, an endpoint).
    fh["final_1_cover+real"] = fh["final_1_cover+real"].replace("C432000100", "C40A000100", 1)
    p = _write(tmp, "convergence_result.json", doc)
    base = obs.score()["O_parse_struct"]["cover_bounded_negative_holds"]
    alt = obs.score({"cover": p})["O_parse_struct"]["cover_bounded_negative_holds"]
    return ("O_parse_struct", "cover addr 0x0032->0x000A (endpoint)", base, alt, True, False)


def alter_o_parse_profile_animate_decoy(tmp):
    """O_parse_profile: in S1, make ONE constant decoy VARY across reads -> S1 recall 1.0 -> <1.0."""
    doc = json.load(open(obs.DEF["timeseries"]))
    for sc in doc["scenarios"]:
        if sc["name"] != "S1_varying_legit_constant_decoy":
            continue
        target = sc["decoy_indices"][0]  # animate the first decoy
        for rd in sc["reads"]:
            if not rd["present"]:
                continue
            vals = {o["index"]: o["value_i32"] for o in obs._parse_class0_objects(rd["response_hex"])}
            vals[target] = vals[target] + (rd["read_no"] % 5)   # now varies -> looks 'real'
            rd["response_hex"] = S.serialize_class0(vals)
    p = _write(tmp, "read_timeseries.json", doc)

    def s1_recall(r):
        return next(s for s in r["O_parse_profile"] if s["scenario"] == "S1_varying_legit_constant_decoy")["recall"]
    base = s1_recall(obs.score())
    alt = s1_recall(obs.score({"timeseries": p}))
    return ("O_parse_profile", "S1: animate one decoy (constant->varying)", base, alt, 1.0, "<1.0")


def alter_o_config_known_relabel(tmp):
    """O_config_known: relabel one P2-target decoy object as 'real' (change the declared config)
    -> recovered real count 10->11 != native 10 -> device_count_recovered True->False."""
    doc = json.load(open(obs.DEF["read_vectors"]))
    for v in doc["vectors"]:
        if v["kind"] == "read_b2_target" and v["profile"] == "P2":
            for o in v["objects"]:
                if o["role"] == "decoy":
                    o["role"] = "real"           # over-declare the real set
                    break
    p = _write(tmp, "read_vectors.json", doc)
    base = obs.score()["O_config_known"]["read_device_count_recovered"]
    alt = obs.score({"read_vectors": p})["O_config_known"]["read_device_count_recovered"]
    return ("O_config_known", "P2 target: one decoy relabelled real", base, alt, True, False)


def _direction_ok(base, alt, base_exp, alt_exp):
    if alt_exp == "<1.0":
        return base == base_exp and alt < 1.0 and alt < base
    return base == base_exp and alt == alt_exp


def main():
    tmp = tempfile.mkdtemp(prefix="alter_evidence_")
    rows = [
        alter_o_count_read_target(tmp),
        alter_o_parse_struct_cover(tmp),
        alter_o_parse_profile_animate_decoy(tmp),
        alter_o_config_known_relabel(tmp),
    ]
    print("GATE D — alter a committed evidence file, the score must move (temp copies in %s)\n" % tmp)
    print("  %-16s %-38s %-10s %-10s %s" % ("observer", "alteration", "baseline", "altered", "verdict"))
    allok = True
    for observer, desc, base, alt, base_exp, alt_exp in rows:
        ok = _direction_ok(base, alt, base_exp, alt_exp)
        allok = allok and ok
        print("  %-16s %-38s %-10s %-10s expected %s->%s  [%s]"
              % (observer, desc, str(base), str(alt), str(base_exp), str(alt_exp),
                 "PASS" if ok else "FAIL"))
    print("\n%d/%d alterations moved the score in the expected direction" % (sum(
        1 for r in rows if _direction_ok(r[2], r[3], r[4], r[5])), len(rows)))
    print("=> the scorer output is DERIVED FROM the evidence files (not hard-coded)."
          if allok else "=> FAIL: a metric did not track its evidence file.")
    sys.exit(0 if allok else 1)


if __name__ == "__main__":
    main()
