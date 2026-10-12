#!/usr/bin/env python3
"""Build an isolated N CRC-residue stage experiment from incremental_55."""
import argparse
import hashlib
import json
import re
from pathlib import Path


BASE = Path(__file__).resolve().parents[2]
SOURCE = BASE / "evidence" / "incremental_55" / "response_only.p4"
RESIDUE = "16w0x993a"


def one(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise AssertionError(f"{label}: expected one replacement, found {count}")
    return text.replace(old, new, 1)


def transform(text):
    original = text
    edits = []

    replacements = [
        (
            "action crc_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}",
            "action crc_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc});}",
            "link header residue hash",
        ),
        (
            "action crc_head_first(){crc_head();m.bcrc=hash_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3});}",
            "action crc_head_first(){crc_head();m.bcrc=hash_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3,hdr.first.crc});}",
            "first block residue hash",
        ),
        (
            "action input_tail(){m.tcrc=hash_tail.get({hdr.tail.off,hdr.tail.status});}",
            "action input_tail(){m.tcrc=hash_tail.get({hdr.tail.off,hdr.tail.status,hdr.tail.crc});}",
            "native tail residue hash",
        ),
        (
            "action response_crct(){m.tcrc=hash_response_tail.get({hdr.rtail.on_lo,hdr.rtail.off,hdr.rtail.status});}",
            "action response_crct(){m.tcrc=hash_response_tail.get({hdr.rtail.on_lo,hdr.rtail.off,hdr.rtail.status,hdr.rtail.crc});}",
            "response tail residue hash",
        ),
        (
            "action rd_second_crc(){m.crc1=hash_rd_second.get({hdr.second.w0,hdr.second.w1,hdr.second.w2,hdr.second.w3});}",
            "action rd_second_crc(){m.crc1=hash_rd_second.get({hdr.second.w0,hdr.second.w1,hdr.second.w2,hdr.second.w3,hdr.second.crc});}",
            "read second block residue hash",
        ),
        (
            "action rd_request_crc(){m.bcrc=hash_rd_request.get({hdr.rd_req.tp,hdr.rd_req.app,hdr.rd_req.func,hdr.rd_req.group,hdr.rd_req.variation,hdr.rd_req.qualifier,hdr.rd_req.first,hdr.rd_req.last});}",
            "action rd_request_crc(){m.bcrc=hash_rd_request.get({hdr.rd_req.tp,hdr.rd_req.app,hdr.rd_req.func,hdr.rd_req.group,hdr.rd_req.variation,hdr.rd_req.qualifier,hdr.rd_req.first,hdr.rd_req.last,hdr.rd_req.crc});}",
            "read request residue hash",
        ),
        (
            "action rd_tail_crc(){m.tcrc=hash_rd_tail.get({hdr.rd_tail.value});}",
            "action rd_tail_crc(){m.tcrc=hash_rd_tail.get({hdr.rd_tail.value,hdr.rd_tail.crc});}",
            "read tail residue hash",
        ),
    ]
    for old, new, label in replacements:
        text = one(text, old, new, label)
        edits.append(label)

    deletes = [
        (
            "    if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=(bit<1>)(8w1);}\n"
            "    if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=(bit<1>)(8w1);}\n"
            "    if((bit<8>)m.response==8w1){if(hdr.rtail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=(bit<1>)(8w1);}}\n"
            "    else{if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=(bit<1>)(8w1);}}\n",
            "native control/response compare removal",
        ),
        (
            "    if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=(bit<1>)(8w1);}\n",
            "read link-header compare removal",
        ),
        (
            "    if(m.packet_kind==8w9){if(hdr.rd_req.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=(bit<1>)(8w1);}}\n"
            "    else{if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=(bit<1>)(8w1);}if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=(bit<1>)(8w1);}if(hdr.rd_tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=(bit<1>)(8w1);}}\n",
            "read body/tail compare removal",
        ),
    ]
    for old, label in deletes:
        text = one(text, old, "", label)
        edits.append(label)

    key_old = "m.badh:ternary;m.badb:ternary;m.bad1:ternary;m.badt:ternary;m.output_port:ternary;"
    key_new = "m.badh:ternary;m.hcrc:ternary;m.bcrc:ternary;m.crc1:ternary;m.tcrc:ternary;m.output_port:ternary;"
    text = one(text, key_old, key_new, "guard residue keys")
    edits.append("guard residue keys")

    guard_start = text.index("table guard{")
    guard_end = text.index(" apply{", guard_start)
    guard = text[guard_start:guard_end]
    rewritten = guard.count("1w1,8w1,1w0,1w0,1w0,1w0,")
    if rewritten != 11:
        raise AssertionError(f"guard entries: expected eleven CRC tuples, found {rewritten}")

    def widen_rows(match):
        terms = [term.strip() for term in match.group(1).split(",")]
        if len(terms) == 12:
            packet_kind, kind = terms[1], terms[2]
            crc_qualified = (terms[5:11] == ["1w1", "8w1", "1w0", "1w0", "1w0", "1w0"])
            if crc_qualified and packet_kind in {"8w5", "8w6", "8w7"}:
                terms = terms[:8] + [RESIDUE, RESIDUE, "_", RESIDUE] + [terms[11]]
            elif crc_qualified and packet_kind == "8w9":
                terms = terms[:8] + [RESIDUE, RESIDUE, "_", "_"] + [terms[11]]
            elif crc_qualified and packet_kind == "8w11":
                terms = terms[:8] + [RESIDUE, RESIDUE, RESIDUE, RESIDUE] + [terms[11]]
            else:
                # Non-CRC control/lifecycle rows must not inherit the old
                # badb/bad1/badt columns as constraints on the new residue
                # fields. Preserve the old link-mismatch bit (badh), then
                # wildcard all four residue keys explicitly.
                terms = terms[:8] + ["_", "_", "_", "_"] + [terms[11]]
        if len(terms) != 13:
            raise AssertionError(f"guard row width: expected 13 terms, found {len(terms)}")
        return "(" + ",".join(terms) + "):"

    replaced = re.sub(r"\(([^()]*)\):", widen_rows, guard)
    text = text[:guard_start] + replaced + text[guard_end:]
    edits.append("guard residue entries")

    if any(token in text for token in (
        "hdr.dl.crc!=(m.hcrc", "hdr.first.crc!=(m.bcrc",
        "hdr.rd_req.crc!=(m.bcrc", "hdr.second.crc!=(m.crc1",
        "hdr.rd_tail.crc!=(m.tcrc", "hdr.tail.crc!=(m.tcrc",
        "hdr.rtail.crc!=(m.tcrc",
    )):
        raise AssertionError("old CRC compare survived")

    return text, {
        "experiment": "n_crc_residue",
        "residue": "0x993a",
        "edits": edits,
        "baseline_source": str(SOURCE),
        "baseline_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    text, metadata = transform(args.source.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text)
    args.output.with_suffix(".json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    print(json.dumps(metadata, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
