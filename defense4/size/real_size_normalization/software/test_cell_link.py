from __future__ import annotations

from pathlib import Path

from defense4.size.real_size_normalization.offline.cell_codec import (
    Direction,
    KeyState,
    default_policy,
    derive_offline_test_keys,
    encode_slot,
)
from defense4.size.real_size_normalization.offline.pcapio import PcapPacket, read_pcap, write_pcap

from defense4.size.real_size_normalization.software.cell_link import (
    FaultPlan,
    FaultRule,
    FrameClassifier,
    apply_fault_plan,
)
from defense4.size.real_size_normalization.software.packet_capture import (
    CaptureRecord,
    write_metadata_csv,
    write_metadata_jsonl,
)

KEY_EPOCH = 4
TEST_KEY_SEED = "Defense4-S4-software-public-evidence-v1"


def _encoded_request_frames() -> tuple[bytes, ...]:
    keys = derive_offline_test_keys(TEST_KEY_SEED)
    encoded = encode_slot(
        (),
        default_policy(),
        "request",
        7,
        KeyState.fresh(KEY_EPOCH, keys),
        protected_type=1,
    )
    return tuple(cell.frame for cell in encoded.cells)


def _events(frames: tuple[bytes, ...]):
    classifier = FrameClassifier()
    return tuple(classifier.event("left0", "right0", frame, "a_to_b") for frame in frames)


def test_baseline_fault_plan_forwards_exact_l2_bytes_in_order() -> None:
    frames = _encoded_request_frames()

    assert apply_fault_plan(_events(frames), FaultPlan()) == frames


def test_fault_plan_drops_after_public_counter_match() -> None:
    frames = _encoded_request_frames()
    events = _events(frames)
    target_counter = events[1].identity.counter

    delivered = apply_fault_plan(
        events,
        FaultPlan([FaultRule(action="drop", direction=Direction.FORWARD.value, counter=target_counter)]),
    )

    assert delivered == (frames[0], frames[2], frames[3])


def test_fault_plan_duplicates_by_slot_position() -> None:
    frames = _encoded_request_frames()

    delivered = apply_fault_plan(_events(frames), FaultPlan([FaultRule(action="duplicate", position=2)]))

    assert delivered == (frames[0], frames[1], frames[2], frames[2], frames[3])


def test_fault_plan_reorders_with_next_frame_without_mutating_bytes() -> None:
    frames = _encoded_request_frames()

    delivered = apply_fault_plan(_events(frames), FaultPlan([FaultRule(action="reorder", position=1)]))

    assert delivered == (frames[0], frames[2], frames[1], frames[3])


def test_fault_plan_replays_archived_public_counter() -> None:
    frames = _encoded_request_frames()
    events = _events(frames)

    delivered = apply_fault_plan(
        events,
        FaultPlan(
            [
                FaultRule(
                    action="replay",
                    position=3,
                    replay_direction=Direction.FORWARD.value,
                    replay_counter=events[0].identity.counter,
                )
            ]
        ),
    )

    assert delivered == (frames[0], frames[1], frames[2], frames[3], frames[0])


def test_reorder_hold_is_isolated_per_egress_lane() -> None:
    frames = _encoded_request_frames()
    classifier = FrameClassifier()
    fwd0 = classifier.event("left0", "right0", frames[0], "a_to_b")
    rev0 = classifier.event("right0", "left0", frames[1], "b_to_a")
    fwd1 = classifier.event("left0", "right0", frames[2], "a_to_b")

    plan = FaultPlan(
        [FaultRule(action="reorder", direction=Direction.FORWARD.value, counter=fwd0.identity.counter)]
    )

    assert plan.apply(fwd0) == ()
    # A reverse-lane frame passes straight through its own egress and must NOT
    # drag the held forward frame out the reverse interface.
    assert plan.apply(rev0) == (frames[1],)
    # The next forward-lane frame releases the held one behind it, same egress.
    assert plan.apply(fwd1) == (frames[2], frames[0])
    assert plan.flush_events() == ()


def test_held_reorder_frame_flushes_through_its_own_egress() -> None:
    frames = _encoded_request_frames()
    classifier = FrameClassifier()
    fwd0 = classifier.event("left0", "right0", frames[0], "a_to_b")
    rev0 = classifier.event("right0", "left0", frames[1], "b_to_a")

    plan = FaultPlan(
        [FaultRule(action="reorder", direction=Direction.FORWARD.value, counter=fwd0.identity.counter)]
    )

    assert plan.apply(fwd0) == ()
    assert plan.apply(rev0) == (frames[1],)
    flushed = plan.flush_events()

    assert len(flushed) == 1
    assert flushed[0].egress == "right0"
    assert flushed[0].frame == frames[0]


def test_independent_capture_writes_committed_pcap_and_metadata(tmp_path: Path) -> None:
    frame = _encoded_request_frames()[0]
    record = CaptureRecord(
        timestamp_us=1_900_000_000_000_000,
        interface="v_obs",
        packet_type=4,
        frame=frame,
        direction=Direction.FORWARD.value,
        key_epoch=KEY_EPOCH,
        cell_counter=0,
    )
    pcap = tmp_path / "outer.pcap"
    jsonl = tmp_path / "outer.jsonl"
    csv = tmp_path / "outer.csv"

    write_pcap(pcap, [PcapPacket(record.timestamp_us, record.frame)])
    write_metadata_jsonl(jsonl, [record])
    write_metadata_csv(csv, [record])

    assert tuple(read_pcap(pcap)) == (PcapPacket(record.timestamp_us, frame),)
    assert '"packet_type_name": "outgoing"' in jsonl.read_text(encoding="utf-8")
    assert "direction,key_epoch,cell_counter" in csv.read_text(encoding="utf-8").splitlines()[0]
