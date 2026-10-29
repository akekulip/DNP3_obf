import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
import fig_validation  # noqa: E402


def test_the_e3_points_and_e2_counts_come_from_the_retained_evidence():
    points = fig_validation.e3_points()
    assert len(points) == 19                                   # 18 recovery trials + qualification block 10 t3
    assert sorted((c, round(y, 3)) for c, y, ok in points if not ok) == [
        ('qualification', 1024.263), ('r1_d20_combined', 1228.81), ('r3_d5_combined', 1008.565)]
    assert fig_validation.e2_counts() == dict(none=32, handshake_ack=5, first_request=3)


def test_the_figure_has_two_panels_and_is_byte_stable(tmp_path):
    fig_validation.figure(tmp_path / 'a')
    fig_validation.figure(tmp_path / 'b')
    assert fig_validation.fs.AXES_PER_FIGURE['fig_validation_recovery'] == 2
    for name in ('fig_validation_recovery.pdf', 'fig_validation_recovery.svg'):
        assert (tmp_path / 'a' / name).read_bytes() == (tmp_path / 'b' / name).read_bytes()
