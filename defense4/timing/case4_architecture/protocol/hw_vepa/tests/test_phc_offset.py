"""phc_offset: decoding of PTP_SYS_OFFSET_EXTENDED and the PHC lookup; a live sample only with sudo -n."""
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import phc_offset as po  # noqa: E402


def raw(triples):
    buf = bytearray(po.SIZE)
    po.HEADER.pack_into(buf, 0, len(triples), 0, 0, 0)
    for i, triple in enumerate(triples):
        for k, ns in enumerate(triple):
            po.TIME.pack_into(buf, po.HEADER.size + (i * 3 + k) * po.TIME.size, ns // 10**9, ns % 10**9, 0)
    return bytes(buf)


def test_ioctl_number_matches_linux_header():
    # _IOWR('=', 9, struct ptp_sys_offset_extended): 16-byte header + 25*3 16-byte ptp_clock_time
    assert po.SIZE == 16 + 25 * 3 * 16 == 1216
    assert po.PTP_SYS_OFFSET_EXTENDED == (3 << 30) | (1216 << 16) | (0x3d << 8) | 9


def test_offset_and_bound_from_the_narrowest_window():
    t = 1_700_000_000_000_000_000
    r = po.parse(raw([(t, t + 5_000, t + 1_000), (t + 10_000, t + 15_100, t + 10_200)]), 2)
    assert r['samples'][0]['offset_ns'] == 4_500 and r['samples'][0]['bound_ns'] == 500
    assert r['offset_ns'] == 5_000 and r['bound_ns'] == 100   # second sample: window 200 ns
    assert r['spread_ns'] == 500
    assert r['narrow_count'] == 1 and r['narrow_spread_ns'] == 0    # the 1000 ns window is > 2x the 200 ns one


def test_preempted_wide_window_does_not_enter_the_narrow_spread():
    t = 1_700_000_000_000_000_000
    r = po.parse(raw([(t, t + 300, t + 600), (t + 10_000, t + 10_310, t + 10_600),
                      (t + 20_000, t + 1_020_000, t + 2_020_000)]), 3)       # third read preempted for 2 ms
    assert r['bound_ns'] == 300 and r['narrow_count'] == 2 and r['narrow_spread_ns'] == 10
    assert r['spread_ns'] == 10


def test_rejects_backwards_system_clock_and_bad_counts():
    t = 1_700_000_000_000_000_000
    with pytest.raises(ValueError):
        po.parse(raw([(t + 10, t, t)]), 1)
    for n in (0, 26):
        with pytest.raises(ValueError):
            po.parse(raw([(t, t, t)]), n)


def test_ptp_device_needs_exactly_one_phc(tmp_path):
    (tmp_path / 'eth9' / 'device' / 'ptp' / 'ptp3').mkdir(parents=True)
    assert po.ptp_device('eth9', sysfs=tmp_path) == Path('/dev/ptp3')
    (tmp_path / 'eth8' / 'device').mkdir(parents=True)
    with pytest.raises(ValueError):
        po.ptp_device('eth8', sysfs=tmp_path)


def test_sample_passes_the_buffer_to_the_ioctl(tmp_path):
    t = 1_700_000_000_000_000_000
    payload = raw([(t, t + 7, t + 2)] * 3)
    dev = tmp_path / 'ptp0'
    dev.write_bytes(b'')
    seen = {}

    def fake_ioctl(fd, request, buf):
        seen['request'], seen['n'] = request, struct.unpack_from('<I', buf)[0]
        buf[:] = payload

    r = po.sample(dev, 3, ioctl=fake_ioctl)
    assert seen == {'request': po.PTP_SYS_OFFSET_EXTENDED, 'n': 3}
    assert r['offset_ns'] == 6 and r['bound_ns'] == 1


def _local_phc():
    for net in sorted(Path('/sys/class/net').iterdir()):
        if list((net / 'device' / 'ptp').glob('ptp*')):
            return net.name
    return None


@pytest.mark.privileged
@pytest.mark.skipif(_local_phc() is None or subprocess.run(['sudo', '-n', 'true']).returncode != 0,
                    reason='needs a local PHC and passwordless sudo')
def test_live_sample_on_a_local_phc(tmp_path):
    out = tmp_path / 'phc.json'
    r = subprocess.run(['sudo', '-n', sys.executable, str(HERE.parent / 'phc_offset.py'), _local_phc(),
                        '--json', str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    nic = json.loads(out.read_text())['nics'][_local_phc()]
    assert len(nic['samples']) == 25 and 0 <= nic['bound_ns'] < 1_000_000
