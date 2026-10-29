import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/hardware'))
import campaign_base  # noqa: E402

CONFIG = ROOT / 'results/hardware/campaigns/rc01_hw_c72_e4b_20261029_01/configs/e4b_select_only_d20_combined.json'


@pytest.mark.parametrize('key', ['host_diagnostics', 'host_diagnostic'])
def test_both_spellings_of_the_retired_host_diagnostic_are_refused(tmp_path, key):
    # the host diagnostics were removed (results/analysis/purge/PURGE_LOG.json); a config asking for one must not load
    cfg = json.loads(CONFIG.read_text())
    cfg[key] = {'cpu_latency': True}
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(cfg))
    with pytest.raises(ValueError, match='diagnostics are outside the current matrix'):
        campaign_base.load_config(str(path))


def test_the_retained_config_without_diagnostics_still_loads():
    assert campaign_base.load_config(str(CONFIG))['traffic']['sbo_select_only'] is True
