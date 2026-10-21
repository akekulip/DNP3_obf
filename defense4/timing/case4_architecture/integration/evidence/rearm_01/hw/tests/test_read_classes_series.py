"""Per-class READ declarations in the candidate series harness.

vision_candidate runs only the range READ (one SBO, no schedule), so a series build that declares read_images takes
its READ image from read_images['range'] and refuses a configured READ-class schedule or an unsupported range
class instead of silently expecting the native or the legacy read_image_len."""
import sys
from pathlib import Path

import pytest

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_candidate_series import _dup_gate, configured  # noqa: E402


def test_growth_uses_the_declared_range_image():
    module, cfg = configured()
    build = cfg['builds'][cfg['arms'][0]['build']]
    build.update(image_len=61, read_images={'range': 141, 'analog': 141, 'class0': 247, 'integrity': 247})
    _failures, observed = _dup_gate(module, cfg, 0, False)
    assert observed['external_growth_expected'] == 20 * (141 - 49) + 2 * 24


def test_series_command_passes_the_declared_range_image():
    module, cfg = configured()
    build_name = cfg['arms'][0]['build']
    cfg['builds'][build_name].update(image_len=61, read_images={'range': 141})
    campaign = module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'series_rc', arms=['combined'],
                                              fixtures=['separate_ack'])
    campaign._series_build, campaign._series_padding, campaign._series_control_padding = build_name, 1, 1
    command = campaign.series_vision_cmd('x', 59420, 20, 8, 0)
    assert '--read-image-len 141' in command


def test_unsupported_range_class_is_refused():
    module, cfg = configured()
    cfg['builds'][cfg['arms'][0]['build']].update(image_len=61, read_images={'range': None})
    with pytest.raises(ValueError, match='not supported'):
        module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'series_rc_bad', arms=['combined'],
                                       fixtures=['separate_ack'])


def test_a_read_schedule_is_refused():
    module, cfg = configured()
    cfg['traffic'].update(read_schedule='rotate4', db='base')
    with pytest.raises(ValueError, match='read_schedule'):
        module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'series_rc_sched', arms=['combined'],
                                       fixtures=['separate_ack'])
