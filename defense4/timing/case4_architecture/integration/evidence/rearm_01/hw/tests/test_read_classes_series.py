"""Per-class READ declarations in the candidate series harness.

vision_candidate runs only the range READ (one SBO, no schedule), so a series build that declares read_images takes
its READ image from read_images['range'] and refuses a configured READ-class schedule or an unsupported range
class instead of silently expecting the native or the legacy read_image_len."""
import json
import sys
from pathlib import Path

import pytest

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_candidate_series import _dup_gate, configured, actual_lifecycle  # noqa: E402


def _series_gate(module, cfg, acct_lo):
    """series_switch_gate over the three-connection evidence of a passing protected series, with the egress mapper
    growth counter set to `acct_lo` (front = 1000). Mirrors _dup_gate but lets a per-class growth match exactly."""
    before = {'outcomes': {'OUT_ACK_COMMIT': 0, 'OUT_ACK_FALLBACK': 0, 'OUT_RESP_RELEASE': 0, 'OUT_RESP_FALLBACK': 0,
                           'OUT_OP_RELEASE': 0, 'OUT_TOKEN_STALE': 0, 'OUT_OP_DUP_DROP': 0},
              'pktgen': {'READ': {'trigger_counter': 0, 'pkt_counter': 0},
                         'OPERATE': {'trigger_counter': 0, 'pkt_counter': 0}},
              'loop_ports': {role: {'$OctetsReceived': 0, '$OctetsReceivedinGoodFrames': 0}
                             for role in module.checks.LOOP_ROLES},
              'regs': {'acct': {'acct.lo': [acct_lo], 'acct.hi': [0]}, 'front': {'front': [0]}}}
    after = json.loads(json.dumps(before))
    after['outcomes'].update(OUT_ACK_COMMIT=60, OUT_RESP_RELEASE=60, OUT_OP_RELEASE=3)
    after['pktgen']['READ'] = {'trigger_counter': 60, 'pkt_counter': 240}
    after['pktgen']['OPERATE'] = {'trigger_counter': 3, 'pkt_counter': 12}
    lifecycle = actual_lifecycle()
    lifecycle['registers']['p0.r_Egress.acct']['r_Egress.acct.lo'] = [acct_lo]
    return module.series_switch_gate(cfg, cfg['arms'][0], 20, {'before': before, 'after': after}, lifecycle)


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


def test_series_read_shape_defaults_to_the_range_read():
    module, cfg = configured()
    build = cfg['builds'][cfg['arms'][0]['build']]
    build.update(image_len=58, read_images={'range': 141})
    # default (no series_read_class): the range image with the legacy native 49
    assert module.series_read_shape(cfg, build, 58) == (141, 49)


@pytest.mark.parametrize('cls,length', [('analog', 141), ('class0', 247), ('integrity', 247)])
def test_series_issues_a_single_frame_class_and_preserves_growth(cls, length):
    module, cfg = configured()
    build = cfg['builds'][cfg['arms'][0]['build']]
    build['read_images'] = {cls: length}                              # a padded series must declare the class image
    cfg['traffic'].update(series_read_class=cls, db='base')
    # a single-frame class is already at its target size on base: no per-READ growth, only control padding
    assert module.series_read_shape(cfg, build, build.get('image_len', 58)) == (length, length)
    control = 2 * (build.get('image_len', 58) - 37)
    failures, observed = _series_gate(module, cfg, 1000 + control)
    assert observed['external_growth_expected'] == 20 * (length - length) + control
    assert observed['external_growth_bytes'] == control
    assert failures == [], failures                                   # delivery + recovery + preserved growth


def test_series_refuses_an_undeclared_class_on_a_padded_arm():
    module, cfg = configured()
    cfg['traffic'].update(series_read_class='analog', db='base')      # build declares no read_images
    with pytest.raises(ValueError, match='declare'):
        module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'series_undecl', arms=['combined'],
                                       fixtures=['separate_ack'])


def test_series_command_passes_the_chosen_single_frame_class_image():
    module, cfg = configured()
    build_name = cfg['arms'][0]['build']
    cfg['builds'][build_name]['read_images'] = {'analog': 141}
    cfg['traffic'].update(series_read_class='analog', db='base')
    campaign = module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'series_ac', arms=['combined'],
                                              fixtures=['separate_ack'])
    campaign._series_build, campaign._series_padding, campaign._series_control_padding = build_name, 1, 1
    assert '--read-image-len 141' in campaign.series_vision_cmd('x', 59420, 20, 8, 0)


def test_series_refuses_a_segmented_class_not_exercised():
    module, cfg = configured()
    cfg['builds'][cfg['arms'][0]['build']]['read_images'] = {'class0': 401}
    cfg['traffic'].update(series_read_class='class0', db='large')      # large DB class0 = 292 + 85, two frames
    with pytest.raises(ValueError, match='NOT_EXERCISED|segmented'):
        module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'series_seg', arms=['combined'],
                                       fixtures=['separate_ack'])


def test_series_refuses_db_without_a_chosen_class():
    module, cfg = configured()
    cfg['traffic'].update(db='base')
    with pytest.raises(ValueError, match='series_read_class'):
        module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'series_db', arms=['combined'],
                                       fixtures=['separate_ack'])
