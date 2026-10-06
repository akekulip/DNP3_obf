"""SBO retains its own outstation timer origin; no hardware or traffic."""
import dataclasses
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_request_anchor_admission import request_inputs
from test_delay_admission import b
import delay_admission as da

PROFILE = 'a' * 64


def control_inputs(**over):
    inp = request_inputs(context=da.PolicyContext('conn-1', 'frozen-7ce30494',
        operation='SBO', operation_profile_sha256=PROFILE))
    for field in dataclasses.fields(inp):
        value = getattr(inp, field.name)
        if isinstance(value, da.Bound) and value.applies_to is not None:
            inp = dataclasses.replace(inp, **{field.name: dataclasses.replace(value,
                applies_to=dataclasses.replace(value.applies_to, operation_profile_sha256=PROFILE))})
    return dataclasses.replace(inp, **over)


def sbo(budget=100., native=5., operate=4., **over):
    def bound(name, value, direction='', timer='', provenance=da.Provenance.MEASURED_THIS_CONNECTION):
        return b(name, value, provenance, applies_to=da.Applicability('conn-1', direction,
            'frozen-7ce30494', timer, operation_profile_sha256=PROFILE))
    fields = dict(budget_ms=bound('sbo_budget_ms', budget, 'select_to_operate',
        'outstation_select_retention', da.Provenance.OPERATOR_SUPPLIED),
        native_cycle_ms=bound('sbo_native_cycle_ms', native, 'select_to_operate'),
        operate_added_ms=bound('sbo_operate_added_ms', operate, 'master_to_outstation'),
        origin='outstation_successful_select_accept', endpoint='outstation_matching_operate_accept',
        operation_profile_sha256=PROFILE)
    fields.update(over)
    return da.SBOInputs(**fields)


class SBOAdmission(unittest.TestCase):
    def test_missing_sbo_does_not_admit_a_control_policy(self):
        verdict = da.evaluate(control_inputs())
        self.assertEqual(verdict['verdict'], 'provisional')
        self.assertIn('sbo_budget_ms', verdict['unknown_inputs'])

    def test_whole_native_cycle_and_each_added_hold_charged_once(self):
        verdict = da.evaluate(control_inputs(sbo=sbo()))
        checks = {c['constraint']: c for c in verdict['checks']}
        self.assertAlmostEqual(checks['outstation SELECT retention normal']['consumed_ms'],
            5 + 20 + .0012 + .0017 + 4 + 3)
        self.assertAlmostEqual(checks['outstation SELECT retention recovery']['consumed_ms'],
            5 + 37.1517 + 4 + 3)
        self.assertEqual(verdict['verdict'], 'admitted_conditional')

    def test_selection_can_expire_despite_large_application_budget(self):
        verdict = da.evaluate(control_inputs(sbo=sbo(budget=30)))
        self.assertEqual(verdict['verdict'], 'refused')
        self.assertFalse(next(c for c in verdict['checks']
            if c['constraint'] == 'outstation SELECT retention normal')['ok'])

    def test_recovery_checked_even_when_normal_cycle_fits(self):
        verdict = da.evaluate(control_inputs(sbo=sbo(budget=40)))
        checks = {c['constraint']: c for c in verdict['checks']}
        self.assertTrue(checks['outstation SELECT retention normal']['ok'])
        self.assertFalse(checks['outstation SELECT retention recovery']['ok'])

    def test_master_receive_origin_is_rejected(self):
        verdict = da.evaluate(control_inputs(sbo=sbo(origin='master_select_response_receive')))
        self.assertEqual(verdict['verdict'], 'rejected')

    def test_missing_origin_is_unavailable_not_zero_elapsed(self):
        verdict = da.evaluate(control_inputs(sbo=sbo(origin='')))
        self.assertEqual(verdict['verdict'], 'provisional')
        self.assertIn('sbo_clock_origin', verdict['unknown_inputs'])

    def test_wrong_profile_or_connection_never_admits(self):
        wrong_profile = sbo(operation_profile_sha256='b' * 64)
        wrong_connection = sbo(budget_ms=dataclasses.replace(sbo().budget_ms,
            applies_to=dataclasses.replace(sbo().budget_ms.applies_to, connection_id='other')))
        for budget in (wrong_profile, wrong_connection):
            self.assertEqual(da.evaluate(control_inputs(sbo=budget))['verdict'], 'provisional')

    def test_wrong_timer_cannot_fill_retention_budget(self):
        budget = sbo(budget_ms=dataclasses.replace(sbo().budget_ms,
            applies_to=dataclasses.replace(sbo().budget_ms.applies_to, timer='master_rto')))
        self.assertEqual(da.evaluate(control_inputs(sbo=budget))['verdict'], 'provisional')

    def test_read_has_no_sbo_dependency(self):
        verdict = da.evaluate(request_inputs())
        self.assertEqual(verdict['verdict'], 'admitted_conditional')
        self.assertNotIn('sbo_budget_ms', verdict['unknown_inputs'])

    def test_non_hash_control_profile_is_rejected(self):
        inp=control_inputs(sbo=sbo())
        inp=dataclasses.replace(inp,context=dataclasses.replace(inp.context,operation_profile_sha256='label'))
        self.assertEqual(da.evaluate(inp)['verdict'],'rejected')


if __name__ == '__main__':
    unittest.main()
