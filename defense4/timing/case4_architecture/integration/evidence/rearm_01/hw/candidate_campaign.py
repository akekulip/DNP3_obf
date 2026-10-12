#!/usr/bin/env python3
"""Explicit candidate CP deployment using the ordinary guarded campaign/rollback.

Uses the same CLI as protocol/hw_vepa/campaign.py. Every selected build must
declare lifecycle_rearm:true; frozen baseline campaigns use their original CLI.
"""
import sys
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
sys.path.insert(0, str(ARCH / 'protocol' / 'hw_vepa'))
import campaign as base

CANDIDATE = 'integration/core/response_only_rearm'
EXTRA_FILES = (CANDIDATE + '/cp.py', CANDIDATE + '/hw/bringup_composite.py',
               CANDIDATE + '/hw/snapshot_counters.py', CANDIDATE + '/hw/sealed_profile.py')


class CandidateCampaign(base.Campaign):
    def _require_hardware_authorization(self):
        if not self.rn.dry and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
            raise ValueError('candidate hardware execution requires DEFENSE4_HW_AUTHORIZED=1')

    def execute(self):
        self._require_hardware_authorization()
        return super().execute()

    def deploy_only(self):
        self._require_hardware_authorization()
        return super().deploy_only()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in base.selected_builds(self.cfg, self.arms):
            if self.cfg['builds'][name].get('lifecycle_rearm') is not True:
                raise ValueError('candidate installer requires lifecycle_rearm:true on selected build ' + name)
        self.candidate_identity = {rel: base.sha256_file(ARCH / rel) for rel in EXTRA_FILES}
        self.record['candidate_source_identity'] = self.candidate_identity

    def deploy_switch(self):
        super().deploy_switch()
        host = self.cfg['hosts']['switch']
        self.step('local', 'copy isolated candidate CP and installer',
                  'rsync -aR %s %s:%s/src/' %
                  (' '.join(base.q(rel) for rel in EXTRA_FILES), host, self.R), cwd=str(ARCH))
        remote = {rel: '%s/src/%s' % (self.R, rel) for rel in EXTRA_FILES}
        result = self.step('switch', 'verify isolated candidate CP and installer identity',
                           'sha256sum ' + ' '.join(base.q(path) for path in remote.values()))
        if not self.rn.dry:
            observed = {line.split()[1]: line.split()[0] for line in result.out.splitlines()
                        if len(line.split()) == 2}
            for rel, path in remote.items():
                if observed.get(path) != self.candidate_identity[rel]:
                    raise base.StepFailed('candidate installer identity mismatch: ' + path)

    def installer_cmd(self, *args, **kwargs):
        command = super().installer_cmd(*args, **kwargs)
        original = '%s/%s/bringup_composite.py' % (self.R, base.HW)
        replacement = '%s/src/%s/hw/bringup_composite.py' % (self.R, CANDIDATE)
        if command.count(original) != 1:
            raise ValueError('baseline installer command no longer has the expected entrypoint')
        return command.replace(original, replacement, 1)

    def switch_cmd(self, script, args):
        if script == 'snapshot_counters.py':
            return 'python3 %s/src/%s/hw/%s %s' % (self.R, CANDIDATE, script, args)
        return super().switch_cmd(script, args)


if __name__ == '__main__':
    # The ordinary CLI continues to own binding checks, authorization and cleanup.
    base.Campaign = CandidateCampaign
    sys.exit(base.main())
