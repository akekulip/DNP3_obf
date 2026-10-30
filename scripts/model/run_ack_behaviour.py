"""Run the master-ACK behaviour cases once on a build. NOT part of the model gate.

Usage: python3 scripts/model/run_ack_behaviour.py BUILD ATTEMPT
Evidence: results/models/BUILD_NAME_ack_behaviour/model_ack_behaviour_BUILD_NAME_NN/

The launch path, preconditions, environment and records are run_connection_start's (and so run_model's), with
scripts/model/model_ack_behaviour.py as the driver and closure target. The rule and cases are registered in
results/analysis/ack_behaviour/DESIGN.json. Refuses to start while another tofino-model process is running."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_connection_start as base  # noqa: E402

base.DRIVER = HERE / 'model_ack_behaviour.py'
base.SCENARIO = ('master-ACK behaviour against results/analysis/ack_behaviour/DESIGN.json (late handshake ACK in both '
                 'orders, R1/R2, window update and zero window while a READ is outstanding, keepalives, duplicate and '
                 'response ACK controls); a separate labelled scenario, not part of the 17-driver model gate')


def evidence_dir(build, attempt):
    name = Path(build).name
    return base.ROOT / 'results/models' / (name + '_ack_behaviour') / ('model_ack_behaviour_%s_%02d' % (name, attempt))


base.evidence_dir = evidence_dir

if __name__ == '__main__':
    raise SystemExit(base.main())
