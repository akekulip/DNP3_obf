"""Run the c74 connection-start correction regressions once on a build. NOT part of the model gate.

Usage: python3 scripts/model/run_connection_fix.py BUILD ATTEMPT
Evidence: results/models/BUILD_NAME_connection_fix/model_connection_fix_BUILD_NAME_NN/

The launch path, preconditions, environment and records are run_connection_start's (and so run_model's), with
scripts/model/model_connection_fix.py as the driver and closure target. Refuses to start while another tofino-model
process is running."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_connection_start as base  # noqa: E402

base.DRIVER = HERE / 'model_connection_fix.py'
base.SCENARIO = ('c74 connection-start correction regressions (H1/H2/H2r/collision/H1prime/H1_sbo, retry exhaustion '
                 'and staleness, duplicates, stale ACKs, FIN/RST, reconnect, SELECT/OPERATE association, residuals); '
                 'a separate labelled scenario, not part of the 17-driver model gate')


def evidence_dir(build, attempt):
    name = Path(build).name
    return base.ROOT / 'results/models' / (name + '_connection_fix') / ('model_connection_fix_%s_%02d' % (name, attempt))


base.evidence_dir = evidence_dir

if __name__ == '__main__':
    raise SystemExit(base.main())
