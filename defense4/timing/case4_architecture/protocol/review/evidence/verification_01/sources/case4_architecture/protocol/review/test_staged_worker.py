"""Same independent byte oracle, actual frozen staged-root compiler input."""
import test_fixed_worker


class StagedWorkerReview(test_fixed_worker.FixedWorkerReview):
    SOURCE = test_fixed_worker.ARCH / 'integration/assembly_passes/evidence/staged_worker_0_01/source/staged_worker_0.p4'
