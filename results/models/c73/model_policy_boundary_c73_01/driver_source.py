"""Entry point: model_policy.py in its C3/C5 boundary mode (see that file)."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ['POLICY_CASE'] = 'boundary'
import model_policy  # noqa: E402

if __name__ == '__main__':
    raise SystemExit(model_policy.model_main())
