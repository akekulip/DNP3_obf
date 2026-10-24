"""model_smoke on a SIZE-OFF connection (E fwd_conn enable 0, no pipe-1 p1_conn row): the C1 regression for the
pipe-1 READ padder. Every READ/SBO response must stay exactly native (49/37) end to end, with zero cumulative
growth, on the same image whose size-on connections pad. (run_model sets PAD_ENABLE=1 for every driver; this
entry point alone overrides it in-process.)"""
import os
import sys
from pathlib import Path

os.environ['PAD_ENABLE'] = '0'
sys.path.insert(0, str(Path(__file__).resolve().parent))
import model_smoke  # noqa: E402

if __name__ == '__main__':
    raise SystemExit(model_smoke.main())
