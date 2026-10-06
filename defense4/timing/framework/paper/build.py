#!/usr/bin/env python3
"""Gate and compile only this working draft, with read-only frozen citations."""
import os
import subprocess
from pathlib import Path

from working_gate import check

HERE = Path(__file__).resolve().parent
check()
env = os.environ.copy()
env['BIBINPUTS'] = os.pathsep.join((str(HERE),
    str(HERE.parents[3] / 'paper/rewrite'), env.get('BIBINPUTS', '')))
subprocess.run(['latexmk', '-pdf', '-interaction=nonstopmode', '-halt-on-error',
                '-outdir=build', 'main.tex'], cwd=HERE, env=env, check=True)
