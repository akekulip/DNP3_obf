"""Shared test setup: puts the harness on sys.path and builds a configured Pipeline."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(ARCH.parent / 'framework/size'))
sys.path.insert(0, str(ARCH / 'integration/connection'))

SOURCE = ARCH / 'integration/connection/binding/native_binding.p4'
EXPECTED_SHA256_PREFIX = '35bf9aa3'
