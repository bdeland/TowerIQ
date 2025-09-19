import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
STUBS_DIR = TESTS_DIR / "_stubs"
SRC_DIR = TESTS_DIR.parent / "src"

if str(STUBS_DIR) not in sys.path:
    sys.path.insert(0, str(STUBS_DIR))

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
