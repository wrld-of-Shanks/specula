import os
import sys

# Make service modules importable from test packages regardless of the working
# directory pytest runs from.
_ROOT = os.path.dirname(os.path.abspath(__file__))
_SRC_DIRS = [
    os.path.join(_ROOT, 'backend/services/code/models'),
    os.path.join(_ROOT, 'backend/services/code'),
    os.path.join(_ROOT, 'backend/services/dast'),
    os.path.join(_ROOT, 'backend/services/network'),
]
for _d in _SRC_DIRS:
    if _d not in sys.path:
        sys.path.insert(0, _d)
