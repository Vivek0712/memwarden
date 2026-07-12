# Compatibility shim: the system's pre-review name was `memctl` and the paper's
# shipped heldout_eval.py imports `memctl.detect.rules`. Real code lives in `engram`.
from engram import detect  # noqa: F401
