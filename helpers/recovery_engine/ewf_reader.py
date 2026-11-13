"""Load only the pinned EWF dependency shipped with the application."""
from pathlib import Path
import sys

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "vendor/ewfprobe"))

from ewfprobe import EwfImage, ewf_segments
