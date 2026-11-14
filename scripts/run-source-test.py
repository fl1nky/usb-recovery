"""Run an unchanged source test with value-free CI failure locations."""
from pathlib import Path
import os
import re
import runpy
import sys
import traceback
import unittest


def location(test, error):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    # Only identifiers and source locations; never exception values or locals.
    identity = re.sub(r"[^A-Za-z0-9_.]", "_", test.id().split(" (", 1)[0])[:240]
    frames = traceback.extract_tb(error[2])
    frames = [f"{re.sub(r'[^A-Za-z0-9_.-]', '_', Path(frame.filename).name)}:{frame.lineno}"
              for frame in frames[-5:]]
    kind = re.sub(r"[^A-Za-z0-9_]", "_", error[0].__name__)
    print(f"::error title=Source failure location::{identity}; {kind}; {' > '.join(frames)}", flush=True)


if __name__ == "__main__":
    path = Path(sys.argv[1]).resolve(strict=True)
    for method in ("addFailure", "addError"):
        original = getattr(unittest.TextTestResult, method)

        def report(self, test, error, base=original):
            location(test, error)
            return base(self, test, error)

        setattr(unittest.TextTestResult, method, report)
    original_subtest = unittest.TextTestResult.addSubTest

    def report_subtest(self, test, subtest, error):
        if error is not None:
            location(test, error)
        return original_subtest(self, test, subtest, error)

    unittest.TextTestResult.addSubTest = report_subtest
    sys.argv = [str(path), *sys.argv[2:]]
    # Support tests which load the entry point by filename, as well as modules.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'helpers/recovery_engine'))
    sys.path.insert(0, str(path.parent))
    runpy.run_path(str(path), run_name="__main__")
