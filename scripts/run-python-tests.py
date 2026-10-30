"""Run every source-owned Python bridge and analysis-efficiency test."""

from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
bridge_tests = sorted(root.joinpath("bridge").rglob("test_*.py"))
if not bridge_tests:
    sys.exit("No Python bridge tests discovered")
if not list(root.joinpath("tests/support/analysis-efficiency").glob("test_*.py")):
    sys.exit("No Python analysis-efficiency tests discovered")
modules = [
    ".".join(path.relative_to(root).with_suffix("").parts) for path in bridge_tests
]
commands = [
    [sys.executable, "-m", "unittest", "-v", *modules],
    [
        sys.executable, "-m", "unittest", "discover",
        "-s", "tests/support/analysis-efficiency", "-p", "test_*.py", "-v",
    ],
]
for command in commands:
    result = subprocess.run(command, cwd=root, check=False)
    if result.returncode:
        sys.exit(result.returncode)
