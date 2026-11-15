import pathlib
import subprocess
import sys

import entra_auditor

PACKAGE_DIR = pathlib.Path(entra_auditor.__file__).parent


def test_running_the_package_directory_as_a_script_explains_the_right_command():
    """`python entra_auditor` (no -m) used to die with 'attempted relative import with no known parent package'."""
    result = subprocess.run([sys.executable, str(PACKAGE_DIR)], capture_output=True, text=True, timeout=60)
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "python -m entra_auditor" in output and "relative import" not in output
