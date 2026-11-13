#!/usr/bin/env python3
"""Install the pinned Python forensic toolkit locally; no sample is executed."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
subprocess.run([
    sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check',
    '--only-binary=:all:', '--target', str(root / 'python'),
    '-r', str(root / 'requirements.txt'),
], check=True)
