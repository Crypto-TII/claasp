"""Compile/import regressions run in the documented Sage9.5/Python3.10 CI job.

They use the actual interpreter, not newer Python's best-effort grammar flags.
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def test_diagram_source_compiles_on_test_interpreter():
    paths = [ROOT / 'claasp/diagrams.py',
             *sorted((ROOT / 'claasp/cipher_modules/diagram').glob('*.py'))]
    for path in paths:
        compile(path.read_text(), str(path), 'exec')


def test_fresh_process_imports_public_diagram_api():
    program = ('from claasp.diagrams import Diagrams\n'
               'from claasp.cipher_modules.diagram import Diagrams as implementation\n'
               'assert Diagrams is implementation\n')
    subprocess.run([sys.executable, '-c', program], cwd=ROOT, check=True, timeout=30)
