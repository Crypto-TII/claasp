"""Ordinary Alzette/Gimli evidence and byte checks against a frozen matrix.

Run: python docs/diagrams/check_inline_constants.py OUTPUT FROZEN_MATRIX_RESULTS
The baseline argument contains the admitted .asciiart/.tikz files produced by
check_instance_matrix.py at d26a8f03. It is never used to choose a layout.
"""
import argparse
import importlib
import json
from pathlib import Path
from check_instance_matrix import CASES, BOUNDS, one_case


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    parser.add_argument('baseline', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    reports = [one_case(case, args.output) for case in CASES if case[0] in ('alzette', 'gimli1')]
    from claasp.diagrams import Diagrams
    checks = []
    for name, module, class_name, kwargs in CASES:
        existing = [path for path in args.baseline.glob(name+'-*') if path.suffix in ('.asciiart', '.tikz')]
        if not existing:
            continue
        diagram = Diagrams(getattr(importlib.import_module('claasp.ciphers.'+module), class_name)(**kwargs))
        for path in sorted(existing):
            routed = path.stem.endswith('-routed')
            options = dict(BOUNDS, routed_words=routed)
            text = (diagram.to_ascii(annotations=True, **options) if path.suffix == '.asciiart'
                    else diagram.to_tikz(maxPanels=32, **options))
            assert text.encode() == path.read_bytes(), path
            checks.append({'file': path.name, 'byte_identical': True})
    (args.output/'evidence.json').write_text(json.dumps({'instances': reports, 'baseline_checks': checks}, indent=2))
    print(json.dumps({'instances': len(reports), 'byte_identical_baseline_files': len(checks)}))


if __name__ == '__main__':
    main()
