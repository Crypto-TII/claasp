"""The normal docs generator discovers only the selected public diagram guides."""
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('mode', ['html', 'pdf'])
def test_public_diagram_navigation_and_deterministic_generation(tmp_path, mode):
    docs = tmp_path / 'docs'
    docs.mkdir()
    for name in ('create_rst_structure.py', 'conf.py', 'references.rst'):
        shutil.copyfile(ROOT / 'docs' / name, docs / name)
    shutil.copytree(ROOT / 'docs/diagrams', docs / 'diagrams')
    modules = tmp_path / 'claasp'
    modules.mkdir()
    (modules / 'core_reference.py').write_text('"""Unrelated reference."""\n')
    (modules / 'diagrams.py').write_text('"""Compatibility reference."""\n')
    package = modules / 'cipher_modules/diagram'
    package.mkdir(parents=True)
    for name in ('api', 'facade'):
        (package / (name + '.py')).write_text('"""Diagram reference."""\n')

    def generate():
        subprocess.run([sys.executable, 'create_rst_structure.py', mode], cwd=docs, check=True)
        return {str(path.relative_to(docs / 'source')): path.read_bytes()
                for path in (docs / 'source').rglob('*') if path.is_file()}

    first = generate()
    assert generate() == first
    index = first['index.rst'].decode()
    assert '    core_reference\n' in index
    assert '    diagrams\n' in index
    assert '    cipher_modules/diagram/api\n' in index
    assert '    cipher_modules/diagram/facade\n' in index
    assert '    diagrams/index\n' in index
    # Match the existing top-level Utils/Components/General Information
    # sections: an equals underline, with no overline introducing a new level.
    assert '\nDiagram guides\n==============\n\n.. toctree::' in index
    assert '\n--------------\nDiagram guides' not in index
    assert first['diagrams/index.rst'] == (ROOT / 'docs/diagrams/index.rst').read_bytes()
    assert first['diagrams/persistent_word_examples.rst'] == (
        ROOT / 'docs/diagrams/persistent_word_examples.rst').read_bytes()
    for rounds in (1, 2):
        path = f'diagrams/examples/speck{rounds}-persistent.asciiart'
        assert first[path] == (ROOT / 'docs' / path).read_bytes()
    assert set(path for path in first if path.startswith('diagrams/')) == {
        'diagrams/index.rst', 'diagrams/persistent_word_examples.rst',
        'diagrams/examples/speck1-persistent.asciiart', 'diagrams/examples/speck2-persistent.asciiart',
    }
    assert 'four_input_xor_design' not in index
    assert 'ordinary_instance_matrix' not in index
