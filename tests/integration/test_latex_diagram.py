import shutil

import pytest

from claasp.drivers.renderers import LaTeXDriver
from claasp.primitives import MiMC
from claasp.representations.diagrams import DiagramCompiler, TikZSerializer

pytestmark = pytest.mark.external


def test_pdflatex_renders_tikz_representation_to_pdf():
    assert shutil.which("pdflatex") is not None, "the external test job must install pdflatex"
    primitive = MiMC(17, 3, (1,))
    diagram = DiagramCompiler().compile(primitive)
    tikz = TikZSerializer().serialize(diagram)

    result = LaTeXDriver().render(tikz)

    assert result.pdf.startswith(b"%PDF-")
    assert result.runtime_seconds >= 0
