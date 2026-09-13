import shutil

import pytest

from claasp_next.ciphers import MiMCPermutation
from claasp_next.drivers.renderers import LaTeXDriver


pytestmark = pytest.mark.external


def test_pdflatex_renders_tikz_representation_to_pdf():
    assert shutil.which("pdflatex") is not None, "the external test job must install pdflatex"
    cipher = MiMCPermutation(17, 3, (1,))

    result = LaTeXDriver().render(cipher.draw("tikz"))

    assert result.pdf.startswith(b"%PDF-")
    assert result.runtime_seconds >= 0
    assert cipher.draw("pdf").startswith(b"%PDF-")
