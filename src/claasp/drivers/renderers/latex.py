"""Optional LaTeX driver producing PDF diagram artifacts."""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic


@dataclass(frozen=True, slots=True)
class PDFResult:
    """Rendered PDF bytes and captured LaTeX process diagnostics.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (PDFResult.__dataclass_params__.frozen, tuple(field.name for field in fields(PDFResult)))
        (True, ('pdf', 'runtime_seconds', 'stdout', 'stderr'))
    """

    pdf: bytes
    runtime_seconds: float
    stdout: str
    stderr: str

    def __post_init__(self) -> None:
        if not self.pdf.startswith(b"%PDF-"):
            raise ValueError("renderer result is not a PDF document")


class LaTeXDriver:
    """Compile a standalone LaTeX representation with ``pdflatex``."""

    def __init__(self, executable: str = "pdflatex", timeout_seconds: float | None = 30) -> None:
        if not isinstance(executable, str) or not executable:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def render(self, document: str) -> PDFResult:
        """Compile ``document`` in an isolated temporary directory."""

        if not isinstance(document, str):
            raise TypeError("document must be LaTeX source text")
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"LaTeX executable {self.executable!r} was not found")
        with TemporaryDirectory(prefix="claasp-latex-") as directory:
            source = Path(directory) / "diagram.tex"
            source.write_text(document, encoding="utf-8")
            start = monotonic()
            completed = subprocess.run(
                [
                    executable,
                    "-interaction=nonstopmode",
                    "-halt-on-error",
                    f"-output-directory={directory}",
                    str(source),
                ],
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start
            pdf_path = Path(directory) / "diagram.pdf"
            if completed.returncode != 0 or not pdf_path.exists():
                raise RuntimeError(
                    "LaTeX rendering failed: "
                    + (completed.stderr.strip() or completed.stdout.strip())
                )
            pdf = pdf_path.read_bytes()
        return PDFResult(pdf, elapsed, completed.stdout, completed.stderr)
