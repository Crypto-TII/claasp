import sage.all
import pytest


def _noop(*args, **kwargs):
    return None


@pytest.fixture(autouse=True)
def _disable_gui_image_popups(monkeypatch):
    try:
        import matplotlib

        matplotlib.use("Agg", force=True)
        import matplotlib.pyplot as plt

        monkeypatch.setattr(plt, "show", _noop, raising=False)
    except Exception:
        pass

    try:
        from PIL import Image

        monkeypatch.setattr(Image.Image, "show", _noop, raising=False)
    except Exception:
        pass

    try:
        from plotly.basedatatypes import BaseFigure

        monkeypatch.setattr(BaseFigure, "show", _noop, raising=False)
    except Exception:
        pass