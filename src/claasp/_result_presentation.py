"""Storage-free convenience methods for retained search-result presentation.

These internal mixins hold no result data and import no presentation libraries
at module load time. Type-specific adapters continue to interpret the evidence.
The API authority uses ``__public_api_methods__`` to track their inherited
methods on public receivers without exporting the internal mixin classes.
"""


class PlotMixin:
    """Share plot delegation without adding storage to slotted result classes."""

    __slots__ = ()
    __public_api_methods__ = ("plot",)

    def plot(self, *, details=False, value_format="hex", show=True, save_to=None):
        """Plot retained evidence without repeating a search.

        Requires the optional ``presentation`` extra. ``show=False`` suppresses
        display; ``save_to`` writes a file. Impossible-differential results
        show the retained round path, both meeting states and contradictions;
        ``details=True`` includes component states and ``value_format`` selects
        notation for exact word annotations. Returns a ``FigureArtifact`` with
        the figure and numeric series. Result-specific views and examples are
        documented on the result class.

        EXAMPLES::

            >>> from claasp.analysis import ImpossibleSearchResult
            >>> result = ImpossibleSearchResult((), (1,), False, 'solver unknown')
            >>> artifact = result.plot(show=False)
            >>> artifact.kind, artifact.series
            ('search_evidence', ())
            >>> import matplotlib.pyplot as plt
            >>> plt.close(artifact.figure)
        """
        from claasp.drivers.renderers._search_results import _plot

        return _plot(self, details=details, value_format=value_format, show=show, save_to=save_to)


class TerminalMixin:
    """Share terminal delegation while allowing specialized result overrides."""

    __slots__ = ()
    __public_api_methods__ = ("to_terminal",)

    def to_terminal(self, *, details=False, value_format="hex", file=None):
        """Print retained evidence and status without repeating a search.

        For exact trails, ``details=True`` includes component values and
        ``value_format`` selects ``hex``, ``binary`` (``0b`` prefix), or
        ``underscore_one`` (zero as ``_``, one as ``1``), MSB first.
        Output goes to standard output unless ``file`` is supplied. No plotting
        dependency is required. See the result class for its evidence-specific
        interpretation and examples.

        EXAMPLES::

            >>> from io import StringIO
            >>> from claasp.analysis import ImpossibleSearchResult
            >>> stream = StringIO()
            >>> result = ImpossibleSearchResult((), (1,), False, 'solver unknown')
            >>> result.to_terminal(file=stream)
            >>> 'solver unknown' in stream.getvalue()
            True
        """
        from claasp.presentation._search_results import _to_terminal

        _to_terminal(self, details=details, value_format=value_format, file=file)
