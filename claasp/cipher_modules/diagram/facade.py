"""Object interface for the functional diagram API."""

import copy
from . import api


class Diagrams:
    r"""
    Freeze a primitive's semantic graph and export its generic diagram views.

    INPUT:

    - ``cipher`` -- **Cipher**; the original primitive
    - ``roles`` -- optional **dictionary** mapping input identities to generic roles

    The captured graph is independent of subsequent edits to the original cipher.
    Rendering methods accept the same keyword options and raise the same errors
    as the functional API. No primitive name selects a layout. Persistent shapes
    must be admitted; diagnostic/legacy views require explicit options.

    EXAMPLES::

        sage: from claasp.diagrams import Diagrams, to_ascii
        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: cipher = SpeckBlockCipher(number_of_rounds=int(1))
        sage: diagram = Diagrams(cipher)
        sage: diagram.to_ascii() == to_ascii(diagram.ir)
        True
        sage: diagram.to_tikz(fitToPage=(int(25), int(30))).count('% word-native ')
        5
        sage: values = diagram.evaluate_state_values(list(map(int, [0x6574694c, 0x1918111009080100])))
        sage: frames = diagram.state_snapshots(mode='word', word_bits=None, values=values)
        sage: [len(frame['words']) for frame in frames]
        [6, 6]
    """

    def __init__(self, cipher, *, roles=None):
        """Capture validated native semantics; retain no mutable layout cache."""
        self._ir = api.from_cipher(cipher, roles=roles)

    @property
    def ir(self):
        """Return an independent typed **dictionary** of the captured semantic graph."""
        return copy.deepcopy(self._ir)

    def to_ascii(self, **options):
        r"""
        Export the captured graph using :func:`~claasp.cipher_modules.diagram.api.to_ascii`.

        INPUT:

        - ``options`` -- **keyword options**; identical to :func:`~claasp.cipher_modules.diagram.api.to_ascii`

        OUTPUT:

        An ASCII **string**. Functional validation and unsupported-shape errors are preserved.
        """
        return api.to_ascii(self._ir, **options)

    def to_tikz(self, **options):
        r"""
        Export the captured graph using :func:`~claasp.cipher_modules.diagram.api.to_tikz`.

        INPUT:

        - ``options`` -- **keyword options**; identical to :func:`~claasp.cipher_modules.diagram.api.to_tikz`

        OUTPUT:

        A TikZ **string**. Functional validation and unsupported-shape errors are preserved.
        """
        return api.to_tikz(self._ir, **options)

    def to_cipher(self):
        """Return an executable **Cipher** reconstructed from captured native semantics."""
        return api.to_cipher(self._ir)

    def evaluate_state_values(self, inputs):
        """Return an identity-keyed **dictionary** of evaluated input/component integers.

        ``inputs`` is an ordered **list of integers** fitting native input widths.
        Evaluation uses a reconstruction of the frozen graph, so later changes to
        the constructor's cipher do not affect values. See
        :func:`~claasp.cipher_modules.diagram.api.evaluate_state_values`.
        """
        return api.evaluate_state_values(self.to_cipher(), inputs)

    def state_snapshots(self, **options):
        r"""
        Export the captured graph using :func:`~claasp.cipher_modules.diagram.api.state_snapshots`.

        INPUT:

        - ``options`` -- **keyword options**; identical to :func:`~claasp.cipher_modules.diagram.api.state_snapshots`

        OUTPUT:

        A **list of dictionaries**. Functional validation and unsupported-shape errors are preserved.
        """
        return api.state_snapshots(self._ir, **options)

    def state_ascii(self, **options):
        r"""
        Export the captured graph using :func:`~claasp.cipher_modules.diagram.api.state_ascii`.

        INPUT:

        - ``options`` -- **keyword options**; identical to :func:`~claasp.cipher_modules.diagram.api.state_ascii`

        OUTPUT:

        An ASCII state **string**. Functional validation and unsupported-shape errors are preserved.
        """
        return api.state_ascii(self._ir, **options)

    def state_tikz(self, **options):
        r"""
        Export the captured graph using :func:`~claasp.cipher_modules.diagram.api.state_tikz`.

        INPUT:

        - ``options`` -- **keyword options**; identical to :func:`~claasp.cipher_modules.diagram.api.state_tikz`

        OUTPUT:

        A TikZ state **string**. Functional validation and unsupported-shape errors are preserved.
        """
        return api.state_tikz(self._ir, **options)

    def state_view(self, **options):
        r"""
        Export the captured graph using :func:`~claasp.cipher_modules.diagram.api.state_view`.

        INPUT:

        - ``options`` -- **keyword options**; identical to :func:`~claasp.cipher_modules.diagram.api.state_view`

        OUTPUT:

        A **list of native observation dictionaries**. Functional validation and unsupported-shape errors are preserved.
        """
        return api.state_view(self._ir, **options)
