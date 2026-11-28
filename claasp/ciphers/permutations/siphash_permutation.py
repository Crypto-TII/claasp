# Copyright 2026 Technology Innovation Institute
# SPDX-License-Identifier: GPL-3.0-or-later
"""The unrestricted SipRound permutation, separate from the SipHash MAC."""

from operator import index

from claasp.cipher import Cipher
from claasp.ciphers.mac.siphash_mac import SiphashMAC
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION


_POSITIVE_ROUNDS_ERROR = "number_of_rounds must be a positive integer"


class SipHashPermutation(SiphashMAC):
    """Construct an iteration of the 256-bit SipRound permutation.

    This reuses the SipHash round implementation without message absorption,
    key initialization, finalization constants or the noninvertible MAC output.
    It exposes all four 64-bit state words, in order v0, v1, v2, v3, most
    significant bit first within each word. A round means one full SipRound,
    not one invocation of the full SipHash MAC. See Aumasson and Bernstein,
    *SipHash: a fast short-input PRF*, INDOCRYPT 2012,
    https://cr.yp.to/siphash/siphash-20120918.pdf.

    INPUT:

    - ``number_of_rounds`` -- positive integer (default: ``4``); number of
      complete SipRound applications.

    OUTPUT: a ``Cipher`` with one 256-bit plaintext/state input and one
    equally sized output. Results on unrestricted states do not directly
    establish attacks on SipHash-2-4 or another MAC configuration.

    EXAMPLES::

        sage: from claasp.ciphers.permutations.siphash_permutation import SipHashPermutation
        sage: permutation = SipHashPermutation(number_of_rounds=2)
        sage: permutation.evaluate([0])
        0
        sage: permutation.cipher_inverse().evaluate([permutation.evaluate([1])])
        1
    """

    def __init__(self, number_of_rounds=4):
        if isinstance(number_of_rounds, bool):
            raise ValueError(_POSITIVE_ROUNDS_ERROR)
        try:
            number_of_rounds = index(number_of_rounds)
        except TypeError as exc:
            raise ValueError(_POSITIVE_ROUNDS_ERROR) from exc
        if number_of_rounds < 1:
            raise ValueError(_POSITIVE_ROUNDS_ERROR)
        Cipher.__init__(self, "siphash", PERMUTATION, [INPUT_PLAINTEXT], [256], 256)
        words = [
            ComponentState(INPUT_PLAINTEXT, [list(range(64 * i, 64 * (i + 1)))])
            for i in range(4)
        ]
        for _ in range(number_of_rounds):
            self.add_round()
            words = self._sip_round(*words)
            self.add_round_output_component([w.id for w in words], [list(range(64))] * 4, 256)
        self.add_cipher_output_component([w.id for w in words], [list(range(64))] * 4, 256)
