# ****************************************************************************
# Copyright 2026 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


import secrets
from math import ceil

import numpy as np
from sage.crypto.sbox import SBox

from claasp.editor import get_key_schedule_component_ids
from claasp.name_mappings import (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN,
                                  PERMUTATION_COMPONENT, SBOX, WORD_OPERATION)

SPN = "spn"
FEISTEL = "feistel"
INPUT_PATTERNS = ("todo", "optimal")
LINEAR_COMPONENT_TYPES = (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, MIX_COLUMN, PERMUTATION_COMPONENT)
LINEAR_WORD_OPERATIONS = ("XOR", "ROTATE", "SHIFT", "NOT")
NONLINEAR_WORD_OPERATIONS = ("AND", "OR")


def spn_division_property_trail(sbox_bit_size, sbox_degree, number_of_sboxes, active_bits_per_sbox):
    """
    Return the number of active bits after each round of an ``(l, d, m)``-SPN, following Algorithm 2 of [Tod2015]_.

    The trail stops when at most one active bit is left; every output bit is balanced after the
    rounds with at least two active bits.

    INPUT:

    - ``sbox_bit_size`` -- **integer**; the bit size ``l`` of the S-boxes
    - ``sbox_degree`` -- **integer**; the algebraic degree ``d`` of the S-boxes
    - ``number_of_sboxes`` -- **integer**; the number ``m`` of S-boxes in a round
    - ``active_bits_per_sbox`` -- **list**; the number of active bits at the input of each S-box of
      the first round

    EXAMPLES::

        sage: from claasp.cipher_modules.division_property_path_search import spn_division_property_trail
        sage: spn_division_property_trail(4, 3, 16, [4] * 7 + [0] * 9)
        [28, 10, 4, 2, 1]
    """
    if not 2 <= sbox_degree < sbox_bit_size:
        raise ValueError("sbox_degree must be between 2 and sbox_bit_size - 1")
    if len(active_bits_per_sbox) != number_of_sboxes or not all(0 <= k <= sbox_bit_size for k in active_bits_per_sbox):
        raise ValueError(f"active_bits_per_sbox must list {number_of_sboxes} integers between 0 and {sbox_bit_size}")
    if sum(active_bits_per_sbox) == sbox_bit_size * number_of_sboxes:
        raise ValueError("active_bits_per_sbox must not activate every bit")
    active_bits = sum(k if k == sbox_bit_size else ceil(k / sbox_degree) for k in active_bits_per_sbox)
    trail = [active_bits]
    while active_bits > 1:
        if active_bits <= (sbox_bit_size - 1) * number_of_sboxes:
            active_bits = ceil(active_bits / sbox_degree)
        else:
            full_sboxes = number_of_sboxes - sbox_bit_size * number_of_sboxes + active_bits
            active_bits = (ceil((sbox_bit_size - 1) / sbox_degree) * (number_of_sboxes - full_sboxes)
                           + sbox_bit_size * full_sboxes)
        trail.append(active_bits)
    return trail


def _feistel_function_evaluation(branch_bit_size, function_degree, bijective_function, function_input_bits,
                                 other_bits):
    """Return the division vectors after one round from one division vector (FeistelFuncEval of [Tod2015]_)."""
    vectors = []
    for bits_through_function in range(function_input_bits + 1):
        if bijective_function and bits_through_function == branch_bit_size:
            new_function_input_bits = other_bits + branch_bit_size
        else:
            new_function_input_bits = other_bits + ceil(bits_through_function / function_degree)
        if new_function_input_bits <= branch_bit_size:
            vectors.append((new_function_input_bits, function_input_bits - bits_through_function))
    return vectors


def _minimal_vectors(vectors):
    """Return the vectors that are not componentwise larger than another one (SizeReduce of [Tod2015]_)."""
    vectors = set(vectors)
    minimal = [vector for vector in vectors
               if not any(other != vector and all(o <= v for o, v in zip(other, vector)) for other in vectors)]
    return sorted(minimal, key=lambda vector: (-vector[0], vector[1]))


def feistel_division_property_trail(branch_bit_size, function_degree, active_bits, bijective_function=False):
    """
    Return the division property after each round of an ``(l, d)``-Feistel network, following Algorithm 1 of [Tod2015]_.

    The network has two ``l``-bit branches and the round ``(w1, w2) -> (z1, z2) = (F(w1) xor w2, w1)``,
    where ``F`` has algebraic degree ``d``. The division property after a round is the list of
    minimal pairs ``(k1, k2)``, with ``k1`` active bits in ``z1`` and ``k2`` in ``z2``, which are the
    ``w1`` and ``w2`` of the next round. A bit of ``z1`` (resp. ``z2``) is balanced while no pair is
    ``(1, 0)`` (resp. ``(0, 1)``). The trail stops when every pair has ``k1 + k2 <= 1``. With
    ``r = len(trail) - 1``, every bit is balanced after ``r - 1`` rounds and the bits of ``z2`` after
    ``r`` rounds.

    INPUT:

    - ``branch_bit_size`` -- **integer**; the bit size ``l`` of a branch
    - ``function_degree`` -- **integer**; the algebraic degree ``d`` of ``F``
    - ``active_bits`` -- **tuple**; the number of active bits in ``w1`` and in ``w2`` in the first round
    - ``bijective_function`` -- **boolean** (default: `False`); whether ``F`` is bijective

    EXAMPLES::

        sage: from claasp.cipher_modules.division_property_path_search import feistel_division_property_trail
        sage: feistel_division_property_trail(4, 2, (0, 3))
        [[(3, 0)], [(2, 0), (1, 1), (0, 3)], [(1, 0), (0, 2)], [(1, 0), (0, 1)]]
    """
    if function_degree < 2 or (bijective_function and function_degree >= branch_bit_size):
        raise ValueError("function_degree must be at least 2, and at most branch_bit_size - 1 for a bijective function")
    if len(active_bits) != 2 or not all(0 <= k <= branch_bit_size for k in active_bits):
        raise ValueError(f"active_bits must be a pair of integers between 0 and {branch_bit_size}")
    if tuple(active_bits) == (branch_bit_size, branch_bit_size):
        raise ValueError("active_bits must not activate every bit")

    parameters = (branch_bit_size, function_degree, bijective_function)
    division_vectors = _minimal_vectors(_feistel_function_evaluation(*parameters, *active_bits))
    trail = [division_vectors]
    while max(sum(vector) for vector in division_vectors) > 1:
        next_vectors = []
        for function_input_bits, other_bits in division_vectors:
            next_vectors += _feistel_function_evaluation(*parameters, function_input_bits, other_bits)
        division_vectors = _minimal_vectors(next_vectors)
        trail.append(division_vectors)
    return trail


class DivisionPropertyPathSearch:
    """
    Construct an instance of the division property path search of [Tod2015]_ for the cipher.

    The cipher is analysed as an ``(l, d, m)``-SPN, with ``m`` bijective ``l``-bit S-boxes of
    algebraic degree ``d`` on the whole state and otherwise linear components, or as an
    ``(l, d)``-Feistel network, with two ``l``-bit branches and the round
    ``(w1, w2) -> (F(w1) xor w2, w1)``, where ``F`` has algebraic degree ``d``. Unless ``structure`` is
    given, it is detected from the components of the cipher, ignoring the key schedule.

    The input division property is the list of active bits at the input of each S-box of the
    first round for an SPN, and the pair of active bits in ``w1`` and in ``w2`` of the first round
    for a Feistel network.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of a cipher
    - ``structure`` -- **string** (default: `None`); ``"spn"`` or ``"feistel"``, detected if ``None``
    - ``bijective_function`` -- **boolean** (default: `False`); whether ``F`` is bijective

    EXAMPLES::

        sage: from claasp.cipher_modules.division_property_path_search import DivisionPropertyPathSearch
        sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
        sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
        sage: DivisionPropertyPathSearch(PresentBlockCipher(number_of_rounds=2)).structure
        '(4, 3, 16)-SPN'
        sage: DivisionPropertyPathSearch(SimonBlockCipher(number_of_rounds=4), structure="feistel").structure
        '(16, 2)-Feistel'
    """

    def __init__(self, cipher, structure=None, bijective_function=False):
        self._cipher = cipher
        self._first_sbox_layer = None
        if structure == SPN:
            self.structure_type, self.parameters = SPN, _spn_parameters(cipher)
        elif structure == FEISTEL:
            self.structure_type, self.parameters = FEISTEL, _feistel_parameters(cipher, bijective_function)
        elif structure is None:
            self.structure_type, self.parameters = _detect_structure(cipher, bijective_function)
        else:
            raise ValueError(f"structure must be None, '{SPN}' or '{FEISTEL}'")

    @property
    def structure(self):
        """Return the structure in the notation of [Tod2015]_."""
        if self.structure_type == SPN:
            return "({sbox_bit_size}, {sbox_degree}, {number_of_sboxes})-SPN".format(**self.parameters)
        structure = "({branch_bit_size}, {function_degree})-Feistel".format(**self.parameters)
        return structure + " with bijective round function" if self.parameters["bijective_function"] else structure

    @property
    def state_bit_size(self):
        """Return the bit size of the state."""
        return self._cipher.output_bit_size

    def find_division_property_trail(self, input_division_property):
        """
        Return the division property after each round.

        See :func:`spn_division_property_trail` and :func:`feistel_division_property_trail`.

        INPUT:

        - ``input_division_property`` -- **list** or **tuple**; the input division property

        EXAMPLES::

            sage: from claasp.cipher_modules.division_property_path_search import DivisionPropertyPathSearch
            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: path_search = DivisionPropertyPathSearch(PresentBlockCipher(number_of_rounds=2))
            sage: path_search.find_division_property_trail(path_search.todo_input(28))
            [28, 10, 4, 2, 1]
        """
        if self.structure_type == SPN:
            return spn_division_property_trail(**self.parameters, active_bits_per_sbox=input_division_property)
        return feistel_division_property_trail(**self.parameters, active_bits=input_division_property)

    def find_number_of_balanced_rounds(self, input_division_property):
        """
        Return the number of rounds ``r`` of the integral distinguisher.

        For an SPN every output bit is balanced after ``r`` rounds. For a Feistel network every bit is
        balanced after ``r - 1`` rounds and the bits of ``z2`` after ``r`` rounds.

        INPUT:

        - ``input_division_property`` -- **list** or **tuple**; the input division property

        EXAMPLES::

            sage: from claasp.cipher_modules.division_property_path_search import DivisionPropertyPathSearch
            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: path_search = DivisionPropertyPathSearch(PresentBlockCipher(number_of_rounds=2))
            sage: path_search.find_number_of_balanced_rounds(path_search.todo_input(28))
            4
        """
        return len(self.find_division_property_trail(input_division_property)) - 1

    def todo_input(self, data_bit_size):
        """
        Return the input division property of [Tod2015]_ for ``data_bit_size`` active bits.

        For an SPN, full S-boxes first and then one partial S-box; for a Feistel network, ``w2`` first
        and then ``w1``.

        INPUT:

        - ``data_bit_size`` -- **integer**; the number of active bits

        EXAMPLES::

            sage: from claasp.cipher_modules.division_property_path_search import DivisionPropertyPathSearch
            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: DivisionPropertyPathSearch(PresentBlockCipher(number_of_rounds=2)).todo_input(30)
            [4, 4, 4, 4, 4, 4, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0]
            sage: DivisionPropertyPathSearch(SimonBlockCipher(number_of_rounds=4)).todo_input(31)
            (15, 16)
        """
        self._check_data_bit_size(data_bit_size)
        if self.structure_type == FEISTEL:
            branch_bit_size = self.parameters["branch_bit_size"]
            if data_bit_size <= branch_bit_size:
                return 0, data_bit_size
            return data_bit_size - branch_bit_size, branch_bit_size
        sbox_bit_size, number_of_sboxes = self.parameters["sbox_bit_size"], self.parameters["number_of_sboxes"]
        full_sboxes, remaining_bits = divmod(data_bit_size, sbox_bit_size)
        division_property = [sbox_bit_size] * full_sboxes + [remaining_bits] * (remaining_bits > 0)
        return division_property + [0] * (number_of_sboxes - len(division_property))

    def optimal_input(self, data_bit_size):
        """
        Return the input division property for ``data_bit_size`` active bits that gives the most rounds.

        For an SPN, the active bits are placed so that the most of them remain after the first S-box
        layer; for a Feistel network, every split over the two branches is tried.

        INPUT:

        - ``data_bit_size`` -- **integer**; the number of active bits

        EXAMPLES::

            sage: from claasp.cipher_modules.division_property_path_search import DivisionPropertyPathSearch
            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: DivisionPropertyPathSearch(PresentBlockCipher(number_of_rounds=2)).optimal_input(30)
            [4, 4, 4, 4, 4, 4, 4, 1, 1, 0, 0, 0, 0, 0, 0, 0]
        """
        self._check_data_bit_size(data_bit_size)
        if self.structure_type == FEISTEL:
            branch_bit_size = self.parameters["branch_bit_size"]
            todo_split = self.todo_input(data_bit_size)
            splits = [(bits, data_bit_size - bits) for bits in
                      range(max(0, data_bit_size - branch_bit_size), min(data_bit_size, branch_bit_size) + 1)]
            return max(splits, key=lambda split: (self.find_number_of_balanced_rounds(split), split == todo_split))
        choices = self._first_sbox_layer_choices()
        division_property = []
        for sbox in reversed(range(self.parameters["number_of_sboxes"])):
            active_bits = int(choices[sbox][data_bit_size])
            division_property.append(active_bits)
            data_bit_size -= active_bits
        return sorted(division_property, reverse=True)

    def find_minimum_data_for_rounds(self, number_of_rounds, input_pattern="todo"):
        """
        Return the integral distinguisher with the fewest active bits for ``number_of_rounds`` rounds.

        The result is a dictionary with the keys ``data_bit_size`` and ``input_division_property``, or
        ``None`` if every input set smaller than the whole input space fails.

        INPUT:

        - ``number_of_rounds`` -- **integer**; the number of rounds
        - ``input_pattern`` -- **string** (default: `todo`); ``"todo"`` for :meth:`todo_input` or
          ``"optimal"`` for :meth:`optimal_input`

        EXAMPLES::

            sage: from claasp.cipher_modules.division_property_path_search import DivisionPropertyPathSearch
            sage: from claasp.ciphers.permutations.keccak_sbox_permutation import KeccakSboxPermutation
            sage: keccak = DivisionPropertyPathSearch(KeccakSboxPermutation(number_of_rounds=1))
            sage: keccak.find_minimum_data_for_rounds(12)['data_bit_size']
            1410
        """
        if input_pattern not in INPUT_PATTERNS:
            raise ValueError(f"input_pattern must be one of {INPUT_PATTERNS}")
        input_division_property = self.todo_input if input_pattern == "todo" else self.optimal_input
        for data_bit_size in range(1, self.state_bit_size):
            division_property = input_division_property(data_bit_size)
            if self.find_number_of_balanced_rounds(division_property) >= number_of_rounds:
                return {"data_bit_size": data_bit_size, "input_division_property": division_property}
        return None

    def find_integral_distinguishers(self, max_number_of_rounds=None, input_pattern="todo"):
        """
        Return the integral distinguisher with the fewest active bits for each number of rounds.

        The result has the keys ``input_parameters`` and ``test_results``; ``test_results`` maps each
        number of rounds to the result of :meth:`find_minimum_data_for_rounds`.

        INPUT:

        - ``max_number_of_rounds`` -- **integer** (default: `None`); the last number of rounds; if
          ``None``, as long as a distinguisher exists
        - ``input_pattern`` -- **string** (default: `todo`); ``"todo"`` or ``"optimal"``

        EXAMPLES::

            sage: from claasp.cipher_modules.division_property_path_search import DivisionPropertyPathSearch
            sage: from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher
            sage: result = DivisionPropertyPathSearch(DESBlockCipher(number_of_rounds=4)).find_integral_distinguishers()
            sage: {rounds: entry['data_bit_size'] for rounds, entry in result['test_results'].items()}
            {1: 2, 2: 2, 3: 6, 4: 26, 5: 51, 6: 62}
        """
        results = {}
        number_of_rounds = 1
        while max_number_of_rounds is None or number_of_rounds <= max_number_of_rounds:
            distinguisher = self.find_minimum_data_for_rounds(number_of_rounds, input_pattern)
            if distinguisher is None:
                break
            results[number_of_rounds] = distinguisher
            number_of_rounds += 1
        return {
            "input_parameters": {"cipher": self._cipher, "test_name": "division_property_path_search",
                                 "structure": self.structure, "input_pattern": input_pattern,
                                 "max_number_of_rounds": max_number_of_rounds},
            "test_results": results,
        }

    def _check_data_bit_size(self, data_bit_size):
        if not 0 <= data_bit_size <= self.state_bit_size:
            raise ValueError(f"data_bit_size must be between 0 and {self.state_bit_size}")

    def _first_sbox_layer_choices(self):
        """Return, by dynamic programming over the S-boxes, the active bits of each S-box in an optimal input."""
        if self._first_sbox_layer is None:
            sbox_bit_size, sbox_degree = self.parameters["sbox_bit_size"], self.parameters["sbox_degree"]
            gains = [k if k == sbox_bit_size else ceil(k / sbox_degree) for k in range(sbox_bit_size + 1)]
            size = self.state_bit_size + 1
            best = np.full(size, -1)
            best[0] = 0
            choices = np.zeros((self.parameters["number_of_sboxes"], size), dtype=np.int8)
            for sbox in range(self.parameters["number_of_sboxes"]):
                candidates = np.full((sbox_bit_size + 1, size), -1)
                for active_bits, gain in enumerate(gains):
                    reachable = best[:size - active_bits] >= 0
                    candidates[active_bits, active_bits:] = np.where(reachable, best[:size - active_bits] + gain, -1)
                choices[sbox] = candidates.argmax(axis=0)
                best = candidates.max(axis=0)
            self._first_sbox_layer = choices
        return self._first_sbox_layer


def _detect_structure(cipher, bijective_function):
    try:
        return SPN, _spn_parameters(cipher)
    except ValueError as spn_error:
        try:
            return FEISTEL, _feistel_parameters(cipher, bijective_function)
        except ValueError as feistel_error:
            raise ValueError(f"{cipher.id} is neither an (l, d, m)-SPN ({spn_error}) "
                             f"nor an (l, d)-Feistel network ({feistel_error})") from None


def _spn_parameters(cipher):
    layers = _nonlinear_layers(cipher)
    components = [component for layer in layers for component, _ in layer]
    if any(component.type != SBOX for component in components):
        raise ValueError("the nonlinear components must be S-boxes")
    sbox_bit_size = components[0].input_bit_size
    if any(component.input_bit_size != sbox_bit_size or component.output_bit_size != sbox_bit_size
           for component in components):
        raise ValueError("all S-boxes must map l bits to l bits")
    if not all(SBox(table).is_permutation() for table in {tuple(component.description) for component in components}):
        raise ValueError("the S-boxes must be bijective")
    number_of_sboxes = len(layers[0])
    if any(len(layer) != number_of_sboxes for layer in layers) or \
            number_of_sboxes * sbox_bit_size != cipher.output_bit_size:
        raise ValueError("every round must apply the same number of S-boxes to the whole state")
    sbox_degree = max(degree for layer in layers for _, degree in layer)
    if sbox_degree < 2:
        raise ValueError("the S-boxes must be nonlinear")
    return {"sbox_bit_size": sbox_bit_size, "sbox_degree": sbox_degree, "number_of_sboxes": number_of_sboxes}


def _feistel_parameters(cipher, bijective_function):
    if cipher.output_bit_size % 2:
        raise ValueError("the state size must be even")
    branch_bit_size = cipher.output_bit_size // 2
    layers = _nonlinear_layers(cipher)
    if any(sum(component.output_bit_size for component, _ in layer) != branch_bit_size for layer in layers):
        raise ValueError("the nonlinear components of every round must produce half of the state")
    _check_two_branch_structure(cipher)
    function_degree = max(degree for layer in layers for _, degree in layer)
    if function_degree < 2:
        raise ValueError("the round function must be nonlinear")
    return {"branch_bit_size": branch_bit_size, "function_degree": function_degree,
            "bijective_function": bijective_function}


def _nonlinear_layers(cipher):
    """Return, for each round, the nonlinear components outside the key schedule with their algebraic degree."""
    key_schedule_ids = set(get_key_schedule_component_ids(cipher))
    sbox_degrees = {}
    layers = []
    for cipher_round in cipher.rounds_as_list:
        layer = []
        for component in cipher_round.components:
            if component.id not in key_schedule_ids:
                degree = _nonlinear_degree(component, sbox_degrees)
                if degree is not None:
                    layer.append((component, degree))
        _check_nonlinear_layer(cipher_round.id, layer)
        layers.append(layer)
    return layers


def _nonlinear_degree(component, sbox_degrees):
    """Return the algebraic degree of a nonlinear component and None for a linear one."""
    if component.type == SBOX:
        table = tuple(component.description)
        if table not in sbox_degrees:
            sbox_degrees[table] = SBox(table).max_degree()
        return sbox_degrees[table]
    if component.type == WORD_OPERATION:
        operation = component.description[0]
        if operation in NONLINEAR_WORD_OPERATIONS:
            return component.description[1]
        if operation in LINEAR_WORD_OPERATIONS:
            return None
    elif component.type in LINEAR_COMPONENT_TYPES:
        return None
    raise ValueError(f"component {component.id} is not supported")


def _check_nonlinear_layer(round_id, layer):
    """Check that the nonlinear components of a round are applied in parallel and that there is at least one."""
    nonlinear_ids = {component.id for component, _ in layer}
    if any(link in nonlinear_ids for component, _ in layer for link in component.input_id_links):
        raise ValueError(f"round {round_id} composes nonlinear components")
    if not layer:
        raise ValueError(f"round {round_id} has no nonlinear component")


def _check_two_branch_structure(cipher, number_of_samples=3):
    """Check on random inputs that every round output keeps one half of the previous round output."""
    half = cipher.output_bit_size // 2
    mask = (1 << half) - 1
    for _ in range(number_of_samples):
        cipher_input = [secrets.randbits(bit_size) for bit_size in cipher.inputs_bit_size]
        round_outputs = cipher.evaluate(cipher_input, intermediate_output=True)[1].get("round_output", [])
        if len(round_outputs) < 2:
            raise ValueError("at least two round outputs are needed to check the two-branch structure")
        for previous, current in zip(round_outputs, round_outputs[1:]):
            if not {previous >> half, previous & mask} & {current >> half, current & mask}:
                raise ValueError("a round does not keep one half of its input")
