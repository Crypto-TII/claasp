# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
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

from typing import Any, List, NamedTuple, Tuple

from claasp.cipher import Cipher
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK


class State(NamedTuple):
    id: str
    bits: List[int]

    @staticmethod
    def get_inputs_parameter(states: List[Any]) -> Tuple[List[str], List[List[int]]]:
        return ([state.id for state in states], [state.bits for state in states])


class LinearCoefficients(NamedTuple):
    alpha: int
    beta0: int
    beta1: int
    beta2: int


LINEAR_COEFFICIENTS = {
    'L32': LinearCoefficients(11, 5, 9, 12),
    'L32-prime': LinearCoefficients(11, 1, 26, 30),
    'L40': LinearCoefficients(17, 1, 9, 30),
    'L64': LinearCoefficients(3, 1, 26, 50),
    'L128': LinearCoefficients(17, 7, 11, 14)
}


class ChilowBlockCipher(Cipher):
    """
    Construct an instance of the ChilowBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    References: Implementations and test vectors from [BDG+25]_

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `1`); number of rounds of the cipher.
    - ``tau`` -- **integer** (default: `None`); tag's bit size

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.chilow_block_cipher import ChilowBlockCipher
        sage: chilow = ChilowBlockCipher()
        sage: chilow.number_of_rounds
        1
        sage: chilow = ChilowBlockCipher(number_of_rounds=8, tau=0)
        sage: X = 0x01234567
        sage: T = 0x0011223344556677
        sage: K = 0xFEDCBA98765432107766554433221100
        sage: pt = chilow.evaluate([X, T, K])
        sage: print("0x{:X}".format(pt))
        0x2E75D127

    """

    def __init__(self, number_of_rounds=1, tau: int | None = None):
        self.tau = tau if tau is not None else -1
        self.is_chilow_40 = tau is None

        self.block_bit_size = 40 if self.is_chilow_40 else 32
        self.key_bit_size = 128
        self.tweak_bit_size = 64

        inputs = [INPUT_PLAINTEXT, INPUT_TWEAK, INPUT_KEY]
        inputs_size = [self.block_bit_size, self.tweak_bit_size, self.key_bit_size]
        output_bit_size = self.block_bit_size if self.is_chilow_40 else 32

        if tau is not None:
            inputs_size.append(tau)
            output_bit_size += tau

        super().__init__(
            family_name='chilow',
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=inputs,
            cipher_inputs_bit_size=inputs_size,
            cipher_output_bit_size=output_bit_size,
        )

        state = State(INPUT_PLAINTEXT, list(range(self.block_bit_size)))
        tweak = State(INPUT_TWEAK, list(range(self.tweak_bit_size)))
        key = State(INPUT_KEY, list(range(self.key_bit_size)))

        if self.is_chilow_40:
            self.chilow_40(state, tweak, key, number_of_rounds)
        else:
            self.chilow_32_tau(state, tweak, key, number_of_rounds)

    def chilow_32_tau(self, state: State, tweak: State, key: State, number_of_rounds: int) -> None:
        """Implement all rounds for ChiLow-(32+τ)."""
        self.add_round()
        state1, state2, tweak = self.whitening_32(state, tweak, key)

        ids, bits = State.get_inputs_parameter([state1, state2])
        self.add_round_output_component(ids, bits, self.block_bit_size * 2)

        for i in range(0, number_of_rounds - 1):
            self.add_round()
            # add round constant to the key
            key = self.round_constant(key, i)

            # non linear layer
            state1 = self.chichi(state1, self.block_bit_size)
            state2 = self.chichi(state2, self.block_bit_size)
            tweak = self.chichi(tweak, self.tweak_bit_size)
            key = self.chichi(key, self.key_bit_size)

            # linear layer
            state1 = self.l32(state1)
            state2 = self.l32_prime(state2)
            tweak = self.l64(tweak)
            key = self.l128(key)

            # interaction
            state1, state2 = self.state_tweak_interaction_32(state1, state2, tweak)

            key_0_64 = State(key.id, list(range(*self.key_rev_range(0, 64))))
            ids, bits = State.get_inputs_parameter([tweak, key_0_64])
            self.add_xor_component(ids, bits, self.tweak_bit_size)
            tweak = State(self.get_current_component_id(), list(range(self.tweak_bit_size)))

            if i != number_of_rounds - 1:
                self.add_round_output_component([state1.id, state2.id], [state1.bits,
                                                state2.bits], self.block_bit_size * 2)

        tag, plaintext = self.last_round_32(state1, state2, tweak)

        self.add_cipher_output_component([tag.id, plaintext.id], [
                                         tag.bits, plaintext.bits], self.tau + self.block_bit_size)

    def chilow_40(self, state: State, tweak: State, key: State, number_of_rounds: int) -> None:
        """Implement all rounds for ChiLow-40."""
        self.add_round()
        state, tweak = self.whitening_40(state, tweak, key)
        self.add_round_output_component([state.id], [state.bits], self.block_bit_size)

        for i in range(0, number_of_rounds - 1):
            self.add_round()

            # add round constant to the key
            key = self.round_constant(key, i)

            # non linear layer
            state = self.chichi(state, self.block_bit_size)
            tweak = self.chichi(tweak, self.tweak_bit_size)
            key = self.chichi(key, self.key_bit_size)

            # linear layer
            state = self.l40(state)
            tweak = self.l64(tweak)
            key = self.l128(key)

            # interaction from tweak to cipher state
            state = self.state_tweak_interaction_40(state, tweak)

            # interaction from key to tweak state
            key_0_64 = State(key.id, list(range(*self.key_rev_range(0, 64))))
            ids, bits = State.get_inputs_parameter([tweak, key_0_64])
            self.add_xor_component(ids, bits, self.tweak_bit_size)
            tweak = State(self.get_current_component_id(), list(range(self.tweak_bit_size)))

            if i != number_of_rounds - 1:
                self.add_round_output_component([state.id], [state.bits], self.block_bit_size)

        state = self.last_round_40(state, tweak)
        self.add_cipher_output_component([state.id], [state.bits], self.block_bit_size)

    def last_round_40(self, state: State, tweak: State) -> State:
        state = self.chichi(state, self.block_bit_size)
        tweak = self.l64(tweak)
        return self.state_tweak_interaction_40(state, tweak)

    def state_tweak_interaction_40(self, state: State, tweak: State) -> State:
        tweak_0_size = State(tweak.id, list(range(*self.tweak_rev_range(0, self.block_bit_size))))
        ids, bits = State.get_inputs_parameter([state, tweak_0_size])
        self.add_xor_component(ids, bits, self.block_bit_size)
        return State(self.get_current_component_id(), list(range(self.block_bit_size)))

    def whitening_40(self, state: State, tweak: State, key: State) -> Tuple[State, State]:
        k_state = State(key.id, list(range(*self.key_rev_range(64, 64 + self.block_bit_size))))

        ids, bits = State.get_inputs_parameter([state, k_state])
        xor = self.add_xor_component(ids, bits, self.block_bit_size)
        state = State(xor.id, list(range(self.block_bit_size)))

        k_tweak = State(key.id, list(range(*self.key_rev_range(0, 64))))
        ids, bits = State.get_inputs_parameter([tweak, k_tweak])
        xor = self.add_xor_component(ids, bits, self.tweak_bit_size)
        tweak = State(xor.id, list(range(self.tweak_bit_size)))

        return state, tweak

    def last_round_32(self, state1: State, state2: State, tweak: State) -> Tuple[State, State]:
        state1 = self.chichi(state1, self.block_bit_size)
        state2 = self.chichi(state2, self.block_bit_size)
        tweak = self.l64(tweak)

        tweak_0_32 = State(tweak.id, list(range(*self.tweak_rev_range(0, 32))))
        ids, bits = State.get_inputs_parameter([state1, tweak_0_32])
        self.add_xor_component(ids, bits, self.block_bit_size)
        plaintext = State(self.get_current_component_id(), list(range(self.block_bit_size)))

        tweak_32_64 = State(tweak.id, list(range(*self.tweak_rev_range(32, 64))))
        ids, bits = State.get_inputs_parameter([state2, tweak_32_64])
        self.add_xor_component(ids, bits, self.block_bit_size)
        tag = State(self.get_current_component_id(), list(range(*self.state_rev_range(0, self.tau))))

        return tag, plaintext

    def state_tweak_interaction_32(self, state1: State, state2: State, tweak: State) -> Tuple[State, State]:
        tweak_0_32 = State(tweak.id, list(range(*self.tweak_rev_range(0, 32))))
        tweak_32_64 = State(tweak.id, list(range(*self.tweak_rev_range(32, 64))))

        ids, bits = State.get_inputs_parameter([state1, tweak_0_32])
        self.add_xor_component(ids, bits, self.block_bit_size)
        state1 = State(self.get_current_component_id(), list(range(self.block_bit_size)))

        ids, bits = State.get_inputs_parameter([state2, tweak_32_64])
        self.add_xor_component(ids, bits, self.block_bit_size)
        state2 = State(self.get_current_component_id(), list(range(self.block_bit_size)))

        return state1, state2

    def whitening_32(self, state: State, tweak: State, key: State) -> Tuple[State, State, State]:
        key_64_96 = State(key.id, list(range(*self.key_rev_range(64, 96))))
        key_96_128 = State(key.id, list(range(*self.key_rev_range(96, 128))))
        key_0_64 = State(key.id, list(range(*self.key_rev_range(0, 64))))

        ids, bits = State.get_inputs_parameter([state, key_64_96])
        self.add_xor_component(ids, bits, self.block_bit_size)
        state1 = State(self.get_current_component_id(), list(range(self.block_bit_size)))

        ids, bits = State.get_inputs_parameter([state, key_96_128])
        self.add_xor_component(ids, bits, self.block_bit_size)
        state2 = State(self.get_current_component_id(), list(range(self.block_bit_size)))

        ids, bits = State.get_inputs_parameter([tweak, key_0_64])
        self.add_xor_component(ids, bits, self.tweak_bit_size)
        tweak = State(self.get_current_component_id(), list(range(self.tweak_bit_size)))

        return state1, state2, tweak

    def l32(self, state: State) -> State:
        return self.linear(state, 32, LINEAR_COEFFICIENTS['L32'])

    def l32_prime(self, state: State) -> State:
        return self.linear(state, 32, LINEAR_COEFFICIENTS['L32-prime'])

    def l40(self, state: State) -> State:
        return self.linear(state, 40, LINEAR_COEFFICIENTS['L40'])

    def l64(self, state: State) -> State:
        return self.linear(state, 64, LINEAR_COEFFICIENTS['L64'])

    def l128(self, state: State) -> State:
        return self.linear(state, 128, LINEAR_COEFFICIENTS['L128'])

    def linear(self, state: State, n: int, coeff: LinearCoefficients) -> State:
        alpha, beta0, beta1, beta2 = coeff
        x1 = [state.bits[self.rev((self.rev(p, n) * alpha + beta0) % n, n)] for p in range(n)]
        x2 = [state.bits[self.rev((self.rev(p, n) * alpha + beta1) % n, n)] for p in range(n)]
        x3 = [state.bits[self.rev((self.rev(p, n) * alpha + beta2) % n, n)] for p in range(n)]

        self.add_xor_component([state.id, state.id, state.id], [x1, x2, x3], n)

        return State(self.get_current_component_id(), list(range(n)))

    def chichi(self, state: State, n: int) -> State:
        m = n // 2
        part1 = State(state.id, list(range(*self.rev_range(0, m - 1, n))))
        self.add_intermediate_output_component([part1.id], [part1.bits], m - 1, 'part1')
        part1 = self.chi(part1, m - 1)

        part2 = State(state.id, list(range(*self.rev_range(m - 1, n, n))))
        self.add_intermediate_output_component([part2.id], [part2.bits], m + 1, 'part2')
        part2 = self.chi(part2, m + 1)

        ids, bits = State.get_inputs_parameter([part2, part1])
        concat = self.add_intermediate_output_component(ids, bits, n, 'concat')
        lam = self.lambda_term(state, n)
        lam = self.add_intermediate_output_component([lam.id], [lam.bits], n, 'lambda')

        self.add_xor_component([concat.id, lam.id], [list(range(n)), list(range(n))], n)
        return State(self.get_current_component_id(), list(range(n)))

    def chi(self, state: State, m: int) -> State:
        pos = state.bits

        x1 = State(state.id, [pos[self.rev((self.rev(i, m) + 1) % m, m)] for i in range(m)])
        x2 = State(state.id, [pos[self.rev((self.rev(i, m) + 2) % m, m)] for i in range(m)])

        self.add_not_component([x1.id], [x1.bits], m)
        not_x1 = State(self.get_current_component_id(), list(range(m)))

        ids, bits = State.get_inputs_parameter([not_x1, x2])
        self.add_and_component(ids, bits, m)
        and_term = State(self.get_current_component_id(), list(range(m)))

        ids, bits = State.get_inputs_parameter([state, and_term])
        self.add_xor_component(ids, bits, m)

        return State(self.get_current_component_id(), list(range(m)))

    def _bit(self, state: State, i: int, n: int) -> State:
        """Extract a single bit at position i as a State tuple."""
        comp_id = state.id
        positions = state.bits
        p = self.rev(i, n)
        return State(comp_id, [positions[p]])

    def lambda_term(self, state: State, n: int) -> State:
        m = n // 2

        x_m3 = self._bit(state, m - 3, n)
        x_m2 = self._bit(state, m - 2, n)
        x_m1 = self._bit(state, m - 1, n)
        x_m = self._bit(state, m, n)

        ids, bits = State.get_inputs_parameter([x_m, x_m3])
        self.add_xor_component(ids, bits, 1)
        lam_m3 = (self.get_current_component_id(), 0)

        ids, bits = State.get_inputs_parameter([x_m1, x_m2])
        self.add_xor_component(ids, bits, 1)
        lam_m2 = (self.get_current_component_id(), 0)

        ids, bits = State.get_inputs_parameter([x_m3, x_m, x_m1])
        self.add_xor_component(ids, bits, 1)
        lam_m1 = (self.get_current_component_id(), 0)

        ids, bits = State.get_inputs_parameter([x_m, x_m2])
        self.add_xor_component(ids, bits, 1)
        lam_m = (self.get_current_component_id(), 0)

        lam_wires = {m - 3: lam_m3, m - 2: lam_m2, m - 1: lam_m1, m: lam_m}

        self.add_constant_component(n, 0)
        zero_id = self.get_current_component_id()

        ids_full, bits_full = [], []
        for j in range(n):
            abstract_index = self.rev(j, n)
            if abstract_index in lam_wires:
                comp_id, p = lam_wires[abstract_index]
            else:
                comp_id, p = zero_id, 0
            ids_full.append(comp_id)
            bits_full.append([p])

        self.add_intermediate_output_component(ids_full, bits_full, n, 'lamda term')

        return State(self.get_current_component_id(), list(range(n)))

    def round_constant_value(self, i: int, b=1) -> int:
        return i ^ (1 << (i + 4)) ^ (b << 31)

    def round_constant(self, key: State, i: int) -> State:
        """Add the round constant to the key."""
        b = 1 if self.is_chilow_40 else 0
        key_last_32 = State(key.id, list(range(*self.key_rev_range(96, 128))))

        self.add_constant_component(32, self.round_constant_value(i, b))
        const = State(self.get_current_component_id(), list(range(32)))

        ids, bits = State.get_inputs_parameter([key_last_32, const])
        self.add_xor_component(ids, bits, 32)
        xor = State(self.get_current_component_id(), list(range(32)))

        key_first_96 = State(key.id, list(range(*self.key_rev_range(0, 96))))

        ids, bits = State.get_inputs_parameter([xor, key_first_96])

        self.add_intermediate_output_component(ids, bits, self.key_bit_size, 'add round constant')
        return State(self.get_current_component_id(), list(range(self.key_bit_size)))

    def rev(self, i: int, n: int) -> int:
        """Convert indexing from (LSB=0) to (MSB=0) for a bit string of size n."""
        return n - i - 1

    def rev_range(self, s: int, e: int, n: int) -> Tuple[int, int]:
        """Convert range [s, e) from (LSB=0) to (MSB=0) for a bit string of size n."""
        return (self.rev(e, n) + 1, self.rev(s, n) + 1)

    def state_rev(self, i: int) -> int:
        return self.rev(i, self.block_bit_size)

    def state_rev_range(self, s: int, e: int) -> Tuple[int, int]:
        return self.rev_range(s, e, self.block_bit_size)

    def key_rev(self, i: int) -> int:
        return self.rev(i, self.key_bit_size)

    def key_rev_range(self, s: int, e: int) -> Tuple[int, int]:
        return self.rev_range(s, e, self.key_bit_size)

    def tweak_rev(self, i: int) -> int:
        return self.rev(i, self.tweak_bit_size)

    def tweak_rev_range(self, s: int, e: int) -> Tuple[int, int]:
        return self.rev_range(s, e, self.tweak_bit_size)
