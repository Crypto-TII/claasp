"""Native-prime-field Poseidon permutation graph."""

from collections.abc import Iterable
from math import gcd

from claasp_next.components import Add, Concatenate, Constant, LinearMap, Power
from claasp_next.core import Cipher, Port, ValueType
from claasp_next.domains import PrimeField


class PoseidonPermutation(Cipher):
    """A parameterized Poseidon-style HADES permutation.

    Each round adds a state-width vector of constants, applies the power map
    either to the full state or to its first element, and then applies the
    supplied square linear-layer matrix. Full rounds are split equally around
    the partial rounds.

    Parameter generation and endorsement are intentionally outside this class.
    Callers must supply constants and a matrix from an appropriate parameter
    generation procedure or specification.

    EXAMPLES::

        >>> from claasp_next.ciphers import PoseidonPermutation
        >>> from claasp_next.evaluators import ScalarEvaluator
        >>> cipher = PoseidonPermutation(
        ...     modulus=17,
        ...     exponent=3,
        ...     full_rounds=2,
        ...     partial_rounds=1,
        ...     round_constants=((1, 2), (3, 4), (5, 6)),
        ...     linear_layer=((1, 1), (1, 2)),
        ... )
        >>> ScalarEvaluator().evaluate(cipher, {"state": (0, 1)}).output
        (4, 15)

    These are teaching parameters, not a secure parameter set.
    """

    def __init__(
        self,
        modulus: int,
        exponent: int,
        full_rounds: int,
        partial_rounds: int,
        round_constants: Iterable[Iterable[int]],
        linear_layer: Iterable[Iterable[int]],
    ) -> None:
        self._validate_round_counts(full_rounds, partial_rounds)
        field = PrimeField(modulus)
        if not isinstance(exponent, int) or isinstance(exponent, bool):
            raise TypeError("exponent must be an integer")
        if exponent <= 1:
            raise ValueError("exponent must be greater than one")
        if gcd(exponent, modulus - 1) != 1:
            raise ValueError("exponent must be coprime to modulus - 1")

        matrix = tuple(tuple(row) for row in linear_layer)
        if not matrix or any(len(row) != len(matrix) for row in matrix):
            raise ValueError("linear_layer must be a non-empty square matrix")
        width = len(matrix)
        constants = tuple(tuple(row) for row in round_constants)
        number_of_rounds = full_rounds + partial_rounds
        if len(constants) != number_of_rounds:
            raise ValueError(f"round_constants must contain {number_of_rounds} rows")
        if any(len(row) != width for row in constants):
            raise ValueError(f"every round-constant row must contain {width} elements")

        state_type = ValueType(field, (width,))
        super().__init__("poseidon", {"state": state_type})
        state = self.input("state")
        full_rounds_at_start = full_rounds // 2

        for round_number, constants_for_round in enumerate(constants):
            self.add_round()
            constant = Constant(
                state_type,
                constants_for_round,
                component_id=f"constant_{round_number}_0",
            )
            constant_output = self.add_component(constant)
            addition = Add(
                (state, constant_output), component_id=f"add_{round_number}_1"
            )
            state = self.add_component(addition)

            is_full_round = (
                round_number < full_rounds_at_start
                or round_number >= full_rounds_at_start + partial_rounds
            )
            state = self._add_sbox_layer(state, exponent, round_number, is_full_round)

            linear_map = LinearMap(
                state,
                matrix,
                component_id=f"linear_map_{round_number}_4",
            )
            state = self.add_component(linear_map)

        self.set_output(state)

    @staticmethod
    def _validate_round_counts(full_rounds: int, partial_rounds: int) -> None:
        for name, count in (("full_rounds", full_rounds), ("partial_rounds", partial_rounds)):
            if not isinstance(count, int) or isinstance(count, bool):
                raise TypeError(f"{name} must be an integer")
            if count < 0:
                raise ValueError(f"{name} must be non-negative")
        if full_rounds == 0 or full_rounds % 2:
            raise ValueError("full_rounds must be a positive even number")

    def _add_sbox_layer(
        self,
        state: Port,
        exponent: int,
        round_number: int,
        is_full_round: bool,
    ) -> Port:
        if is_full_round:
            power = Power(state, exponent, component_id=f"power_{round_number}_2")
            return self.add_component(power)

        first = Power(state[0], exponent, component_id=f"power_{round_number}_2")
        first_output = self.add_component(first)
        if state.value_type.unit_count == 1:
            return first_output
        concatenate = Concatenate(
            (first_output, state[1:]),
            component_id=f"concatenate_{round_number}_3",
        )
        return self.add_component(concatenate)
