"""Typed one-operation primitive fixtures used to test component semantics."""

from collections.abc import Iterable

from claasp_next.components import (
    BitVectorSBox, BitwiseAnd, BitwiseNot, BitwiseOr, Constant as ConstantComponent,
    FeedbackRegister, FeedbackRegisterSpec, FeedbackTerm, IDEAMultiply, Identity as IdentityComponent,
    LinearMap, ModularAdd, ModularMultiply, ModularSubtract, Permutation as PermutationComponent,
    Rotate as RotateComponent, Shift as ShiftComponent, VariableRotate as VariableRotateComponent,
    VariableShift as VariableShiftComponent, Xor as XorComponent,
)
from claasp_next.components.permutation import gaston_theta, keccak_theta, sigma, xoodoo_theta
from claasp_next.domains import BinaryExtensionField, Bit, Word
from claasp_next.domains.validation import is_irreducible_binary_polynomial
from claasp_next.encoding import bits_from_int
from claasp_next.graph import Primitive, ValueType


def _positive(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _inputs(word_bit_size: int, number_of_inputs: int):
    _positive(word_bit_size, "word_bit_size")
    if not isinstance(number_of_inputs, int) or isinstance(number_of_inputs, bool) or number_of_inputs < 2:
        raise ValueError("number_of_inputs must be at least 2")
    value_type = ValueType(Word(word_bit_size), (1,))
    return {f"input_{index}": value_type for index in range(number_of_inputs)}


class _NaryWordPrimitive(Primitive):
    operation = None

    def __init__(self, name: str, word_bit_size: int, number_of_inputs: int, **options) -> None:
        super().__init__(name, _inputs(word_bit_size, number_of_inputs))
        self.add_round()
        operands = tuple(self.input(name) for name in self.inputs)
        output = self.add_component(self.operation(operands, **options))
        self.set_output(output)


class And(_NaryWordPrimitive):
    operation = BitwiseAnd

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__("and", word_bit_size, number_of_inputs)


class Or(_NaryWordPrimitive):
    operation = BitwiseOr

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__("or", word_bit_size, number_of_inputs)


class Xor(_NaryWordPrimitive):
    operation = XorComponent

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__("xor", word_bit_size, number_of_inputs)


class Modadd(_NaryWordPrimitive):
    operation = ModularAdd

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, 1 << word_bit_size):
            raise ValueError("Modadd supports the canonical modulus 2^word_bit_size")
        super().__init__("modadd", word_bit_size, number_of_inputs)


class Modmul(_NaryWordPrimitive):
    operation = ModularMultiply

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, 1 << word_bit_size):
            raise ValueError("Modmul supports the canonical modulus 2^word_bit_size")
        super().__init__("modmul", word_bit_size, number_of_inputs)


class Modsub(_NaryWordPrimitive):
    operation = ModularSubtract

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, 1 << word_bit_size):
            raise ValueError("Modsub supports the canonical modulus 2^word_bit_size")
        super().__init__("modsub", word_bit_size, number_of_inputs)


class IdeaModmul(_NaryWordPrimitive):
    operation = IDEAMultiply

    def __init__(self, word_bit_size: int = 16, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, (1 << word_bit_size) + 1):
            raise ValueError("IDEA multiplication modulus must be 2^word_bit_size + 1")
        super().__init__("idea_modmul", word_bit_size, number_of_inputs)


class Constant(Primitive):
    def __init__(self, output_bit_size: int = 3, value: int = 0b010) -> None:
        output_bit_size = _positive(output_bit_size, "output_bit_size")
        super().__init__("constant", {})
        self.add_round()
        output = self.add_component(ConstantComponent(
            ValueType(Bit(), (output_bit_size,)), bits_from_int(value, output_bit_size)
        ))
        self.set_output(output)


class Identity(Primitive):
    def __init__(self, block_bit_size: int = 32) -> None:
        block_bit_size = _positive(block_bit_size, "block_bit_size")
        super().__init__("identity", {"input": ValueType(Bit(), (block_bit_size,))})
        self.add_round()
        self.set_output(self.add_component(IdentityComponent(self.input("input"))))


class Not(Primitive):
    def __init__(self, bit_size: int = 4) -> None:
        bit_size = _positive(bit_size, "bit_size")
        value_type = ValueType(Word(bit_size), (1,))
        super().__init__("not", {"input": value_type})
        self.add_round()
        self.set_output(self.add_component(BitwiseNot(self.input("input"))))


class Rotate(Primitive):
    def __init__(self, bit_size: int = 8, rotation_amount: int = 1) -> None:
        bit_size = _positive(bit_size, "bit_size")
        super().__init__("rotate", {"input": ValueType(Word(bit_size), (1,))})
        self.add_round()
        direction = "right" if rotation_amount >= 0 else "left"
        self.set_output(self.add_component(RotateComponent(
            self.input("input"), abs(rotation_amount), direction
        )))


class Shift(Primitive):
    def __init__(self, bit_size: int = 8, shift_amount: int = 1) -> None:
        bit_size = _positive(bit_size, "bit_size")
        super().__init__("shift", {"input": ValueType(Word(bit_size), (1,))})
        self.add_round()
        direction = "right" if shift_amount >= 0 else "left"
        self.set_output(self.add_component(ShiftComponent(
            self.input("input"), abs(shift_amount), direction
        )))


class VariableRotate(Primitive):
    def __init__(self, bit_size: int = 8, amount_bit_size: int = 3, direction: int = 1) -> None:
        bit_size = _positive(bit_size, "bit_size")
        _positive(amount_bit_size, "amount_bit_size")
        value_type = ValueType(Word(bit_size), (1,))
        amount_type = ValueType(Word(amount_bit_size), (1,))
        super().__init__("variable_rotate", {"input": value_type, "amount": amount_type})
        self.add_round()
        self.set_output(self.add_component(VariableRotateComponent(
            self.input("input"), self.input("amount"), "right" if direction >= 0 else "left"
        )))


class VariableShift(Primitive):
    def __init__(self, bit_size: int = 8, amount_bit_size: int = 3, direction: int = 1) -> None:
        bit_size = _positive(bit_size, "bit_size")
        _positive(amount_bit_size, "amount_bit_size")
        value_type = ValueType(Word(bit_size), (1,))
        amount_type = ValueType(Word(amount_bit_size), (1,))
        super().__init__("variable_shift", {"input": value_type, "amount": amount_type})
        self.add_round()
        self.set_output(self.add_component(VariableShiftComponent(
            self.input("input"), self.input("amount"), "right" if direction >= 0 else "left"
        )))


class Sbox(Primitive):
    def __init__(self, bit_size: int = 4, lookup_table: Iterable[int] | None = None) -> None:
        bit_size = _positive(bit_size, "bit_size")
        table = tuple(range(1 << bit_size)) if lookup_table is None else tuple(lookup_table)
        super().__init__("sbox", {"input": ValueType(Bit(), (bit_size,))})
        self.add_round()
        self.set_output(self.add_component(BitVectorSBox(self.input("input"), table)))


def _inverse_mapping(destination_by_source: tuple[int, ...]) -> tuple[int, ...]:
    if sorted(destination_by_source) != list(range(len(destination_by_source))):
        raise ValueError("permutation_description must be a permutation")
    return tuple(destination_by_source.index(destination) for destination in range(len(destination_by_source)))


class Permutation(Primitive):
    def __init__(self, bit_size: int = 8, permutation_description=None, word_size: int = 1) -> None:
        bit_size = _positive(bit_size, "bit_size")
        word_size = _positive(word_size, "word_size")
        if bit_size % word_size:
            raise ValueError("bit_size must be divisible by word_size")
        count = bit_size // word_size
        description = tuple(reversed(range(count))) if permutation_description is None else tuple(permutation_description)
        domain = Bit() if word_size == 1 else Word(word_size)
        super().__init__("permutation", {"input": ValueType(domain, (count,))})
        self.add_round()
        self.set_output(self.add_component(PermutationComponent(
            self.input("input"), _inverse_mapping(description)
        )))


class Reverse(Permutation):
    def __init__(self, bit_size: int = 8) -> None:
        super().__init__(bit_size, tuple(reversed(range(bit_size))))
        self._family_name = "reverse"


class WordPermutation(Permutation):
    def __init__(self, word_size: int = 4, number_of_words: int = 4, permutation_description=None) -> None:
        description = [1, 2, 3, 0] if permutation_description is None else permutation_description
        super().__init__(word_size * number_of_words, description, word_size)
        self._family_name = "word_permutation"


class ShiftRows(Primitive):
    def __init__(self, rotation_amount: int = 1, word_bit_size: int = 8, number_of_words: int = 4) -> None:
        _positive(word_bit_size, "word_bit_size")
        _positive(number_of_words, "number_of_words")
        value_type = ValueType(Word(word_bit_size), (number_of_words,))
        super().__init__("shift_rows", {"input": value_type})
        self.add_round()
        mapping = tuple((index - rotation_amount) % number_of_words for index in range(number_of_words))
        self.set_output(self.add_component(PermutationComponent(self.input("input"), mapping)))


class LinearLayer(Primitive):
    def __init__(self, bit_size: int = 4, description=None) -> None:
        bit_size = _positive(bit_size, "bit_size")
        matrix = tuple(tuple(row) for row in description) if description is not None else tuple(
            tuple(int(row == column) for column in range(bit_size)) for row in range(bit_size)
        )
        # Legacy linear-layer descriptions store output columns. LinearMap uses
        # the conventional row-per-output representation.
        matrix = tuple(zip(*matrix))
        super().__init__("linear_layer", {"input": ValueType(Bit(), (bit_size,))})
        self.add_round()
        self.set_output(self.add_component(LinearMap(self.input("input"), matrix)))


def _first_irreducible(degree: int) -> int:
    for polynomial in range((1 << degree) | 1, 1 << (degree + 1), 2):
        if is_irreducible_binary_polynomial(polynomial, degree):
            return polynomial
    raise ValueError(f"no irreducible polynomial found for degree {degree}")


class MixColumn(Primitive):
    def __init__(self, word_size: int = 4, matrix=None, irreducible_polynomial: int = 0) -> None:
        word_size = _positive(word_size, "word_size")
        frozen = tuple(tuple(row) for row in (matrix or tuple(
            tuple(int(i == j) for j in range(4)) for i in range(4)
        )))
        modulus = irreducible_polynomial or _first_irreducible(word_size)
        field = BinaryExtensionField(word_size, modulus)
        super().__init__("mix_column", {"input": ValueType(field, (len(frozen[0]),))})
        self.add_round()
        self.set_output(self.add_component(LinearMap(self.input("input"), frozen)))


class Sigma(Primitive):
    def __init__(self, bit_size: int = 8, rotation_amounts_parameter=None) -> None:
        bit_size = _positive(bit_size, "bit_size")
        amounts = (1, 2) if rotation_amounts_parameter is None else tuple(rotation_amounts_parameter)
        super().__init__("sigma", {"input": ValueType(Bit(), (bit_size,))})
        self.add_round()
        self.set_output(self.add_component(sigma(self.input("input"), amounts)))


class ThetaGaston(Primitive):
    def __init__(self, bit_size: int = 320, rotation_amounts_parameter=None) -> None:
        amounts = (1, 18, 23, 25, 32, 52, 60, 63) if rotation_amounts_parameter is None else tuple(rotation_amounts_parameter)
        super().__init__("theta_gaston", {"input": ValueType(Bit(), (_positive(bit_size, "bit_size"),))})
        self.add_round()
        self.set_output(self.add_component(gaston_theta(self.input("input"), amounts)))


class ThetaKeccak(Primitive):
    def __init__(self, bit_size: int = 25) -> None:
        super().__init__("theta_keccak", {"input": ValueType(Bit(), (_positive(bit_size, "bit_size"),))})
        self.add_round()
        self.set_output(self.add_component(keccak_theta(self.input("input"))))


class ThetaXoodoo(Primitive):
    def __init__(self, bit_size: int = 384) -> None:
        super().__init__("theta_xoodoo", {"input": ValueType(Bit(), (_positive(bit_size, "bit_size"),))})
        self.add_round()
        self.set_output(self.add_component(xoodoo_theta(self.input("input"))))


class Fsr(Primitive):
    def __init__(self, register_size: int = 4, description=None) -> None:
        register_size = _positive(register_size, "register_size")
        if description is None:
            description = [[[register_size, [[0], [1]]]], 1]
        if not isinstance(description, (list, tuple)) or len(description) not in (2, 3):
            raise ValueError("description must contain registers, word width, and optional clocks")
        legacy_registers, word_width = description[:2]
        clocks = 1 if len(description) == 2 else description[2]
        word_width = _positive(word_width, "description word width")
        domain = Bit() if word_width == 1 else BinaryExtensionField(word_width, _first_irreducible(word_width))
        if register_size % word_width:
            raise ValueError("register_size must be divisible by the description word width")

        def terms(polynomial):
            if polynomial == []:
                return (FeedbackTerm((), 1),)
            if word_width == 1:
                return tuple(FeedbackTerm(tuple(monomial)) for monomial in polynomial)
            return tuple(FeedbackTerm(tuple(monomial[1]), monomial[0]) for monomial in polynomial)

        specs = []
        for legacy_register in legacy_registers:
            if len(legacy_register) not in (2, 3):
                raise ValueError("each register needs a length, feedback, and optional clock")
            clock = None if len(legacy_register) == 2 else terms(legacy_register[2])
            specs.append(FeedbackRegisterSpec(legacy_register[0], terms(legacy_register[1]), clock))
        if sum(spec.length for spec in specs) != register_size // word_width:
            raise ValueError("description register lengths do not cover register_size")
        super().__init__("fsr", {"input": ValueType(domain, (register_size // word_width,))})
        self.add_round()
        self.set_output(self.add_component(FeedbackRegister(self.input("input"), tuple(specs), clocks)))
