import inspect
import json
from pathlib import Path

from claasp.components import (
    Add as AddComponent,
)
from claasp.components import (
    BinaryAffineMap as BinaryAffineMapComponent,
)
from claasp.components import (
    BitVectorSBox as BitVectorSBoxComponent,
)
from claasp.components import (
    BitwiseAnd as BitwiseAndComponent,
)
from claasp.components import (
    BitwiseNot as BitwiseNotComponent,
)
from claasp.components import (
    BitwiseOr as BitwiseOrComponent,
)
from claasp.components import (
    Constant as ConstantComponent,
)
from claasp.components import (
    FeedbackRegister as FeedbackRegisterComponent,
)
from claasp.components import (
    IDEAMultiply as IDEAMultiplyComponent,
)
from claasp.components import (
    Identity as IdentityComponent,
)
from claasp.components import (
    LinearMap as LinearMapComponent,
)
from claasp.components import (
    ModularAdd as ModularAddComponent,
)
from claasp.components import (
    ModularMultiply as ModularMultiplyComponent,
)
from claasp.components import (
    ModularSubtract as ModularSubtractComponent,
)
from claasp.components import (
    Multiply as MultiplyComponent,
)
from claasp.components import (
    Permutation as PermutationComponent,
)
from claasp.components import (
    Power as PowerComponent,
)
from claasp.components import (
    Rotate as RotateComponent,
)
from claasp.components import (
    SBox as SBoxComponent,
)
from claasp.components import (
    Shift as ShiftComponent,
)
from claasp.components import (
    VariableRotate as VariableRotateComponent,
)
from claasp.components import (
    VariableShift as VariableShiftComponent,
)
from claasp.components import (
    Xor as XorComponent,
)
from claasp.domains import BinaryExtensionField, PrimeField, Word
from claasp.graph import PrimitiveKind
from claasp.primitives._catalogue_exports import CATEGORY_EXPORTS
from claasp.primitives.single_component_primitives import (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    FeedbackRegister,
    IDEAMultiply,
    Identity,
    LinearMap,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Multiply,
    Permutation,
    Power,
    Rotate,
    SBox,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
)

CLASSES = (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    FeedbackRegister,
    IDEAMultiply,
    Identity,
    LinearMap,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Multiply,
    Permutation,
    Power,
    Rotate,
    SBox,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
)

COMPONENT_CLASSES = (
    AddComponent,
    BinaryAffineMapComponent,
    BitVectorSBoxComponent,
    BitwiseAndComponent,
    BitwiseNotComponent,
    BitwiseOrComponent,
    ConstantComponent,
    FeedbackRegisterComponent,
    IDEAMultiplyComponent,
    IdentityComponent,
    LinearMapComponent,
    ModularAddComponent,
    ModularMultiplyComponent,
    ModularSubtractComponent,
    MultiplyComponent,
    PermutationComponent,
    PowerComponent,
    RotateComponent,
    SBoxComponent,
    ShiftComponent,
    VariableRotateComponent,
    VariableShiftComponent,
    XorComponent,
)


def test_catalogue_is_one_to_one_with_public_base_components():
    advertised = CATEGORY_EXPORTS["single_component_primitives"]
    expected = {component.__name__ for component in COMPONENT_CLASSES}
    assert set(advertised) == expected
    assert {primitive.__name__ for primitive in CLASSES} == expected
    assert all(primitive().__class__.__name__ == primitive.__name__ for primitive in CLASSES)
    assert all(
        type(primitive().components[0]).__name__ == primitive.__name__ for primitive in CLASSES
    )


def test_machine_catalogue_matches_generated_exports():
    path = Path(__file__).parents[2] / "migration" / "single_component_catalogue.json"
    assert json.loads(path.read_text()) == CATEGORY_EXPORTS["single_component_primitives"]


def test_fixed_semantic_examples():
    assert Add().evaluate(1, 1) == 0
    assert Add(PrimeField(17)).evaluate(5, 14) == 2
    assert Multiply().evaluate(1, 0) == 0
    assert Multiply(PrimeField(17)).evaluate(5, 7) == 1
    assert Power().evaluate(1) == 1
    assert Power(3, PrimeField(17)).evaluate(3) == 10
    assert BinaryAffineMap(offset=3).evaluate(10) == 9
    assert LinearMap([[1, 0], [1, 1]]).evaluate(0b10) == 0b11
    assert Constant(8, 0x5A).evaluate() == 0x5A
    assert FeedbackRegister().evaluate(0b1010) == 0b0101
    assert Identity(16).evaluate(0xCAFE) == 0xCAFE
    assert Permutation([3, 2, 1, 0]).evaluate(0b1100) == 0b0011
    assert BitVectorSBox(2, [3, 2, 1, 0]).evaluate(1) == 2
    assert SBox([3, 2, 1, 0], Word(2), unit_count=2).evaluate(0b0001) == 0b1110
    assert BitwiseAnd().evaluate(0b1010, 0b1100) == 0b1000
    assert BitwiseNot().evaluate(0b1010) == 0b0101
    assert BitwiseOr().evaluate(0b1010, 0b0101) == 0b1111
    assert IDEAMultiply(4).evaluate(3, 5) == 15
    assert ModularAdd().evaluate(11, 7) == 2
    assert ModularMultiply().evaluate(3, 5) == 15
    assert ModularSubtract().evaluate(3, 5) == 14
    assert Rotate(8, 2, "left").evaluate(0x81) == 0x06
    assert Shift(8, 1).evaluate(0x81) == 0x40
    assert VariableRotate().evaluate(0x81, 2) == 0x60
    assert VariableShift().evaluate(0x81, 2) == 0x20
    assert Xor().evaluate(0b1010, 0b1100) == 0b0110


def test_linear_map_replaces_binary_and_mixcolumn_legacy_wrappers():
    field = BinaryExtensionField(4, 0b10011)
    assert LinearMap([[1, 0], [0, 1]], field).evaluate(0xAB) == 0xAB
    assert LinearMap([[1, 0], [0, 0]]).kind is PrimitiveKind.FUNCTION
    assert Power(2, PrimeField(17)).kind is PrimitiveKind.FUNCTION


def test_each_wrapper_is_a_documented_one_round_one_component_example():
    advertised = CATEGORY_EXPORTS["single_component_primitives"]
    for primitive_class in CLASSES:
        primitive = primitive_class()
        assert len(primitive.rounds) == 1
        assert len(primitive.components) == 1
        assert primitive_class.__module__ == advertised[primitive_class.__name__]
        assert ">>>" in inspect.getdoc(primitive_class)
        source = inspect.getsource(primitive_class)
        assert "self.add_round()" in source
        assert "self.add_component(" in source
        assert "self.set_output(" in source


def test_each_wrapper_docstring_covers_its_public_parameters():
    for primitive_class in CLASSES:
        documentation = inspect.getdoc(primitive_class)
        for parameter in inspect.signature(primitive_class).parameters:
            assert parameter in documentation, (primitive_class.__name__, parameter)


def test_all_default_kinds_are_explicit():
    permutations = {
        BinaryAffineMap,
        BitVectorSBox,
        BitwiseNot,
        Identity,
        LinearMap,
        Permutation,
        Power,
        Rotate,
        SBox,
    }
    for primitive_class in CLASSES:
        expected = (
            PrimitiveKind.PERMUTATION if primitive_class in permutations else PrimitiveKind.FUNCTION
        )
        assert primitive_class().kind is expected
