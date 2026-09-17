import inspect
import json
from pathlib import Path

from claasp_next.components import (
    Add as AddComponent,
    BinaryAffineMap as BinaryAffineMapComponent,
    BitVectorSBox as BitVectorSBoxComponent,
    BitwiseAnd as BitwiseAndComponent,
    BitwiseNot as BitwiseNotComponent,
    BitwiseOr as BitwiseOrComponent,
    Concatenate as ConcatenateComponent,
    Constant as ConstantComponent,
    FeedbackRegister as FeedbackRegisterComponent,
    IDEAMultiply as IDEAMultiplyComponent,
    Identity as IdentityComponent,
    LinearMap as LinearMapComponent,
    ModularAdd as ModularAddComponent,
    ModularMultiply as ModularMultiplyComponent,
    ModularSubtract as ModularSubtractComponent,
    Multiply as MultiplyComponent,
    PackBits as PackBitsComponent,
    Permutation as PermutationComponent,
    Power as PowerComponent,
    Rotate as RotateComponent,
    SBox as SBoxComponent,
    Shift as ShiftComponent,
    UnpackBits as UnpackBitsComponent,
    VariableRotate as VariableRotateComponent,
    VariableShift as VariableShiftComponent,
    Xor as XorComponent,
)
from claasp_next.domains import BinaryExtensionField, Word
from claasp_next.graph import PrimitiveKind
from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS
from claasp_next.primitives.single_component_primitives import (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Concatenate,
    Constant,
    FeedbackRegister,
    IDEAMultiply,
    Identity,
    LinearMap,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Multiply,
    PackBits,
    Permutation,
    Power,
    Rotate,
    SBox,
    Shift,
    UnpackBits,
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
    Concatenate,
    Constant,
    FeedbackRegister,
    IDEAMultiply,
    Identity,
    LinearMap,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Multiply,
    PackBits,
    Permutation,
    Power,
    Rotate,
    SBox,
    Shift,
    UnpackBits,
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
    ConcatenateComponent,
    ConstantComponent,
    FeedbackRegisterComponent,
    IDEAMultiplyComponent,
    IdentityComponent,
    LinearMapComponent,
    ModularAddComponent,
    ModularMultiplyComponent,
    ModularSubtractComponent,
    MultiplyComponent,
    PackBitsComponent,
    PermutationComponent,
    PowerComponent,
    RotateComponent,
    SBoxComponent,
    ShiftComponent,
    UnpackBitsComponent,
    VariableRotateComponent,
    VariableShiftComponent,
    XorComponent,
)


def test_catalogue_is_one_to_one_with_public_base_components():
    advertised = CATEGORY_EXPORTS["single_component_primitives"]
    expected = {component.__name__ for component in COMPONENT_CLASSES}
    assert set(advertised) == expected
    assert {primitive.__name__ for primitive in CLASSES} == expected
    assert all(
        primitive().__class__.__name__ == primitive.__name__ for primitive in CLASSES
    )
    assert all(
        type(primitive().components[0]).__name__ == primitive.__name__
        for primitive in CLASSES
    )


def test_machine_catalogue_matches_generated_exports():
    path = Path(__file__).parents[2] / "migration" / "single_component_catalogue.json"
    assert (
        json.loads(path.read_text()) == CATEGORY_EXPORTS["single_component_primitives"]
    )


def test_fixed_semantic_examples():
    assert Add().evaluate(5, 14) == 2
    assert Multiply().evaluate(5, 7) == 1
    assert Power().evaluate(3) == 10
    assert BinaryAffineMap(offset=3).evaluate(10) == 9
    assert LinearMap([[1, 0], [1, 1]]).evaluate(0b10) == 0b11
    assert PackBits().evaluate(0xAB) == 0xAB
    assert UnpackBits().evaluate(0xAB) == 0xAB
    assert Concatenate().evaluate(0b10, 0b01) == 0b1001
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
    assert Power(2).kind is PrimitiveKind.FUNCTION


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


def test_all_default_kinds_are_explicit():
    permutations = {
        BinaryAffineMap,
        BitVectorSBox,
        BitwiseNot,
        Identity,
        LinearMap,
        PackBits,
        Permutation,
        Power,
        Rotate,
        SBox,
        UnpackBits,
    }
    for primitive_class in CLASSES:
        expected = (
            PrimitiveKind.PERMUTATION
            if primitive_class in permutations
            else PrimitiveKind.FUNCTION
        )
        assert primitive_class().kind is expected
