from pathlib import Path

from claasp.components import BitVectorSBox
from claasp.domains import Bit
from claasp.graph import ArrayType, Port, Primitive
from claasp.representations.constraints.sat import BooleanCNFModel
from claasp.representations.execution import ScalarEvaluator


def test_rectangular_bit_vector_sbox_has_distinct_input_and_output_widths():
    component = BitVectorSBox(
        Port("input", ArrayType(Bit(), (2,))),
        (0x00, 0x55, 0xAA, 0xFF),
        output_bit_size=8,
    )
    assert component.output_type == ArrayType(Bit(), (8,))


def test_rectangular_sbox_evaluation_and_cnf_use_all_output_bits():
    primitive = Primitive("rectangular_sbox", {"input": ArrayType(Bit(), (2,))})
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        BitVectorSBox(
            primitive.graph.input("input"),
            (0x00, 0x55, 0xAA, 0xFF),
            output_bit_size=8,
        )
    )
    primitive._builder.set_output(output)
    sbox = primitive.graph.components[0]
    assert ScalarEvaluator().evaluate(primitive, {"input": (1, 0)}).output == (
        1,
        0,
        1,
        0,
        1,
        0,
        1,
        0,
    )
    cnf = BooleanCNFModel(primitive).cnf_formula()
    assert all(f"{sbox.output.owner_id}_{position}" in cnf.variables for position in range(8))


def test_runtime_has_no_generated_graph_indexes_or_loader():
    primitive_root = (
        next(
            parent
            for parent in Path(__file__).resolve().parents
            if (parent / "pyproject.toml").is_file()
        )
        / "src/claasp/primitives"
    )
    assert not tuple(primitive_root.glob("**/data/index.json"))
    assert not tuple(primitive_root.glob("**/*.json.gz"))
    assert not (primitive_root / "_catalogue_graph.py").exists()
