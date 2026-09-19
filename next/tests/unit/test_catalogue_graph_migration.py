from pathlib import Path

from claasp_next.components import BitVectorSBox
from claasp_next.domains import Bit
from claasp_next.graph import Port, Primitive, ValueType
from claasp_next.representations.constraints.sat import BooleanCNFModel
from claasp_next.representations.execution import ScalarEvaluator


def test_rectangular_bit_vector_sbox_has_distinct_input_and_output_widths():
    component = BitVectorSBox(
        Port("input", ValueType(Bit(), (2,))),
        (0x00, 0x55, 0xAA, 0xFF),
        output_bit_size=8,
    )
    assert component.output_type == ValueType(Bit(), (8,))


def test_rectangular_sbox_evaluation_and_cnf_use_all_output_bits():
    primitive = Primitive("rectangular_sbox", {"input": ValueType(Bit(), (2,))})
    primitive.add_round()
    output = primitive.add_component(
        BitVectorSBox(
            primitive.input("input"),
            (0x00, 0x55, 0xAA, 0xFF),
            output_bit_size=8,
        )
    )
    primitive.set_output(output)
    sbox = primitive.components[0]
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
    primitive_root = Path(__file__).parents[2] / "src/claasp_next/primitives"
    assert not tuple(primitive_root.glob("**/data/index.json"))
    assert not tuple(primitive_root.glob("**/*.json.gz"))
    assert not (primitive_root / "_catalogue_graph.py").exists()
