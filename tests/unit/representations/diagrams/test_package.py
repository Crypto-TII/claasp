import pytest

from claasp import ArrayType, Primitive
from claasp.components import Identity
from claasp.domains import Bit
from claasp.primitives import Present
from claasp.primitives.block_ciphers.present import PRESENT_SBOX
from claasp.representations.diagrams import (
    ASCIIArtSerializer,
    DiagramCompiler,
    DiagramEdge,
    DiagramNode,
    DiagramRound,
    PrimitiveDiagram,
    TikZSerializer,
)
from claasp.semantics.cryptanalysis import (
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
)


def _toy_primitive():
    primitive = Primitive("toy diagram", {"state": ArrayType(Bit(), (4,))})
    primitive._builder.add_round()
    shuffled = primitive._builder.add_component(
        Identity(primitive.graph.input("state")[3, 1, 2, 0])
    )
    primitive._builder.add_round()
    copied = primitive._builder.add_component(Identity(shuffled))
    primitive._builder.set_output(copied)
    return primitive


def test_diagram_ir_preserves_rounds_dependencies_and_logical_selections():
    diagram = DiagramCompiler().compile(_toy_primitive())

    assert isinstance(diagram, PrimitiveDiagram)
    assert tuple(group.number for group in diagram.rounds) == (0, 1)
    assert tuple(group.node_ids for group in diagram.rounds) == (
        ("identity_0_0",),
        ("identity_1_0",),
    )
    assert diagram.edges[0].source_id == "state"
    assert diagram.edges[0].positions == (3, 1, 2, 0)
    assert diagram.edges[-1].destination_id == "__primitive_output__"


def test_ascii_and_tikz_are_independent_views_of_the_same_ir():
    primitive = _toy_primitive()
    diagram = DiagramCompiler().compile(primitive)

    ascii_art = ASCIIArtSerializer().serialize(diagram)
    assert "[0] state[3,1,2,0] --> +--------------+" in ascii_art
    assert "| identity_0_0 |" in ascii_art
    assert "[0] identity_1_0[0:4] --> +--------+" in ascii_art

    tikz = TikZSerializer().serialize(diagram)
    assert tikz.startswith("\\documentclass{article}\n\\usepackage{tikz}")
    assert "\\node[component] (n1)" in tikz
    assert "\\draw[->] (n0)" in tikz


def test_execution_trace_can_annotate_every_diagram_layer():
    primitive = _toy_primitive()
    trace = primitive.evaluate_with_trace(0b1010).trace

    diagram = DiagramCompiler().compile(primitive, trace)
    assert all(node.annotation is not None for node in diagram.nodes)
    ascii_art = ASCIIArtSerializer().serialize(diagram)
    assert "# (0x1,0x0,0x1,0x0)" in ascii_art
    assert "component,annotated" in TikZSerializer().serialize(diagram)


def test_cryptanalytic_trail_is_accepted_without_renderer_specific_adaptation():
    primitive = Present(number_of_rounds=1)
    component = next(item for item in primitive.graph.components if item.component_id == "sbox_1_0")
    component_id = component.component_id
    assert component_id is not None
    transition = SBoxTransitionSemantics(PRESENT_SBOX).xor_differential(1, 3)
    trail = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(1 << 60, 64),
        XorDifference(0, 64),
        (TrailStep(component_id, transition),),
    )

    diagram = DiagramCompiler().compile(primitive, trail.annotate(primitive))

    assert diagram.node(component_id).annotation == transition
    ascii_art = ASCIIArtSerializer().serialize(diagram)
    assert "0x1->0x3 w=2" in ascii_art


def test_ascii_routes_multiple_inputs_in_declared_order():
    primitive = Present(number_of_rounds=1)
    component = next(
        item for item in primitive.graph.components if item.component_id == "add_round_key_1"
    )

    ascii_art = ASCIIArtSerializer().serialize(DiagramCompiler().compile(primitive))
    first = f"[0] {component.inputs[0].source.owner_id}"
    second = f"[1] {component.inputs[1].source.owner_id}"

    assert ascii_art.index(first) < ascii_art.index(second)
    assert "--+--> +" in ascii_art


def test_diagram_rejects_annotation_from_another_primitive():
    first = _toy_primitive()
    second = _toy_primitive()

    with pytest.raises(ValueError, match="different primitive"):
        DiagramCompiler().compile(first, second.evaluate_with_trace(0).trace)


def test_tikz_escapes_labels_and_is_deterministic():
    diagram = PrimitiveDiagram(
        "escape",
        (
            DiagramNode("in", "input_100%&{}#\\", "input", None),
            DiagramNode("copy", "copy", "Identity", 0),
        ),
        (DiagramEdge("in", "copy", (0,), 0),),
        (DiagramRound(0, ("copy",)),),
    )
    first = TikZSerializer().serialize(diagram)
    assert first == TikZSerializer().serialize(diagram)
    assert r"input\_100\%\&\{\}\#\textbackslash{}" in first
