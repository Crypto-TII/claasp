import pytest

from claasp_next import Bit, Cipher, ValueType
from claasp_next.components import Identity
from claasp_next.ciphers import PresentBlockCipher
from claasp_next.ciphers.block_ciphers.present import PRESENT_SBOX
from claasp_next.interpretations.cryptanalysis import (
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
)
from claasp_next.representations.diagrams import (
    ASCIIArtSerializer,
    ASCIIArtWorkInProgressWarning,
    CipherDiagram,
    DiagramCompiler,
    TikZSerializer,
)


def _toy_cipher():
    cipher = Cipher("toy diagram", {"state": ValueType(Bit(), (4,))})
    cipher.add_round()
    shuffled = cipher.add_component(Identity(cipher.input("state")[3, 1, 2, 0]))
    cipher.add_round()
    copied = cipher.add_component(Identity(shuffled))
    cipher.set_output(copied)
    return cipher


def test_diagram_ir_preserves_rounds_dependencies_and_logical_selections():
    diagram = DiagramCompiler().compile(_toy_cipher())

    assert isinstance(diagram, CipherDiagram)
    assert tuple(group.number for group in diagram.rounds) == (0, 1)
    assert tuple(group.node_ids for group in diagram.rounds) == (
        ("identity_0_0",),
        ("identity_1_0",),
    )
    assert diagram.edges[0].source_id == "state"
    assert diagram.edges[0].positions == (3, 1, 2, 0)
    assert diagram.edges[-1].destination_id == "__cipher_output__"


def test_ascii_and_tikz_are_independent_views_of_the_same_ir():
    cipher = _toy_cipher()
    diagram = cipher.diagram()

    with pytest.warns(ASCIIArtWorkInProgressWarning, match="structural listing"):
        ascii_art = ASCIIArtSerializer().serialize(diagram)
    assert "round 0\n  identity_0_0: Identity <- state[3,1,2,0]" in ascii_art
    assert "output <- identity_1_0[0:4]" in ascii_art

    tikz = TikZSerializer().serialize(diagram)
    assert tikz.startswith("\\documentclass{article}\n\\usepackage{tikz}")
    assert "\\node[component] (n1)" in tikz
    assert "\\draw[->] (n0)" in tikz


def test_execution_trace_can_annotate_every_diagram_layer():
    cipher = _toy_cipher()
    trace = cipher.evaluate_with_trace(0b1010).trace

    diagram = cipher.diagram(trace)
    assert all(node.annotation is not None for node in diagram.nodes)
    with pytest.warns(ASCIIArtWorkInProgressWarning):
        ascii_art = cipher.draw("ascii", trace)
    assert "# (0x1,0x0,0x1,0x0)" in ascii_art
    assert "component,annotated" in cipher.draw("tikz", trace)


def test_cryptanalytic_trail_is_accepted_without_renderer_specific_adaptation():
    cipher = PresentBlockCipher(number_of_rounds=1)
    component = next(item for item in cipher.components if item.component_id == "sbox_1_0")
    transition = SBoxTransitionSemantics(PRESENT_SBOX).xor_differential(1, 3)
    trail = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(1 << 60, 64),
        XorDifference(0, 64),
        (TrailStep(component.component_id, transition),),
    )

    diagram = cipher.diagram(trail)

    assert diagram.node(component.component_id).annotation == transition
    with pytest.warns(ASCIIArtWorkInProgressWarning):
        ascii_art = cipher.draw("ascii", trail)
    assert "0x1->0x3 w=2" in ascii_art


def test_public_drawing_api_rejects_unknown_formats():
    with pytest.raises(ValueError, match="ascii.*tikz.*pdf"):
        _toy_cipher().draw("canvas")


def test_diagram_rejects_annotation_from_another_cipher():
    first = _toy_cipher()
    second = _toy_cipher()

    with pytest.raises(ValueError, match="different cipher"):
        first.diagram(second.evaluate_with_trace(0).trace)
