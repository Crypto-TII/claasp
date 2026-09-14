"""Whole-graph monomial-trail composition for supported primitive slices."""

from dataclasses import dataclass

from claasp_next.components import BitVectorSBox, Permutation
from claasp_next.representations.constraints.polynomial import monomial_transition_table
from claasp_next.semantics.cryptanalysis.monomial import ComponentMonomialSemantics


@dataclass(frozen=True, slots=True)
class MonomialTrailStep:
    """One named component input/output exponent transition."""

    component_id: str
    input_mask: int
    output_mask: int


@dataclass(frozen=True, slots=True)
class MonomialTrail:
    """A reachable monomial exponent pair and its component witness."""

    input_mask: int
    output_mask: int
    width: int
    steps: tuple[MonomialTrailStep, ...]
    variable_group: str
    provenance: str


class PresentRoundMonomialSemantics:
    """Compose exact S-box monomial transitions through one typed PRESENT round.

    The tracked variable group is plaintext. XOR with key variables therefore
    selects the state term, while concatenation is structural and the p-layer
    permutes exponent bits. This is monomial-trail reachability; parity-based
    cancellation is a separate analysis.
    """

    def __init__(self, primitive) -> None:
        sboxes = tuple(
            component for component in primitive.components
            if isinstance(component, BitVectorSBox) and component.component_id.startswith("sbox_1_")
        )
        permutations = tuple(
            component for component in primitive.components
            if isinstance(component, Permutation) and component.component_id == "p_layer_1"
        )
        if primitive.family_name != "present" or len(primitive.rounds) != 1:
            raise ValueError("primitive must be a one-round typed PRESENT graph")
        if len(sboxes) != 16 or len(permutations) != 1:
            raise ValueError("PRESENT graph does not expose the expected S-box/p-layer structure")
        self.primitive = primitive
        self.sboxes = tuple(sorted(sboxes, key=lambda component: int(component.component_id.rsplit("_", 1)[1])))
        self.permutation = permutations[0]
        self.tables = tuple(monomial_transition_table(component.table) for component in self.sboxes)

    def trail(self, input_mask: int, output_mask: int) -> MonomialTrail | None:
        """Return a component witness, or ``None`` when the pair is unreachable."""

        limit = 1 << 64
        if any(not isinstance(mask, int) or isinstance(mask, bool) or not 0 <= mask < limit
               for mask in (input_mask, output_mask)):
            raise ValueError("PRESENT monomial masks must be 64-bit integers")
        before_permutation = self._inverse_permute(output_mask)
        steps = []
        for index, table in enumerate(self.tables):
            shift = 4 * (15 - index)
            local_input = (input_mask >> shift) & 0xF
            local_output = (before_permutation >> shift) & 0xF
            if not ComponentMonomialSemantics.is_possible(
                self.sboxes[index], (local_input,), local_output
            ):
                return None
            steps.append(MonomialTrailStep(
                self.sboxes[index].component_id, local_input, local_output
            ))
        steps.append(MonomialTrailStep("p_layer_1", before_permutation, output_mask))
        if not ComponentMonomialSemantics.is_possible(
            self.permutation, (before_permutation,), output_mask
        ):
            raise RuntimeError("typed permutation mapping produced an inconsistent monomial boundary")
        return MonomialTrail(
            input_mask, output_mask, 64, tuple(steps), "plaintext",
            "typed PRESENT round; exact component 3SDP-woU transitions",
        )

    def check(self, trail: MonomialTrail) -> bool:
        """Independently reconstruct and validate every component boundary."""

        if not isinstance(trail, MonomialTrail) or trail.width != 64 or len(trail.steps) != 17:
            return False
        rebuilt = self.trail(trail.input_mask, trail.output_mask)
        return rebuilt == trail

    def _inverse_permute(self, output_mask: int) -> int:
        output_bits = tuple((output_mask >> (63 - index)) & 1 for index in range(64))
        input_bits = [0] * 64
        for output_position, input_position in enumerate(self.permutation.mapping):
            input_bits[input_position] = output_bits[output_position]
        result = 0
        for bit in input_bits:
            result = (result << 1) | bit
        return result
