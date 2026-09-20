"""Graph-wired Speck linear masks over exact modular-add SMT relations."""

from claasp.analysis.arx import check_speck_linear_trail
from claasp.components import Rotate
from claasp.domains import Word
from claasp.representations.constraints.smt.formula import SMTFormula
from claasp.representations.constraints.smt.trails import _at_most
from claasp.representations.constraints.smt.transitions import (
    ModularAddLinearSMTModel,
    _xor_equivalence,
)
from claasp.semantics.cryptanalysis import Trail, TrailKind, TrailStep, XorMask


class SpeckLinearSMTModel:
    """Compose data-path masks with zero round-key masks and explicit weights.

    The plaintext mask is nonzero. Key-schedule masks and related-key linear
    characteristics are deliberately outside this model's scope.


    EXAMPLES::

        >>> try:
        ...     SpeckLinearSMTModel()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(
        self,
        primitive,
        *,
        maximum_weight=None,
        fixed_weight=None,
        input_mask=None,
        output_mask=None,
    ):
        plaintext = primitive.input_ports.get("plaintext")
        if (
            primitive.family_name != "speck"
            or plaintext is None
            or not isinstance(plaintext.value_type.domain, Word)
            or not primitive.rounds
        ):
            raise NotImplementedError("linear SMT composition requires a typed Speck primitive")
        if maximum_weight is not None and fixed_weight is not None:
            raise ValueError("choose maximum_weight or fixed_weight, not both")
        for weight in (maximum_weight, fixed_weight):
            if weight is not None and (
                not isinstance(weight, int) or isinstance(weight, bool) or weight < 0
            ):
                raise ValueError("weights must be nonnegative integers")
        self.primitive = primitive
        self.width = plaintext.value_type.domain.width
        for mask in (input_mask, output_mask):
            if mask is not None and (
                not isinstance(mask, int)
                or isinstance(mask, bool)
                or not 0 <= mask < (1 << (2 * self.width))
            ):
                raise ValueError("boundary masks must fit the primitive block width")
        self.input_mask = input_mask
        self.output_mask = output_mask
        self.maximum_weight = maximum_weight
        self.fixed_weight = fixed_weight
        self._states = ()

    def smt_formula(self):
        """Build deterministic Boolean constraints and sequential weight bounds."""
        variables, indices, clauses, provenance = [], {}, [], []

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(items, label):
            clauses.append(tuple(items))
            provenance.append(label)

        width = self.width
        states = tuple(
            tuple(allocate(f"state_{r}_{bit}") for bit in range(2 * width))
            for r in range(len(self.primitive.rounds) + 1)
        )
        weights = []
        for r in range(len(self.primitive.rounds)):
            local = ModularAddLinearSMTModel(width).smt_formula()
            mapping = {
                i: indices[allocate(f"round_{r}_{name}")]
                for i, name in enumerate(local.variables, 1)
            }
            for clause, label in zip(local.assertions, local.provenance):
                add(
                    (mapping[abs(literal)] * (1 if literal > 0 else -1) for literal in clause),
                    label,
                )
            alpha = self._rotation(r, "right")
            beta = self._rotation(r, "left")
            for bit in range(width):
                relations = (
                    (f"round_{r}_left_{bit}", states[r][(bit - alpha) % width]),
                    (
                        f"round_{r}_right_{bit}",
                        states[r][width + bit],
                        states[r + 1][width + (bit - beta) % width],
                    ),
                    (f"round_{r}_output_{bit}", states[r + 1][bit], states[r + 1][width + bit]),
                )
                for names in relations:
                    _xor_equivalence(names, indices, clauses, provenance)
                weights.append(f"round_{r}_weight_{bit}")
        add((indices[name] for name in states[0]), "nonzero_linear_input")
        for names, mask, label in (
            (states[0], self.input_mask, "fixed_linear_input"),
            (states[-1], self.output_mask, "fixed_linear_output"),
        ):
            if mask is not None:
                for bit, name in enumerate(names):
                    value = (mask >> (2 * width - 1 - bit)) & 1
                    add((indices[name] if value else -indices[name],), label)
        bound = self.fixed_weight if self.fixed_weight is not None else self.maximum_weight
        if bound is not None:
            _at_most(weights, bound, allocate, indices, add)
        if self.fixed_weight is not None:
            complements = tuple(allocate(f"not_{name}") for name in weights)
            for name, complement in zip(weights, complements):
                add((indices[name], indices[complement]), "weight_complement")
                add((-indices[name], -indices[complement]), "weight_complement")
            if self.fixed_weight > len(weights):
                add((indices[weights[0]],), "impossible_fixed_weight")
                add((-indices[weights[0]],), "impossible_fixed_weight")
            else:
                _at_most(
                    complements,
                    len(weights) - self.fixed_weight,
                    lambda name: allocate("lower" + name),
                    indices,
                    add,
                )
        self._states = states
        return SMTFormula(tuple(variables), tuple(clauses), tuple(provenance))

    def decode_trail(self, assignment):
        """Recount correlations and reject invalid wiring or requested weights."""
        if not self._states:
            raise ValueError("build the SMT formula before decoding a trail")
        steps = []
        for r in range(len(self.primitive.rounds)):
            local = ModularAddLinearSMTModel(self.width)
            projected = {
                name: assignment[f"round_{r}_{name}"] for name in local.smt_formula().variables
            }
            component_id = self.primitive.round_operations[r]["modular_add"].component_id
            steps.append(TrailStep(component_id, local.decode_transition(projected)))

        def packed(names):
            value = 0
            for name in names:
                value = (value << 1) | assignment[name]
            return value

        trail = Trail(
            TrailKind.XOR_LINEAR,
            XorMask(packed(self._states[0]), 2 * self.width),
            XorMask(packed(self._states[-1]), 2 * self.width),
            tuple(steps),
        )
        if (
            not trail.input_pattern.value
            or not check_speck_linear_trail(self.primitive, trail)
            or (self.maximum_weight is not None and trail.total_weight > self.maximum_weight)
            or (self.fixed_weight is not None and trail.total_weight != self.fixed_weight)
            or (self.input_mask is not None and trail.input_pattern.value != self.input_mask)
            or (self.output_mask is not None and trail.output_pattern.value != self.output_mask)
        ):
            raise ValueError("assignment disagrees with Speck linear semantics or weight")
        return trail

    def _rotation(self, round_number, direction):
        component = self.primitive.round_operations[round_number][f"rotate_{direction}"]
        if not isinstance(component, Rotate):
            raise ValueError(f"Speck round {round_number} is missing its {direction} rotation")
        return component.amount
