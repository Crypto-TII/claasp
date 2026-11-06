"""Restricted legacy ARX boomerang trail search over typed graph cuts."""

from dataclasses import dataclass, replace
from fractions import Fraction

from claasp.components import Constant, Identity, ModularAdd, Permutation, Rotate, Xor
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.semantics.cryptanalysis.composed import ModularAddBoomerangAutomaton
from claasp.unit_types import Word


@dataclass(frozen=True, slots=True)
class ARXBoomerangTrail:
    """Two checked outer characteristics and exact local switch probabilities.

    The outer weight excludes the middle switch, as in legacy CLAASP. Neither
    its sum nor the product of local switch probabilities is an exact
    fixed-key probability for the whole primitive.

    EXAMPLES::

        >>> ARXBoomerangTrail.__dataclass_params__.frozen
        True
    """

    upper: object
    lower: object
    switches: tuple[tuple[str, tuple[int, int, int, int], Fraction], ...]
    outer_weight: float
    model_complete: bool = False
    scope: str = "legacy restricted large-switch characteristic model"

    def to_terminal(self, *, file=None):
        """Print the outer objective and independently checked local switches."""
        from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

        rows = (
            TableRow.of("outer weight", self.outer_weight),
            TableRow.of("model complete", self.model_complete),
            TableRow.of("scope", self.scope),
        ) + tuple(TableRow.of(name, str(probability)) for name, _, probability in self.switches)
        print(
            render_terminal_table(
                Table((TableColumn("field", "Field"), TableColumn("value", "Value")), rows)
            ),
            file=file,
        )


class BoomerangSATModel:
    """Compose two exact ARX trail models with the legacy large-switch subset.

    Choose one or several independent modular additions in a round. The cuts
    must form a word-state permutation (x,y)->(x+y,y). Unsupported cuts fail
    explicitly. Key differences are zero; related-key boomerangs are excluded.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = BoomerangSATModel(ToySpeck(3), switch_round=1)
        >>> len(model.switches)
        1
        >>> model.cnf_formula(maximum_weight=4).variable_count > 0
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "BoomerangSATModel",
        "boomerang",
        "legacy restricted modular-addition large-switch automaton",
        "The GPL legacy Boolean table and at-most-one-halving restriction are composed with exact outer trails; switch witnesses are checked by an independent carry/borrow count.",
    )

    def __init__(
        self,
        primitive,
        *,
        switch_round=None,
        components=None,
        input_difference=None,
        output_difference=None,
        upper_window=None,
        lower_window=None,
    ):
        from claasp.representations.constraints.sat.trails import WordXorDifferentialSATModel
        from claasp.transformations import slice_primitive

        self.primitive = primitive
        graph = primitive.graph
        self._widths = {
            name: array.array_type.unit_type.width
            for name, array in graph.input_arrays.items()
            if isinstance(array.array_type.unit_type, Word)
        }
        for component in graph.components:
            if not isinstance(
                component, (Constant, Identity, ModularAdd, Permutation, Rotate, Xor)
            ):
                raise NotImplementedError(
                    f"legacy ARX boomerang model does not support {type(component).__name__}"
                )
            if not isinstance(component.output_type.unit_type, Word):
                raise NotImplementedError("boomerang search requires a Word graph")
            self._widths[component.component_id] = component.output_type.unit_type.width
        if len(self._widths) != len(graph.input_arrays) + len(graph.components):
            raise NotImplementedError("boomerang search requires Word inputs")
        secret = set(graph.secret_inputs)
        public = [name for name in graph.input_arrays if name not in secret]
        if len(public) != 1:
            raise NotImplementedError("boomerang search needs one public state input")
        self.input_name = public[0]
        # Physical bit dependencies avoid structural joins tainting key-only data.
        dependencies = {
            c.component_id: {
                name for selection in c.inputs for name, _ in graph.selection_bit_sources(selection)
            }
            for c in graph.components
        }
        tainted = set(public)
        for component in graph.components:
            if dependencies[component.component_id] & tainted:
                tainted.add(component.component_id)
        if components is None:
            if switch_round is None:
                switch_round = len(graph.rounds) // 2
            if (
                not isinstance(switch_round, int)
                or isinstance(switch_round, bool)
                or not 0 <= switch_round < len(graph.rounds)
            ):
                raise ValueError("switch_round must name a zero-based round")
            candidates = [
                c
                for c in graph.rounds[switch_round].components
                if isinstance(c, ModularAdd) and c.component_id in tainted
            ]
            # First independent layer; subsequent additions belong to the lower trail.
            chosen = []
            descendants: set[str] = set()
            for c in graph.components:
                if dependencies[c.component_id] & descendants:
                    descendants.add(c.component_id)
                if c in candidates and c.component_id not in descendants:
                    chosen.append(c.component_id)
                    descendants.add(c.component_id)
            components = chosen
        elif switch_round is not None:
            raise ValueError("choose components or switch_round, not both")
        if isinstance(components, str):
            components = (components,)
        ids = tuple(components)
        by_id = {c.component_id: c for c in graph.components}
        if not ids or len(ids) != len(set(ids)) or any(name not in by_id for name in ids):
            raise ValueError("choose distinct modular-addition component IDs")
        selected = set(ids)
        lower: set[str] = set()
        for c in graph.components:
            name = c.component_id
            if dependencies[name] & (lower | selected):
                lower.add(name)
                if name in selected:
                    raise ValueError("middle additions must be independent")

        # Keep only ancestors of the middle layer above the cut. Independent
        # side operations stay below it, preserving each addition's right word.
        upper = set()
        pending = [source for name in ids for source in dependencies[name]]
        while pending:
            name = pending.pop()
            if name in by_id and name not in upper:
                upper.add(name)
                pending.extend(dependencies[name])
        upper.update(set(by_id) - tainted)
        lower = set(by_id) - upper - selected

        def units(selection):
            bits = graph.selection_bit_sources(selection)
            result = []
            position = 0
            while position < len(bits):
                name, bit = bits[position]
                width = self._widths[name]
                if bit % width or tuple(bits[position : position + width]) != tuple(
                    (name, bit + j) for j in range(width)
                ):
                    raise NotImplementedError("boomerang boundaries must be whole ordered words")
                result.append((name, bit // width))
                position += width
            return tuple(result)

        self._switch_units = []
        for name in ids:
            c = by_id[name]
            if (
                not isinstance(c, ModularAdd)
                or len(c.inputs) != 2
                or c.output_type.unit_count != 1
                or c.modulus not in (None, 1 << self._widths[name])
            ):
                raise NotImplementedError(
                    "middle switch needs one standard two-input modular addition"
                )
            operands = tuple(units(s) for s in c.inputs)
            if any(len(operand) != 1 for operand in operands):
                raise NotImplementedError("middle switch operands must be single words")
            self._switch_units.append((name, operands[0][0], operands[1][0]))
        pre, post = set(), set()
        for c in graph.components:
            if c.component_id not in lower | selected:
                continue
            for s in c.inputs:
                for unit in units(s):
                    if unit[0] in tainted and unit[0] not in lower | selected:
                        pre.add(unit)
                    if c.component_id in lower and unit[0] in tainted and unit[0] not in lower:
                        post.add(unit)
        if graph.output is None:
            raise ValueError("primitive needs an output")
        for unit in units(graph.output):
            if unit[0] not in lower:
                post.add(unit)
                if unit[0] not in selected:
                    pre.add(unit)
        occupied: set[tuple[str, int]] = set()
        for name, left, right in self._switch_units:
            involved = {left, right}
            if (
                len(involved) != 2
                or occupied & involved
                or left in post
                or right not in post
                or (name, 0) not in post
            ):
                raise NotImplementedError("cut is not a disjoint triangular addition permutation")
            occupied |= involved
        if post - {(name, 0) for name in ids} != pre - {left for _, left, _ in self._switch_units}:
            raise NotImplementedError("middle cut changes a non-switch state word")
        state_width = graph.input_arrays[self.input_name].array_type.encoded_bit_size
        if (
            sum(self._widths[name] for name, _ in pre) != state_width
            or sum(self._widths[name] for name, _ in post) != state_width
        ):
            raise NotImplementedError("middle cut does not preserve the public state width")
        self.switches = ids
        self.pre = tuple(sorted(pre))
        self.post = tuple(sorted(post))

        def selection(unit):
            name, position = unit
            return graph.unit_array(name).select(position)

        self.upper = slice_primitive(
            primitive, tuple(selection(unit) for unit in self.pre)
        ).primitive
        grouped: dict[str, list[int]] = {}
        for name, unit in self.post:
            grouped.setdefault(name, []).append(unit)
        ports = {name: f"switch_state_{i}" for i, name in enumerate(grouped)}
        self._ports = {
            (name, unit): (ports[name], index)
            for name, positions in grouped.items()
            for index, unit in enumerate(positions)
        }
        self.lower = slice_primitive(
            primitive,
            inputs={
                ports[name]: graph.unit_array(name).select(*positions)
                for name, positions in grouped.items()
            },
        ).primitive
        self._models = (
            WordXorDifferentialSATModel(
                self.upper,
                nonzero_input=self.input_name,
                n_window=upper_window,
                fixed_input_differences={name: 0 for name in self.upper.graph.secret_inputs}
                | ({self.input_name: input_difference} if input_difference is not None else {}),
            ),
            WordXorDifferentialSATModel(
                self.lower,
                fixed_input_differences={name: 0 for name in self.lower.graph.secret_inputs},
                output_difference=output_difference,
                n_window=lower_window,
            ),
        )
        self._formula = None

    def cnf_formula(self, *, maximum_weight=None):
        """Build the restricted search formula with an optional outer-weight bound."""
        if maximum_weight is not None and (
            not isinstance(maximum_weight, int)
            or isinstance(maximum_weight, bool)
            or maximum_weight < 0
        ):
            raise ValueError("maximum_weight must be a nonnegative integer")
        from claasp.representations.constraints.sat._boomerang_switch import add_large_switch
        from claasp.representations.constraints.sat.quasidifferential import _BooleanBuilder
        from claasp.representations.constraints.sat.trails import _at_most

        builder = _BooleanBuilder()
        self._formulas = tuple(m.cnf_formula() for m in self._models)
        self._maps = []
        weights: list[str] = []
        for prefix, formula in zip(("upper_", "lower_"), self._formulas):
            mapping = {
                i: builder.indices[builder.allocate(prefix + name)]
                for i, name in enumerate(formula.variables, 1)
            }
            self._maps.append(mapping)
            for clause, label in zip(formula.clauses, formula.provenance):
                builder.add(
                    tuple(mapping[abs(lit)] * (1 if lit > 0 else -1) for lit in clause),
                    prefix + label,
                )
            weights.extend(
                prefix + name for name in formula.variables if name.startswith("weight_")
            )
        self._weight_names = tuple(weights)

        def upper_bits(unit):
            name, index = unit
            width = self._widths[name]
            wires = self._models[0]._shared._unit_arrays[name][index * width : (index + 1) * width]
            return tuple(builder.indices["upper_" + wire] for wire in wires)

        def lower_bits(unit):
            name, index = self._ports[unit]
            width = self._widths[unit[0]]
            wires = self._models[1]._shared._unit_arrays[name][index * width : (index + 1) * width]
            return tuple(builder.indices["lower_" + wire] for wire in wires)

        self._switch_bits = []
        for name, left, right in self._switch_units:
            bits = (upper_bits(left), upper_bits(right), lower_bits((name, 0)), lower_bits(right))
            self._switch_bits.append(bits)
            add_large_switch(builder, *bits)
        output = self._models[1]._shared._output
        builder.add(
            tuple(builder.indices["lower_" + name] for name in output), "nonzero_boomerang_output"
        )
        if maximum_weight is not None:
            _at_most(
                weights,
                maximum_weight,
                builder.allocate,
                builder.indices,
                builder.add,
                "outer_weight_bound",
            )
        applications = tuple(a for f in self._formulas for a in f.constraint_models) + (
            ConstraintModelApplication(self.model_provenance, self.switches),
        )
        self._formula = replace(builder.formula(), constraint_models=applications)
        return self._formula

    def decode(self, assignment):
        """Check both trails, every clause and the exact local quartet counts."""
        if self._formula is None or not self._formula.is_satisfied(assignment):
            raise ValueError("invalid boomerang SAT witness")
        trails = []
        for prefix, model, formula in zip(("upper_", "lower_"), self._models, self._formulas):
            trails.append(
                model.decode_characteristic(
                    {name: assignment[prefix + name] for name in formula.variables}
                )
            )
        switches = []
        for (name, _, _), bits in zip(self._switch_units, self._switch_bits):
            values = tuple(
                sum(
                    int(bool(assignment[self._formula.variables[abs(lit) - 1]]))
                    << (len(vector) - 1 - i)
                    for i, lit in enumerate(vector)
                )
                for vector in bits
            )
            entry = ModularAddBoomerangAutomaton(len(bits[0])).connectivity(*values)
            probability = Fraction(entry.count, 1 << (2 * len(bits[0])))
            if probability == 0:
                raise ValueError("legacy switch candidate has zero exact probability")
            switches.append((name, (values[0], values[1], values[2], values[3]), probability))
        weight = sum(int(bool(assignment[name])) for name in self._weight_names)
        if abs(weight - sum(t.total_weight for t in trails)) > 1e-8:
            raise ValueError("outer weight differs from independently checked transitions")
        return ARXBoomerangTrail(trails[0], trails[1], tuple(switches), float(weight))
