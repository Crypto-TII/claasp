"""Exact integer ARX trail weights partitioned between key and data paths."""

from dataclasses import dataclass, replace

from claasp.components import (
    Constant,
    Identity,
    ModularAdd,
    ModularSubtract,
    Permutation,
    Rotate,
    Xor,
)
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.unit_types import Word


@dataclass(frozen=True, slots=True)
class PartitionedDifferentialTrail:
    """Checked local-transition characteristic with two distinct weight sums.

    EXAMPLES::

        >>> PartitionedDifferentialTrail(None, 2, 3).objective_weight
        3
        >>> PartitionedDifferentialTrail(None, 2, 3).total_weight
        5
    """

    characteristic: object
    key_schedule_weight: int
    data_path_weight: int

    @property
    def objective_weight(self):
        """Return max(key schedule weight, data path weight), not their sum."""
        return max(self.key_schedule_weight, self.data_path_weight)

    @property
    def total_weight(self):
        """Return the ordinary total characteristic weight for comparison."""
        return self.key_schedule_weight + self.data_path_weight

    def to_terminal(self, *, file=None):
        """Print retained evidence without rerunning a solver.

        The min-max objective is 3 while the ordinary sum is 5; the plot preserves both path weights.

        Output goes to standard output unless ``file`` is supplied.

        EXAMPLES::

            >>> result = PartitionedDifferentialTrail(None, 2, 3)
            >>> from io import StringIO
            >>> output = StringIO()
            >>> result.to_terminal(file=output)
            >>> bool(output.getvalue().strip())
            True
        """
        from claasp.presentation._search_results import _to_terminal

        _to_terminal(self, file=file)

    def plot(self, *, show=True, save_to=None):
        """Plot retained evidence without rerunning a solver.

        The min-max objective is 3 while the ordinary sum is 5; the plot preserves both path weights.

        Requires the optional ``presentation`` extra. ``show=False`` suppresses
        display; ``save_to`` writes a file. Returns a ``FigureArtifact`` with
        the figure and plotted numeric series. Empty searches show their status.

        EXAMPLES::

            >>> result = PartitionedDifferentialTrail(None, 2, 3)
            >>> artifact = result.plot(show=False)
            >>> artifact.kind
            'search_evidence'
            >>> import matplotlib.pyplot as plt
            >>> plt.close(artifact.figure)
        """
        from claasp.drivers.renderers._search_results import _plot

        return _plot(self, show=show, save_to=save_to)


class KeyScheduleMinimaxSATModel:
    """Restore the legacy ARX min-max objective with input-size restrictions.

    Both path weights are bounded by their input bit widths, as in the legacy
    model. Modular additions/subtractions are classified using physical input
    dependencies, so structural joins cannot taint a key-only selection.
    Only exact integer-weight, single-word ARX components are accepted.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = KeyScheduleMinimaxSATModel(ToySpeck(3), fixed_input_differences={'key': 0})
        >>> model.cnf_formula(maximum_partition_weight=2).variable_count > 0
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "KeyScheduleMinimaxSATModel",
        "xor_differential_minimax",
        "exact cardinality bounds on key-schedule and data-path weight bits",
        "The same exact local transition weights are partitioned by physical input dependencies; the objective is their maximum and the legacy input-width bounds are retained.",
    )

    def __init__(
        self,
        primitive,
        *,
        nonzero_input=None,
        fixed_input_differences=None,
        output_difference=None,
        n_window=None,
    ):
        from claasp.representations.constraints.sat.trails import WordXorDifferentialSATModel

        graph = primitive.graph
        secret = set(graph.secret_inputs)
        public = set(graph.input_arrays) - secret
        if not secret or not public:
            raise ValueError("minimax requires secret-key and public-data inputs")
        self.primitive = primitive
        self.key_input_width = sum(
            graph.input_arrays[name].array_type.encoded_bit_size for name in secret
        )
        self.data_input_width = sum(
            graph.input_arrays[name].array_type.encoded_bit_size for name in public
        )
        dependencies = {name: frozenset((name,)) for name in graph.input_arrays}
        self.key_components: set[str] = set()
        self.data_components: set[str] = set()
        for component in graph.components:
            assert component.component_id is not None
            if (
                not isinstance(component.output_type.unit_type, Word)
                or not isinstance(
                    component,
                    (Constant, Identity, ModularAdd, ModularSubtract, Permutation, Rotate, Xor),
                )
                or component.output_type.unit_count != 1
            ):
                raise NotImplementedError("minimax requires exact single-word ARX components")
            roots = frozenset(
                root
                for selected in component.inputs
                for name, _ in graph.selection_bit_sources(selected)
                for root in dependencies[name]
            )
            dependencies[component.component_id] = roots
            if isinstance(component, (ModularAdd, ModularSubtract)):
                (self.key_components if roots <= secret else self.data_components).add(
                    component.component_id
                )
        self.model = WordXorDifferentialSATModel(
            primitive,
            nonzero_input=nonzero_input
            or next(name for name in graph.input_arrays if name in public),
            fixed_input_differences=fixed_input_differences,
            output_difference=output_difference,
            n_window=n_window,
        )
        self._formula = None

    def cnf_formula(self, *, maximum_partition_weight=None):
        """Bound each group separately, retaining the original input-width caps."""
        from claasp.representations.constraints.sat.quasidifferential import _BooleanBuilder
        from claasp.representations.constraints.sat.trails import _at_most

        if maximum_partition_weight is not None and (
            not isinstance(maximum_partition_weight, int)
            or isinstance(maximum_partition_weight, bool)
            or maximum_partition_weight < 0
        ):
            raise ValueError("maximum_partition_weight must be a nonnegative integer")
        base = self.model.cnf_formula()
        builder = _BooleanBuilder(base.variables, base.clauses, base.provenance)
        self._key_weights = tuple(
            name
            for name in base.variables
            if any(name.startswith(f"weight_{component}_") for component in self.key_components)
        )
        self._data_weights = tuple(
            name
            for name in base.variables
            if any(name.startswith(f"weight_{component}_") for component in self.data_components)
        )
        if {name for name in base.variables if name.startswith("weight_")} != set(
            self._key_weights
        ) | set(self._data_weights):
            raise NotImplementedError("cannot partition an unrecognized weight variable")
        for names, width, prefix in (
            (self._key_weights, self.key_input_width, "key_schedule"),
            (self._data_weights, self.data_input_width, "data_path"),
        ):
            bound = (
                width if maximum_partition_weight is None else min(width, maximum_partition_weight)
            )
            _at_most(
                names,
                bound,
                builder.allocate,
                builder.indices,
                lambda clause, label, prefix=prefix: builder.add(clause, f"{prefix}_weight_bound"),
                prefix,
            )
        self._formula = replace(
            builder.formula(),
            constraint_models=base.constraint_models
            + (ConstraintModelApplication(self.model_provenance),),
        )
        return self._formula

    def decode(self, assignment):
        """Check the full formula and independently sum decoded local transitions."""
        if self._formula is None or not self._formula.is_satisfied(assignment):
            raise ValueError("invalid partitioned differential witness")
        base = self.model.cnf_formula()
        trail = self.model.decode_characteristic(
            {name: assignment[name] for name in base.variables}
        )
        key_weight = sum(int(bool(assignment[name])) for name in self._key_weights)
        data_weight = sum(int(bool(assignment[name])) for name in self._data_weights)
        expected_key = sum(
            step.transition.weight
            for step in trail.steps
            if step.component_id.removesuffix("[0]") in self.key_components
        )
        expected_data = sum(
            step.transition.weight
            for step in trail.steps
            if step.component_id.removesuffix("[0]") in self.data_components
        )
        if (
            abs(key_weight - expected_key) > 1e-8
            or abs(data_weight - expected_data) > 1e-8
            or abs(trail.total_weight - key_weight - data_weight) > 1e-8
        ):
            raise ValueError("partition weights differ from independent local transitions")
        return PartitionedDifferentialTrail(trail, key_weight, data_weight)


__all__ = ["KeyScheduleMinimaxSATModel", "PartitionedDifferentialTrail"]
