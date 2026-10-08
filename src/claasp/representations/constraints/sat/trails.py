"""Exact SAT adapters for weighted Word-graph characteristics."""

from claasp.components import BitwiseAnd, BitwiseOr, ModularAdd, ModularSubtract
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    direct_model,
)
from claasp.representations.constraints.sat.cnf import CNFFormula
from claasp.representations.constraints.smt import WordDifferentialSMTModel, WordLinearSMTModel


def _applications(primitive, analysis_kind):
    graph_model = direct_model(
        ConstraintBackend.SAT,
        f"Word{analysis_kind.title().replace('_', '')}SATModel",
        analysis_kind,
        "direct Word-graph CNF composition",
        "The graph wiring and exact component relations are encoded directly as CNF.",
    )
    weighted = tuple(
        component.component_id
        for component in primitive.components
        if isinstance(component, (ModularAdd, ModularSubtract, BitwiseAnd, BitwiseOr))
        and component.component_id is not None
    )
    wiring = tuple(
        component.component_id
        for component in primitive.components
        if component.component_id is not None and component.component_id not in weighted
    )
    return tuple(
        ConstraintModelApplication(graph_model, component_ids)
        for component_ids in (weighted, wiring)
        if component_ids
    )


class WordDifferentialSATModel:
    """Expose the shared exact Word differential encoding as ordinary CNF.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> model = WordDifferentialSATModel(Simon(number_of_rounds=1))
        >>> model.cnf_formula().variable_count > 0
        True
    """

    def __init__(self, primitive, **options):
        self._shared = WordDifferentialSMTModel(primitive, **options)
        self.primitive = primitive
        self.constraint_models = _applications(primitive, "xor_differential")

    def cnf_formula(self):
        """Build a solver-ready CNF formula.

        EXAMPLES::

            >>> from claasp.primitives import Simon
            >>> WordDifferentialSATModel(Simon(number_of_rounds=1)).cnf_formula().clause_count > 0
            True
        """

        formula = self._shared.smt_formula()
        return CNFFormula(formula.variables, formula.assertions, formula.provenance)

    def decode_characteristic(self, assignment):
        """Decode and independently validate a solver witness.

        EXAMPLES::

            >>> callable(WordDifferentialSATModel.decode_characteristic)
            True
        """

        return self._shared.decode_characteristic(assignment)

    def check_characteristic(self, characteristic):
        """Independently check graph wiring and all local transitions.

        EXAMPLES::

            >>> callable(WordDifferentialSATModel.check_characteristic)
            True
        """

        return self._shared.check_characteristic(characteristic)


class WordLinearSATModel:
    """Expose the shared exact Word linear encoding as ordinary CNF.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> model = WordLinearSATModel(Simon(number_of_rounds=1), maximum_weight=None)
        >>> model.cnf_formula().variable_count > 0
        True
    """

    def __init__(self, primitive, **options):
        self._shared = WordLinearSMTModel(primitive, **options)
        self.primitive = primitive
        self.constraint_models = _applications(primitive, "xor_linear")

    def cnf_formula(self):
        """Build a solver-ready CNF formula.

        EXAMPLES::

            >>> from claasp.primitives import Simon
            >>> WordLinearSATModel(Simon(number_of_rounds=1), maximum_weight=None).cnf_formula().clause_count > 0
            True
        """

        formula = self._shared.smt_formula()
        return CNFFormula(formula.variables, formula.assertions, formula.provenance)

    def decode_characteristic(self, assignment):
        """Decode and independently validate a solver witness.

        EXAMPLES::

            >>> callable(WordLinearSATModel.decode_characteristic)
            True
        """

        return self._shared.decode_characteristic(assignment)

    def check_characteristic(self, characteristic):
        """Independently check graph fanout and all local transitions.

        EXAMPLES::

            >>> callable(WordLinearSATModel.check_characteristic)
            True
        """

        return self._shared.check_characteristic(characteristic)


__all__ = ["WordDifferentialSATModel", "WordLinearSATModel"]
