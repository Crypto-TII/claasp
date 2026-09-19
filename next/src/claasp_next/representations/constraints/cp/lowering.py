"""Lower portable Boolean constraints to MiniZinc CP items."""

from claasp_next.representations.constraints.cp.model import MiniZincModel
from claasp_next.representations.constraints.sat import CNFFormula


class BooleanMiniZincLowerer:
    """Translate CNF exactly while retaining stable logical variable names.

    EXAMPLES::

        >>> from claasp_next.representations.constraints.cp import BooleanMiniZincLowerer
        >>> from claasp_next.representations.constraints.sat import CNFFormula
        >>> model = BooleanMiniZincLowerer().lower(CNFFormula(("x",), ((1,),), ("fixed",)))
        >>> model.constraints
        ('constraint v_x;',)
    """

    def lower(self, formula: CNFFormula) -> MiniZincModel:
        """Return a MiniZinc Boolean model equivalent to ``formula``."""

        if not isinstance(formula, CNFFormula):
            raise TypeError("formula must be a CNFFormula")
        encoded = tuple(f"v_{name}" for name in formula.variables)
        declarations = tuple(f"var bool: {name};" for name in encoded)
        constraints = tuple(
            "constraint "
            + " \\/ ".join(
                encoded[abs(literal) - 1]
                if literal > 0
                else f"not {encoded[abs(literal) - 1]}"
                for literal in clause
            )
            + ";"
            for clause in formula.clauses
        )
        return MiniZincModel(
            declarations,
            constraints,
            provenance=formula.provenance,
            name_mapping=tuple(zip(encoded, formula.variables)),
        )
