"""CP encodings of local S-box transition relations."""

from typing import cast

from claasp.components import BitVectorSBox
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
    _verified_model,
)
from claasp.representations.constraints.cp.model import MiniZincModel
from claasp.semantics import XOR_DIFFERENTIAL
from claasp.semantics.cryptanalysis import (
    PropagationProblem,
    SBoxBoomerangSemantics,
)


class SBoxXorDifferentialCPModel:
    """Exact local feasibility model for possible and impossible differences.

    EXAMPLES::

        >>> from claasp.components import BitVectorSBox
        >>> from claasp.primitives import Present
        >>> primitive = Present(number_of_rounds=1)
        >>> sbox = next(item for item in primitive.components if isinstance(item, BitVectorSBox))
        >>> problem = PropagationProblem(
        ...     primitive, XOR_DIFFERENTIAL, component_ids=(sbox.component_id,)
        ... )
        >>> model = SBoxXorDifferentialCPModel(problem, sbox.component_id, 1, 3)
        >>> query = model.cp_model()
        >>> query.constraints[-2:]
        ('constraint input_difference = 1;', 'constraint output_difference = 3;')
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "SBoxXorDifferentialCPModel",
        "xor_differential",
        "exhaustive DDT table constraint",
        "The feasible rows are enumerated directly from the supplied S-box table.",
    )

    def __init__(
        self,
        problem: PropagationProblem,
        component_id: str,
        input_difference: int,
        output_difference: int,
    ) -> None:
        if problem.semantics != XOR_DIFFERENTIAL:
            raise ValueError("impossible-pair CP lowering requires XOR-differential semantics")
        component = next(
            (item for item in problem.components if item.component_id == component_id), None
        )
        if not isinstance(component, BitVectorSBox):
            raise ValueError("component_id must select a scoped bit-vector S-box")
        width = component.output_type.unit_count
        limit = 1 << width
        if not 0 <= input_difference < limit or not 0 <= output_difference < limit:
            raise ValueError("difference is outside the S-box width")
        self.problem = problem
        self.component = component
        self.input_difference = input_difference
        self.output_difference = output_difference

    def cp_model(self) -> MiniZincModel:
        """Return a table whose absence of a fixed pair proves impossibility."""

        semantics = self.problem.provider_for(self.component)
        width = self.component.output_type.unit_count
        feasible = [
            (source, target)
            for source in range(1 << width)
            for target in range(1 << width)
            if semantics.transition((source,), target).is_possible
        ]
        values = ",".join(str(item) for row in feasible for item in row)
        declarations = (
            f"array[0..{len(feasible) - 1}, 1..2] of int: transitions = "
            f"array2d(0..{len(feasible) - 1}, 1..2, [{values}]);",
            f"var 0..{(1 << width) - 1}: input_difference;",
            f"var 0..{(1 << width) - 1}: output_difference;",
        )
        constraints = (
            "constraint table([input_difference,output_difference], transitions);",
            f"constraint input_difference = {self.input_difference};",
            f"constraint output_difference = {self.output_difference};",
        )
        return MiniZincModel(
            declarations,
            constraints,
            includes=('include "table.mzn";',),
            provenance=self.problem.provenance,
            constraint_models=(
                ConstraintModelApplication(
                    self.model_provenance, (cast(str, self.component.component_id),)
                ),
            ),
        )


class SBoxBoomerangCPModel:
    """Exact BCT table lowering for one bijective bit-vector S-box.

    EXAMPLES::

        >>> from claasp.components import BitVectorSBox
        >>> from claasp.primitives import Present
        >>> primitive = Present(number_of_rounds=1)
        >>> sbox = next(item for item in primitive.components if isinstance(item, BitVectorSBox))
        >>> model = SBoxBoomerangCPModel(sbox, input_difference=1, output_difference=2)
        >>> query = model.cp_model()
        >>> query.constraints[-2:]
        ('constraint input_difference = 1;', 'constraint output_difference = 2;')
        >>> query.solve
        'solve maximize quartet_count;'
    """

    model_provenance = _verified_model(
        ConstraintBackend.CP,
        "SBoxBoomerangCPModel",
        "boomerang",
        "exhaustive BCT table constraint",
        "10.1007/978-3-319-78375-8_22",
        "Boomerang Connectivity Table: A New Cryptanalysis Tool",
        "section 3.1, Definition 3.1",
    )

    def __init__(
        self, component: BitVectorSBox, input_difference=None, output_difference=None
    ) -> None:
        if not isinstance(component, BitVectorSBox):
            raise TypeError("component must be a BitVectorSBox")
        semantics = SBoxBoomerangSemantics(component.table)
        for name, value in (
            ("input_difference", input_difference),
            ("output_difference", output_difference),
        ):
            if value is not None and (
                not isinstance(value, int) or not 0 <= value < len(component.table)
            ):
                raise ValueError(f"{name} must fit the S-box width")
        self.component = component
        self.semantics = semantics
        self.input_difference = input_difference
        self.output_difference = output_difference

    def cp_model(self) -> MiniZincModel:
        """Lower every nonzero BCT entry with its exact quartet count."""

        rows = []
        for source in range(len(self.component.table)):
            for target in range(len(self.component.table)):
                entry = self.semantics.connectivity(source, target)
                if entry.is_possible:
                    rows.append((source, target, entry.count))
        flattened = ",".join(str(value) for row in rows for value in row)
        limit = len(self.component.table) - 1
        declarations = (
            f"array[0..{len(rows) - 1}, 1..3] of int: bct = "
            f"array2d(0..{len(rows) - 1}, 1..3, [{flattened}]);",
            f"var 0..{limit}: input_difference;",
            f"var 0..{limit}: output_difference;",
            f"var 1..{len(self.component.table)}: quartet_count;",
        )
        constraints = [
            "constraint table([input_difference, output_difference, quartet_count], bct);"
        ]
        if self.input_difference is not None:
            constraints.append(f"constraint input_difference = {self.input_difference};")
        if self.output_difference is not None:
            constraints.append(f"constraint output_difference = {self.output_difference};")
        return MiniZincModel(
            declarations,
            tuple(constraints),
            includes=('include "table.mzn";',),
            solve="solve maximize quartet_count;",
            provenance=(f"exact exhaustive BCT for {self.component.component_id}",),
            constraint_models=(
                ConstraintModelApplication(
                    self.model_provenance, (cast(str, self.component.component_id),)
                ),
            ),
        )

    def decode(self, assignment):
        """Decode and independently recompute the selected BCT entry."""

        entry = self.semantics.connectivity(
            int(assignment["input_difference"]), int(assignment["output_difference"])
        )
        if entry.count != int(assignment["quartet_count"]):
            raise ValueError("MiniZinc returned an invalid BCT count")
        return entry


SBoxDifferenceCPModel = SBoxXorDifferentialCPModel
