"""MILP encoding of modular-addition component trail relations."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _verified_model,
)
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)
from claasp.semantics.cryptanalysis import ModularAddLinearSemantics


class ModularAddLinearMILPModel:
    """Exact XOR-linear mask relation for addition modulo ``2**width``.

    EXAMPLES::

        >>> model = ModularAddLinearMILPModel(4).milp_model(
        ...     left_mask=1, right_mask=0, output_mask=1
        ... )
        >>> tuple(variable.name for variable in model.variables[:4])
        ('left_0', 'left_1', 'left_2', 'left_3')
        >>> tuple(name for name, coefficient in model.objective.terms if coefficient == 1)
        ('weight_0', 'weight_1', 'weight_2', 'weight_3')
    """

    model_provenance = _verified_model(
        ConstraintBackend.MILP,
        "ModularAddLinearMILPModel",
        "xor_linear",
        "exact finite modular-add mask relation",
        "10.1007/978-3-319-39555-5_26",
        "Automatic Search of Linear Trails in ARX with Applications to SPECK and Chaskey",
        "section 3.1, Proposition 1 and equation (1)",
    )

    def __init__(self, width: int) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or width < 2:
            raise ValueError("width must be an integer of at least 2")
        self.width = width
        self._groups = ()

    def milp_model(
        self,
        *,
        left_mask: int | None = None,
        right_mask: int | None = None,
        output_mask: int | None = None,
    ) -> MILPModel:
        """Build the exact support relation with unary correlation weight."""

        for name, value in (
            ("left_mask", left_mask),
            ("right_mask", right_mask),
            ("output_mask", output_mask),
        ):
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value < 1 << self.width
            ):
                raise ValueError(f"{name} must fit the configured width")
        variables = []
        constraints = []

        def binary(name):
            variables.append(LinearVariable(name, VariableKind.BINARY))
            return name

        left = tuple(binary(f"left_{bit}") for bit in range(self.width))
        right = tuple(binary(f"right_{bit}") for bit in range(self.width))
        output = tuple(binary(f"output_{bit}") for bit in range(self.width))
        weight = tuple(binary(f"weight_{bit}") for bit in range(self.width))
        constraints.append(_equal({weight[0]: 1}, 0))
        parity = binary("parity_1")
        _parity(constraints, variables, (weight[1], output[0], left[0], right[0]), parity, 1)
        for bit in range(2, self.width):
            parity = binary(f"parity_{bit}")
            _parity(
                constraints,
                variables,
                (weight[bit], weight[bit - 1], output[bit - 1], left[bit - 1], right[bit - 1]),
                parity,
                2,
            )
        for bit in range(1, self.width):
            for operand in (left, right):
                constraints.append(_greater({weight[bit]: 1, output[bit]: -1, operand[bit]: 1}, 0))
                constraints.append(_greater({weight[bit]: 1, output[bit]: 1, operand[bit]: -1}, 0))
        for names, value in ((left, left_mask), (right, right_mask), (output, output_mask)):
            if value is not None:
                for bit, name in enumerate(names):
                    constraints.append(_equal({name: 1}, _bit(value, self.width, bit)))
        self._groups = left, right, output
        return MILPModel(
            tuple(variables),
            tuple(constraints),
            LinearExpression.from_terms({name: 1 for name in weight}),
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )

    def decode_transition(self, assignment):
        """Decode and independently validate a solver assignment."""

        if not self._groups:
            raise ValueError("build the MILP model before decoding a transition")
        values = tuple(
            _integer(round(assignment[name]) for name in group) for group in self._groups
        )
        transition = ModularAddLinearSemantics(self.width).xor_linear(*values)
        if not transition.is_possible:
            raise ValueError("assignment does not describe a possible modular-add transition")
        return transition


def _parity(constraints, variables, names, parity_name, upper):
    # parity_name is an integer quotient: sum(names) = 2 * parity_name.
    index = next(index for index, variable in enumerate(variables) if variable.name == parity_name)
    variables[index] = LinearVariable(parity_name, VariableKind.INTEGER, 0, upper)
    terms = {name: 1 for name in names}
    terms[parity_name] = -2
    constraints.append(_equal(terms, 0))


def _equal(terms, rhs):
    return LinearConstraint(LinearExpression.from_terms(terms), ConstraintSense.EQUAL, rhs)


def _greater(terms, rhs):
    return LinearConstraint(LinearExpression.from_terms(terms), ConstraintSense.GREATER_EQUAL, rhs)


def _bit(value, width, position):
    return (value >> (width - 1 - position)) & 1


def _integer(bits):
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value
