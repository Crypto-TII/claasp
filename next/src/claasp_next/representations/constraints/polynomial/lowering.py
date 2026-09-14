"""Lower typed prime-field graphs to sparse polynomial representations."""

from enum import Enum

from claasp_next.components.algebraic import Add, LinearMap, Multiply, Power
from claasp_next.components.structural import Concatenate, Constant, Identity, Permutation
from claasp_next.graph import Primitive, Selection
from claasp_next.domains import PrimeField
from claasp_next.representations.constraints.polynomial.expression import Polynomial
from claasp_next.representations.constraints.polynomial.system import PolynomialSystem


class PowerLoweringPolicy(str, Enum):
    """Available translations of a fixed power map."""

    DIRECT = "direct"
    BINARY_CHAIN = "binary_chain"


class PrimeFieldPolynomialModel:
    """Generate one native-field equation for each component output unit.

    EXAMPLES::

        >>> from claasp_next.primitives import MiMC
        >>> from claasp_next.representations.constraints.polynomial import PrimeFieldPolynomialModel
        >>> system = PrimeFieldPolynomialModel(MiMC(17, 3, (1,))).polynomial_system()
        >>> len(system.variables), len(system.equations), system.maximum_degree
        (4, 3, 3)
        >>> system.provenance
        ('constant_0_0', 'add_0_1', 'power_0_2')
    """

    _supported_components = (Constant, Identity, Permutation, Concatenate, Add, Multiply, Power, LinearMap)

    def __init__(
        self,
        primitive: Primitive,
        power_lowering: PowerLoweringPolicy | str = PowerLoweringPolicy.DIRECT,
    ) -> None:
        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")
        domains = {port.value_type.domain for port in primitive.inputs.values()}
        domains.update(component.output_type.domain for component in primitive.components)
        if len(domains) != 1 or not isinstance(next(iter(domains)), PrimeField):
            raise ValueError("PrimeFieldPolynomialModel requires one homogeneous prime field")
        self._primitive = primitive
        self._field = next(iter(domains))
        try:
            self._power_lowering = PowerLoweringPolicy(power_lowering)
        except ValueError as error:
            choices = ", ".join(policy.value for policy in PowerLoweringPolicy)
            raise ValueError(f"power_lowering must be one of: {choices}") from error
        self._auxiliary_variables: list[str] = []
        self._auxiliary_powers: dict[str, tuple[str, int]] = {}
        self._used_variables: set[str] = set()

    @staticmethod
    def variable_name(source_id: str, position: int) -> str:
        return f"{source_id}_{position}"

    def _variable(self, source_id: str, position: int) -> Polynomial:
        return Polynomial.variable(self._field, self.variable_name(source_id, position))

    def _selection(self, selection: Selection) -> tuple[Polynomial, ...]:
        return tuple(self._variable(selection.source.owner_id, position) for position in selection.positions)

    def polynomial_system(self) -> PolynomialSystem:
        variables = []
        for name, port in self._primitive.inputs.items():
            variables.extend(self.variable_name(name, position) for position in range(port.value_type.unit_count))
        for component in self._primitive.components:
            variables.extend(
                self.variable_name(component.component_id, position)
                for position in range(component.output_type.unit_count)
            )

        self._used_variables = set(variables)
        self._auxiliary_variables = []
        self._auxiliary_powers = {}
        equations = []
        provenance = []
        for component in self._primitive.components:
            lowered, lowered_provenance = self._lower_component(component)
            equations.extend(lowered)
            provenance.extend(lowered_provenance)
        variables.extend(self._auxiliary_variables)
        return PolynomialSystem(self._field, tuple(variables), tuple(equations), tuple(provenance))

    def witness(self, evaluation: object) -> dict[str, int]:
        """Build a complete polynomial assignment from an evaluation result."""

        if not hasattr(evaluation, "values"):
            raise TypeError("evaluation must provide a values mapping")
        self.polynomial_system()
        assignment = {
            self.variable_name(source_id, position): value
            for source_id, source_value in evaluation.values.items()
            for position, value in enumerate(source_value)
        }
        for auxiliary, (base, exponent) in self._auxiliary_powers.items():
            assignment[auxiliary] = pow(assignment[base], exponent, self._field.modulus)
        return assignment

    def _outputs(self, component: object) -> tuple[Polynomial, ...]:
        return tuple(
            self._variable(component.component_id, position)
            for position in range(component.output_type.unit_count)
        )

    def _lower_component(self, component: object) -> tuple[tuple[Polynomial, ...], tuple[str, ...]]:
        if not isinstance(component, self._supported_components):
            raise NotImplementedError(
                f"PrimeFieldPolynomialModel does not support {type(component).__name__}"
            )
        outputs = self._outputs(component)

        if isinstance(component, Constant):
            equations = tuple(output - value for output, value in zip(outputs, component.values))
            return equations, (component.component_id,) * len(equations)

        selected_inputs = tuple(self._selection(item) for item in component.inputs)
        if isinstance(component, Identity):
            expressions = selected_inputs[0]
        elif isinstance(component, Permutation):
            expressions = tuple(selected_inputs[0][position] for position in component.mapping)
        elif isinstance(component, Concatenate):
            expressions = tuple(value for group in selected_inputs for value in group)
        elif isinstance(component, Add):
            expressions = tuple(sum(values) for values in zip(*selected_inputs))
        elif isinstance(component, Multiply):
            expressions = tuple(self._product(values) for values in zip(*selected_inputs))
        elif isinstance(component, Power):
            if self._power_lowering is PowerLoweringPolicy.BINARY_CHAIN:
                return self._lower_power_chain(component, outputs)
            expressions = tuple(value**component.exponent for value in selected_inputs[0])
        elif isinstance(component, LinearMap):
            expressions = tuple(
                sum(coefficient * value for coefficient, value in zip(row, selected_inputs[0]))
                for row in component.matrix
            )
        else:  # pragma: no cover - guarded by the supported tuple
            raise AssertionError("unreachable component lowering")
        equations = tuple(output - expression for output, expression in zip(outputs, expressions))
        return equations, (component.component_id,) * len(equations)

    def _lower_power_chain(
        self, component: Power, outputs: tuple[Polynomial, ...]
    ) -> tuple[tuple[Polynomial, ...], tuple[str, ...]]:
        equations: list[Polynomial] = []
        provenance: list[str] = []
        selection = component.inputs[0]
        for position, (source_position, output) in enumerate(zip(selection.positions, outputs)):
            base_name = self.variable_name(selection.source.owner_id, source_position)
            base = Polynomial.variable(self._field, base_name)
            powers: dict[int, Polynomial] = {1: base}

            def lower(exponent: int, *, final: bool = False) -> Polynomial:
                if exponent in powers:
                    return powers[exponent]
                left_exponent = exponent // 2 if exponent % 2 == 0 else exponent - 1
                right_exponent = exponent - left_exponent
                left = lower(left_exponent)
                right = lower(right_exponent)
                result = output if final else self._new_auxiliary(
                    component.component_id, position, exponent, base_name
                )
                equations.append(result - left * right)
                provenance.append(f"{component.component_id}:unit={position}:power={exponent}")
                powers[exponent] = result
                return result

            if component.exponent == 1:
                equations.append(output - base)
                provenance.append(f"{component.component_id}:unit={position}:power=1")
            else:
                lower(component.exponent, final=True)
        return tuple(equations), tuple(provenance)

    def _new_auxiliary(
        self, component_id: str, position: int, exponent: int, base_name: str
    ) -> Polynomial:
        stem = f"__aux_power_{component_id}_{position}_{exponent}"
        name = stem
        suffix = 1
        while name in self._used_variables:
            name = f"{stem}_{suffix}"
            suffix += 1
        self._used_variables.add(name)
        self._auxiliary_variables.append(name)
        self._auxiliary_powers[name] = (base_name, exponent)
        return Polynomial.variable(self._field, name)

    @staticmethod
    def _product(values: tuple[Polynomial, ...]) -> Polynomial:
        result = values[0]
        for value in values[1:]:
            result *= value
        return result
