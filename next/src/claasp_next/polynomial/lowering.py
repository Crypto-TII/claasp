"""Lower typed prime-field graphs to sparse polynomial systems."""

from claasp_next.components.algebraic import Add, LinearMap, Multiply, Power
from claasp_next.components.structural import Concatenate, Constant, Identity, Permutation
from claasp_next.core import Cipher, Selection
from claasp_next.domains import PrimeField
from claasp_next.polynomial.expression import Polynomial
from claasp_next.polynomial.system import PolynomialSystem


class PrimeFieldPolynomialModel:
    """Generate one native-field equation for each component output unit.

    EXAMPLES::

        >>> from claasp_next.ciphers import MiMCPermutation
        >>> from claasp_next.polynomial import PrimeFieldPolynomialModel
        >>> system = PrimeFieldPolynomialModel(MiMCPermutation(17, 3, (1,))).polynomial_system()
        >>> len(system.variables), len(system.equations), system.maximum_degree
        (4, 3, 3)
        >>> system.provenance
        ('constant_0_0', 'add_0_1', 'power_0_2')
    """

    _supported_components = (Constant, Identity, Permutation, Concatenate, Add, Multiply, Power, LinearMap)

    def __init__(self, cipher: Cipher) -> None:
        if not isinstance(cipher, Cipher):
            raise TypeError("cipher must be a Cipher")
        domains = {port.value_type.domain for port in cipher.inputs.values()}
        domains.update(component.output_type.domain for component in cipher.components)
        if len(domains) != 1 or not isinstance(next(iter(domains)), PrimeField):
            raise ValueError("PrimeFieldPolynomialModel requires one homogeneous prime field")
        self._cipher = cipher
        self._field = next(iter(domains))

    @staticmethod
    def variable_name(source_id: str, position: int) -> str:
        return f"{source_id}_{position}"

    def _variable(self, source_id: str, position: int) -> Polynomial:
        return Polynomial.variable(self._field, self.variable_name(source_id, position))

    def _selection(self, selection: Selection) -> tuple[Polynomial, ...]:
        return tuple(self._variable(selection.source.owner_id, position) for position in selection.positions)

    def polynomial_system(self) -> PolynomialSystem:
        variables = []
        for name, port in self._cipher.inputs.items():
            variables.extend(self.variable_name(name, position) for position in range(port.value_type.unit_count))
        for component in self._cipher.components:
            variables.extend(
                self.variable_name(component.component_id, position)
                for position in range(component.output_type.unit_count)
            )

        equations = []
        provenance = []
        for component in self._cipher.components:
            lowered = self._lower_component(component)
            equations.extend(lowered)
            provenance.extend(component.component_id for _ in lowered)
        return PolynomialSystem(self._field, tuple(variables), tuple(equations), tuple(provenance))

    def _outputs(self, component: object) -> tuple[Polynomial, ...]:
        return tuple(
            self._variable(component.component_id, position)
            for position in range(component.output_type.unit_count)
        )

    def _lower_component(self, component: object) -> tuple[Polynomial, ...]:
        if not isinstance(component, self._supported_components):
            raise NotImplementedError(
                f"PrimeFieldPolynomialModel does not support {type(component).__name__}"
            )
        outputs = self._outputs(component)

        if isinstance(component, Constant):
            return tuple(output - value for output, value in zip(outputs, component.values))

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
            expressions = tuple(value**component.exponent for value in selected_inputs[0])
        elif isinstance(component, LinearMap):
            expressions = tuple(
                sum(coefficient * value for coefficient, value in zip(row, selected_inputs[0]))
                for row in component.matrix
            )
        else:  # pragma: no cover - guarded by the supported tuple
            raise AssertionError("unreachable component lowering")
        return tuple(output - expression for output, expression in zip(outputs, expressions))

    @staticmethod
    def _product(values: tuple[Polynomial, ...]) -> Polynomial:
        result = values[0]
        for value in values[1:]:
            result *= value
        return result
