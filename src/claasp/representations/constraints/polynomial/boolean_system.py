"""Local Boolean equations retaining intermediate graph and carry variables."""

from dataclasses import dataclass

from claasp.components import ModularAdd, ModularSubtract
from claasp.representations.constraints.polynomial.boolean import (
    BooleanPolynomial,
    modular_addition_polynomials,
    modular_subtraction_polynomials,
)
from claasp.unit_types import Bit, Word


def _flatten(units):
    return tuple(
        bit for unit in units for bit in ((unit,) if isinstance(unit, BooleanPolynomial) else unit)
    )


@dataclass(frozen=True, slots=True)
class BooleanEquationSystem:
    """Equations equal to zero over Boolean variables, with round ownership.

    Intermediate outputs and ripple carries stay symbolic, so constructing
    an ARX system does not expand the whole cipher's output ANFs.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> system = BooleanEquationSystem.from_primitive(Speck(number_of_rounds=1))
        >>> max(equation.degree for equation in system.equations)
        2
    """

    equations: tuple[BooleanPolynomial, ...]
    rounds: tuple[int, ...]
    variables: tuple[str, ...]
    inputs: tuple[tuple[str, tuple[str, ...]], ...]
    outputs: tuple[BooleanPolynomial, ...]

    @classmethod
    def from_primitive(cls, primitive) -> "BooleanEquationSystem":
        """Lower supported Bit/Word graphs to local, exact equations."""
        from claasp.representations.execution.symbolic_boolean import BooleanSymbolicEvaluator

        values = {}
        variables: list[str] = []
        equations: list[BooleanPolynomial] = []
        rounds: list[int] = []
        inputs: list[tuple[str, tuple[str, ...]]] = []

        def fresh(array_type):
            unit_type = array_type.unit_type
            if not isinstance(unit_type, (Bit, Word)):
                raise NotImplementedError("Boolean systems support Bit and Word units")
            units = []
            for _ in range(array_type.unit_count):
                bits = []
                for _ in range(unit_type.encoded_bit_size):
                    name = f"v{len(variables)}"
                    variables.append(name)
                    bits.append(BooleanPolynomial.variable(name))
                units.append(bits[0] if isinstance(unit_type, Bit) else tuple(bits))
            return tuple(units)

        for name, array in primitive.graph.input_arrays.items():
            first = len(variables)
            values[name] = fresh(array.array_type)
            inputs.append((name, tuple(variables[first:])))
        owner = {
            component.component_id: number + 1
            for number, round_ in enumerate(primitive.graph.rounds)
            for component in round_.components
        }
        evaluator = BooleanSymbolicEvaluator()
        cache: dict = {}
        for component in primitive.graph.components:
            operands = tuple(
                primitive.graph.resolve_selection(selection, values, cache)
                for selection in component.inputs
            )
            output = fresh(component.output_type)
            local: list[BooleanPolynomial] = []
            if isinstance(component, (ModularAdd, ModularSubtract)):
                operation = (
                    modular_addition_polynomials
                    if isinstance(component, ModularAdd)
                    else modular_subtraction_polynomials
                )
                left = operands[0]
                for index, right in enumerate(operands[1:]):
                    target = output if index == len(operands) - 2 else fresh(component.output_type)
                    carries = fresh(component.output_type)
                    for a, b, z, c in zip(left, right, target, carries):
                        local.extend(
                            operation(
                                tuple(reversed(a)),
                                tuple(reversed(b)),
                                tuple(reversed(z)),
                                tuple(reversed(c)),
                            )
                        )
                    left = target
            else:
                expected = evaluator._component(component, operands)
                local.extend(a + b for a, b in zip(_flatten(output), _flatten(expected)))
            values[component.component_id] = output
            equations.extend(local)
            rounds.extend([owner[component.component_id]] * len(local))
        outputs = (
            ()
            if primitive.graph.output is None
            else _flatten(primitive.graph.resolve_selection(primitive.graph.output, values, cache))
        )
        return cls(tuple(equations), tuple(rounds), tuple(variables), tuple(inputs), outputs)

    def singular_program(self, *, fixed_variables=None) -> str:
        """Serialize a GF(2) ideal including Boolean field equations.

        Only registered variable names and Boolean assignments are accepted.
        """
        fixed = dict(fixed_variables or {})
        if set(fixed) - set(self.variables) or any(
            type(value) is not int or value not in (0, 1) for value in fixed.values()
        ):
            raise ValueError("fixed_variables must assign registered variables to zero or one")
        if not self.variables:
            raise ValueError("a polynomial ring requires variables")
        polynomials = [
            "+".join("*".join(term.variables) or "1" for term in equation.monomials) or "0"
            for equation in self.equations
        ]
        polynomials.extend(f"{name}^2+{name}" for name in self.variables)
        polynomials.extend(f"{name}+{value}" for name, value in sorted(fixed.items()))
        return (
            "ring R=2,(" + ",".join(self.variables) + "),dp;\n"
            "ideal I=" + ",".join(polynomials) + ";\n"
            "ideal G=std(I);\n"
            'print("CLAASP_BASIS_BEGIN");\n'
            'for(int i=1;i<=size(G);i++){print("CLAASP_POLY:"+string(G[i]));}\n'
            'print("CLAASP_BASIS_END");\nquit;\n'
        )
