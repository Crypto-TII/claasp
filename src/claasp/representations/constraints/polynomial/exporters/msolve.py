"""msolve serialization for small prime-field polynomial systems."""

from claasp.representations.constraints.polynomial.expression import Monomial, Polynomial
from claasp.representations.constraints.polynomial.system import PolynomialSystem


class MsolveExporter:
    """Render a polynomial system in msolve's native input format.

    msolve supports prime characteristics strictly below ``2^31``. Graph
    variables are renamed deterministically to ``x0``, ``x1``, and so on in
    :attr:`PolynomialSystem.variables` order.

    EXAMPLES::

        >>> from claasp.primitives import MiMC
        >>> from claasp.representations.constraints.polynomial import PrimeFieldPolynomialModel
        >>> system = PrimeFieldPolynomialModel(MiMC(17, 3, (1,))).polynomial_system()
        >>> text = MsolveExporter().export(system)
        >>> text.splitlines()[:2]
        ['x0,x1,x2,x3', '17']
        >>> text.endswith(chr(10))
        True
    """

    MAX_CHARACTERISTIC = 1 << 31

    def export(self, system: PolynomialSystem) -> str:
        """Compute the export for this public typed contract."""

        if not isinstance(system, PolynomialSystem):
            raise TypeError("system must be a PolynomialSystem")
        if system.field.modulus >= self.MAX_CHARACTERISTIC:
            raise ValueError("msolve requires a prime characteristic smaller than 2^31")
        if not system.variables:
            raise ValueError("msolve input requires at least one variable")
        if not system.equations:
            raise ValueError("msolve input requires at least one equation")

        external_names = tuple(f"x{index}" for index in range(len(system.variables)))
        names = dict(zip(system.variables, external_names))
        equations = [self._polynomial(polynomial, names) for polynomial in system.equations]
        rendered_equations = ",\n".join(equations)
        # The final newline is accepted by current msolve and avoids an EOF
        # parser crash in the msolve 0.6.5 package shipped by Ubuntu 24.04.
        return (
            "\n".join((",".join(external_names), str(system.field.modulus), rendered_equations))
            + "\n"
        )

    def _polynomial(self, polynomial: Polynomial, names: dict[str, str]) -> str:
        if not polynomial.terms:
            return "0"
        return "+".join(
            self._term(monomial, coefficient, names) for monomial, coefficient in polynomial.terms
        )

    def _term(self, monomial: Monomial, coefficient: int, names: dict[str, str]) -> str:
        factors = []
        if coefficient != 1 or not monomial.powers:
            factors.append(str(coefficient))
        for variable, exponent in monomial.powers:
            try:
                external_name = names[variable]
            except KeyError as error:
                raise ValueError(f"polynomial uses undeclared variable {variable!r}") from error
            factors.append(external_name if exponent == 1 else f"{external_name}^{exponent}")
        return "*".join(factors)
