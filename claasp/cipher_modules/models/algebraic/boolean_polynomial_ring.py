
# ****************************************************************************
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing


def is_boolean_polynomial_ring(R):
    """
    Return whether the ring `R` is an instance of BooleanPolynomialRing.

    INPUT:

    - ``R`` -- **Polynomial Ring object**; a ring

    EXAMPLES::

        sage: from claasp.cipher_modules.models.algebraic.boolean_polynomial_ring import is_boolean_polynomial_ring
        sage: B.<a, b, c> = BooleanPolynomialRing()
        sage: is_boolean_polynomial_ring(B)
        True

        sage: R.<x, y, z> = PolynomialRing(GF(2))
        sage: is_boolean_polynomial_ring(R)
        False
    """
    return isinstance(R, BooleanPolynomialRing)
