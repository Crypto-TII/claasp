
# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
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


"""

This module implements functions that operate on sequence types, such as list or tuple.
More detail on sequence types can be found on the following link:

https://docs.python.org/3/library/stdtypes.html#sequence-types-list-tuple-range

"""

from sage.numerical.linear_functions import LinearFunction


def rotate_right(x, n):
    """
    Return a new list/tuple by performing right rotation on `x` for `n` steps.

    INPUT:

    - ``x`` -- **list**
    - ``n`` -- **integer**; a non-negative integer

    EXAMPLES::

        sage: from claasp.utils.sequence_operations import rotate_right
        sage: l = [1, 2, 3, 4, 5]
        sage: rotate_right(l, 2)
        [4, 5, 1, 2, 3]

        sage: t = (1, 1, 0, 1, 0, 1, 0)
        sage: rotate_right(t, 4)
        (1, 0, 1, 0, 1, 1, 0)
    """
    if not isinstance(x, (list, tuple)):
        raise TypeError("x must either be a list or tuple")

    if n < 0:
        raise ValueError("n must be a non-negative integer")

    return x[-n:] + x[:-n]


def rotate_left(x, n):
    """
    Return a new list/tuple by performing left rotation on `x` for `n` steps.

    INPUT:

    - ``x`` -- **list**
    - ``n`` -- **integer**; a non-negative integer

    EXAMPLES::

        sage: from claasp.utils.sequence_operations import rotate_left
        sage: l = [1, 2, 3, 4, 5]
        sage: rotate_left(l, 2)
        [3, 4, 5, 1, 2]

        sage: t = (1, 1, 0, 1, 0, 1, 0)
        sage: rotate_left(t, 4)
        (0, 1, 0, 1, 1, 0, 1)
    """
    return rotate_right(x, len(x) - n)


def shift_right(x, n):
    """
    Return a new list/tuple by right shifting `x` for `n` steps.

    INPUT:

    - ``x`` -- **list**
    - ``n`` -- **integer**; an integer (0 <= n <= len(x))

    EXAMPLES::

        sage: from claasp.utils.sequence_operations import shift_right
        sage: l = [1, 2, 3, 4, 5]
        sage: shift_right(l, 2)
        [0, 0, 1, 2, 3]

        sage: t = (1, 1, 0, 1, 0, 1, 0)
        sage: shift_right(t, 4)
        (0, 0, 0, 0, 1, 1, 0)
    """

    if not isinstance(x, (list, tuple)):
        raise TypeError("x must either be a list or tuple")

    if n < 0 or n > len(x):
        raise ValueError("n must be an integer in the range 0 <= n <= %d" % len(x))

    if n == 0:
        return x

    if isinstance(x[0], LinearFunction):
        parent = x[0].parent()
        return type(x)([LinearFunction(parent, 0)] * n) + x[:-n]
    else:
        return type(x)([0] * n) + x[:-n]


def shift_left(x, n):
    """
    Return a new list by left shifting `x` for `n` steps.

    INPUT:

    - ``x`` -- **list**
    - ``n`` -- **integer**; an integer (0 <= n <= len(x))

    EXAMPLES::

        sage: from claasp.utils.sequence_operations import shift_left
        sage: l = [1, 2, 3, 4, 5]
        sage: shift_left(l, 2)
        [3, 4, 5, 0, 0]

        sage: t = (1, 1, 0, 1, 0, 1, 0)
        sage: shift_left(t, 4)
        (0, 1, 0, 0, 0, 0, 0)
    """

    if not isinstance(x, (list, tuple)):
        raise TypeError("x must either be a list or tuple")

    if n < 0 or n > len(x):
        raise ValueError("n must be an integer in the range 0 <= n <= %d" % len(x))

    if isinstance(x[0], LinearFunction):
        parent = x[0].parent()
        return type(x)([LinearFunction(parent, 0)] * n) + x[:-n]
    else:
        return x[n:] + type(x)([0] * n)
