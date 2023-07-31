from sage.numerical.mip import MixedIntegerLinearProgram
from sage.numerical.linear_functions import LinearFunction

from claasp.utils.sequence_operations import shift_left
from claasp.utils.sequence_operations import shift_right
from claasp.utils.sequence_operations import rotate_left
from claasp.utils.sequence_operations import rotate_right


def test_rotate_left():
    t = [1, 2, 3, 4, 5]
    assert rotate_left(t, 2) == [3, 4, 5, 1, 2]

    t = (1, 1, 0, 1, 0, 1, 0)
    assert rotate_left(t, 4) == (0, 1, 0, 1, 1, 0, 1)


def test_rotate_right():
    t = [1, 2, 3, 4, 5]
    assert rotate_right(t, 2) == [4, 5, 1, 2, 3]

    t = (1, 1, 0, 1, 0, 1, 0)
    assert rotate_right(t, 4) == (1, 0, 1, 0, 1, 1, 0)


def test_shift_left():
    m = MixedIntegerLinearProgram(solver="GLPK")
    x = m.new_variable(name="x", indices=range(10))
    left = [x[i] for i in range(10)]
    shifted_l = shift_left(left, 3)
    assert all(isinstance(elem, LinearFunction) for elem in shifted_l) is True

    left = [0, 1, 2]
    assert shift_left(left, 0) == [0, 1, 2]
    assert shift_left(left, len(left)) == [0, 0, 0]


def test_shift_right():
    m = MixedIntegerLinearProgram(solver="GLPK")
    x = m.new_variable(name="x", indices=range(10))
    left = [x[i] for i in range(10)]
    shifted_l = shift_right(left, 3)
    assert all(isinstance(elem, LinearFunction) for elem in shifted_l) is True

    left = [0, 1, 2]
    assert shift_right(left, 0) == [0, 1, 2]
    assert shift_right(left, len(left)) == [0, 0, 0]
