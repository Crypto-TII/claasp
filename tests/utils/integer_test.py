from claasp.utils.integer import to_binary
from claasp.utils.integer import generate_bitmask


def test_generate_bitmask():
    assert bin(generate_bitmask(4)) == '0b1111'
    assert hex(generate_bitmask(32)) == '0xffffffff'


def test_to_binary():
    assert to_binary(0x67452301, 32) == \
           [1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0]
