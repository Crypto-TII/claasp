"""A genuine four-word ChaCha quarter round, separate from generic layout code."""
from claasp.cipher import Cipher


def quarter_round():
    """Return a four-word permutation with 12 native operations, no constants/key inputs.

    Input/output words are ordered a,b,c,d, each 32 bits. Rotations are 16, 12, 8, 7.
    This is an evaluation/example graph; the renderer has no quarter-round adapter.
    """
    cipher = Cipher('quarter_round_example', 'permutation', ['data'], [128], 128)
    cipher.add_round()
    words = [('data', list(range(i*32, (i+1)*32))) for i in range(4)]
    for rotation_a, rotation_b in ((16,12),(8,7)):
        for target, operand, rotated, rotation in ((0,1,3,rotation_a),(2,3,1,rotation_b)):
            first, second = words[target], words[operand]
            addition = cipher.add_modadd_component([first[0], second[0]], [first[1], second[1]], 32)
            words[target] = (addition.id, list(range(32)))
            source = words[rotated]
            xor = cipher.add_xor_component([source[0], addition.id], [source[1], list(range(32))], 32)
            result = cipher.add_rotate_component([xor.id], [list(range(32))], 32, -rotation)
            words[rotated] = (result.id, list(range(32)))
    cipher.add_cipher_output_component([word[0] for word in words], [word[1] for word in words], 128)
    return cipher
