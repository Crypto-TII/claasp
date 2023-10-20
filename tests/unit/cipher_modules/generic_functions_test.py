from bitstring import BitArray
from claasp.cipher_modules.generic_functions import ROTATE, SIGMA, THETA_KECCAK, THETA_XOODOO, SHIFT


def test_ROTATE():
    b = BitArray("0x8")

    assert b.bin == '1000'
    assert ROTATE(b, 1).bin == '0100'
    assert ROTATE(b, -2).bin == '0010'


def test_SIGMA():
    b = BitArray("0x8")

    assert SIGMA(b, [1, 3]).bin == '1101'


def test_THETA_KECCAK():
    b = BitArray(f"0xf1258f7940e1dde784d5ccf933c0478ad598261ea65aa9eebd1547306f80494d8b284e056253d057ff97a42d7f8e6f"
                 f"d490fee5a0a44647c48c5bda0cd6192e76ad30a6f71b19059c30935ab7d08ffc64eb5aa93f2317d635a9a6e6260d7121"
                 f"0381a57c16dbcf555f43b831cd0347c82601f22f1a11a5569f05e5635a21d9ae6164befef28cc970f2613670957bc466"
                 f"11b87c5a554fd00ecb8c3ee88a1ccf32c8940c7922ae3a26141841f924a2c509e416f53526e70465c275f644e97f30a1"
                 f"3beaf1ff7b5ceca249")

    assert THETA_KECCAK(b).hex == f'09b84e4804496b9b7c480dc87768f1f62d05e72fe2f21f92458886012b28ff3173b58f3426fb662b' \
                                  f'6be4933769b0bcec048dd2bab27894fc1828ed16c027fd4e394391ed0d27d6a4a4e06dadc6b12f5c' \
                                  f'fd95713beec720a9bf693e22c0a1d79f976aa412161fa3c35577e9c9ce973eba173df71edc75a003' \
                                  f'8f8853e756dc0031eed3ce4ffbccdea2eb5b40280cc1c84132116ae838d5a09b0653d8376bca9c98' \
                                  f'8c89ff979aa0f7a600c47f91965fd8560e70b393d39eb4706d73c25c4baa7089f27479ce687673fb'


def test_THETA_XOODOO():
    b = BitArray("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

    assert THETA_XOODOO(b).bin[:10] == '0101100100'


def test_SHIFT():
    b = BitArray("0xF")

    assert b.bin == '1111'
    assert SHIFT(b, 1).bin == '0111'
    assert SHIFT(b, -2).bin == '1100'
