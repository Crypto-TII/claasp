from claasp.ciphers.stream_ciphers.bluetooth_stream_cipher_e0 import BluetoothStreamCipherE0


def test_bluetooth_stream_cipher_e0_test_vector():
    e0 = BluetoothStreamCipherE0(keystream_bit_len=125)
    fsm = 0xb
    key = 0x25ac1ea08e1ec131e0a1780f7a2a42bb
    input = int(hex(key << 4 | fsm), 16)  # key.append(fsm)
    keystream = 0x8cd29cc32668b90ee2312924376f1b4
    assert e0.evaluate([input]) == keystream

    fsm = 0xd
    key = 0xe22f92fff8c245c49d10359a02f1e555
    input = int(hex(key << 4 | fsm), 16)  # key.append(fsm)
    keystream = 0x1198636720bac54986d1ab5a494866c9
    assert e0.evaluate([input]) == keystream
