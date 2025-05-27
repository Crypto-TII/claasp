from claasp.ciphers.stream_ciphers.bluetooth_stream_cipher_e0 import BluetoothStreamCipherE0


def test_bluetooth_stream_cipher_e0_test_vector():
    e0 = BluetoothStreamCipherE0(keystream_bit_len=8)
    fsm = 0xb
    key = 0x25ac1ea08e1ec131e0a1780f7a2a42bb
    input = int(hex(key << 4 | fsm), 16)  # key.append(fsm)
    keystream = 0x46
    assert e0.evaluate([input]) == keystream
