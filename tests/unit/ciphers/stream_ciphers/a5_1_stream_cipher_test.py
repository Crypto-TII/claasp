from claasp.ciphers.stream_ciphers.a5_1_stream_cipher import A51StreamCipher

def test_a51():
    a51 = A51StreamCipher()
    assert a51.family_name == 'a51'
    assert a51.type == 'stream_cipher'
    assert a51.number_of_rounds == 229
    assert a51.id == 'a51_k64_i22_o228_r229'
    assert a51.component_from(0, 0).id == 'constant_0_0'
    assert a51.component_from(1, 0).id == 'fsr_1_0'

    key = 0x48c4a2e691d5b3f7
    frame = 0b0010110010000000000000
    keystream = 0x534eaa582fe8151ab6e1855a728c093f4d68d757ed949b4cbe41b7c6b
    assert a51.evaluate([key, frame]) == keystream

