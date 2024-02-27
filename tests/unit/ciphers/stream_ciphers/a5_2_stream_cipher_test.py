from claasp.ciphers.stream_ciphers.a5_2_stream_cipher import A52StreamCipher

def test_a52():
    a52 = A52StreamCipher()
    assert a52.family_name == 'a52'
    assert a52.type == 'stream_cipher'
    assert a52.number_of_rounds == 229
    assert a52.id == 'a52_k64_i22_o228_r229'
    assert a52.component_from(0, 0).id == 'constant_0_0'
    assert a52.component_from(1, 0).id == 'fsr_1_0'

    key = 0x003fffffffffffff
    frame = 0b1000010000000000000000
    keystream = 0xf4512cac13593764460b722dadd51200350ca385a853735ee5c889944
    assert a52.evaluate([key, frame]) == keystream

