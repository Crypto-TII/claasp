from claasp.ciphers.block_ciphers.chilow_block_cipher import ChilowBlockCipher


def test_chilow_block_cipher_40():
    """Test ChilowBlockCipher-40 with tests vectors from [BDG+25]_."""
    chilow = ChilowBlockCipher(number_of_rounds=8)
    assert chilow.family_name == 'chilow'

    X = 0x317C83E4A7
    T = 0x0011223344556677
    K = 0xFEDCBA98765432107766554433221100

    pt = chilow.evaluate([X, T, K])
    assert f'0x{pt:010X}' == '0x0090545706'


def test_chilow_block_cipher_32():
    """Test ChilowBlockCipher-32 with tests vectors from [BDG+25]_."""
    chilow = ChilowBlockCipher(number_of_rounds=8, tau=0)

    X = 0x01234567
    T = 0x0011223344556677
    K = 0xFEDCBA98765432107766554433221100

    pt = chilow.evaluate([X, T, K])
    assert f'0x{pt:X}' == '0x2E75D127'
