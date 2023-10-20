import pytest

from claasp.ciphers.permutations.photon_permutation import PhotonPermutation


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_photon_permutation():
    photon = PhotonPermutation()
    assert photon.family_name == 'photon'
    assert photon.type == 'permutation'
    assert photon.number_of_rounds == 12
    assert photon.id == 'photon_p256_o256_r12'
    assert photon.component_from(0, 0).id == 'constant_0_0'

    photon = PhotonPermutation(t=256)
    assert photon.number_of_rounds == 12
    assert photon.component_from(11, 0).id == 'xor_11_0'

    photon = PhotonPermutation(t=256)
    plaintext = 0x0000000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0x01165907DBDA659C2AF1704BBA93E74BA05C1AB38B8D458260DFF04C062D72E5
    assert photon.evaluate([plaintext]) == ciphertext

    plaintext1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    ciphertext1 = 0x429AC9438631CB7F5FDFB81A3F86AD1ED88A9541F2EAEF882959367C8E197294
    plaintext2 = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    ciphertext2 = 0x94A0BFDC7DB954B3F3A84670EF8881D912706DCA31690ED1B78D3DCCA58B3740
    input_list = [[plaintext1], [plaintext2]]
    output_list = [ciphertext1, ciphertext2]
    assert photon.test_vector_check(input_list, output_list) is True
