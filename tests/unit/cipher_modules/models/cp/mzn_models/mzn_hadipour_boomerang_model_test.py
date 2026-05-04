from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher
from claasp.ciphers.block_ciphers.twine_block_cipher import TwineBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher



def test_build_boomerang_model_chacha():
    # cipher = ChachaPermutation(number_of_rounds=5)
    # cipher = SpeckBlockCipher(number_of_rounds=10)
    cipher = LeaBlockCipher(number_of_rounds=14)
    # cipher = SpeckBlockCipher(block_bit_size=48, key_bit_size=72, number_of_rounds=12)
    # cipher = SimonBlockCipher(block_bit_size=48, key_bit_size=72, number_of_rounds=15)

    top_part_number_of_rounds = 7
    middle_part_number_of_rounds = 1
    bottom_part_number_of_rounds = 6

    component_dict = {
        "top_part_number_of_rounds": top_part_number_of_rounds,
        "middle_part_number_of_rounds": middle_part_number_of_rounds,
        "bottom_part_number_of_rounds": bottom_part_number_of_rounds
    }

    mzn_bct_model = MznHadipourBoomerangModel(cipher, component_dict)
    mzn_bct_model.build_hadipour_boomerang_model()

# if __name__ == "__main__":
#     test_build_boomerang_model_chacha()
