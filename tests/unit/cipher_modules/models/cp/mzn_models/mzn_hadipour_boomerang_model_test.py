from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation


def test_build_boomerang_model_chacha():
    chacha = ChachaPermutation(number_of_rounds=6)

    top_part_number_of_rounds = 2
    middle_part_number_of_rounds = 2
    bottom_part_number_of_rounds = 2

    component_dict = {
        "top_part_number_of_rounds": top_part_number_of_rounds,
        "middle_part_number_of_rounds": middle_part_number_of_rounds,
        "bottom_part_number_of_rounds": bottom_part_number_of_rounds
    }

    mzn_bct_model = MznHadipourBoomerangModel(chacha, component_dict)

