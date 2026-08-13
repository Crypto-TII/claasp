from claasp.ciphers.permutations.forro_permutation import ForroPermutation
from claasp.ciphers.permutations.util import print_state_ids

def test_print_state_ids():
    forro = ForroPermutation(number_of_rounds=2)
    print_state_ids(forro.state_of_components)

def test_forro_permutation_structure():
    """Test standard structure for Forró permutation."""
    forro = ForroPermutation()
    assert forro.family_name == 'forro_permutation'
    assert forro.type == 'permutation'
    assert forro.number_of_rounds == 14
    assert forro.id == 'forro_permutation_p512_o512_r14'

    forro = ForroPermutation(number_of_rounds=10)
    assert forro.number_of_rounds == 10
    assert forro.id == 'forro_permutation_p512_o512_r10'

def test_forro_permutation():
    """Test from [CryptDances22]_."""
    forro = ForroPermutation(number_of_rounds=12)
    state = ["686e696d", "69762061", "65206164", "646e6120",
             "656c6120", "61697267", "746c6f76", "61616461",
             "70207261", "6520726f", "20657473", "73696170",
             "74736f6d", "61206f72", "72626173", "61636e61"]
    plaintext = int("0x" + "".join(state), 16)
    output = int('0x925e96eeeaaf318f81c23bae191324c7e046856404ce6e3176ebeb23ae71c8de1890aba4184af14ec274c706'
                 '7f7cb820a5e94db32d440c7a612ed734fb70d121', 16)
    assert forro.evaluate([plaintext]) == output
    assert forro.evaluate_vectorized([plaintext], evaluate_api=True) == output