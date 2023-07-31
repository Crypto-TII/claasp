from claasp.ciphers.permutations.grain_core_permutation import GrainCorePermutation


def test_grain_core_permutation():
    grain_core = GrainCorePermutation()
    assert grain_core.family_name == 'grain_core'
    assert grain_core.type == 'permutation'
    assert grain_core.number_of_rounds == 160
    assert grain_core.id == 'grain_core_i80_o80_r160'
    assert grain_core.component_from(0, 0).id == 'xor_0_0'

    grain_core = GrainCorePermutation(number_of_rounds=4)
    assert grain_core.number_of_rounds == 4
    assert grain_core.id == 'grain_core_i80_o80_r4'
    assert grain_core.component_from(3, 0).id == 'xor_3_0'

    grain_core = GrainCorePermutation()
    state = 0xffffffffffffffff
    state_output = 0xf0f3fa8999f72655ecfb
    assert grain_core.evaluate([state]) == state_output
    assert grain_core.test_against_reference_code(2) is True
