from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.name_mappings import CIPHER
key_bit_size = 64
block_bit_size = 32
key_schedule_bit_size = 16


def adding_constraint(component_id_, bit_size, bit_values):
    constraint_ = (
        set_fixed_variables(
            component_id=component_id_,
            constraint_type="equal",
            bit_positions=list(range(bit_size)),
            bit_values=bit_values)
    )
    return constraint_


def create_constraints(list_key, list_data, key_differential):
    key_pair1_pair2 = set_fixed_variables(
        component_id='key_pair1_pair2',
        constraint_type='equal',
        bit_positions=list(range(key_bit_size)),
        bit_values=integer_to_bit_list(key_differential, key_bit_size, 'big'))

    round_number = 0
    component_ids = []
    number_of_states = len(list_key)
    fixed_variables = [key_pair1_pair2]
    for num in list_key:
        binary_list = integer_to_bit_list(num, key_schedule_bit_size, 'big')
        component_id = ""
        if round_number == 0:
            component_id = 'intermediate_output_0_5_pair1_pair2'
        if 0 < round_number < number_of_states:
            component_id = f'intermediate_output_{round_number}_11_pair1_pair2'
        component_ids.append(component_id)
        fixed_variables.append(adding_constraint(component_id, key_schedule_bit_size, binary_list))
        round_number += 1

    round_number = 0
    number_of_states = len(list_data)
    for num in list_data:
        binary_list = integer_to_bit_list(num, block_bit_size, 'big')
        component_id = ""
        if round_number == 0:
            component_id = 'plaintext_pair1_pair2'
        if round_number == 1:
            component_id = 'intermediate_output_0_6_pair1_pair2'
        if 1 < round_number < number_of_states - 1:
            component_id = f'intermediate_output_{round_number - 1}_12_pair1_pair2'
        if round_number == number_of_states - 1:
            component_id = f'cipher_output_{number_of_states - 2}_12_pair1_pair2'
        component_ids.append(component_id)
        fixed_variables.append(adding_constraint(component_id, block_bit_size, binary_list))
        round_number += 1
    return fixed_variables, component_ids


def test_satisfiable_differential_trail_related_key():
    speck = SpeckBlockCipher(number_of_rounds=14, block_bit_size=block_bit_size, key_bit_size=key_bit_size)
    speck.create_compounded_cipher()
    sat = SatCipherModel(speck)
    list_key = [
        0x1000,
        0x0,
        0x31,
        0x80,
        0x200,
        0x2800,
        0x0,
        0x0,
        0x40,
        0x0,
        0x0,
        0x8000,
        0x8000,
        0x8002,
    ]

    list_data = [
        0x14080008,
        0x200000,
        0x40004000,
        0xc0b1c0b0,
        0x667764b4,
        0x907002a1,
        0x8810205,
        0x140800,
        0x20000000,
        0x0,
        0x0,
        0x0,
        0x80008000,
        0x1000102,
        0x8102850a,
    ]
    fixed_variables, component_ids = create_constraints(list_key, list_data, 0x0a80088000681000)
    sat.build_cipher_model(fixed_variables=fixed_variables)
    assert sat.solve(CIPHER, solver_name="cryptominisat")["status"] == "SATISFIABLE"


def test_satisfiable_differential_trail_single_key():
    """ The following is an incompatible trail presented in Table 5 of [SongHY16]_."""
    speck = SpeckBlockCipher(number_of_rounds=10, block_bit_size=block_bit_size, key_bit_size=key_bit_size)
    speck.create_compounded_cipher()
    sat = SatCipherModel(speck)
    list_data = [
        0x20400040,
        0x80008100,
        0x80008402,
        0x8D029D08,
        0x60021420,
        0x106040E0,
        0x03800001,
        0x00040000,
        0x08000800,
        0x08102810,
        0x0800A840
    ]
    fixed_variables, component_ids = create_constraints([], list_data, 0x0)
    sat.build_cipher_model(fixed_variables=fixed_variables)
    assert sat.solve(CIPHER, solver_name="cryptominisat")["status"] == "SATISFIABLE"


def test_unsatisfiable_differential_trail_related_key():
    """ The following is an incompatible trail presented in Table 28 of [Sad2020]_."""

    speck = SpeckBlockCipher(number_of_rounds=14, block_bit_size=block_bit_size, key_bit_size=key_bit_size)
    speck.create_compounded_cipher()
    sat = SatCipherModel(speck)
    list_key = [
        0x0025,
        0x0080,
        0x0200,
        0x0800,
        0x0000,
        0x0000,
        0x0000,
        0x0040,
        0x0140,
        0x0240,
        0x87C0,
        0x0042,
        0x8140,
        0x0557
    ]

    list_data = [
        0x50A45021,
        0x508100A0,
        0x02810001,
        0x00040000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00400040,
        0x81008000,
        0x81428140,
        0x80028500,
        0x80429440,
        0x9000C102,
        0xC575C17E
    ]
    fixed_variables, component_ids = create_constraints(list_key, list_data, 0x0001400008800025)
    sat.build_cipher_model(fixed_variables=fixed_variables)
    assert sat.solve(CIPHER, solver_name="cryptominisat")["status"] == "UNSATISFIABLE"
