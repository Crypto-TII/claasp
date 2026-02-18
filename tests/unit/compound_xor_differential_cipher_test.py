from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.sat.solvers import CRYPTOMINISAT_EXT, KISSAT_EXT
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import CIPHER, SATISFIABLE, UNSATISFIABLE, XOR_DIFFERENTIAL

KEY_BIT_SIZE = 64
BLOCK_BIT_SIZE = 32
KEY_SCHEDULE_BIT_SIZE = 16


def get_round_key_values(dictionary, number_of_rounds):
    round_key_values = []
    for round_number in range(number_of_rounds):
        component_id = get_intermediate_component_id_from_key_schedule(round_number, number_of_rounds)
        if component_id != "":
            round_key_values.append(int(dictionary[component_id]["value"], 16))
    return round_key_values


def get_round_data_values(dictionary, number_of_rounds, suffix=""):
    round_data_values = []
    for round_number in range(number_of_rounds + 1):
        component_id = get_intermediate_component_id_from_main_process(round_number, number_of_rounds, suffix)
        if component_id != "":
            round_data_values.append(int(dictionary[component_id]["value"], 16))
    return round_data_values


def get_intermediate_component_id_from_key_schedule(round_number, number_of_rounds):
    component_id = ""
    if round_number == 0:
        component_id = "intermediate_output_0_5"
    if 0 < round_number < number_of_rounds:
        component_id = f"intermediate_output_{round_number}_11"
    return component_id


def get_intermediate_component_id_from_main_process(round_number, number_of_rounds, suffix):
    component_id = ""
    if round_number == 0:
        component_id = f"plaintext{suffix}"
    if round_number == 1:
        component_id = "intermediate_output_0_6"
    if 1 < round_number < number_of_rounds:
        component_id = f"intermediate_output_{round_number - 1}_12"
    if round_number == number_of_rounds:
        component_id = f"cipher_output_{number_of_rounds - 1}_12"
    return component_id


def get_constraint(component_id_, bit_size, bit_values):
    constraint_ = set_fixed_variables(
        component_id=component_id_, constraint_type="equal", bit_positions=list(range(bit_size)), bit_values=bit_values
    )
    return constraint_


def get_constraints(list_key, list_data, key_differential, suffix=""):
    key_pair1_pair2 = set_fixed_variables(
        component_id="key_pair1_pair2",
        constraint_type="equal",
        bit_positions=list(range(KEY_BIT_SIZE)),
        bit_values=integer_to_bit_list(key_differential, KEY_BIT_SIZE, "big"),
    )

    round_number = 0
    component_ids = []
    number_of_states = len(list_key)
    fixed_variables = [key_pair1_pair2]
    for num in list_key:
        binary_list = integer_to_bit_list(num, KEY_SCHEDULE_BIT_SIZE, "big")
        component_id = get_intermediate_component_id_from_key_schedule(round_number, number_of_states)
        component_ids.append(component_id)
        fixed_variables.append(get_constraint(component_id, KEY_SCHEDULE_BIT_SIZE, binary_list))
        round_number += 1

    round_number = 0
    number_of_states = len(list_data) - 1
    for num in list_data:
        binary_list = integer_to_bit_list(num, BLOCK_BIT_SIZE, "big")
        component_id = get_intermediate_component_id_from_main_process(round_number, number_of_states, suffix)
        component_ids.append(component_id)
        fixed_variables.append(get_constraint(component_id, BLOCK_BIT_SIZE, binary_list))
        round_number += 1
    return fixed_variables, component_ids


def test_satisfiable_differential_trail_related_key():
    speck = SpeckBlockCipher(number_of_rounds=14, block_bit_size=BLOCK_BIT_SIZE, key_bit_size=KEY_BIT_SIZE)
    speck.convert_to_compound_xor_cipher()
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
        0xC0B1C0B0,
        0x667764B4,
        0x907002A1,
        0x8810205,
        0x140800,
        0x20000000,
        0x0,
        0x0,
        0x0,
        0x80008000,
        0x1000102,
        0x8102850A,
    ]
    fixed_variables, _ = get_constraints(list_key, list_data, 0x0A80088000681000, "_pair1_pair2")
    sat.build_cipher_model(fixed_variables=fixed_variables)

    assert sat.solve(CIPHER, solver_name=CRYPTOMINISAT_EXT)["status"] == SATISFIABLE


def test_satisfiable_differential_trail_single_key():
    """The following is an compatible trail presented in Table 5 of [SongHY16]_."""

    speck = SpeckBlockCipher(number_of_rounds=10, block_bit_size=BLOCK_BIT_SIZE, key_bit_size=KEY_BIT_SIZE)
    speck.convert_to_compound_xor_cipher()
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
        0x0800A840,
    ]
    fixed_variables, _ = get_constraints([], list_data, 0x0, "_pair1_pair2")
    sat.build_cipher_model(fixed_variables=fixed_variables)
    assert sat.solve(CIPHER, solver_name=CRYPTOMINISAT_EXT)["status"] == SATISFIABLE


def test_unsatisfiable_differential_trail_related_key():
    """The following is an incompatible trail presented in Table 28 of [Sad2020]_."""

    speck = SpeckBlockCipher(number_of_rounds=14, block_bit_size=BLOCK_BIT_SIZE, key_bit_size=KEY_BIT_SIZE)
    speck.convert_to_compound_xor_cipher()
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
        0x0557,
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
        0xC575C17E,
    ]
    fixed_variables, _ = get_constraints(list_key, list_data, 0x0001400008800025, "_pair1_pair2")
    sat.build_cipher_model(fixed_variables=fixed_variables)
    assert sat.solve(CIPHER, solver_name=CRYPTOMINISAT_EXT)["status"] == UNSATISFIABLE


def test_satisfiable_differential_trail_single_key_generated_using_claasp():
    speck = SpeckBlockCipher(number_of_rounds=4, block_bit_size=BLOCK_BIT_SIZE, key_bit_size=KEY_BIT_SIZE)
    sat = SatCipherModel(speck)
    sat_xor_diff_model = SatXorDifferentialModel(
        speck,
    )
    fixed_variables = [
        set_fixed_variables("key", "not_equal", range(64), integer_to_bit_list(0, 64, "little")),
        set_fixed_variables("plaintext", "not_equal", range(32), integer_to_bit_list(0, 32, "little")),
    ]
    sat_xor_diff_model.build_xor_differential_trail_model(5, fixed_variables=fixed_variables)
    sat_output = sat_xor_diff_model._solve_with_external_sat_solver(XOR_DIFFERENTIAL, CRYPTOMINISAT_EXT, [])

    list_key = get_round_key_values(sat_output["components_values"], speck.number_of_rounds)
    list_data = get_round_data_values(sat_output["components_values"], speck.number_of_rounds)

    speck.convert_to_compound_xor_cipher()
    fixed_variables, _ = get_constraints(list_key, list_data, 0x0)
    sat.build_cipher_model(fixed_variables=fixed_variables)
    assert sat.solve(CIPHER, solver_name=CRYPTOMINISAT_EXT)["status"] == SATISFIABLE


def test_build_xor_differential_model_and_checker_unsat():
    list_key = [0x0, 0x0, 0x0, 0x8000, 0x8002, 0xFFF4, 0x19BF, 0x0E0D, 0x3834, 0x6090, 0x0, 0x0, 0x8100, 0x606, 0x1E1E]
    list_data = [
        0x0,
        0x0,
        0x0,
        0x80008000,
        0x1020100,
        0xFB0AFF0A,
        0xBB534778,
        0xE1FFFC1E,
        0xFA7F0A04,
        0x28000010,
        0x400000,
        0x80008000,
        0x2,
        0x0604060C,
        0x101E082E,
    ]
    fixed_variables, _ = get_constraints(list_key, list_data, 0x0040000000000000, "_pair1_pair2")
    speck = SpeckBlockCipher(number_of_rounds=15)
    sat = SatXorDifferentialModel(speck)
    sat.window_size_by_round_values = [0, 0, 0, 0, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, 0]
    sat.build_xor_differential_trail_and_checker_model_at_intermediate_output_level(
        144, fixed_variables=fixed_variables
    )
    solution = sat.solve(XOR_DIFFERENTIAL, solver_name=KISSAT_EXT)
    assert solution["status"] == UNSATISFIABLE


def test_build_xor_differential_model_and_checker_sat():
    list_key = [0x0, 0x40, 0x8100, 0x8002, 0x8, 0x00D8, 0x400, 0x1000, 0x4001, 0x0, 0x0, 0x200, 0x0, 0x0, 0x4]
    list_data = [
        0x28140810,
        0x20400000,
        0x80008000,
        0x2,
        0x80008008,
        0x81008122,
        0x8284860E,
        0x8B099333,
        0xB7D9FB17,
        0xFC771028,
        0x00A04000,
        0x10000,
        0x0,
        0x0,
        0x0,
        0x40004,
    ]
    fixed_variables, _ = get_constraints(list_key, list_data, 0x8002204020000000, "_pair1_pair2")
    speck = SpeckBlockCipher(number_of_rounds=15)
    sat = SatXorDifferentialModel(speck)
    sat.window_size_by_round_values = [0, 0, 0, 0, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, 0]
    sat.build_xor_differential_trail_and_checker_model_at_intermediate_output_level(92, fixed_variables=fixed_variables)
    solution = sat.solve(XOR_DIFFERENTIAL, solver_name=KISSAT_EXT)
    assert solution["status"] == SATISFIABLE
