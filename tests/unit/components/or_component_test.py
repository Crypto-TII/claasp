from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.ciphers.single_component_ciphers.or_cipher import OrCipher
from claasp.components.or_component import Or
from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import (
    SmtXorQuasidifferentialModel,
)

def test_algebraic_polynomials():
    cipher = OrCipher(word_bit_size=4, number_of_inputs=2)
    or_component = cipher.component_from_id("or_0_0")
    algebraic = AlgebraicModel(cipher)
    algebraic_polynomials = or_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials[0]) == "or_0_0_x0*or_0_0_x4 + or_0_0_y0 + or_0_0_x4 + or_0_0_x0"
    assert str(algebraic_polynomials[1]) == "or_0_0_x1*or_0_0_x5 + or_0_0_y1 + or_0_0_x5 + or_0_0_x1"
    assert str(algebraic_polynomials[-2]) == "or_0_0_x2*or_0_0_x6 + or_0_0_y2 + or_0_0_x6 + or_0_0_x2"
    assert str(algebraic_polynomials[-1]) == "or_0_0_x3*or_0_0_x7 + or_0_0_y3 + or_0_0_x7 + or_0_0_x3"


def test_cp_constraints():
    from minizinc import Instance, Model, Solver
    for operands in [2, 3]:
        names = ["a", "b", "c"][:operands]
        component = Or(0, 0, names, [[0, 1]] * operands, 2)
        declarations, constraints = component.cp_constraints()
        model = Model()
        model.add_string("\n".join(
            [f"array[0..1] of var 0..1: {name};" for name in names]
            + declarations + constraints + ["solve satisfy;"]
        ))
        result = Instance(Solver.lookup("gecode"), model).solve(all_solutions=True)
        assert len(result.solution) == 4 ** operands
        for solution in result.solution:
            words = [sum(bit << (1-i) for i, bit in enumerate(getattr(solution, name))) for name in names]
            expected = 0
            for word in words:
                expected |= word
            actual = sum(bit << (1-i) for i, bit in enumerate(solution.or_0_0))
            assert actual == expected


def test_cp_xor_linear_mask_propagation_constraints():
    cipher = OrCipher(word_bit_size=4, number_of_inputs=2)
    or_component = cipher.component_from_id("or_0_0")
    cp = MznModel(cipher)
    declarations, constraints = or_component.cp_xor_linear_mask_propagation_constraints(cp)

    assert declarations == ['array[0..3] of var 0..400: p_or_0_0;', 'array[0..7] of var 0..1:or_0_0_i;',
                            'array[0..3] of var 0..1:or_0_0_o;']

    assert constraints[0] == 'constraint table([or_0_0_i[0]]++[or_0_0_i[4]]++[or_0_0_o[0]]++[p_or_0_0[0]],and2inputs_LAT);'
    assert constraints[-2] == 'constraint table([or_0_0_i[3]]++[or_0_0_i[7]]++[or_0_0_o[3]]++[p_or_0_0[3]],' \
                              'and2inputs_LAT);'
    assert constraints[-1] == 'constraint p[0] = sum(p_or_0_0);'


def test_generic_sign_linear_constraints():
    or_component = Or(0, 0, ['plaintext', 'key'], [list(range(4)), list(range(4))], 4)
    input_tert = [0, 0, 0, 0, 0, 0, 0, 0]

    assert or_component.generic_sign_linear_constraints(input_tert, [0, 0, 0, 0]) == 1
    assert or_component.generic_sign_linear_constraints(input_tert, [0, 0, 0, 1]) == -1


def test_sat_constraints():
    or_component = Or(0, 0, ['plaintext', 'key'], [list(range(4)), list(range(4))], 4)
    output_bit_ids, constraints = or_component.sat_constraints()

    assert output_bit_ids[0] == 'or_0_0_0'
    assert output_bit_ids[1] == 'or_0_0_1'
    assert output_bit_ids[2] == 'or_0_0_2'

    assert constraints[-3] == 'or_0_0_3 -plaintext_3'
    assert constraints[-2] == 'or_0_0_3 -key_3'
    assert constraints[-1] == '-or_0_0_3 plaintext_3 key_3'


def test_smt_constraints():
    or_component = Or(0, 0, ['plaintext', 'key'], [list(range(4)), list(range(4))], 4)
    output_bit_ids, constraints = or_component.smt_constraints()

    assert output_bit_ids[0] == 'or_0_0_0'
    assert output_bit_ids[1] == 'or_0_0_1'
    assert output_bit_ids[-2] == 'or_0_0_2'
    assert output_bit_ids[-1] == 'or_0_0_3'

    assert constraints[0] == '(assert (= or_0_0_0 (or plaintext_0 key_0)))'
    assert constraints[1] == '(assert (= or_0_0_1 (or plaintext_1 key_1)))'
    assert constraints[-2] == '(assert (= or_0_0_2 (or plaintext_2 key_2)))'
    assert constraints[-1] == '(assert (= or_0_0_3 (or plaintext_3 key_3)))'

def test_smt_xor_quasidifferential_propagation_constraints():
    cipher = OrCipher(word_bit_size=2, number_of_inputs=2)
    model = SmtXorQuasidifferentialModel(cipher)
    or_component = cipher.component_from(0, 0)
    variables, constraints = or_component.smt_xor_quasidifferential_propagation_constraints(model)

    assert variables == ['or_0_0_0', 'or_0_0_1', 'qdt_or_0_0_0', 'qdt_or_0_0_1',
                         'hw_qdt_or_0_0_0', 'hw_qdt_or_0_0_1']

    assert len(constraints) == 8
    assert constraints[0] == '(assert (=> or_0_0_0 (or plaintext_0 key_0)))'
    assert constraints[-1] == '(assert (= hw_qdt_or_0_0_1 (or plaintext_1 key_1 qdt_or_0_0_1)))'


def test_smt_xor_quasidifferential_propagation_constraints_more_than_two_operands():
    cipher = OrCipher(word_bit_size=2, number_of_inputs=3)
    model = SmtXorQuasidifferentialModel(cipher)
    or_component = cipher.component_from(0, 0)

    try:
        or_component.smt_xor_quasidifferential_propagation_constraints(model)
        raised = False
    except NotImplementedError:
        raised = True

    assert raised