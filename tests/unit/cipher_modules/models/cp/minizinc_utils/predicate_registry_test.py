from claasp.cipher_modules.models.cp.minizinc_utils.predicate_registry import (
    BOOMERANG_BCT_SAT,
    CIPHER_EVALUATION_CP,
    CONTINUOUS_DIFFERENTIAL_LINEAR,
    DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP,
    GENERIC_CP_UTILS,
    XOR_DIFFERENTIAL_CP,
    XOR_DIFFERENTIAL_ARX_SAT,
    XOR_LINEAR_CP,
    collect_used_helpers,
    render_helper_block,
    resolve_helper_closure,
)


def test_collect_used_helpers_finds_actual_cp_helper_calls():
    fragments = [
        "constraint out = RShift(pre_out, shift_amount);",
        "array[0..31] of var 0..1: eq_out = Eq(a, b, c);",
        "constraint Ham_weight(Andz(a, b, c)) == 0 /\\ p[0] = Ham_weight(OR(a, b));",
    ]

    assert collect_used_helpers(fragments, model_contexts=(GENERIC_CP_UTILS, XOR_DIFFERENTIAL_CP)) == {
        "RShift",
        "Eq",
        "Ham_weight",
        "Andz",
        "OR",
    }


def test_collect_used_helpers_ignores_comments_strings_and_identifier_substrings():
    fragments = [
        "% constraint modadd(a, b, c);",
        'output ["debug RRot(x, 3) and bitArrayToInt(a, b)"];',
        "array[0..3] of var 0..1: customRRot;",
        "constraint customRRot[0] = 0;",
        "constraint foo_modadd = 0;",
    ]

    assert collect_used_helpers(fragments, model_contexts=(GENERIC_CP_UTILS, CIPHER_EVALUATION_CP)) == set()


def test_collect_used_helpers_detects_helpers_in_output_expression():
    fragments = [
        'output ["carries:" ++ show(Xor3(a, b, c)) ++ "\\n"];',
    ]

    assert collect_used_helpers(fragments, model_contexts=(GENERIC_CP_UTILS,)) == {"Xor3"}


def test_resolve_helper_closure_adds_recursive_dependencies():
    closure = resolve_helper_closure(
        {"modular_addition_word"},
        model_contexts=(GENERIC_CP_UTILS, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP),
    )
    names = [name for _, name in closure]

    assert names == ["LShift", "xor_bit_p1", "modular_addition_word"]


def test_render_helper_block_includes_dependencies_once():
    helper_block = render_helper_block(
        {"modular_addition_word"},
        model_contexts=(GENERIC_CP_UTILS, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP),
    )

    assert helper_block.count("function array[int] of var 0..2: LShift") == 1
    assert helper_block.count("predicate xor_bit_p1") == 1
    assert helper_block.count("predicate modular_addition_word") == 1
    assert "predicate modadd(" not in helper_block


def test_generic_utils_do_not_include_cryptanalysis_specific_helpers():
    fragments = [
        "constraint modadd_linear(a, b, c, p);",
        "constraint modadd(a, b, c);",
        "constraint RRot(x, 3) = y;",
    ]

    assert collect_used_helpers(fragments, model_contexts=(GENERIC_CP_UTILS,)) == {"RRot"}
    assert collect_used_helpers(fragments, model_contexts=(XOR_LINEAR_CP,)) == {"modadd_linear"}
    assert collect_used_helpers(fragments, model_contexts=(CIPHER_EVALUATION_CP,)) == {"modadd"}


def test_collect_used_helpers_respects_context_variants():
    fragments = [
        "constraint out = continuous_modadd(a, b, out);",
        "constraint rotated = RRot(x, 3);",
    ]

    assert collect_used_helpers(fragments, model_contexts=(CONTINUOUS_DIFFERENTIAL_LINEAR,)) == {"continuous_modadd"}
    assert collect_used_helpers(fragments, model_contexts=(GENERIC_CP_UTILS,)) == {"RRot"}


def test_boomerang_bct_sat_context_renders_word_ops_and_bct_helpers():
    fragments = [
        "constraint modular_addition_word(A, B, C, d_list, 3);",
        "constraint onlyLargeSwitch_BCT_enum(dL, dR, nL, nR, 1, 24);",
    ]

    used = collect_used_helpers(fragments, model_contexts=(BOOMERANG_BCT_SAT,))
    helper_block = render_helper_block(used, model_contexts=(BOOMERANG_BCT_SAT,))

    assert used == {"modular_addition_word", "onlyLargeSwitch_BCT_enum"}
    assert 'include "table.mzn";' in helper_block
    assert "predicate modular_addition_bit_level_sat" in helper_block
    assert "predicate BVAssign" in helper_block
    assert "predicate onlyLargeSwitch_BCT_enum" in helper_block
