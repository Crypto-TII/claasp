def get_evaluation_bct_operations(nbit):
    """Return MiniZinc source for modular-addition boomerang probability evaluation.

    The transition tables follow Wang, Wang and Sun, *SAT-aided Automatic
    Search of Boomerang Distinguishers for ARX Ciphers*, ToSC 2023(1),
    https://doi.org/10.46586/tosc.v2023.i1.152-191. Connectivity uses bits
    from least to most significant; probability evaluation takes CLAASP's
    most-significant-bit-first arrays and ignores the final carry.

    INPUT: ``nbit`` -- integer word size, at least 2.

    OUTPUT: string of MiniZinc declarations and predicates; include it once
    in the model after ``get_approx_logarithm_operation()``. The helper
    generates source and does not invoke a solver.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.cp.minizinc_utils.mzn_evaluation_bct_predicate import get_evaluation_bct_operations
        sage: import minizinc  # optional - minizinc
        sage: model = minizinc.Model()  # optional - minizinc
        sage: from claasp.cipher_modules.models.cp.minizinc_utils.mzn_approx_logarithm_predicate import get_approx_logarithm_operation
        sage: model.add_string(get_approx_logarithm_operation())  # optional - minizinc
        sage: model.add_string(get_evaluation_bct_operations(4))  # optional - minizinc
        sage: model.add_string('solve satisfy;')  # optional - minizinc
        sage: result = minizinc.Instance(minizinc.Solver.lookup('gecode'), model).solve()  # optional - minizinc
        sage: str(result.status)  # optional - minizinc
        'SATISFIED'
    """
    bct_string = f"""
        array[0..15, 0..3, 0..3] of 0..4: tables_bct = array3d(0..15, 0..3, 0..3, 
[
4,2,2,0,
0,2,0,0,
0,0,2,0,
0,0,0,0,

2,2,0,2,
2,2,0,0,
0,0,0,0,
0,0,0,2,

2,2,0,0,
2,2,2,0,
0,0,2,0,
0,0,0,0,

2,0,0,0,
2,4,0,2,
0,0,0,0,
0,0,0,2,

2,0,2,2,
0,0,0,0,
2,0,2,0,
0,0,0,2,

2,0,0,0,
0,0,0,0,
0,0,0,0,
2,0,0,0,

0,0,0,0,
0,2,0,0,
0,2,0,0,
0,0,0,0,

0,0,0,0,
0,2,2,2,
0,0,2,0,
0,2,0,2,

2,0,2,0,
0,2,0,0,
2,2,2,0,
0,0,0,0,

0,0,0,0,
0,0,2,0,
0,0,2,0,
0,0,0,0,

0,0,0,2,
0,0,0,0,
0,0,0,0,
0,0,0,2,

2,0,0,0,
0,2,0,2,
0,0,0,0,
2,2,0,2,

2,0,0,0,
0,0,0,0,
2,0,4,2,
0,0,0,2,

0,0,0,0,
0,2,0,0,
0,2,2,2,
0,0,2,2,

2,0,0,0,
0,0,0,0,
0,0,2,2,
2,0,2,2,

0,0,0,0,
0,2,0,0,
0,0,2,0,
0,2,2,4 ]);


predicate bct_compute(
    array[0..{nbit-1}] of var 0..1: d_l,
    array[0..{nbit-1}] of var 0..1: d_r,
    array[0..{nbit-1}] of var 0..1: n_l,
    array[0..{nbit-1}] of var 0..1: n_r,
    int: branch_size,
    var 0..3200: bct_minus_log_2
) =
let {{
    array[1..branch_size-1,0..3] of var 0.0..1.0: dp_bct;
    array[1..branch_size-1] of var 0..15: tmp0;
    var 0.0..1.0: bct_value;
}} in
(
    ( 
        tmp0[1] == n_r[branch_size-1]*8 + n_l[branch_size-1]*4 + d_r[branch_size-1]*2 + d_l[branch_size-1]*1
    ) /\\
    forall(j in 0..3)(
        dp_bct[1,j] == int2float(tables_bct[tmp0[1],j,0]) / 4.0
    ) /\\
    forall(i in 2..branch_size-1)(
        tmp0[i] == n_r[branch_size-i]*8 + n_l[branch_size-i]*4 + d_r[branch_size-i]*2 + d_l[branch_size-i]*1
    ) /\\
    forall(i in 2..branch_size-1, j in 0..3)(
            dp_bct[i,j] == sum(k in 0..3)(
                 dp_bct[i-1,k] * int2float(tables_bct[tmp0[i],j,k]) 
            ) / 4.0
    ) /\\
    (
        bct_value == sum(state in 0..3)( dp_bct[branch_size-1,state] )
    ) /\\
    (
        approx_prob_log(bct_value,bct_minus_log_2)
    )
);
    """
    return bct_string