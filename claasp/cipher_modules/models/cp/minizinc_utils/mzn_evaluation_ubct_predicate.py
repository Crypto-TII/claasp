def get_evaluation_ubct_operations(nbit):
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

        sage: from claasp.cipher_modules.models.cp.minizinc_utils.mzn_evaluation_ubct_predicate import get_evaluation_ubct_operations
        sage: import minizinc  # optional - minizinc
        sage: model = minizinc.Model()  # optional - minizinc
        sage: from claasp.cipher_modules.models.cp.minizinc_utils.mzn_approx_logarithm_predicate import get_approx_logarithm_operation
        sage: model.add_string(get_approx_logarithm_operation())  # optional - minizinc
        sage: model.add_string(get_evaluation_ubct_operations(4))  # optional - minizinc
        sage: model.add_string('solve satisfy;')  # optional - minizinc
        sage: result = minizinc.Instance(minizinc.Solver.lookup('gecode'), model).solve()  # optional - minizinc
        sage: str(result.status)  # optional - minizinc
        'SATISFIED'
    """
    ubct_string = f"""
        array[0..31, 0..3, 0..3] of 0..4: tables_ubct = array3d(0..31, 0..3, 0..3, 
[
 4, 0, 2, 0,
 0, 0, 0, 0,
 0, 0, 2, 0,
 0, 0, 0, 0,

 0, 2, 0, 2,
 0, 2, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 2,

 0, 2, 0, 0,
 0, 2, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,

 2, 0, 0, 0,
 2, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,

 2, 0, 2, 0,
 0, 0, 0, 0,
 2, 0, 2, 0,
 0, 0, 0, 0,

 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,

 0, 0, 0, 0,
 0, 2, 0, 0,
 0, 2, 0, 0,
 0, 0, 0, 0,

 0, 0, 0, 0,
 0, 0, 2, 0,
 0, 0, 2, 0,
 0, 0, 0, 0,

 2, 0, 2, 0,
 0, 0, 0, 0,
 2, 0, 2, 0,
 0, 0, 0, 0,

 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,

 0, 0, 0, 2,
 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 2,

 2, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,
 2, 0, 0, 0,

 2, 0, 0, 0,
 0, 0, 0, 0,
 2, 0, 4, 0,
 0, 0, 0, 0,

 0, 0, 0, 0,
 0, 2, 0, 0,
 0, 2, 0, 2,
 0, 0, 0, 2,

 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 2,
 0, 0, 0, 2,

 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 2, 0,
 0, 0, 2, 0,

 0, 2, 0, 0,
 0, 2, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,

 2, 0, 0, 0,
 2, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,

 2, 0, 0, 0,
 2, 0, 2, 0,
 0, 0, 2, 0,
 0, 0, 0, 0,

 0, 0, 0, 0,
 0, 4, 0, 2,
 0, 0, 0, 0,
 0, 0, 0, 2,

 0, 0, 0, 2,
 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 2,

 2, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,
 2, 0, 0, 0,

 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,

 0, 0, 0, 0,
 0, 2, 0, 2,
 0, 0, 0, 0,
 0, 2, 0, 2,

 0, 0, 0, 0,
 0, 2, 0, 0,
 0, 2, 0, 0,
 0, 0, 0, 0,

 0, 0, 0, 0,
 0, 0, 2, 0,
 0, 0, 2, 0,
 0, 0, 0, 0,

 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 0,

 0, 0, 0, 0,
 0, 2, 0, 2,
 0, 0, 0, 0,
 0, 2, 0, 2,

 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 0, 2,
 0, 0, 0, 2,

 0, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 2, 0,
 0, 0, 2, 0,

 2, 0, 0, 0,
 0, 0, 0, 0,
 0, 0, 2, 0,
 2, 0, 2, 0,

 0, 0, 0, 0,
 0, 2, 0, 0,
 0, 0, 0, 0,
 0, 2, 0, 4]);
 
array[0..3,0..1] of 0..1: valid_state_ubct = array2d(0..3,0..1,
 [ 0,0,
   1,0,
   1,1,
   0,1
]);

predicate ubct_compute(
    array[0..{nbit-1}] of var 0..1: d_l,
    array[0..{nbit-1}] of var 0..1: d_r,
    array[0..{nbit-1}] of var 0..1: n_l,
    array[0..{nbit-1}] of var 0..1: n_r,
    array[0..{nbit-1}] of var 0..1: d_ll,
    int: branch_size,
    var 0..3200: ubct_minus_log_2
) =
let {{
    array[1..branch_size-1,0..3] of var 0.0..1.0: dp_ubct;
    array[1..branch_size-1] of var 0..31: tmp0;
    var 0.0..1.0: ubct_value;
}} in
(
    ( 
        tmp0[1] == d_ll[branch_size-1]*16 + n_r[branch_size-1]*8 + n_l[branch_size-1]*4 + d_r[branch_size-1]*2 + d_l[branch_size-1]*1
    ) /\\
    forall(j in 0..3)(
        dp_ubct[1,j] == int2float(tables_ubct[tmp0[1],j,0]) / 4.0
    ) /\\
    forall(i in 2..branch_size-1)(
        tmp0[i] == d_ll[branch_size-i]*16 + n_r[branch_size-i]*8 + n_l[branch_size-i]*4 + d_r[branch_size-i]*2 + d_l[branch_size-i]*1
    ) /\\
    forall(i in 2..branch_size-1, j in 0..3)(
            dp_ubct[i,j] == sum(k in 0..3)(
                 dp_ubct[i-1,k] * int2float(tables_ubct[tmp0[i],j,k]) 
            ) / 4.0
    ) /\\
    (
        ubct_value == sum(state in 0..3)( 
                                if (((valid_state_ubct[state,0] + valid_state_ubct[state,1] + d_ll[0] + d_r[0] + d_l[0]) mod 2) == 0)
                                    then dp_ubct[branch_size-1,state]
                                else 0
                                endif
        )
    ) /\\
    (
        approx_prob_log(ubct_value,ubct_minus_log_2)
    )
);
    """
    return ubct_string
