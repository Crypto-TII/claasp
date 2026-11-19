def get_evaluation_ubct_operations(nbit):
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
    array[0..{nbit-1}] of var 0..1: dL,
    array[0..{nbit-1}] of var 0..1: dR,
    array[0..{nbit-1}] of var 0..1: nL,
    array[0..{nbit-1}] of var 0..1: nR,
    array[0..{nbit-1}] of var 0..1: dLL,
    int: branchSize,
    var 0..3200: ubct_minus_log_2
) =
let {{
    array[1..branchSize-1,0..3] of var 0.0..1.0: dp_ubct;
    array[1..branchSize-1] of var 0..31: tmp0;
    var 0.0..1.0: ubct_value;
}} in
(
    ( 
        tmp0[1] == dLL[branchSize-1]*16 + nR[branchSize-1]*8 + nL[branchSize-1]*4 + dR[branchSize-1]*2 + dL[branchSize-1]*1
    ) /\\
    forall(j in 0..3)(
        dp_ubct[1,j] == int2float(tables_ubct[tmp0[1],j,0]) / 4.0
    ) /\\
    forall(i in 2..branchSize-1)(
        tmp0[i] == dLL[branchSize-i]*16 + nR[branchSize-i]*8 + nL[branchSize-i]*4 + dR[branchSize-i]*2 + dL[branchSize-i]*1
    ) /\\
    forall(i in 2..branchSize-1, j in 0..3)(
            dp_ubct[i,j] == sum(k in 0..3)(
                 dp_ubct[i-1,k] * int2float(tables_ubct[tmp0[i],j,k]) 
            ) / 4.0
    ) /\\
    (
        ubct_value == sum(state in 0..3)( 
                                if (((valid_state_ubct[state,0] + valid_state_ubct[state,1] + dLL[1] + nR[1] + nL[1]) mod 2) == 0)
                                    then dp_ubct[branchSize-1,state]
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