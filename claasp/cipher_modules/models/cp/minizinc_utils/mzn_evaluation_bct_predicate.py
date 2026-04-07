def get_evaluation_bct_operations(nbit):
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
    array[0..{nbit-1}] of var 0..1: dL,
    array[0..{nbit-1}] of var 0..1: dR,
    array[0..{nbit-1}] of var 0..1: nL,
    array[0..{nbit-1}] of var 0..1: nR,
    int: branchSize,
    var 0..3200: bct_minus_log_2
) =
let {{
    array[1..branchSize-1,0..3] of var 0.0..1.0: dp_bct;
    array[1..branchSize-1] of var 0..15: tmp0;
    var 0.0..1.0: bct_value;
}} in
(
    ( 
        tmp0[1] == nR[branchSize-1]*8 + nL[branchSize-1]*4 + dR[branchSize-1]*2 + dL[branchSize-1]*1
    ) /\\
    forall(j in 0..3)(
        dp_bct[1,j] == int2float(tables_bct[tmp0[1],j,0]) / 4.0
    ) /\\
    forall(i in 2..branchSize-1)(
        tmp0[i] == nR[branchSize-i]*8 + nL[branchSize-i]*4 + dR[branchSize-i]*2 + dL[branchSize-i]*1
    ) /\\
    forall(i in 2..branchSize-1, j in 0..3)(
            dp_bct[i,j] == sum(k in 0..3)(
                 dp_bct[i-1,k] * int2float(tables_bct[tmp0[i],j,k]) 
            ) / 4.0
    ) /\\
    (
        bct_value == sum(state in 0..3)( dp_bct[branchSize-1,state] )
    ) /\\
    (
        approx_prob_log(bct_value,bct_minus_log_2)
    )
);
    """
    return bct_string