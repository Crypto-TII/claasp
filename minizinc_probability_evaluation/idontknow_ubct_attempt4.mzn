array[0..31, 0..3, 0..3] of -200..1: tables_ubct = array3d(0..31, 0..3, 0..3, 
[
 -200, 1, -100, 1,
 1, 1, 1, 1,
 1, 1, -100, 1,
 1, 1, 1, 1,

 1, -100, 1, -100,
 1, -100, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, -100,

 1, -100, 1, 1,
 1, -100, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,

 -100, 1, 1, 1,
 -100, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,

 -100, 1, -100, 1,
 1, 1, 1, 1,
 -100, 1, -100, 1,
 1, 1, 1, 1,

 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,

 1, 1, 1, 1,
 1, -100, 1, 1,
 1, -100, 1, 1,
 1, 1, 1, 1,

 1, 1, 1, 1,
 1, 1, -100, 1,
 1, 1, -100, 1,
 1, 1, 1, 1,

 -100, 1, -100, 1,
 1, 1, 1, 1,
 -100, 1, -100, 1,
 1, 1, 1, 1,

 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,

 1, 1, 1, -100,
 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, -100,

 -100, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,
 -100, 1, 1, 1,

 -100, 1, 1, 1,
 1, 1, 1, 1,
 -100, 1, -200, 1,
 1, 1, 1, 1,

 1, 1, 1, 1,
 1, -100, 1, 1,
 1, -100, 1, -100,
 1, 1, 1, -100,

 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, -100,
 1, 1, 1, -100,

 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, -100, 1,
 1, 1, -100, 1,

 1, -100, 1, 1,
 1, -100, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,

 -100, 1, 1, 1,
 -100, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,

 -100, 1, 1, 1,
 -100, 1, -100, 1,
 1, 1, -100, 1,
 1, 1, 1, 1,

 1, 1, 1, 1,
 1, -200, 1, -100,
 1, 1, 1, 1,
 1, 1, 1, -100,

 1, 1, 1, -100,
 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, -100,

 -100, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,
 -100, 1, 1, 1,

 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,

 1, 1, 1, 1,
 1, -100, 1, -100,
 1, 1, 1, 1,
 1, -100, 1, -100,

 1, 1, 1, 1,
 1, -100, 1, 1,
 1, -100, 1, 1,
 1, 1, 1, 1,

 1, 1, 1, 1,
 1, 1, -100, 1,
 1, 1, -100, 1,
 1, 1, 1, 1,

 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, 1,

 1, 1, 1, 1,
 1, -100, 1, -100,
 1, 1, 1, 1,
 1, -100, 1, -100,

 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, 1, -100,
 1, 1, 1, -100,

 1, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, -100, 1,
 1, 1, -100, 1,

 -100, 1, 1, 1,
 1, 1, 1, 1,
 1, 1, -100, 1,
 -100, 1, -100, 1,

 1, 1, 1, 1,
 1, -100, 1, 1,
 1, 1, 1, 1,
 1, -100, 1, -200]);
 
array[0..3,0..1] of 0..1: valid_state_ubct = array2d(0..3,0..1,
 [ 0,0,
   1,0,
   1,1,
   0,1
]);

int: nbit = 16;

array[0..nbit-1] of var 0..1: dL = array1d(0..nbit-1, [0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);
array[0..nbit-1] of var 0..1: dR = array1d(0..nbit-1, [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..nbit-1] of var 0..1: nL = array1d(0..nbit-1, [0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0]);
array[0..nbit-1] of var 0..1: nR = array1d(0..nbit-1, [0,0,0,0,1,0,0,0,0,0,0,1,1,1,0,0]);
array[0..nbit-1] of var 0..1: dLL = array1d(0..nbit-1,[1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);

predicate ubct_compute(
    array[0..16-1] of var 0..1: dL,
    array[0..16-1] of var 0..1: dR,
    array[0..16-1] of var 0..1: nL,
    array[0..16-1] of var 0..1: nR,
    array[0..16-1] of var 0..1: dLL,
    int: nbit,
    var int: ubct_prob
) =
let {
    array[1..nbit-1,0..3] of var int: dp_ubct;
    array[1..nbit-1] of var 0..15: tmp0;
    array[1..nbit-1, 0..3] of var 0..7: how_many_cross_elements_differ_from_0_in_the_dp_ubct;
    var 0..4: how_many_cross_elements_differ_from_0_in_the_dp_ubct_last_condition;
    var int: ubct_value;
} in
(
    tmp0[1] = dLL[nbit-1]*16 + nR[nbit-1]*8 + nL[nbit-1]*4 + dR[nbit-1]*2 + dL[nbit-1]*1 /\

    dp_ubct[1,0] = tables_ubct[tmp0[1],0,0] /\
    dp_ubct[1,1] = tables_ubct[tmp0[1],1,0] /\
    dp_ubct[1,2] = tables_ubct[tmp0[1],2,0] /\
    dp_ubct[1,3] = tables_ubct[tmp0[1],3,0] /\

    forall(i in 2..nbit-1, j in 0..3)(
        tmp0[i] = nR[nbit-i]*8 + nL[nbit-i]*4 + dR[nbit-i]*2 + dL[nbit-i]
        /\
        how_many_cross_elements_differ_from_0_in_the_dp_ubct[i,j] = sum(k in 0..3)(
                    if tables_ubct[tmp0[i],j,k] <= 0 /\ dp_ubct[i-1,k]<=0 then 1 else 0 endif
        )
        /\
        (how_many_cross_elements_differ_from_0_in_the_dp_ubct[i,j] = 0
              -> dp_ubct[i,j] = 1
        )
        /\
        (how_many_cross_elements_differ_from_0_in_the_dp_ubct[i,j] = 1 ->
            dp_ubct[i,j] = sum(k in 0..3)(
                if tables_ubct[tmp0[i],j,k] <= 0 /\ dp_ubct[i-1,k]<=0 then dp_ubct[i-1,k] + tables_ubct[tmp0[i],j,k]
                else 0 endif
            )
         )
         /\
         (how_many_cross_elements_differ_from_0_in_the_dp_ubct[i,j] >= 2
            -> (
                  dp_ubct[i,j] = min(k in 0..3)(
                     if tables_ubct[tmp0[i],j,k] <= 0 /\ dp_ubct[i-1,k]<=0 then dp_ubct[i-1,k] + tables_ubct[tmp0[i],j,k]
                     else 1 endif)
            )
         )
    ) /\
    how_many_cross_elements_differ_from_0_in_the_dp_ubct_last_condition = sum(state in 0..3)(if 
              (valid_state_ubct[state,0]
              + valid_state_ubct[state,1]
              + dLL[1] + nR[1] + nL[1]) mod 2 = 0 /\ dp_ubct[nbit-1,state] <= 0 then 1 else 0 endif)
    /\
    (how_many_cross_elements_differ_from_0_in_the_dp_ubct_last_condition = 0 -> ubct_value = 3200) 
    /\
    (how_many_cross_elements_differ_from_0_in_the_dp_ubct_last_condition = 1 -> 
            ubct_value = -200 + sum(state in 0..3)(
                  if (valid_state_ubct[state,0]
                      + valid_state_ubct[state,1]
                      + dLL[1] + nR[1] + nL[1]) mod 2 = 0 /\ dp_ubct[nbit-1,state] <= 0
                 then dp_ubct[nbit-1,state]
                 else 0
                 endif
            ) + 3200
     ) 
     /\
     (how_many_cross_elements_differ_from_0_in_the_dp_ubct_last_condition >= 2 -> 
            (                   
                    ubct_value = -200 + min(state in 0..3)(
                        if (valid_state_ubct[state,0]
                            + valid_state_ubct[state,1]
                            + dLL[1] + nR[1] + nL[1]) mod 2 = 0 /\ dp_ubct[nbit-1,state] <= 0
                        then dp_ubct[nbit-1,state] else 1 endif  ) + 3200
            )
     )
    /\
    ubct_prob = ubct_value
);

var int: ubct_prob;

constraint ubct_compute(dL, dR, nL, nR, dLL, 16, ubct_prob);


output[
      "ubct_entry/2^32 = \(ubct_prob)"
      ];