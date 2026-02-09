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
 
int: nbit = 16;

% array[0..nbit-1] of var 0..1: dL = array1d(0..nbit-1, [1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);
% array[0..nbit-1] of var 0..1: dR = array1d(0..nbit-1, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
% array[0..nbit-1] of var 0..1: nL = array1d(0..nbit-1, [0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0]);
% array[0..nbit-1] of var 0..1: nR = array1d(0..nbit-1, [0,0,0,0,1,0,0,0,0,0,0,1,1,1,0,0]);
% array[0..nbit-1] of var 0..1: dLL = array1d(0..nbit-1,[1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);

array[0..nbit-1] of var 0..1: dL = array1d(0..nbit-1, [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..nbit-1] of var 0..1: dR = array1d(0..nbit-1, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..nbit-1] of var 0..1: nL = array1d(0..nbit-1, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..nbit-1] of var 0..1: nR = array1d(0..nbit-1, [0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..nbit-1] of var 0..1: dLL = array1d(0..nbit-1,[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);

% array[0..nbit-1] of var 0..1: dL = array1d(0..nbit-1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
% array[0..nbit-1] of var 0..1: dR = array1d(0..nbit-1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
% array[0..nbit-1] of var 0..1: nL = array1d(0..nbit-1, [0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
% array[0..nbit-1] of var 0..1: nR = array1d(0..nbit-1, [0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0]);
% array[0..nbit-1] of var 0..1: dLL = array1d(0..nbit-1,[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0]);

predicate approx_prob_log(
  var float: prob,
  var int: minus_log2_prob
) = (
  minus_log2_prob = if prob <= 0.001021453702391378 then
                          floor((-19931.57001201849*prob+29.89737278555626)*100)
                    elseif prob <= 0.004151650554233785 /\ prob > 0.001021453702391378 then
                          floor((-584.962260272084*prob+10.13570866882117)*100)
                    elseif prob <= 0.01359667098324998 /\ prob > 0.004151650554233785 then
                          floor((-192.6450521799878*prob+8.506944714410169)*100)
                    elseif prob <= 0.05399137458004444 /\ prob > 0.01359667098324998 then
                           floor((-50.62607129324977*prob+6.575959357916722)*100)
                    elseif prob <= 0.1420480516058986 /\ prob > 0.05399137458004444 then
                           floor((-11.87410019056137*prob+4.483687170396419)*100)
                    elseif prob <= 0.2463455066216964 /\ prob > 0.1420480516058986 then
                           floor((-8.613130253286352*prob+4.020472744461092)*100)
                    elseif prob <= 0.595815289564374 /\ prob > 0.2463455066216964 then
                           floor((-3.761918786389538*prob+2.825398597919413)*100)
                    elseif prob <= 0.998000001 /\ prob > 0.595815289564374 then
                          floor((-1.444862453710759*prob+1.44486100812744)*100)
                    else
                          0
                    endif
);

predicate ubct_compute(
    array[0..nbit-1] of var 0..1: dL,
    array[0..nbit-1] of var 0..1: dR,
    array[0..nbit-1] of var 0..1: nL,
    array[0..nbit-1] of var 0..1: nR,
    array[0..nbit-1] of var 0..1: dLL,
    var int: ubct_approx,
    var int: ubct_prob
) =
let {
    array[1..nbit-1,0..3] of var int: dp_ubct;
    array[1..nbit-1] of var 0..31: tmp0;
    var int: ubct_value;
} in
(
    tmp0[1] = dLL[nbit-1]*16 + nR[nbit-1]*8 + nL[nbit-1]*4 + dR[nbit-1]*2 + dL[nbit-1]*1 /\

    dp_ubct[1,0] = tables_ubct[tmp0[1],0,0] /\
    dp_ubct[1,1] = tables_ubct[tmp0[1],1,0] /\
    dp_ubct[1,2] = tables_ubct[tmp0[1],2,0] /\
    dp_ubct[1,3] = tables_ubct[tmp0[1],3,0] /\

    forall(i in 2..nbit-1)(
        tmp0[i] = dLL[nbit-i]*16 + nR[nbit-i]*8 + nL[nbit-i]*4 + dR[nbit-i]*2 + dL[nbit-i]*1 /\
        forall(j in 0..3)(
            dp_ubct[i,j] = sum(k in 0..3)(dp_ubct[i-1,k] * tables_ubct[tmp0[i],j,k])
        )
    ) /\

    ubct_value =
        4 * sum(state in 0..3)(
            if (valid_state_ubct[state,0] + valid_state_ubct[state,1]
                + dLL[1] + nR[1] + nL[1]) mod 2 = 0
            then dp_ubct[nbit-1,state]
            else 0 endif
        ) /\
    approx_prob_log(ubct_value/2^30, ubct_approx)
    /\
    ubct_prob = floor((-log2(ubct_value) + 32) * 100)
);

var int: ubct_prob;
var int: approx_ubct;
constraint ubct_compute(dL, dR, nL, nR, dLL, approx_ubct, ubct_prob);


output[
      "-log_2(ubct_entry/2^32)*100 = \(ubct_prob)" ++ "\n" ++ "approx  -log_2(ubct_entry/2^32)*100 = \(approx_ubct)"
      ];