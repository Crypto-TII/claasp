include "table.mzn";

int: nbit = 16;

%=================== INPUT PRE-CALCOLATI ===================
array[0..15] of var 0..1: pre_upper_modadd_0_1_0 = array1d(0..16-1, [0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);
array[0..15] of var 0..1: pre_upper_modadd_0_1_1 = array1d(0..16-1, [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..15] of var 0..1: pre_lower_modadd_0_1_0 = array1d(0..16-1, [0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0]);
array[0..15] of var 0..1: pre_lower_modadd_0_1_1 = array1d(0..16-1, [0,0,0,0,1,0,0,0,0,0,0,1,1,1,0,0]);
array[0..15] of var 0..1: upper_modadd_0_1 = array1d(0..16-1,[1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);


array[0..3,0..3] of 0..1: valid_state_ubct = array2d(0..3,0..3,
[
0,0,0,0,
0,0,1,1,
0,1,0,1,
0,1,1,0
]);


array[0..3,0..1] of 0..1: xy_array = array2d(0..3,0..1,
[
0,0,
0,1,
1,0,
1,1
]);

array[0..7] of int: state2index_ubct = array1d(0..7, [0, -1, -1, 1, -1, 2, 3, -1]);
array[0..7] of var 0..1: isValid_ubct = array1d(0..7, [1, 0, 0, 1, 0, 1, 1, 0]);

%=================== VARIABILI DECISIONALI ===================
array[0..14,0..3,0..3] of var int: index_dp_t_element_to_sum;
array[0..14,0..3] of var int: dp_t;
array[0..15,0..3] of var int: dp_ubct; 

%=================== INIZIALIZZAZIONE BASE ===================
constraint (dp_ubct[0,0] == 1);
constraint forall(k in 1..3)(dp_ubct[0,k] == 0);

var 0..1: bdL;
var 0..1: bdR;
var 0..1: bnL;
var 0..1: bnR;
var 0..1: bdLL;

array[0..3] of var 0..1: valid_state_0bit;
array[0..3] of var 0..1: valid_state_2bit;
array[0..0,0..3] of var 0..1: c1;
array[0..0,0..3] of var 0..1: b1;
array[0..0,0..3] of var 0..1: c2;
array[0..0,0..3] of var 0..1: b2;
array[0..0,0..3] of var 0..1: condition;

%=================== ITERAZIONE PRINCIPALE ===================
%% until nbit-4 it works
%% for nbit-1 i have overflow
constraint
forall(l in 1..1) (

         (bdL == pre_upper_modadd_0_1_0[nbit-l]) /\
         (bdR == pre_upper_modadd_0_1_1[nbit-l]) /\
         (bnL == pre_lower_modadd_0_1_0[nbit-l]) /\
         (bnR == pre_lower_modadd_0_1_1[nbit-l]) /\
         (bdLL == upper_modadd_0_1[nbit-l]) /\

    forall(state in 0..3) (
        (valid_state_0bit[state] == c1[0,state])/\
        (valid_state_2bit[state] == c2[0,state])/\
        (c1[0,state] == valid_state_ubct[state,3])/\
        (b1[0,state] == valid_state_ubct[state,2])/\
        (c2[0,state] == valid_state_ubct[state,1])/\
        (b2[0,state] == valid_state_ubct[state,0])/\
        (condition[0,state] == (valid_state_0bit[state] + valid_state_2bit[state] + bdLL + bdR + bdL) mod 2)/\
         
        (condition[0,state] !=0) -> (forall(xy in 0..3) (index_dp_t_element_to_sum[l-1,state,xy] = 1)) /\
        (condition[0,state] = 0) -> (
        forall(xy in 0..3)(
                let {
                     var 0..1: x = xy_array[xy,0]; %msb bit
                     var 0..1: y = xy_array[xy,1]; %lsb bit
                     var 0..1: tmp1 = (x*y + x*c1[0,state] + y*c1[0,state]) mod 2;
                     var 0..1: app2_0 = (x+y+c1[0,state]+bnL+1) mod 2;
                     var 0..1: app2_1 = (y+bnR) mod 2;
                     var 0..1: tmp2 = min(1,(app2_0*app2_1)+(app2_0*b1[0,state])+(app2_1*b1[0,state]));
                     var 0..1: app3_0 = (x+bdL) mod 2;
                     var 0..1: app3_1 = (y+bdR) mod 2;
                     var 0..1: tmp3 = ((app3_0*app3_1)+(app3_0*c2[0,state])+(app3_1*c2[0,state])) mod 2;
                     var 0..1: app4_0 = (x+bdL+y+bdR+c2[0,state]+bdL) mod 2;
                     var 0..1: app4_1 = (y+bdR+bnR) mod 2;
                     var 0..1: tmp4 = min(1,(app4_0*app4_1)+(app4_0*b2[0,state])+(app4_1*b2[0,state]));
                     var int: next_state;
                } in
                (next_state = if tmp4=0 then tmp3*4 + tmp2*2 + tmp1
                                     else (tmp3+1 mod 2)*4 + (tmp2+1 mod 2)*2 + (tmp1+1 mod 2)
                                     endif) /\
                (index_dp_t_element_to_sum[l-1,state,xy] = next_state)
            )
        )   
    ) /\
    forall(j in 0..3)(
    dp_t[l-1,j] =
        sum(state in 0..3, xy in 0..3)(
            let {
                var int: ns = index_dp_t_element_to_sum[l-1,state,xy];
            } in
            if isValid_ubct[ns] = 1 /\ state2index_ubct[ns] = j
            then dp_ubct[l-1,state]
            else 0 endif
        )
    ) /\
    forall(k in 0..3)(dp_ubct[l,k] = dp_t[l-1,k])
);

%=================== CALCOLO PROBABILITÀ ===================
var int: ubct_prob;
constraint ubct_prob = 4 * sum(state in 0..3)(
    let {
        var 0..1: dL = pre_upper_modadd_0_1_0[0];
        var 0..1: dR = pre_upper_modadd_0_1_1[0];
        var 0..1: nL = pre_lower_modadd_0_1_0[0];
        var 0..1: nR = pre_lower_modadd_0_1_1[0];
        var 0..1: dLL = upper_modadd_0_1[0];
        var 0..1: state_0bit = valid_state_ubct[state,3];
        var 0..1: state_2bit = valid_state_ubct[state,1];
    } in
    if (state_0bit + state_2bit + dLL + dR + dL) mod 2 = 0 then
        dp_ubct[1,state]
    else 0
    endif
);

var float: ubct_value = ubct_prob / 2^32;

%=================== OUTPUT ===================
output ["ubct_entry/2^32 = \(ubct_value)"];

output [
  "ubct_entry/2^32 = \(ubct_value)\n\n",
  "bdL = \(bdL), bdR = \(bdR), bnL =\(bnL), bnR =\(bnR), bdLL = \(bdLL) \n\n",
  concat(["c1[\(state)] = \(c1[0,state]) " | state in 0..3]) ++ "\n",
  concat(["b1[\(state)] = \(b1[0,state]) " | state in 0..3]) ++ "\n",
  concat(["c2[\(state)] = \(c2[0,state]) " | state in 0..3]) ++ "\n",
  concat(["b2[\(state)] = \(b2[0,state]) " | state in 0..3]) ++ "\n",
  "valid_ubct:\n",
  concat([concat(["(\(state),\(column)): \(valid_state_ubct[state,column]) " | column in 0..3]) ++ "\n" | state in 0..3]),
  "index_dp_t_element_to_sum:\n",
  concat([
    "l = \(l)\n" ++ concat([
          "  state = \(s): " ++ concat([
                             "\(index_dp_t_element_to_sum[l,s,xy]) " | xy in 0..3]) ++ "\n"
         | s in 0..3]) ++ "\n"
    | l in 0..0])
];

