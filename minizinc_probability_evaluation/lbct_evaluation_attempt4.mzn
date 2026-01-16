include "table.mzn";

int: nbit = 16;

%=================== INPUT PRE-CALCOLATI ===================
array[0..15] of var 0..1: pre_upper_modadd_1_7_0 = array1d(0..16-1, [0,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0]);
array[0..15] of var 0..1: pre_upper_modadd_1_7_1 = array1d(0..16-1, [1,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0]);
array[0..15] of var 0..1: pre_lower_modadd_1_7_0 = array1d(0..16-1, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..15] of var 0..1: pre_lower_modadd_1_7_1 = array1d(0..16-1, [0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0]);
array[0..15] of var 0..1: lower_modadd_1_7 = array1d(0..16-1, [1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0]);

array[0..7,0..4] of var 0..1: valid_state_lbct = array2d(0..7,0..4,
[
0,0,0,0,0,
0,0,0,1,1,
0,0,1,0,1,
0,0,1,1,0,
0,1,0,0,1,
0,1,0,1,0,
0,1,1,0,0,
0,1,1,1,1
]);

array[0..15] of int: state2index_lbct = array1d(0..15, [0, -1, -1, 1, -1, 2, 3, -1, -1, 4, 5, -1, 6, -1, -1, 7]);
array[0..15] of var 0..1: isValid_lbct = array1d(0..15, [1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1]);

%=================== VARIABILI DECISIONALI ===================
array[0..14,0..7,0..3] of var 0..31: index_dp_t_element_to_sum;
array[0..14,0..7] of var int: dp_t;
array[0..15,0..7] of var int: dp_lbct;

%=================== INIZIALIZZAZIONE BASE ===================
constraint dp_lbct[0,0] = 1;
constraint forall(k in 1..7)(dp_lbct[0,k] = 0);

%=================== ITERAZIONE PRINCIPALE ===================
%% until nbit-4 it works
%% for nbit-1 i have overflow
constraint
forall(l in 1..nbit-1) (
    let {
         var 0..1: bdL = pre_upper_modadd_1_7_0[nbit-l];
         var 0..1: bdR = pre_upper_modadd_1_7_1[nbit-l];
         var 0..1: bnL = pre_lower_modadd_1_7_0[nbit-l];
         var 0..1: bnR = pre_lower_modadd_1_7_1[nbit-l];
         var 0..1: bnLL = lower_modadd_1_7[nbit-l];
    } in
    forall(state in 0..7) (
        let {
             var 0..1: valid_state_0bit = valid_state_lbct[state,4];
             var 0..1: valid_state_4bit = valid_state_lbct[state,0];
             var 0..1: c1 = valid_state_lbct[state,4];
             var 0..1: b1 = valid_state_lbct[state,3];
             var 0..1: c2 = valid_state_lbct[state,2];
             var 0..1: b2 = valid_state_lbct[state,1];
             var 0..1: c3 = valid_state_lbct[state,0];
             var 0..1: condition = (valid_state_0bit + valid_state_4bit + bnLL + bnR + bnL) mod 2;
        } in 
        (condition !=0) -> (forall(xy in 0..3) (index_dp_t_element_to_sum[l-1,state,xy] = 1)) /\
        (condition = 0) -> (
        forall(xy in 0..3)(
                let {
                     var 0..1: x = xy div 2;
                     var 0..1: y = xy mod 2;
                     var 0..1: tmp1 = (x*y + x*c1 + y*c1) mod 2;
                     var 0..1: app2_0 = (x+y+c1+bnL+1) mod 2;
                     var 0..1: app2_1 = (y+bnR) mod 2;
                     var 0..1: tmp2 = min(1,(app2_0*app2_1)+(app2_0*b1)+(app2_1*b1));
                     var 0..1: app3_0 = (x+bdL) mod 2;
                     var 0..1: app3_1 = (y+bdR) mod 2;
                     var 0..1: tmp3 = ((app3_0*app3_1)+(app3_0*c2)+(app3_1*c2)) mod 2;
                     var 0..1: app4_0 = (x+bdL+y+bdR+c2+bdL) mod 2;
                     var 0..1: app4_1 = (y+bdR+bnR) mod 2;
                     var 0..1: tmp4 = min(1,(app4_0*app4_1)+(app4_0*b2)+(app4_1*b2));
                     var 0..1: app5_0 = (x+bnLL) mod 2;
                     var 0..1: app5_1 = (y+bnR) mod 2;
                     var 0..1: tmp5 = (app5_0*app5_1)+(app5_0*c3)+(app5_1*c3) mod 2;
                     var 0..31: next_state = if tmp5=0 then tmp4*8 + tmp3*4 + tmp2*2 + tmp1
                                     else ((tmp4+1 mod 2)*8 + (tmp3+1 mod 2)*4 + (tmp2+1 mod 2)*2 + (tmp1+1 mod 2))
                                     endif;
                } in
                (index_dp_t_element_to_sum[l-1,state,xy] = next_state)
            )
        )   
    ) /\
    forall(j in 0..7)(
    dp_t[l-1,j] =
        sum(state in 0..7, xy in 0..3)(
            let {
                var 0..31: ns = index_dp_t_element_to_sum[l-1,state,xy];
            } in
            if isValid_lbct[ns] = 1 /\ state2index_lbct[ns] = j
            then dp_lbct[l-1,state]
            else 0 endif
        )
    ) /\
    forall(k in 0..7)(dp_lbct[l,k] = dp_t[l-1,k])
);

%=================== CALCOLO PROBABILITÀ ===================
var int: lbct_prob;
constraint lbct_prob = 4 * sum(state in 0..7)(
    let {
        var 0..1: bdL = pre_upper_modadd_1_7_0[nbit-1];
        var 0..1: bdR = pre_upper_modadd_1_7_1[nbit-1];
        var 0..1: bnL = pre_lower_modadd_1_7_0[nbit-1];
        var 0..1: bnR = pre_lower_modadd_1_7_1[nbit-1];
        var 0..1: bnLL = lower_modadd_1_7[nbit-1];
        var 0..1: valid_state_0bit = valid_state_lbct[state,4];
        var 0..1: valid_state_4bit = valid_state_lbct[state,0];
    } in
    if (valid_state_0bit + valid_state_4bit + bnLL + bnR + bnL) mod 2 = 0 then
        dp_lbct[nbit-1,state]
    else 0
    endif
);

var float: lbct_value = lbct_prob / 2^32;

%=================== OUTPUT ===================
output ["lbct_entry/2^32 = \(lbct_value)"];
