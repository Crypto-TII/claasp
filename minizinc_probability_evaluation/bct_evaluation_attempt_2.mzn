include "table.mzn";

array[0..15,0..15] of int: bct_table_evaluation = array2d(0..15,0..15,
[
4,2,2,0,0,2,0,0,0,0,2,0,0,0,0,0,
2,2,0,2,2,2,0,0,0,0,0,0,0,0,0,2,
2,2,0,0,2,2,2,0,0,0,2,0,0,0,0,0,
2,0,0,0,2,4,0,2,0,0,0,0,0,0,0,2,
2,0,2,2,0,0,0,0,2,0,2,0,0,0,0,2,
2,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,
0,0,0,0,0,2,0,0,0,2,0,0,0,0,0,0,
0,0,0,0,0,2,2,2,0,0,2,0,0,2,0,2,
2,0,2,0,0,2,0,0,2,2,2,0,0,0,0,0,
0,0,0,0,0,0,2,0,0,0,2,0,0,0,0,0,
0,0,0,2,0,0,0,0,0,0,0,0,0,0,0,2,
2,0,0,0,0,2,0,2,0,0,0,0,2,2,0,2,
2,0,0,0,0,0,0,0,2,0,4,2,0,0,0,2,
0,0,0,0,0,2,0,0,0,2,2,2,0,0,2,2,
2,0,0,0,0,0,0,0,0,0,2,2,2,0,2,2,
0,0,0,0,0,2,0,0,0,0,2,0,0,2,2,4
]);

%=================== VAR INT BASE ====================
function var int: lsb(var int: x) = x mod 2;
function var int: shift_right(var int: x) = x div 2;

%=================== MODELLO PRINCIPALE ====================

int: nbit = 16;
array[0..15] of var 0..1: pre_upper_modadd_0_1_0 = array1d(0..16-1, [0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]); %2^8 = 256
array[0..15] of var 0..1: pre_upper_modadd_0_1_1 = array1d(0..16-1, [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]); %2^15 = 32768
array[0..15] of var 0..1: pre_lower_modadd_0_1_0 = array1d(0..16-1, [0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0]); %2^4+2^5+2^6 = 112
array[0..15] of var 0..1: pre_lower_modadd_0_1_1 = array1d(0..16-1, [0,0,0,0,1,0,0,0,0,0,0,1,1,1,0,0]); %2^2+2^3+2^4+2^11 = 2076
var int: dL; var int: dR; var int: nL; var int: nR;

% Inizializza cnt[0..nbit,0..3]
array[0..nbit,0..3] of var int: cnt;
array[0..nbit] of var int: tot;

% Livello 0
constraint cnt[0,0] = 1;
constraint cnt[0,1] = 0;
constraint cnt[0,2] = 0;
constraint cnt[0,3] = 0;
constraint tot[0] = sum(i in 0..3)(cnt[0,i]);

% Loop sui livelli successivi
constraint
forall(l in 1..nbit-1) (
    let {
        var int: bdL = pre_upper_modadd_0_1_0[nbit-l];
        var int: bdR = pre_upper_modadd_0_1_1[nbit-l];
        var int: bnL = pre_lower_modadd_0_1_0[nbit-l];
        var int: bnR = pre_lower_modadd_0_1_1[nbit-l];
        var int: idx = bnR*8 + bnL*4 + bdR*2 + bdL
    } in
    forall(i in 0..3)(
        (tot[l-1] = 0) -> (cnt[l,i] = 0) /\
        (tot[l-1] != 0) -> (cnt[l,i] = sum(j in 0..3)(bct_table_evaluation[idx,i*4+j]*cnt[l-1,j]))
    ) /\
    tot[l] = sum(i in 0..3)(cnt[l,i])
);

% Risultato finale
var int: bct_result = 4 * sum(i in 0..3)(cnt[nbit-1,i]);
var float: bct_value = bct_result / 2^32;

%=================== ESEMPIO ====================


output ["bct_entry/2^32 = \(bct_value)"];
