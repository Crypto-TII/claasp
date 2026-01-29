float:lower=-1;
float:upper=1;

% This function corresponds to equation 5
function var lower..upper: continuous_xor_bit(var lower..upper: x, var lower..upper: y) = -1*x*y;

% This function corresponds to equation 5
function array [int] of var lower..upper: continuous_xor(array [int] of var float: aa,array [int] of var float: bb, array [int] of var float: output_diff) = 
let {
    int: n = length(aa);
    constraint output_diff = array1d(0..n-1, [continuous_xor_bit(aa[i], bb[i])|i in 0..n-1]);
} in 
output_diff;

% This function corresponds to equation 3
function var lower..upper: continuous_maj_bit(var lower..upper: x, var lower..upper: y, var lower..upper: z) = 0.25*(x+y+z+x*y*z);


% This function corresponds to equation 4
function array [int] of var lower..upper: continuous_modadd(array [int] of var float: aa,array [int] of var float: bb,array [int] of var float: output_diff)= let { 
    int: n = length(aa); 
    array [0..n-1] of var lower..upper: carry_diff; 
    constraint carry_diff[n-1] = -1; 
    constraint forall(i in 0..n-2)(carry_diff[n-i-2] = continuous_maj_bit(aa[n-i-1], bb[n-i-1], carry_diff[n-i-1])); 
    constraint output_diff = reverse(array1d(0..n-1,[continuous_xor_bit(continuous_xor_bit(aa[n-i-1], bb[n-i-1]), carry_diff[n-i-1]) |i in 0..n-1])); 
} in 
output_diff;



function array[int] of var lower..upper: continuous_LRot(array[int] of var lower..upper: X, int: val, array[int] of var lower..upper: output_LRot)=
let {
    int: n = length(X);
    constraint output_LRot = array1d(0..n-1, [X[(j+val) mod n] | j in 0..n-1]);
} in 
output_LRot;

function array[int] of var lower..upper: continuous_RRot(array[int] of var lower..upper: X, int: val, array[int] of var lower..upper: output_RRot)=
let {
    int: n = length(X);
    constraint output_RRot = array1d(0..n-1, [X[(n+j-val) mod n] | j in 0..n-1]);
} in 
output_RRot;

function array [int] of var lower..upper: cast(array [int] of var 0..1:int_var) = 
let {
    int: n = length(int_var);
} in 
    array1d(0..n-1, [if int_var[i] = 0 then -1.0 else 1.0 endif|i in 0..n-1]);

