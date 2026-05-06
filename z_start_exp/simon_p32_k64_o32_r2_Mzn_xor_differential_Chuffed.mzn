include "globals.mzn";

include "globals.mzn";

% XOR of 2 arrays
function array[int] of var 0..1: Xor2(array[int] of var 0..1: a, array[int] of var 0..1: b)=
array1d(0..(length(a)-1), [(a[j]+b[j]) mod 2  | j in 0..(length(a)-1)]);

% XOR of 3 arrays
function array[int] of var 0..1: Xor3(array[int] of var 0..1: a, array[int] of var 0..1: b, array[int] of var 0..1: c)=
array1d(0..(length(a)-1), [(a[j]+b[j]+c[j]) mod 2  | j in 0..(length(a)-1)]);

% If a and b are known, then regular XOR. Otherwise, c is unknown (=2)
predicate xor_bit_p1(var 0..2:a, var 0..2:b, var 0..2:c) =
if ((a<2) /\ (b<2)) then (c=(a+b) mod 2) else c = 2 endif;

% AND of 2 arrays
function array[int] of var 0..1: And(array[int] of var 0..1: a, array[int] of var 0..1: b)=
array1d(0..(length(a)-1), [(a[j]*b[j]) mod 2  | j in 0..(length(a)-1)]);

% OR of 2 arrays
function array[int] of var 0..1: OR(array[int] of var 0..1: a, array[int] of var 0..1: b)=
array1d(0..(length(a)-1), [(a[j]+b[j]+a[j]*b[j]) mod 2  | j in 0..(length(a)-1)]);

% Compl of an array
function array[int] of var 0..1: Compl(array[int] of var 0..1: a)=
array1d(0..(length(a)-1), [a[j]+1 mod 2| j in 0..(length(a)-1)]);

% ANDZ of 2 arrays
function array[int] of var 0..1: Andz(array[int] of var 0..1: a, array[int] of var 0..1: b, array[int] of var 0..1: c)=
array1d(0..(length(a)-1), [(c[j]*(a[j]+b[j]+a[j]*b[j]+1)) mod 2 | j in 0..(length(a)-1)]);

% Eq
function array[int] of var 0..1: Eq(array[int] of var 0..1: a, array[int] of var 0..1: b, array[int] of var 0..1: c)=
array1d(0..(length(a)-1), [all_equal([a[j],b[j],c[j]]) | j in 0..length(a)-1]);

% Left rotation of X by val positions
function array[int] of var 0..1: LRot(array[int] of var 0..1: X, var int: val)=
array1d(0..(length(X)-1), [X[(j+val) mod length(X)] | j in 0..(length(X)-1)]);

% Right rotation of X by val positions
function array[int] of var 0..1: RRot(array[int] of var 0..1: X, var int: val)=
array1d(0..(length(X)-1), [X[(length(X)+j-val) mod length(X)] | j in 0..(length(X)-1)]);

% Left shift of X by val positions
function array[int] of var 0..2: LShift(array[int] of var 0..2: X, var int:val)=
array1d(0..(length(X)-1), [if j<length(X)-val then X[(j+val) mod length(X)] else 0 endif | j in 0..(length(X)-1)]);

% Right shift of X by val positions
function array[int] of var 0..1: RShift(array[int] of var 0..1: X, var int:val)=
array1d(0..(length(X)-1), [if j>val-1 then X[(j-val) mod length(X)] else 0 endif | j in 0..(length(X)-1)]);

%BitToInt
predicate bitArrayToInt(array[int] of var 0..1: a, var int: n) =
          let { int: len = length(a) }
          in
          n = sum(i in 1..len) (
            ceil(pow(2, int2float(len-i))) * a[i]
          )
          /\ forall(i in 1..len) (a[i] >= 0)
;

%IntToBit
predicate IntTobitArray(array[1..8] of var 0..1: a, int: n) = if n==0 then forall(i in 1..8)(a[i]=0) elseif n==1 then a[8]=1 /\ forall(i in 1..7)(a[i]=0) else
          let { float: len = log2(n);
          var int : len1 = floor(len);}
          in
          forall(i in 0..7)(a[8-i]=(n div pow(2,i) mod 2)) endif
;

%IntToBitOfFixedLength
function array[int] of var 0..1: IntToBitLen(int: n, int: len)=
array1d(0..(len-1), [floor(n/(pow(2,len-j-1))) mod 2  | j in 0..(len-1)]);

%Count elements in array
predicate count_eq(array[int] of var int: x, var int: y, var int: c) =
    c = sum(i in index_set(x)) ( bool2int(x[i] == y) );
    
%Modular addition for xor linear
predicate modadd_linear(array[int] of var 0..1: a, array[int] of var 0..1: b, array[int] of var 0..1: c, var int:p) = (
   let {
    array [0..length(a)] of var 0..1: state,
    array [0..length(a)-1] of var 0..1: prob,
    array [0..length(a)-1] of var 0..1: X=Xor3(a,b,c)
   } in
   state[0]=0 /\
   forall (i in 0..length(a)-1)(
        if state[i]==0 then all_equal([a[i],b[i],c[i]]) else true endif /\
        state[i+1]=((X[i]+state[i]) mod 2) /\
        if state[i]==1 then prob[i]=1 else prob[i]=0 endif) /\
   p=100 * sum(prob)
);

%Modular addition for cipher
predicate modadd(array[int] of var 0..1: a, array[int] of var 0..1: b, array[int] of var 0..1: c) = (
   let {
    array [0..length(a)-1] of var 0..1: carry,
   } in
   carry[length(a)-1] = 0  /\ forall (i in 0..length(a)-2)(carry[i] = ((carry[i+1]*a[i+1]+a[i+1]*b[i+1]+carry[i+1]*b[i+1]) mod 2))/\ forall (i in 0..length(a)-1)(c[i] = ((a[i] + b[i] + carry[i]) mod 2))
);

% Modular addition for truncated
predicate modular_addition_word(array[int] of var 0..2: a, array[int] of var 0..2: b,array[int] of var 0..2:c) = (
  let {
    array [0..length(a)-1] of var 0..2: as = LShift(a,1),
    array [0..length(a)-1] of var 0..2: bs = LShift(b,1),
    array [0..length(a)-1] of var 0..2: cs = LShift(c,1),
    var 0..length(a)-1: pivot;
  } in
  forall (i in 0..length(a)-1) (
    if i<pivot then c[i]=2 else (as[i]=0) /\ (bs[i]=0) /\ (cs[i]=0) endif
  ) /\
  xor_bit_p1(a[pivot],b[pivot],c[pivot])
  /\ if pivot>0 then a[pivot]+b[pivot]>0 else true endif
);

%Hamming weight of an array
function var 0..512: Ham_weight(array[int] of var int: x) = sum(i in index_set(x))(x[i] != 0);

array[0..31] of var 0..1: plaintext;
array[0..63] of var 0..1: key;
array[0..15] of var 0..1: intermediate_output_0_0;
array[0..15] of var 0..1: rot_0_1;
array[0..15] of var 0..1: rot_0_2;
array[0..15] of var 0..1: rot_0_3;
array[0..15] of var 0..1: and_0_4;
array [1..7, 1..4] of int: and2inputs_DDT = array2d(1..7, 1..4, [0,0,0,0,0,1,0,100,0,1,1,100,1,0,0,100,1,0,1,100,1,1,0,100,1,1,1,100]);
array[0..15] of var 0..1: xor_0_5;
array[0..15] of var 0..1: xor_0_6;
array[0..31] of var 0..1: intermediate_output_0_7;
array[0..15] of var 0..1: intermediate_output_1_0;
array[0..15] of var 0..1: rot_1_1;
array[0..15] of var 0..1: rot_1_2;
array[0..15] of var 0..1: rot_1_3;
array[0..15] of var 0..1: and_1_4;
array[0..15] of var 0..1: xor_1_5;
array[0..15] of var 0..1: xor_1_6;
array[0..31] of var 0..1: intermediate_output_1_7;
array[0..31] of var 0..1: cipher_output_1_8;
array[0..63] of var {0, 100}: p;
var int: weight = sum(p);
constraint weight = 100;
constraint key[0] = 0 /\ key[1] = 0 /\ key[2] = 0 /\ key[3] = 0 /\ key[4] = 0 /\ key[5] = 0 /\ key[6] = 0 /\ key[7] = 0 /\ key[8] = 0 /\ key[9] = 0 /\ key[10] = 0 /\ key[11] = 0 /\ key[12] = 0 /\ key[13] = 0 /\ key[14] = 0 /\ key[15] = 0 /\ key[16] = 0 /\ key[17] = 0 /\ key[18] = 0 /\ key[19] = 0 /\ key[20] = 0 /\ key[21] = 0 /\ key[22] = 0 /\ key[23] = 0 /\ key[24] = 0 /\ key[25] = 0 /\ key[26] = 0 /\ key[27] = 0 /\ key[28] = 0 /\ key[29] = 0 /\ key[30] = 0 /\ key[31] = 0 /\ key[32] = 0 /\ key[33] = 0 /\ key[34] = 0 /\ key[35] = 0 /\ key[36] = 0 /\ key[37] = 0 /\ key[38] = 0 /\ key[39] = 0 /\ key[40] = 0 /\ key[41] = 0 /\ key[42] = 0 /\ key[43] = 0 /\ key[44] = 0 /\ key[45] = 0 /\ key[46] = 0 /\ key[47] = 0 /\ key[48] = 0 /\ key[49] = 0 /\ key[50] = 0 /\ key[51] = 0 /\ key[52] = 0 /\ key[53] = 0 /\ key[54] = 0 /\ key[55] = 0 /\ key[56] = 0 /\ key[57] = 0 /\ key[58] = 0 /\ key[59] = 0 /\ key[60] = 0 /\ key[61] = 0 /\ key[62] = 0 /\ key[63] = 0;
constraint plaintext[0] != 0 \/ plaintext[1] != 0 \/ plaintext[2] != 0 \/ plaintext[3] != 0 \/ plaintext[4] != 0 \/ plaintext[5] != 0 \/ plaintext[6] != 0 \/ plaintext[7] != 0 \/ plaintext[8] != 0 \/ plaintext[9] != 0 \/ plaintext[10] != 0 \/ plaintext[11] != 0 \/ plaintext[12] != 0 \/ plaintext[13] != 0 \/ plaintext[14] != 0 \/ plaintext[15] != 0 \/ plaintext[16] != 0 \/ plaintext[17] != 0 \/ plaintext[18] != 0 \/ plaintext[19] != 0 \/ plaintext[20] != 0 \/ plaintext[21] != 0 \/ plaintext[22] != 0 \/ plaintext[23] != 0 \/ plaintext[24] != 0 \/ plaintext[25] != 0 \/ plaintext[26] != 0 \/ plaintext[27] != 0 \/ plaintext[28] != 0 \/ plaintext[29] != 0 \/ plaintext[30] != 0 \/ plaintext[31] != 0;
constraint intermediate_output_0_0[0] = key[48];
constraint intermediate_output_0_0[1] = key[49];
constraint intermediate_output_0_0[2] = key[50];
constraint intermediate_output_0_0[3] = key[51];
constraint intermediate_output_0_0[4] = key[52];
constraint intermediate_output_0_0[5] = key[53];
constraint intermediate_output_0_0[6] = key[54];
constraint intermediate_output_0_0[7] = key[55];
constraint intermediate_output_0_0[8] = key[56];
constraint intermediate_output_0_0[9] = key[57];
constraint intermediate_output_0_0[10] = key[58];
constraint intermediate_output_0_0[11] = key[59];
constraint intermediate_output_0_0[12] = key[60];
constraint intermediate_output_0_0[13] = key[61];
constraint intermediate_output_0_0[14] = key[62];
constraint intermediate_output_0_0[15] = key[63];
constraint rot_0_1[0] = plaintext[1];
constraint rot_0_1[1] = plaintext[2];
constraint rot_0_1[2] = plaintext[3];
constraint rot_0_1[3] = plaintext[4];
constraint rot_0_1[4] = plaintext[5];
constraint rot_0_1[5] = plaintext[6];
constraint rot_0_1[6] = plaintext[7];
constraint rot_0_1[7] = plaintext[8];
constraint rot_0_1[8] = plaintext[9];
constraint rot_0_1[9] = plaintext[10];
constraint rot_0_1[10] = plaintext[11];
constraint rot_0_1[11] = plaintext[12];
constraint rot_0_1[12] = plaintext[13];
constraint rot_0_1[13] = plaintext[14];
constraint rot_0_1[14] = plaintext[15];
constraint rot_0_1[15] = plaintext[0];
constraint rot_0_2[0] = plaintext[8];
constraint rot_0_2[1] = plaintext[9];
constraint rot_0_2[2] = plaintext[10];
constraint rot_0_2[3] = plaintext[11];
constraint rot_0_2[4] = plaintext[12];
constraint rot_0_2[5] = plaintext[13];
constraint rot_0_2[6] = plaintext[14];
constraint rot_0_2[7] = plaintext[15];
constraint rot_0_2[8] = plaintext[0];
constraint rot_0_2[9] = plaintext[1];
constraint rot_0_2[10] = plaintext[2];
constraint rot_0_2[11] = plaintext[3];
constraint rot_0_2[12] = plaintext[4];
constraint rot_0_2[13] = plaintext[5];
constraint rot_0_2[14] = plaintext[6];
constraint rot_0_2[15] = plaintext[7];
constraint rot_0_3[0] = plaintext[2];
constraint rot_0_3[1] = plaintext[3];
constraint rot_0_3[2] = plaintext[4];
constraint rot_0_3[3] = plaintext[5];
constraint rot_0_3[4] = plaintext[6];
constraint rot_0_3[5] = plaintext[7];
constraint rot_0_3[6] = plaintext[8];
constraint rot_0_3[7] = plaintext[9];
constraint rot_0_3[8] = plaintext[10];
constraint rot_0_3[9] = plaintext[11];
constraint rot_0_3[10] = plaintext[12];
constraint rot_0_3[11] = plaintext[13];
constraint rot_0_3[12] = plaintext[14];
constraint rot_0_3[13] = plaintext[15];
constraint rot_0_3[14] = plaintext[0];
constraint rot_0_3[15] = plaintext[1];
constraint table([rot_0_1[0]]++[rot_0_2[0]]++[and_0_4[0]]++[p[0]],and2inputs_DDT);
constraint table([rot_0_1[1]]++[rot_0_2[1]]++[and_0_4[1]]++[p[1]],and2inputs_DDT);
constraint table([rot_0_1[2]]++[rot_0_2[2]]++[and_0_4[2]]++[p[2]],and2inputs_DDT);
constraint table([rot_0_1[3]]++[rot_0_2[3]]++[and_0_4[3]]++[p[3]],and2inputs_DDT);
constraint table([rot_0_1[4]]++[rot_0_2[4]]++[and_0_4[4]]++[p[4]],and2inputs_DDT);
constraint table([rot_0_1[5]]++[rot_0_2[5]]++[and_0_4[5]]++[p[5]],and2inputs_DDT);
constraint table([rot_0_1[6]]++[rot_0_2[6]]++[and_0_4[6]]++[p[6]],and2inputs_DDT);
constraint table([rot_0_1[7]]++[rot_0_2[7]]++[and_0_4[7]]++[p[7]],and2inputs_DDT);
constraint table([rot_0_1[8]]++[rot_0_2[8]]++[and_0_4[8]]++[p[8]],and2inputs_DDT);
constraint table([rot_0_1[9]]++[rot_0_2[9]]++[and_0_4[9]]++[p[9]],and2inputs_DDT);
constraint table([rot_0_1[10]]++[rot_0_2[10]]++[and_0_4[10]]++[p[10]],and2inputs_DDT);
constraint table([rot_0_1[11]]++[rot_0_2[11]]++[and_0_4[11]]++[p[11]],and2inputs_DDT);
constraint table([rot_0_1[12]]++[rot_0_2[12]]++[and_0_4[12]]++[p[12]],and2inputs_DDT);
constraint table([rot_0_1[13]]++[rot_0_2[13]]++[and_0_4[13]]++[p[13]],and2inputs_DDT);
constraint table([rot_0_1[14]]++[rot_0_2[14]]++[and_0_4[14]]++[p[14]],and2inputs_DDT);
constraint table([rot_0_1[15]]++[rot_0_2[15]]++[and_0_4[15]]++[p[15]],and2inputs_DDT);
constraint xor_0_5[0] = (and_0_4[0] + rot_0_3[0]) mod 2;
constraint xor_0_5[1] = (and_0_4[1] + rot_0_3[1]) mod 2;
constraint xor_0_5[2] = (and_0_4[2] + rot_0_3[2]) mod 2;
constraint xor_0_5[3] = (and_0_4[3] + rot_0_3[3]) mod 2;
constraint xor_0_5[4] = (and_0_4[4] + rot_0_3[4]) mod 2;
constraint xor_0_5[5] = (and_0_4[5] + rot_0_3[5]) mod 2;
constraint xor_0_5[6] = (and_0_4[6] + rot_0_3[6]) mod 2;
constraint xor_0_5[7] = (and_0_4[7] + rot_0_3[7]) mod 2;
constraint xor_0_5[8] = (and_0_4[8] + rot_0_3[8]) mod 2;
constraint xor_0_5[9] = (and_0_4[9] + rot_0_3[9]) mod 2;
constraint xor_0_5[10] = (and_0_4[10] + rot_0_3[10]) mod 2;
constraint xor_0_5[11] = (and_0_4[11] + rot_0_3[11]) mod 2;
constraint xor_0_5[12] = (and_0_4[12] + rot_0_3[12]) mod 2;
constraint xor_0_5[13] = (and_0_4[13] + rot_0_3[13]) mod 2;
constraint xor_0_5[14] = (and_0_4[14] + rot_0_3[14]) mod 2;
constraint xor_0_5[15] = (and_0_4[15] + rot_0_3[15]) mod 2;
constraint xor_0_6[0] = (plaintext[16] + xor_0_5[0] + key[48]) mod 2;
constraint xor_0_6[1] = (plaintext[17] + xor_0_5[1] + key[49]) mod 2;
constraint xor_0_6[2] = (plaintext[18] + xor_0_5[2] + key[50]) mod 2;
constraint xor_0_6[3] = (plaintext[19] + xor_0_5[3] + key[51]) mod 2;
constraint xor_0_6[4] = (plaintext[20] + xor_0_5[4] + key[52]) mod 2;
constraint xor_0_6[5] = (plaintext[21] + xor_0_5[5] + key[53]) mod 2;
constraint xor_0_6[6] = (plaintext[22] + xor_0_5[6] + key[54]) mod 2;
constraint xor_0_6[7] = (plaintext[23] + xor_0_5[7] + key[55]) mod 2;
constraint xor_0_6[8] = (plaintext[24] + xor_0_5[8] + key[56]) mod 2;
constraint xor_0_6[9] = (plaintext[25] + xor_0_5[9] + key[57]) mod 2;
constraint xor_0_6[10] = (plaintext[26] + xor_0_5[10] + key[58]) mod 2;
constraint xor_0_6[11] = (plaintext[27] + xor_0_5[11] + key[59]) mod 2;
constraint xor_0_6[12] = (plaintext[28] + xor_0_5[12] + key[60]) mod 2;
constraint xor_0_6[13] = (plaintext[29] + xor_0_5[13] + key[61]) mod 2;
constraint xor_0_6[14] = (plaintext[30] + xor_0_5[14] + key[62]) mod 2;
constraint xor_0_6[15] = (plaintext[31] + xor_0_5[15] + key[63]) mod 2;
constraint intermediate_output_0_7[0] = xor_0_6[0];
constraint intermediate_output_0_7[1] = xor_0_6[1];
constraint intermediate_output_0_7[2] = xor_0_6[2];
constraint intermediate_output_0_7[3] = xor_0_6[3];
constraint intermediate_output_0_7[4] = xor_0_6[4];
constraint intermediate_output_0_7[5] = xor_0_6[5];
constraint intermediate_output_0_7[6] = xor_0_6[6];
constraint intermediate_output_0_7[7] = xor_0_6[7];
constraint intermediate_output_0_7[8] = xor_0_6[8];
constraint intermediate_output_0_7[9] = xor_0_6[9];
constraint intermediate_output_0_7[10] = xor_0_6[10];
constraint intermediate_output_0_7[11] = xor_0_6[11];
constraint intermediate_output_0_7[12] = xor_0_6[12];
constraint intermediate_output_0_7[13] = xor_0_6[13];
constraint intermediate_output_0_7[14] = xor_0_6[14];
constraint intermediate_output_0_7[15] = xor_0_6[15];
constraint intermediate_output_0_7[16] = plaintext[0];
constraint intermediate_output_0_7[17] = plaintext[1];
constraint intermediate_output_0_7[18] = plaintext[2];
constraint intermediate_output_0_7[19] = plaintext[3];
constraint intermediate_output_0_7[20] = plaintext[4];
constraint intermediate_output_0_7[21] = plaintext[5];
constraint intermediate_output_0_7[22] = plaintext[6];
constraint intermediate_output_0_7[23] = plaintext[7];
constraint intermediate_output_0_7[24] = plaintext[8];
constraint intermediate_output_0_7[25] = plaintext[9];
constraint intermediate_output_0_7[26] = plaintext[10];
constraint intermediate_output_0_7[27] = plaintext[11];
constraint intermediate_output_0_7[28] = plaintext[12];
constraint intermediate_output_0_7[29] = plaintext[13];
constraint intermediate_output_0_7[30] = plaintext[14];
constraint intermediate_output_0_7[31] = plaintext[15];
constraint intermediate_output_1_0[0] = key[32];
constraint intermediate_output_1_0[1] = key[33];
constraint intermediate_output_1_0[2] = key[34];
constraint intermediate_output_1_0[3] = key[35];
constraint intermediate_output_1_0[4] = key[36];
constraint intermediate_output_1_0[5] = key[37];
constraint intermediate_output_1_0[6] = key[38];
constraint intermediate_output_1_0[7] = key[39];
constraint intermediate_output_1_0[8] = key[40];
constraint intermediate_output_1_0[9] = key[41];
constraint intermediate_output_1_0[10] = key[42];
constraint intermediate_output_1_0[11] = key[43];
constraint intermediate_output_1_0[12] = key[44];
constraint intermediate_output_1_0[13] = key[45];
constraint intermediate_output_1_0[14] = key[46];
constraint intermediate_output_1_0[15] = key[47];
constraint rot_1_1[0] = xor_0_6[1];
constraint rot_1_1[1] = xor_0_6[2];
constraint rot_1_1[2] = xor_0_6[3];
constraint rot_1_1[3] = xor_0_6[4];
constraint rot_1_1[4] = xor_0_6[5];
constraint rot_1_1[5] = xor_0_6[6];
constraint rot_1_1[6] = xor_0_6[7];
constraint rot_1_1[7] = xor_0_6[8];
constraint rot_1_1[8] = xor_0_6[9];
constraint rot_1_1[9] = xor_0_6[10];
constraint rot_1_1[10] = xor_0_6[11];
constraint rot_1_1[11] = xor_0_6[12];
constraint rot_1_1[12] = xor_0_6[13];
constraint rot_1_1[13] = xor_0_6[14];
constraint rot_1_1[14] = xor_0_6[15];
constraint rot_1_1[15] = xor_0_6[0];
constraint rot_1_2[0] = xor_0_6[8];
constraint rot_1_2[1] = xor_0_6[9];
constraint rot_1_2[2] = xor_0_6[10];
constraint rot_1_2[3] = xor_0_6[11];
constraint rot_1_2[4] = xor_0_6[12];
constraint rot_1_2[5] = xor_0_6[13];
constraint rot_1_2[6] = xor_0_6[14];
constraint rot_1_2[7] = xor_0_6[15];
constraint rot_1_2[8] = xor_0_6[0];
constraint rot_1_2[9] = xor_0_6[1];
constraint rot_1_2[10] = xor_0_6[2];
constraint rot_1_2[11] = xor_0_6[3];
constraint rot_1_2[12] = xor_0_6[4];
constraint rot_1_2[13] = xor_0_6[5];
constraint rot_1_2[14] = xor_0_6[6];
constraint rot_1_2[15] = xor_0_6[7];
constraint rot_1_3[0] = xor_0_6[2];
constraint rot_1_3[1] = xor_0_6[3];
constraint rot_1_3[2] = xor_0_6[4];
constraint rot_1_3[3] = xor_0_6[5];
constraint rot_1_3[4] = xor_0_6[6];
constraint rot_1_3[5] = xor_0_6[7];
constraint rot_1_3[6] = xor_0_6[8];
constraint rot_1_3[7] = xor_0_6[9];
constraint rot_1_3[8] = xor_0_6[10];
constraint rot_1_3[9] = xor_0_6[11];
constraint rot_1_3[10] = xor_0_6[12];
constraint rot_1_3[11] = xor_0_6[13];
constraint rot_1_3[12] = xor_0_6[14];
constraint rot_1_3[13] = xor_0_6[15];
constraint rot_1_3[14] = xor_0_6[0];
constraint rot_1_3[15] = xor_0_6[1];
constraint table([rot_1_1[0]]++[rot_1_2[0]]++[and_1_4[0]]++[p[16]],and2inputs_DDT);
constraint table([rot_1_1[1]]++[rot_1_2[1]]++[and_1_4[1]]++[p[17]],and2inputs_DDT);
constraint table([rot_1_1[2]]++[rot_1_2[2]]++[and_1_4[2]]++[p[18]],and2inputs_DDT);
constraint table([rot_1_1[3]]++[rot_1_2[3]]++[and_1_4[3]]++[p[19]],and2inputs_DDT);
constraint table([rot_1_1[4]]++[rot_1_2[4]]++[and_1_4[4]]++[p[20]],and2inputs_DDT);
constraint table([rot_1_1[5]]++[rot_1_2[5]]++[and_1_4[5]]++[p[21]],and2inputs_DDT);
constraint table([rot_1_1[6]]++[rot_1_2[6]]++[and_1_4[6]]++[p[22]],and2inputs_DDT);
constraint table([rot_1_1[7]]++[rot_1_2[7]]++[and_1_4[7]]++[p[23]],and2inputs_DDT);
constraint table([rot_1_1[8]]++[rot_1_2[8]]++[and_1_4[8]]++[p[24]],and2inputs_DDT);
constraint table([rot_1_1[9]]++[rot_1_2[9]]++[and_1_4[9]]++[p[25]],and2inputs_DDT);
constraint table([rot_1_1[10]]++[rot_1_2[10]]++[and_1_4[10]]++[p[26]],and2inputs_DDT);
constraint table([rot_1_1[11]]++[rot_1_2[11]]++[and_1_4[11]]++[p[27]],and2inputs_DDT);
constraint table([rot_1_1[12]]++[rot_1_2[12]]++[and_1_4[12]]++[p[28]],and2inputs_DDT);
constraint table([rot_1_1[13]]++[rot_1_2[13]]++[and_1_4[13]]++[p[29]],and2inputs_DDT);
constraint table([rot_1_1[14]]++[rot_1_2[14]]++[and_1_4[14]]++[p[30]],and2inputs_DDT);
constraint table([rot_1_1[15]]++[rot_1_2[15]]++[and_1_4[15]]++[p[31]],and2inputs_DDT);
constraint xor_1_5[0] = (and_1_4[0] + rot_1_3[0]) mod 2;
constraint xor_1_5[1] = (and_1_4[1] + rot_1_3[1]) mod 2;
constraint xor_1_5[2] = (and_1_4[2] + rot_1_3[2]) mod 2;
constraint xor_1_5[3] = (and_1_4[3] + rot_1_3[3]) mod 2;
constraint xor_1_5[4] = (and_1_4[4] + rot_1_3[4]) mod 2;
constraint xor_1_5[5] = (and_1_4[5] + rot_1_3[5]) mod 2;
constraint xor_1_5[6] = (and_1_4[6] + rot_1_3[6]) mod 2;
constraint xor_1_5[7] = (and_1_4[7] + rot_1_3[7]) mod 2;
constraint xor_1_5[8] = (and_1_4[8] + rot_1_3[8]) mod 2;
constraint xor_1_5[9] = (and_1_4[9] + rot_1_3[9]) mod 2;
constraint xor_1_5[10] = (and_1_4[10] + rot_1_3[10]) mod 2;
constraint xor_1_5[11] = (and_1_4[11] + rot_1_3[11]) mod 2;
constraint xor_1_5[12] = (and_1_4[12] + rot_1_3[12]) mod 2;
constraint xor_1_5[13] = (and_1_4[13] + rot_1_3[13]) mod 2;
constraint xor_1_5[14] = (and_1_4[14] + rot_1_3[14]) mod 2;
constraint xor_1_5[15] = (and_1_4[15] + rot_1_3[15]) mod 2;
constraint xor_1_6[0] = (plaintext[0] + xor_1_5[0] + key[32]) mod 2;
constraint xor_1_6[1] = (plaintext[1] + xor_1_5[1] + key[33]) mod 2;
constraint xor_1_6[2] = (plaintext[2] + xor_1_5[2] + key[34]) mod 2;
constraint xor_1_6[3] = (plaintext[3] + xor_1_5[3] + key[35]) mod 2;
constraint xor_1_6[4] = (plaintext[4] + xor_1_5[4] + key[36]) mod 2;
constraint xor_1_6[5] = (plaintext[5] + xor_1_5[5] + key[37]) mod 2;
constraint xor_1_6[6] = (plaintext[6] + xor_1_5[6] + key[38]) mod 2;
constraint xor_1_6[7] = (plaintext[7] + xor_1_5[7] + key[39]) mod 2;
constraint xor_1_6[8] = (plaintext[8] + xor_1_5[8] + key[40]) mod 2;
constraint xor_1_6[9] = (plaintext[9] + xor_1_5[9] + key[41]) mod 2;
constraint xor_1_6[10] = (plaintext[10] + xor_1_5[10] + key[42]) mod 2;
constraint xor_1_6[11] = (plaintext[11] + xor_1_5[11] + key[43]) mod 2;
constraint xor_1_6[12] = (plaintext[12] + xor_1_5[12] + key[44]) mod 2;
constraint xor_1_6[13] = (plaintext[13] + xor_1_5[13] + key[45]) mod 2;
constraint xor_1_6[14] = (plaintext[14] + xor_1_5[14] + key[46]) mod 2;
constraint xor_1_6[15] = (plaintext[15] + xor_1_5[15] + key[47]) mod 2;
constraint intermediate_output_1_7[0] = xor_1_6[0];
constraint intermediate_output_1_7[1] = xor_1_6[1];
constraint intermediate_output_1_7[2] = xor_1_6[2];
constraint intermediate_output_1_7[3] = xor_1_6[3];
constraint intermediate_output_1_7[4] = xor_1_6[4];
constraint intermediate_output_1_7[5] = xor_1_6[5];
constraint intermediate_output_1_7[6] = xor_1_6[6];
constraint intermediate_output_1_7[7] = xor_1_6[7];
constraint intermediate_output_1_7[8] = xor_1_6[8];
constraint intermediate_output_1_7[9] = xor_1_6[9];
constraint intermediate_output_1_7[10] = xor_1_6[10];
constraint intermediate_output_1_7[11] = xor_1_6[11];
constraint intermediate_output_1_7[12] = xor_1_6[12];
constraint intermediate_output_1_7[13] = xor_1_6[13];
constraint intermediate_output_1_7[14] = xor_1_6[14];
constraint intermediate_output_1_7[15] = xor_1_6[15];
constraint intermediate_output_1_7[16] = xor_0_6[0];
constraint intermediate_output_1_7[17] = xor_0_6[1];
constraint intermediate_output_1_7[18] = xor_0_6[2];
constraint intermediate_output_1_7[19] = xor_0_6[3];
constraint intermediate_output_1_7[20] = xor_0_6[4];
constraint intermediate_output_1_7[21] = xor_0_6[5];
constraint intermediate_output_1_7[22] = xor_0_6[6];
constraint intermediate_output_1_7[23] = xor_0_6[7];
constraint intermediate_output_1_7[24] = xor_0_6[8];
constraint intermediate_output_1_7[25] = xor_0_6[9];
constraint intermediate_output_1_7[26] = xor_0_6[10];
constraint intermediate_output_1_7[27] = xor_0_6[11];
constraint intermediate_output_1_7[28] = xor_0_6[12];
constraint intermediate_output_1_7[29] = xor_0_6[13];
constraint intermediate_output_1_7[30] = xor_0_6[14];
constraint intermediate_output_1_7[31] = xor_0_6[15];
constraint cipher_output_1_8[0] = xor_1_6[0];
constraint cipher_output_1_8[1] = xor_1_6[1];
constraint cipher_output_1_8[2] = xor_1_6[2];
constraint cipher_output_1_8[3] = xor_1_6[3];
constraint cipher_output_1_8[4] = xor_1_6[4];
constraint cipher_output_1_8[5] = xor_1_6[5];
constraint cipher_output_1_8[6] = xor_1_6[6];
constraint cipher_output_1_8[7] = xor_1_6[7];
constraint cipher_output_1_8[8] = xor_1_6[8];
constraint cipher_output_1_8[9] = xor_1_6[9];
constraint cipher_output_1_8[10] = xor_1_6[10];
constraint cipher_output_1_8[11] = xor_1_6[11];
constraint cipher_output_1_8[12] = xor_1_6[12];
constraint cipher_output_1_8[13] = xor_1_6[13];
constraint cipher_output_1_8[14] = xor_1_6[14];
constraint cipher_output_1_8[15] = xor_1_6[15];
constraint cipher_output_1_8[16] = xor_0_6[0];
constraint cipher_output_1_8[17] = xor_0_6[1];
constraint cipher_output_1_8[18] = xor_0_6[2];
constraint cipher_output_1_8[19] = xor_0_6[3];
constraint cipher_output_1_8[20] = xor_0_6[4];
constraint cipher_output_1_8[21] = xor_0_6[5];
constraint cipher_output_1_8[22] = xor_0_6[6];
constraint cipher_output_1_8[23] = xor_0_6[7];
constraint cipher_output_1_8[24] = xor_0_6[8];
constraint cipher_output_1_8[25] = xor_0_6[9];
constraint cipher_output_1_8[26] = xor_0_6[10];
constraint cipher_output_1_8[27] = xor_0_6[11];
constraint cipher_output_1_8[28] = xor_0_6[12];
constraint cipher_output_1_8[29] = xor_0_6[13];
constraint cipher_output_1_8[30] = xor_0_6[14];
constraint cipher_output_1_8[31] = xor_0_6[15];
solve satisfy;
output["plaintext = "++ show(plaintext) ++ "\n" ++"key = "++ show(key) ++ "\n" ++"intermediate_output_0_0 = "++ show(intermediate_output_0_0)++ "\n" ++ "0" ++ "\n" ++"rot_0_1 = "++ show(rot_0_1)++ "\n" ++ "0" ++ "\n" ++"rot_0_2 = "++ show(rot_0_2)++ "\n" ++ "0" ++ "\n" ++"rot_0_3 = "++ show(rot_0_3)++ "\n" ++ "0" ++ "\n" ++"and_0_4 = "++ show(and_0_4)++ "\n" ++ show(p[1]/100+p[2]/100+p[3]/100+p[4]/100+p[5]/100+p[6]/100+p[7]/100+p[8]/100+p[9]/100+p[10]/100+p[11]/100+p[12]/100+p[13]/100+p[14]/100+p[15]/100+p[16]/100) ++ "\n" ++"xor_0_5 = "++ show(xor_0_5)++ "\n" ++ "0" ++ "\n" ++"xor_0_6 = "++ show(xor_0_6)++ "\n" ++ "0" ++ "\n" ++"intermediate_output_0_7 = "++ show(intermediate_output_0_7)++ "\n" ++ "0" ++ "\n" ++"intermediate_output_1_0 = "++ show(intermediate_output_1_0)++ "\n" ++ "0" ++ "\n" ++"rot_1_1 = "++ show(rot_1_1)++ "\n" ++ "0" ++ "\n" ++"rot_1_2 = "++ show(rot_1_2)++ "\n" ++ "0" ++ "\n" ++"rot_1_3 = "++ show(rot_1_3)++ "\n" ++ "0" ++ "\n" ++"and_1_4 = "++ show(and_1_4)++ "\n" ++ show(p[17]/100+p[18]/100+p[19]/100+p[20]/100+p[21]/100+p[22]/100+p[23]/100+p[24]/100+p[25]/100+p[26]/100+p[27]/100+p[28]/100+p[29]/100+p[30]/100+p[31]/100+p[32]/100) ++ "\n" ++"xor_1_5 = "++ show(xor_1_5)++ "\n" ++ "0" ++ "\n" ++"xor_1_6 = "++ show(xor_1_6)++ "\n" ++ "0" ++ "\n" ++"intermediate_output_1_7 = "++ show(intermediate_output_1_7)++ "\n" ++ "0" ++ "\n" ++"cipher_output_1_8 = "++ show(cipher_output_1_8)++ "\n" ++ "0" ++ "\n" ++"Trail weight = " ++ show(weight)];
