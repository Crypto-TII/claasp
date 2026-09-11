
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


function array[int] of var 0..2: TRUNCATED_XOR(array[int] of var 0..2: a, array[int] of var 0..2: b, array[int] of var 0..2: c)=
  let { int: n = length(a) } in
  array1d(0..n-1, [if a[j]<2 /\ b[j]<2 /\ c[j]<2 then sum([a[j], b[j], c[j]]) mod 2 else 2 endif| j in 0..n-1]);

function array[int] of var 0..2: TRUNCATED_XOR(array[int] of var 0..2: a, array[int] of var 0..2: b)=
  let { int: n = length(a) } in
  array1d(0..n-1, [if a[j]<2 /\ b[j]<2 then sum([a[j], b[j]]) mod 2 else 2 endif| j in 0..n-1]);

predicate counter_based_modadd_semideterministic(array[int] of var 0..2: a, array[int] of var 0..2: b, array[int] of var 0..2:c, array[int] of var 0..2:delta_carry, array[int] of var {100, 41, 19, 9, 4, 0}: costs, int: windows_size, var int: probability) = ( 
  let { 
  int: n = length(a);
  array [0..n-1] of var 0..windows_size: run_length;
  } in
  c =  TRUNCATED_XOR(a,b,delta_carry) /\
  delta_carry[n-1] = 0 /\
  run_length[n-1] = 0 /\
  forall(i in 0..n-2) (
      if a[i+1] + b[i+1] = 0 /\ delta_carry[i+1] = 2 then run_length[i] = run_length[i+1] + 1
      else run_length[i] = 0
      endif 
  ) /\  
  forall(i in 0..n-2) (
      % CASE 1: deterministic transitions
      if a[i+1] = 0 /\ b[i+1] = 0 /\ c[i+1] = 0 then delta_carry[i] = 0 /\ costs[i] = 0
  elseif a[i+1] = 1 /\ b[i+1] = 1 /\ c[i+1] = 1 then delta_carry[i] = 1 /\ costs[i] = 0
      % CASE 2: we either pay to set the carry or have it unknown
  else
      % CASE 2A: Not paying
      (delta_carry[i] = 2 /\ costs[i] = 0) \/
      % CASE 2B: Paying, run_length = 0
      (run_length[i] = 0 /\ costs[i] = 100 /\ delta_carry[i] = 0) \/
      (run_length[i] = 0 /\ costs[i] = 100 /\ delta_carry[i] = 1) \/
      % CASE 2C: Paying, run_length > 0, transition to 0
          % (d, log) pairs: [(1, 41), (2, 19), (3, 9), (4, 4), (5, 2), (6, 1), (7, 0), (8, 0), (9, 0), (10, 0)]
      (run_length[i] = 1 /\ costs[i] = 41 /\ delta_carry[i] = 0) \/
      (run_length[i] = 2 /\ costs[i] = 19 /\ delta_carry[i] = 0) \/
      (run_length[i] = 3 /\ costs[i] = 9  /\ delta_carry[i] = 0) \/
      (run_length[i] = 4 /\ costs[i] = 4  /\ delta_carry[i] = 0) \/
      (run_length[i] > 4 /\ costs[i] = 0  /\ delta_carry[i] = 0) 
  endif 
  )/\
  probability = sum(costs)
  );

array[0..23] of var 0..1: pre_upper_modadd_0_1_0;
array[0..23] of var 0..1: pre_upper_modadd_0_1_1;
array[0..23] of var 0..1: Shi_pre_upper_modadd_0_1_1 = LShift(pre_upper_modadd_0_1_1,1);
array[0..23] of var 0..1: Shi_pre_upper_modadd_0_1_0 = LShift(pre_upper_modadd_0_1_0,1);
array[0..23] of var 0..1: Shi_upper_modadd_0_1 = LShift(upper_modadd_0_1,1);
array[0..23] of var 0..1: eq_upper_modadd_0_1 = Eq(Shi_pre_upper_modadd_0_1_1, Shi_pre_upper_modadd_0_1_0, Shi_upper_modadd_0_1);
array[0..24-1] of var 0..1: dummy_upper_xor_0_2;
array[0..24-1] of var 0..1: dummy_upper_xor_0_4;
array[0..23] of var 0..1: pre_upper_modadd_1_7_0;
array[0..23] of var 0..1: pre_upper_modadd_1_7_1;
array[0..23] of var 0..1: Shi_pre_upper_modadd_1_7_1 = LShift(pre_upper_modadd_1_7_1,1);
array[0..23] of var 0..1: Shi_pre_upper_modadd_1_7_0 = LShift(pre_upper_modadd_1_7_0,1);
array[0..23] of var 0..1: Shi_upper_modadd_1_7 = LShift(upper_modadd_1_7,1);
array[0..23] of var 0..1: eq_upper_modadd_1_7 = Eq(Shi_pre_upper_modadd_1_7_1, Shi_pre_upper_modadd_1_7_0, Shi_upper_modadd_1_7);
array[0..24-1] of var 0..1: dummy_upper_xor_1_8;
array[0..24-1] of var 0..1: dummy_upper_xor_1_10;
array[0..23] of var 0..1: pre_upper_modadd_2_7_0;
array[0..23] of var 0..1: pre_upper_modadd_2_7_1;
array[0..23] of var 0..1: Shi_pre_upper_modadd_2_7_1 = LShift(pre_upper_modadd_2_7_1,1);
array[0..23] of var 0..1: Shi_pre_upper_modadd_2_7_0 = LShift(pre_upper_modadd_2_7_0,1);
array[0..23] of var 0..1: Shi_upper_modadd_2_7 = LShift(upper_modadd_2_7,1);
array[0..23] of var 0..1: eq_upper_modadd_2_7 = Eq(Shi_pre_upper_modadd_2_7_1, Shi_pre_upper_modadd_2_7_0, Shi_upper_modadd_2_7);
array[0..24-1] of var 0..1: dummy_upper_xor_2_8;
array[0..24-1] of var 0..1: dummy_upper_xor_2_10;
array[0..23] of var 0..1: pre_upper_modadd_3_7_0;
array[0..23] of var 0..1: pre_upper_modadd_3_7_1;
array[0..23] of var 0..1: Shi_pre_upper_modadd_3_7_1 = LShift(pre_upper_modadd_3_7_1,1);
array[0..23] of var 0..1: Shi_pre_upper_modadd_3_7_0 = LShift(pre_upper_modadd_3_7_0,1);
array[0..23] of var 0..1: Shi_upper_modadd_3_7 = LShift(upper_modadd_3_7,1);
array[0..23] of var 0..1: eq_upper_modadd_3_7 = Eq(Shi_pre_upper_modadd_3_7_1, Shi_pre_upper_modadd_3_7_0, Shi_upper_modadd_3_7);
array[0..24-1] of var 0..1: dummy_upper_xor_3_8;
array[0..24-1] of var 0..1: dummy_upper_xor_3_10;
array[0..23] of var 0..1: pre_upper_modadd_4_7_0;
array[0..23] of var 0..1: pre_upper_modadd_4_7_1;
array[0..23] of var 0..1: Shi_pre_upper_modadd_4_7_1 = LShift(pre_upper_modadd_4_7_1,1);
array[0..23] of var 0..1: Shi_pre_upper_modadd_4_7_0 = LShift(pre_upper_modadd_4_7_0,1);
array[0..23] of var 0..1: Shi_upper_modadd_4_7 = LShift(upper_modadd_4_7,1);
array[0..23] of var 0..1: eq_upper_modadd_4_7 = Eq(Shi_pre_upper_modadd_4_7_1, Shi_pre_upper_modadd_4_7_0, Shi_upper_modadd_4_7);
array[0..24-1] of var 0..1: dummy_upper_xor_4_8;
array[0..24-1] of var 0..1: dummy_upper_xor_4_10;
array[0..24-1] of var 0..1: dummy_lower_xor_4_8;
array[0..24-1] of var 0..1: dummy_lower_xor_4_10;
array[0..23] of var 0..1: pre_lower_modadd_4_7_0;
array[0..23] of var 0..1: pre_lower_modadd_4_7_1;
array[0..23] of var 0..1: Shi_pre_lower_modadd_4_7_1 = LShift(pre_lower_modadd_4_7_1,1);
array[0..23] of var 0..1: Shi_pre_lower_modadd_4_7_0 = LShift(pre_lower_modadd_4_7_0,1);
array[0..23] of var 0..1: Shi_lower_modadd_4_7 = LShift(lower_modadd_4_7,1);
array[0..23] of var 0..1: eq_lower_modadd_4_7 = Eq(Shi_pre_lower_modadd_4_7_1, Shi_pre_lower_modadd_4_7_0, Shi_lower_modadd_4_7);
array[0..23] of var 0..1: pre_upper_modadd_5_7_0;
array[0..23] of var 0..1: pre_upper_modadd_5_7_1;
array[0..23] of var 0..1: Shi_pre_upper_modadd_5_7_1 = LShift(pre_upper_modadd_5_7_1,1);
array[0..23] of var 0..1: Shi_pre_upper_modadd_5_7_0 = LShift(pre_upper_modadd_5_7_0,1);
array[0..23] of var 0..1: Shi_upper_modadd_5_7 = LShift(upper_modadd_5_7,1);
array[0..23] of var 0..1: eq_upper_modadd_5_7 = Eq(Shi_pre_upper_modadd_5_7_1, Shi_pre_upper_modadd_5_7_0, Shi_upper_modadd_5_7);
array[0..24-1] of var 0..1: dummy_upper_xor_5_8;
array[0..24-1] of var 0..1: dummy_upper_xor_5_10;
array[0..24-1] of var 0..1: dummy_lower_xor_5_8;
array[0..24-1] of var 0..1: dummy_lower_xor_5_10;
array[0..23] of var 0..1: pre_lower_modadd_5_7_0;
array[0..23] of var 0..1: pre_lower_modadd_5_7_1;
array[0..23] of var 0..1: Shi_pre_lower_modadd_5_7_1 = LShift(pre_lower_modadd_5_7_1,1);
array[0..23] of var 0..1: Shi_pre_lower_modadd_5_7_0 = LShift(pre_lower_modadd_5_7_0,1);
array[0..23] of var 0..1: Shi_lower_modadd_5_7 = LShift(lower_modadd_5_7,1);
array[0..23] of var 0..1: eq_lower_modadd_5_7 = Eq(Shi_pre_lower_modadd_5_7_1, Shi_pre_lower_modadd_5_7_0, Shi_lower_modadd_5_7);
array[0..24-1] of var 0..1: dummy_lower_xor_6_8;
array[0..24-1] of var 0..1: dummy_lower_xor_6_10;
array[0..23] of var 0..1: pre_lower_modadd_6_7_0;
array[0..23] of var 0..1: pre_lower_modadd_6_7_1;
array[0..23] of var 0..1: Shi_pre_lower_modadd_6_7_1 = LShift(pre_lower_modadd_6_7_1,1);
array[0..23] of var 0..1: Shi_pre_lower_modadd_6_7_0 = LShift(pre_lower_modadd_6_7_0,1);
array[0..23] of var 0..1: Shi_lower_modadd_6_7 = LShift(lower_modadd_6_7,1);
array[0..23] of var 0..1: eq_lower_modadd_6_7 = Eq(Shi_pre_lower_modadd_6_7_1, Shi_pre_lower_modadd_6_7_0, Shi_lower_modadd_6_7);
array[0..24-1] of var 0..1: dummy_lower_xor_7_8;
array[0..24-1] of var 0..1: dummy_lower_xor_7_10;
array[0..23] of var 0..1: pre_lower_modadd_7_7_0;
array[0..23] of var 0..1: pre_lower_modadd_7_7_1;
array[0..23] of var 0..1: Shi_pre_lower_modadd_7_7_1 = LShift(pre_lower_modadd_7_7_1,1);
array[0..23] of var 0..1: Shi_pre_lower_modadd_7_7_0 = LShift(pre_lower_modadd_7_7_0,1);
array[0..23] of var 0..1: Shi_lower_modadd_7_7 = LShift(lower_modadd_7_7,1);
array[0..23] of var 0..1: eq_lower_modadd_7_7 = Eq(Shi_pre_lower_modadd_7_7_1, Shi_pre_lower_modadd_7_7_0, Shi_lower_modadd_7_7);
array[0..24-1] of var 0..1: dummy_lower_xor_8_8;
array[0..24-1] of var 0..1: dummy_lower_xor_8_10;
array[0..23] of var 0..1: pre_lower_modadd_8_7_0;
array[0..23] of var 0..1: pre_lower_modadd_8_7_1;
array[0..23] of var 0..1: Shi_pre_lower_modadd_8_7_1 = LShift(pre_lower_modadd_8_7_1,1);
array[0..23] of var 0..1: Shi_pre_lower_modadd_8_7_0 = LShift(pre_lower_modadd_8_7_0,1);
array[0..23] of var 0..1: Shi_lower_modadd_8_7 = LShift(lower_modadd_8_7,1);
array[0..23] of var 0..1: eq_lower_modadd_8_7 = Eq(Shi_pre_lower_modadd_8_7_1, Shi_pre_lower_modadd_8_7_0, Shi_lower_modadd_8_7);
array[0..24-1] of var 0..1: dummy_lower_xor_9_8;
array[0..24-1] of var 0..1: dummy_lower_xor_9_10;
array[0..23] of var 0..1: pre_lower_modadd_9_7_0;
array[0..23] of var 0..1: pre_lower_modadd_9_7_1;
array[0..23] of var 0..1: Shi_pre_lower_modadd_9_7_1 = LShift(pre_lower_modadd_9_7_1,1);
array[0..23] of var 0..1: Shi_pre_lower_modadd_9_7_0 = LShift(pre_lower_modadd_9_7_0,1);
array[0..23] of var 0..1: Shi_lower_modadd_9_7 = LShift(lower_modadd_9_7,1);
array[0..23] of var 0..1: eq_lower_modadd_9_7 = Eq(Shi_pre_lower_modadd_9_7_1, Shi_pre_lower_modadd_9_7_0, Shi_lower_modadd_9_7);
array[0..24-1] of var 0..1: dummy_lower_xor_10_8;
array[0..24-1] of var 0..1: dummy_lower_xor_10_10;
array[0..23] of var 0..1: pre_lower_modadd_10_7_0;
array[0..23] of var 0..1: pre_lower_modadd_10_7_1;
array[0..23] of var 0..1: Shi_pre_lower_modadd_10_7_1 = LShift(pre_lower_modadd_10_7_1,1);
array[0..23] of var 0..1: Shi_pre_lower_modadd_10_7_0 = LShift(pre_lower_modadd_10_7_0,1);
array[0..23] of var 0..1: Shi_lower_modadd_10_7 = LShift(lower_modadd_10_7,1);
array[0..23] of var 0..1: eq_lower_modadd_10_7 = Eq(Shi_pre_lower_modadd_10_7_1, Shi_pre_lower_modadd_10_7_0, Shi_lower_modadd_10_7);
constraint upper_rot_0_0[0] = upper_plaintext[16];
constraint upper_rot_0_0[1] = upper_plaintext[17];
constraint upper_rot_0_0[2] = upper_plaintext[18];
constraint upper_rot_0_0[3] = upper_plaintext[19];
constraint upper_rot_0_0[4] = upper_plaintext[20];
constraint upper_rot_0_0[5] = upper_plaintext[21];
constraint upper_rot_0_0[6] = upper_plaintext[22];
constraint upper_rot_0_0[7] = upper_plaintext[23];
constraint upper_rot_0_0[8] = upper_plaintext[0];
constraint upper_rot_0_0[9] = upper_plaintext[1];
constraint upper_rot_0_0[10] = upper_plaintext[2];
constraint upper_rot_0_0[11] = upper_plaintext[3];
constraint upper_rot_0_0[12] = upper_plaintext[4];
constraint upper_rot_0_0[13] = upper_plaintext[5];
constraint upper_rot_0_0[14] = upper_plaintext[6];
constraint upper_rot_0_0[15] = upper_plaintext[7];
constraint upper_rot_0_0[16] = upper_plaintext[8];
constraint upper_rot_0_0[17] = upper_plaintext[9];
constraint upper_rot_0_0[18] = upper_plaintext[10];
constraint upper_rot_0_0[19] = upper_plaintext[11];
constraint upper_rot_0_0[20] = upper_plaintext[12];
constraint upper_rot_0_0[21] = upper_plaintext[13];
constraint upper_rot_0_0[22] = upper_plaintext[14];
constraint upper_rot_0_0[23] = upper_plaintext[15];
constraint pre_upper_modadd_0_1_0[0] = upper_rot_0_0[0];
constraint pre_upper_modadd_0_1_0[1] = upper_rot_0_0[1];
constraint pre_upper_modadd_0_1_0[2] = upper_rot_0_0[2];
constraint pre_upper_modadd_0_1_0[3] = upper_rot_0_0[3];
constraint pre_upper_modadd_0_1_0[4] = upper_rot_0_0[4];
constraint pre_upper_modadd_0_1_0[5] = upper_rot_0_0[5];
constraint pre_upper_modadd_0_1_0[6] = upper_rot_0_0[6];
constraint pre_upper_modadd_0_1_0[7] = upper_rot_0_0[7];
constraint pre_upper_modadd_0_1_0[8] = upper_rot_0_0[8];
constraint pre_upper_modadd_0_1_0[9] = upper_rot_0_0[9];
constraint pre_upper_modadd_0_1_0[10] = upper_rot_0_0[10];
constraint pre_upper_modadd_0_1_0[11] = upper_rot_0_0[11];
constraint pre_upper_modadd_0_1_0[12] = upper_rot_0_0[12];
constraint pre_upper_modadd_0_1_0[13] = upper_rot_0_0[13];
constraint pre_upper_modadd_0_1_0[14] = upper_rot_0_0[14];
constraint pre_upper_modadd_0_1_0[15] = upper_rot_0_0[15];
constraint pre_upper_modadd_0_1_0[16] = upper_rot_0_0[16];
constraint pre_upper_modadd_0_1_0[17] = upper_rot_0_0[17];
constraint pre_upper_modadd_0_1_0[18] = upper_rot_0_0[18];
constraint pre_upper_modadd_0_1_0[19] = upper_rot_0_0[19];
constraint pre_upper_modadd_0_1_0[20] = upper_rot_0_0[20];
constraint pre_upper_modadd_0_1_0[21] = upper_rot_0_0[21];
constraint pre_upper_modadd_0_1_0[22] = upper_rot_0_0[22];
constraint pre_upper_modadd_0_1_0[23] = upper_rot_0_0[23];
constraint pre_upper_modadd_0_1_1[0] = upper_plaintext[24];
constraint pre_upper_modadd_0_1_1[1] = upper_plaintext[25];
constraint pre_upper_modadd_0_1_1[2] = upper_plaintext[26];
constraint pre_upper_modadd_0_1_1[3] = upper_plaintext[27];
constraint pre_upper_modadd_0_1_1[4] = upper_plaintext[28];
constraint pre_upper_modadd_0_1_1[5] = upper_plaintext[29];
constraint pre_upper_modadd_0_1_1[6] = upper_plaintext[30];
constraint pre_upper_modadd_0_1_1[7] = upper_plaintext[31];
constraint pre_upper_modadd_0_1_1[8] = upper_plaintext[32];
constraint pre_upper_modadd_0_1_1[9] = upper_plaintext[33];
constraint pre_upper_modadd_0_1_1[10] = upper_plaintext[34];
constraint pre_upper_modadd_0_1_1[11] = upper_plaintext[35];
constraint pre_upper_modadd_0_1_1[12] = upper_plaintext[36];
constraint pre_upper_modadd_0_1_1[13] = upper_plaintext[37];
constraint pre_upper_modadd_0_1_1[14] = upper_plaintext[38];
constraint pre_upper_modadd_0_1_1[15] = upper_plaintext[39];
constraint pre_upper_modadd_0_1_1[16] = upper_plaintext[40];
constraint pre_upper_modadd_0_1_1[17] = upper_plaintext[41];
constraint pre_upper_modadd_0_1_1[18] = upper_plaintext[42];
constraint pre_upper_modadd_0_1_1[19] = upper_plaintext[43];
constraint pre_upper_modadd_0_1_1[20] = upper_plaintext[44];
constraint pre_upper_modadd_0_1_1[21] = upper_plaintext[45];
constraint pre_upper_modadd_0_1_1[22] = upper_plaintext[46];
constraint pre_upper_modadd_0_1_1[23] = upper_plaintext[47];
constraint forall(j in 0..23)(if eq_upper_modadd_0_1[j] = 1 then (sum([pre_upper_modadd_0_1_1[j], pre_upper_modadd_0_1_0[j], upper_modadd_0_1[j]]) mod 2) = Shi_pre_upper_modadd_0_1_0[j] else true endif) /\ upper_p[0] = (24-sum(eq_upper_modadd_0_1))*100;
constraint 2*dummy_upper_xor_0_2[0] = (upper_modadd_0_1[0] + upper_key[48] + upper_xor_0_2[0]);
constraint 2*dummy_upper_xor_0_2[1] = (upper_modadd_0_1[1] + upper_key[49] + upper_xor_0_2[1]);
constraint 2*dummy_upper_xor_0_2[2] = (upper_modadd_0_1[2] + upper_key[50] + upper_xor_0_2[2]);
constraint 2*dummy_upper_xor_0_2[3] = (upper_modadd_0_1[3] + upper_key[51] + upper_xor_0_2[3]);
constraint 2*dummy_upper_xor_0_2[4] = (upper_modadd_0_1[4] + upper_key[52] + upper_xor_0_2[4]);
constraint 2*dummy_upper_xor_0_2[5] = (upper_modadd_0_1[5] + upper_key[53] + upper_xor_0_2[5]);
constraint 2*dummy_upper_xor_0_2[6] = (upper_modadd_0_1[6] + upper_key[54] + upper_xor_0_2[6]);
constraint 2*dummy_upper_xor_0_2[7] = (upper_modadd_0_1[7] + upper_key[55] + upper_xor_0_2[7]);
constraint 2*dummy_upper_xor_0_2[8] = (upper_modadd_0_1[8] + upper_key[56] + upper_xor_0_2[8]);
constraint 2*dummy_upper_xor_0_2[9] = (upper_modadd_0_1[9] + upper_key[57] + upper_xor_0_2[9]);
constraint 2*dummy_upper_xor_0_2[10] = (upper_modadd_0_1[10] + upper_key[58] + upper_xor_0_2[10]);
constraint 2*dummy_upper_xor_0_2[11] = (upper_modadd_0_1[11] + upper_key[59] + upper_xor_0_2[11]);
constraint 2*dummy_upper_xor_0_2[12] = (upper_modadd_0_1[12] + upper_key[60] + upper_xor_0_2[12]);
constraint 2*dummy_upper_xor_0_2[13] = (upper_modadd_0_1[13] + upper_key[61] + upper_xor_0_2[13]);
constraint 2*dummy_upper_xor_0_2[14] = (upper_modadd_0_1[14] + upper_key[62] + upper_xor_0_2[14]);
constraint 2*dummy_upper_xor_0_2[15] = (upper_modadd_0_1[15] + upper_key[63] + upper_xor_0_2[15]);
constraint 2*dummy_upper_xor_0_2[16] = (upper_modadd_0_1[16] + upper_key[64] + upper_xor_0_2[16]);
constraint 2*dummy_upper_xor_0_2[17] = (upper_modadd_0_1[17] + upper_key[65] + upper_xor_0_2[17]);
constraint 2*dummy_upper_xor_0_2[18] = (upper_modadd_0_1[18] + upper_key[66] + upper_xor_0_2[18]);
constraint 2*dummy_upper_xor_0_2[19] = (upper_modadd_0_1[19] + upper_key[67] + upper_xor_0_2[19]);
constraint 2*dummy_upper_xor_0_2[20] = (upper_modadd_0_1[20] + upper_key[68] + upper_xor_0_2[20]);
constraint 2*dummy_upper_xor_0_2[21] = (upper_modadd_0_1[21] + upper_key[69] + upper_xor_0_2[21]);
constraint 2*dummy_upper_xor_0_2[22] = (upper_modadd_0_1[22] + upper_key[70] + upper_xor_0_2[22]);
constraint 2*dummy_upper_xor_0_2[23] = (upper_modadd_0_1[23] + upper_key[71] + upper_xor_0_2[23]);
constraint upper_rot_0_3[0] = upper_plaintext[27];
constraint upper_rot_0_3[1] = upper_plaintext[28];
constraint upper_rot_0_3[2] = upper_plaintext[29];
constraint upper_rot_0_3[3] = upper_plaintext[30];
constraint upper_rot_0_3[4] = upper_plaintext[31];
constraint upper_rot_0_3[5] = upper_plaintext[32];
constraint upper_rot_0_3[6] = upper_plaintext[33];
constraint upper_rot_0_3[7] = upper_plaintext[34];
constraint upper_rot_0_3[8] = upper_plaintext[35];
constraint upper_rot_0_3[9] = upper_plaintext[36];
constraint upper_rot_0_3[10] = upper_plaintext[37];
constraint upper_rot_0_3[11] = upper_plaintext[38];
constraint upper_rot_0_3[12] = upper_plaintext[39];
constraint upper_rot_0_3[13] = upper_plaintext[40];
constraint upper_rot_0_3[14] = upper_plaintext[41];
constraint upper_rot_0_3[15] = upper_plaintext[42];
constraint upper_rot_0_3[16] = upper_plaintext[43];
constraint upper_rot_0_3[17] = upper_plaintext[44];
constraint upper_rot_0_3[18] = upper_plaintext[45];
constraint upper_rot_0_3[19] = upper_plaintext[46];
constraint upper_rot_0_3[20] = upper_plaintext[47];
constraint upper_rot_0_3[21] = upper_plaintext[24];
constraint upper_rot_0_3[22] = upper_plaintext[25];
constraint upper_rot_0_3[23] = upper_plaintext[26];
constraint 2*dummy_upper_xor_0_4[0] = (upper_xor_0_2[0] + upper_rot_0_3[0] + upper_xor_0_4[0]);
constraint 2*dummy_upper_xor_0_4[1] = (upper_xor_0_2[1] + upper_rot_0_3[1] + upper_xor_0_4[1]);
constraint 2*dummy_upper_xor_0_4[2] = (upper_xor_0_2[2] + upper_rot_0_3[2] + upper_xor_0_4[2]);
constraint 2*dummy_upper_xor_0_4[3] = (upper_xor_0_2[3] + upper_rot_0_3[3] + upper_xor_0_4[3]);
constraint 2*dummy_upper_xor_0_4[4] = (upper_xor_0_2[4] + upper_rot_0_3[4] + upper_xor_0_4[4]);
constraint 2*dummy_upper_xor_0_4[5] = (upper_xor_0_2[5] + upper_rot_0_3[5] + upper_xor_0_4[5]);
constraint 2*dummy_upper_xor_0_4[6] = (upper_xor_0_2[6] + upper_rot_0_3[6] + upper_xor_0_4[6]);
constraint 2*dummy_upper_xor_0_4[7] = (upper_xor_0_2[7] + upper_rot_0_3[7] + upper_xor_0_4[7]);
constraint 2*dummy_upper_xor_0_4[8] = (upper_xor_0_2[8] + upper_rot_0_3[8] + upper_xor_0_4[8]);
constraint 2*dummy_upper_xor_0_4[9] = (upper_xor_0_2[9] + upper_rot_0_3[9] + upper_xor_0_4[9]);
constraint 2*dummy_upper_xor_0_4[10] = (upper_xor_0_2[10] + upper_rot_0_3[10] + upper_xor_0_4[10]);
constraint 2*dummy_upper_xor_0_4[11] = (upper_xor_0_2[11] + upper_rot_0_3[11] + upper_xor_0_4[11]);
constraint 2*dummy_upper_xor_0_4[12] = (upper_xor_0_2[12] + upper_rot_0_3[12] + upper_xor_0_4[12]);
constraint 2*dummy_upper_xor_0_4[13] = (upper_xor_0_2[13] + upper_rot_0_3[13] + upper_xor_0_4[13]);
constraint 2*dummy_upper_xor_0_4[14] = (upper_xor_0_2[14] + upper_rot_0_3[14] + upper_xor_0_4[14]);
constraint 2*dummy_upper_xor_0_4[15] = (upper_xor_0_2[15] + upper_rot_0_3[15] + upper_xor_0_4[15]);
constraint 2*dummy_upper_xor_0_4[16] = (upper_xor_0_2[16] + upper_rot_0_3[16] + upper_xor_0_4[16]);
constraint 2*dummy_upper_xor_0_4[17] = (upper_xor_0_2[17] + upper_rot_0_3[17] + upper_xor_0_4[17]);
constraint 2*dummy_upper_xor_0_4[18] = (upper_xor_0_2[18] + upper_rot_0_3[18] + upper_xor_0_4[18]);
constraint 2*dummy_upper_xor_0_4[19] = (upper_xor_0_2[19] + upper_rot_0_3[19] + upper_xor_0_4[19]);
constraint 2*dummy_upper_xor_0_4[20] = (upper_xor_0_2[20] + upper_rot_0_3[20] + upper_xor_0_4[20]);
constraint 2*dummy_upper_xor_0_4[21] = (upper_xor_0_2[21] + upper_rot_0_3[21] + upper_xor_0_4[21]);
constraint 2*dummy_upper_xor_0_4[22] = (upper_xor_0_2[22] + upper_rot_0_3[22] + upper_xor_0_4[22]);
constraint 2*dummy_upper_xor_0_4[23] = (upper_xor_0_2[23] + upper_rot_0_3[23] + upper_xor_0_4[23]);
constraint upper_intermediate_output_0_6[0] = upper_xor_0_2[0];
constraint upper_intermediate_output_0_6[1] = upper_xor_0_2[1];
constraint upper_intermediate_output_0_6[2] = upper_xor_0_2[2];
constraint upper_intermediate_output_0_6[3] = upper_xor_0_2[3];
constraint upper_intermediate_output_0_6[4] = upper_xor_0_2[4];
constraint upper_intermediate_output_0_6[5] = upper_xor_0_2[5];
constraint upper_intermediate_output_0_6[6] = upper_xor_0_2[6];
constraint upper_intermediate_output_0_6[7] = upper_xor_0_2[7];
constraint upper_intermediate_output_0_6[8] = upper_xor_0_2[8];
constraint upper_intermediate_output_0_6[9] = upper_xor_0_2[9];
constraint upper_intermediate_output_0_6[10] = upper_xor_0_2[10];
constraint upper_intermediate_output_0_6[11] = upper_xor_0_2[11];
constraint upper_intermediate_output_0_6[12] = upper_xor_0_2[12];
constraint upper_intermediate_output_0_6[13] = upper_xor_0_2[13];
constraint upper_intermediate_output_0_6[14] = upper_xor_0_2[14];
constraint upper_intermediate_output_0_6[15] = upper_xor_0_2[15];
constraint upper_intermediate_output_0_6[16] = upper_xor_0_2[16];
constraint upper_intermediate_output_0_6[17] = upper_xor_0_2[17];
constraint upper_intermediate_output_0_6[18] = upper_xor_0_2[18];
constraint upper_intermediate_output_0_6[19] = upper_xor_0_2[19];
constraint upper_intermediate_output_0_6[20] = upper_xor_0_2[20];
constraint upper_intermediate_output_0_6[21] = upper_xor_0_2[21];
constraint upper_intermediate_output_0_6[22] = upper_xor_0_2[22];
constraint upper_intermediate_output_0_6[23] = upper_xor_0_2[23];
constraint upper_intermediate_output_0_6[24] = upper_xor_0_4[0];
constraint upper_intermediate_output_0_6[25] = upper_xor_0_4[1];
constraint upper_intermediate_output_0_6[26] = upper_xor_0_4[2];
constraint upper_intermediate_output_0_6[27] = upper_xor_0_4[3];
constraint upper_intermediate_output_0_6[28] = upper_xor_0_4[4];
constraint upper_intermediate_output_0_6[29] = upper_xor_0_4[5];
constraint upper_intermediate_output_0_6[30] = upper_xor_0_4[6];
constraint upper_intermediate_output_0_6[31] = upper_xor_0_4[7];
constraint upper_intermediate_output_0_6[32] = upper_xor_0_4[8];
constraint upper_intermediate_output_0_6[33] = upper_xor_0_4[9];
constraint upper_intermediate_output_0_6[34] = upper_xor_0_4[10];
constraint upper_intermediate_output_0_6[35] = upper_xor_0_4[11];
constraint upper_intermediate_output_0_6[36] = upper_xor_0_4[12];
constraint upper_intermediate_output_0_6[37] = upper_xor_0_4[13];
constraint upper_intermediate_output_0_6[38] = upper_xor_0_4[14];
constraint upper_intermediate_output_0_6[39] = upper_xor_0_4[15];
constraint upper_intermediate_output_0_6[40] = upper_xor_0_4[16];
constraint upper_intermediate_output_0_6[41] = upper_xor_0_4[17];
constraint upper_intermediate_output_0_6[42] = upper_xor_0_4[18];
constraint upper_intermediate_output_0_6[43] = upper_xor_0_4[19];
constraint upper_intermediate_output_0_6[44] = upper_xor_0_4[20];
constraint upper_intermediate_output_0_6[45] = upper_xor_0_4[21];
constraint upper_intermediate_output_0_6[46] = upper_xor_0_4[22];
constraint upper_intermediate_output_0_6[47] = upper_xor_0_4[23];
constraint upper_rot_1_6[0] = upper_xor_0_2[16];
constraint upper_rot_1_6[1] = upper_xor_0_2[17];
constraint upper_rot_1_6[2] = upper_xor_0_2[18];
constraint upper_rot_1_6[3] = upper_xor_0_2[19];
constraint upper_rot_1_6[4] = upper_xor_0_2[20];
constraint upper_rot_1_6[5] = upper_xor_0_2[21];
constraint upper_rot_1_6[6] = upper_xor_0_2[22];
constraint upper_rot_1_6[7] = upper_xor_0_2[23];
constraint upper_rot_1_6[8] = upper_xor_0_2[0];
constraint upper_rot_1_6[9] = upper_xor_0_2[1];
constraint upper_rot_1_6[10] = upper_xor_0_2[2];
constraint upper_rot_1_6[11] = upper_xor_0_2[3];
constraint upper_rot_1_6[12] = upper_xor_0_2[4];
constraint upper_rot_1_6[13] = upper_xor_0_2[5];
constraint upper_rot_1_6[14] = upper_xor_0_2[6];
constraint upper_rot_1_6[15] = upper_xor_0_2[7];
constraint upper_rot_1_6[16] = upper_xor_0_2[8];
constraint upper_rot_1_6[17] = upper_xor_0_2[9];
constraint upper_rot_1_6[18] = upper_xor_0_2[10];
constraint upper_rot_1_6[19] = upper_xor_0_2[11];
constraint upper_rot_1_6[20] = upper_xor_0_2[12];
constraint upper_rot_1_6[21] = upper_xor_0_2[13];
constraint upper_rot_1_6[22] = upper_xor_0_2[14];
constraint upper_rot_1_6[23] = upper_xor_0_2[15];
constraint pre_upper_modadd_1_7_0[0] = upper_rot_1_6[0];
constraint pre_upper_modadd_1_7_0[1] = upper_rot_1_6[1];
constraint pre_upper_modadd_1_7_0[2] = upper_rot_1_6[2];
constraint pre_upper_modadd_1_7_0[3] = upper_rot_1_6[3];
constraint pre_upper_modadd_1_7_0[4] = upper_rot_1_6[4];
constraint pre_upper_modadd_1_7_0[5] = upper_rot_1_6[5];
constraint pre_upper_modadd_1_7_0[6] = upper_rot_1_6[6];
constraint pre_upper_modadd_1_7_0[7] = upper_rot_1_6[7];
constraint pre_upper_modadd_1_7_0[8] = upper_rot_1_6[8];
constraint pre_upper_modadd_1_7_0[9] = upper_rot_1_6[9];
constraint pre_upper_modadd_1_7_0[10] = upper_rot_1_6[10];
constraint pre_upper_modadd_1_7_0[11] = upper_rot_1_6[11];
constraint pre_upper_modadd_1_7_0[12] = upper_rot_1_6[12];
constraint pre_upper_modadd_1_7_0[13] = upper_rot_1_6[13];
constraint pre_upper_modadd_1_7_0[14] = upper_rot_1_6[14];
constraint pre_upper_modadd_1_7_0[15] = upper_rot_1_6[15];
constraint pre_upper_modadd_1_7_0[16] = upper_rot_1_6[16];
constraint pre_upper_modadd_1_7_0[17] = upper_rot_1_6[17];
constraint pre_upper_modadd_1_7_0[18] = upper_rot_1_6[18];
constraint pre_upper_modadd_1_7_0[19] = upper_rot_1_6[19];
constraint pre_upper_modadd_1_7_0[20] = upper_rot_1_6[20];
constraint pre_upper_modadd_1_7_0[21] = upper_rot_1_6[21];
constraint pre_upper_modadd_1_7_0[22] = upper_rot_1_6[22];
constraint pre_upper_modadd_1_7_0[23] = upper_rot_1_6[23];
constraint pre_upper_modadd_1_7_1[0] = upper_xor_0_4[0];
constraint pre_upper_modadd_1_7_1[1] = upper_xor_0_4[1];
constraint pre_upper_modadd_1_7_1[2] = upper_xor_0_4[2];
constraint pre_upper_modadd_1_7_1[3] = upper_xor_0_4[3];
constraint pre_upper_modadd_1_7_1[4] = upper_xor_0_4[4];
constraint pre_upper_modadd_1_7_1[5] = upper_xor_0_4[5];
constraint pre_upper_modadd_1_7_1[6] = upper_xor_0_4[6];
constraint pre_upper_modadd_1_7_1[7] = upper_xor_0_4[7];
constraint pre_upper_modadd_1_7_1[8] = upper_xor_0_4[8];
constraint pre_upper_modadd_1_7_1[9] = upper_xor_0_4[9];
constraint pre_upper_modadd_1_7_1[10] = upper_xor_0_4[10];
constraint pre_upper_modadd_1_7_1[11] = upper_xor_0_4[11];
constraint pre_upper_modadd_1_7_1[12] = upper_xor_0_4[12];
constraint pre_upper_modadd_1_7_1[13] = upper_xor_0_4[13];
constraint pre_upper_modadd_1_7_1[14] = upper_xor_0_4[14];
constraint pre_upper_modadd_1_7_1[15] = upper_xor_0_4[15];
constraint pre_upper_modadd_1_7_1[16] = upper_xor_0_4[16];
constraint pre_upper_modadd_1_7_1[17] = upper_xor_0_4[17];
constraint pre_upper_modadd_1_7_1[18] = upper_xor_0_4[18];
constraint pre_upper_modadd_1_7_1[19] = upper_xor_0_4[19];
constraint pre_upper_modadd_1_7_1[20] = upper_xor_0_4[20];
constraint pre_upper_modadd_1_7_1[21] = upper_xor_0_4[21];
constraint pre_upper_modadd_1_7_1[22] = upper_xor_0_4[22];
constraint pre_upper_modadd_1_7_1[23] = upper_xor_0_4[23];
constraint forall(j in 0..23)(if eq_upper_modadd_1_7[j] = 1 then (sum([pre_upper_modadd_1_7_1[j], pre_upper_modadd_1_7_0[j], upper_modadd_1_7[j]]) mod 2) = Shi_pre_upper_modadd_1_7_0[j] else true endif) /\ upper_p[1] = (24-sum(eq_upper_modadd_1_7))*100;
constraint 2*dummy_upper_xor_1_8[0] = (upper_modadd_1_7[0] + upper_xor_1_5[0] + upper_xor_1_8[0]);
constraint 2*dummy_upper_xor_1_8[1] = (upper_modadd_1_7[1] + upper_xor_1_5[1] + upper_xor_1_8[1]);
constraint 2*dummy_upper_xor_1_8[2] = (upper_modadd_1_7[2] + upper_xor_1_5[2] + upper_xor_1_8[2]);
constraint 2*dummy_upper_xor_1_8[3] = (upper_modadd_1_7[3] + upper_xor_1_5[3] + upper_xor_1_8[3]);
constraint 2*dummy_upper_xor_1_8[4] = (upper_modadd_1_7[4] + upper_xor_1_5[4] + upper_xor_1_8[4]);
constraint 2*dummy_upper_xor_1_8[5] = (upper_modadd_1_7[5] + upper_xor_1_5[5] + upper_xor_1_8[5]);
constraint 2*dummy_upper_xor_1_8[6] = (upper_modadd_1_7[6] + upper_xor_1_5[6] + upper_xor_1_8[6]);
constraint 2*dummy_upper_xor_1_8[7] = (upper_modadd_1_7[7] + upper_xor_1_5[7] + upper_xor_1_8[7]);
constraint 2*dummy_upper_xor_1_8[8] = (upper_modadd_1_7[8] + upper_xor_1_5[8] + upper_xor_1_8[8]);
constraint 2*dummy_upper_xor_1_8[9] = (upper_modadd_1_7[9] + upper_xor_1_5[9] + upper_xor_1_8[9]);
constraint 2*dummy_upper_xor_1_8[10] = (upper_modadd_1_7[10] + upper_xor_1_5[10] + upper_xor_1_8[10]);
constraint 2*dummy_upper_xor_1_8[11] = (upper_modadd_1_7[11] + upper_xor_1_5[11] + upper_xor_1_8[11]);
constraint 2*dummy_upper_xor_1_8[12] = (upper_modadd_1_7[12] + upper_xor_1_5[12] + upper_xor_1_8[12]);
constraint 2*dummy_upper_xor_1_8[13] = (upper_modadd_1_7[13] + upper_xor_1_5[13] + upper_xor_1_8[13]);
constraint 2*dummy_upper_xor_1_8[14] = (upper_modadd_1_7[14] + upper_xor_1_5[14] + upper_xor_1_8[14]);
constraint 2*dummy_upper_xor_1_8[15] = (upper_modadd_1_7[15] + upper_xor_1_5[15] + upper_xor_1_8[15]);
constraint 2*dummy_upper_xor_1_8[16] = (upper_modadd_1_7[16] + upper_xor_1_5[16] + upper_xor_1_8[16]);
constraint 2*dummy_upper_xor_1_8[17] = (upper_modadd_1_7[17] + upper_xor_1_5[17] + upper_xor_1_8[17]);
constraint 2*dummy_upper_xor_1_8[18] = (upper_modadd_1_7[18] + upper_xor_1_5[18] + upper_xor_1_8[18]);
constraint 2*dummy_upper_xor_1_8[19] = (upper_modadd_1_7[19] + upper_xor_1_5[19] + upper_xor_1_8[19]);
constraint 2*dummy_upper_xor_1_8[20] = (upper_modadd_1_7[20] + upper_xor_1_5[20] + upper_xor_1_8[20]);
constraint 2*dummy_upper_xor_1_8[21] = (upper_modadd_1_7[21] + upper_xor_1_5[21] + upper_xor_1_8[21]);
constraint 2*dummy_upper_xor_1_8[22] = (upper_modadd_1_7[22] + upper_xor_1_5[22] + upper_xor_1_8[22]);
constraint 2*dummy_upper_xor_1_8[23] = (upper_modadd_1_7[23] + upper_xor_1_5[23] + upper_xor_1_8[23]);
constraint upper_rot_1_9[0] = upper_xor_0_4[3];
constraint upper_rot_1_9[1] = upper_xor_0_4[4];
constraint upper_rot_1_9[2] = upper_xor_0_4[5];
constraint upper_rot_1_9[3] = upper_xor_0_4[6];
constraint upper_rot_1_9[4] = upper_xor_0_4[7];
constraint upper_rot_1_9[5] = upper_xor_0_4[8];
constraint upper_rot_1_9[6] = upper_xor_0_4[9];
constraint upper_rot_1_9[7] = upper_xor_0_4[10];
constraint upper_rot_1_9[8] = upper_xor_0_4[11];
constraint upper_rot_1_9[9] = upper_xor_0_4[12];
constraint upper_rot_1_9[10] = upper_xor_0_4[13];
constraint upper_rot_1_9[11] = upper_xor_0_4[14];
constraint upper_rot_1_9[12] = upper_xor_0_4[15];
constraint upper_rot_1_9[13] = upper_xor_0_4[16];
constraint upper_rot_1_9[14] = upper_xor_0_4[17];
constraint upper_rot_1_9[15] = upper_xor_0_4[18];
constraint upper_rot_1_9[16] = upper_xor_0_4[19];
constraint upper_rot_1_9[17] = upper_xor_0_4[20];
constraint upper_rot_1_9[18] = upper_xor_0_4[21];
constraint upper_rot_1_9[19] = upper_xor_0_4[22];
constraint upper_rot_1_9[20] = upper_xor_0_4[23];
constraint upper_rot_1_9[21] = upper_xor_0_4[0];
constraint upper_rot_1_9[22] = upper_xor_0_4[1];
constraint upper_rot_1_9[23] = upper_xor_0_4[2];
constraint 2*dummy_upper_xor_1_10[0] = (upper_xor_1_8[0] + upper_rot_1_9[0] + upper_xor_1_10[0]);
constraint 2*dummy_upper_xor_1_10[1] = (upper_xor_1_8[1] + upper_rot_1_9[1] + upper_xor_1_10[1]);
constraint 2*dummy_upper_xor_1_10[2] = (upper_xor_1_8[2] + upper_rot_1_9[2] + upper_xor_1_10[2]);
constraint 2*dummy_upper_xor_1_10[3] = (upper_xor_1_8[3] + upper_rot_1_9[3] + upper_xor_1_10[3]);
constraint 2*dummy_upper_xor_1_10[4] = (upper_xor_1_8[4] + upper_rot_1_9[4] + upper_xor_1_10[4]);
constraint 2*dummy_upper_xor_1_10[5] = (upper_xor_1_8[5] + upper_rot_1_9[5] + upper_xor_1_10[5]);
constraint 2*dummy_upper_xor_1_10[6] = (upper_xor_1_8[6] + upper_rot_1_9[6] + upper_xor_1_10[6]);
constraint 2*dummy_upper_xor_1_10[7] = (upper_xor_1_8[7] + upper_rot_1_9[7] + upper_xor_1_10[7]);
constraint 2*dummy_upper_xor_1_10[8] = (upper_xor_1_8[8] + upper_rot_1_9[8] + upper_xor_1_10[8]);
constraint 2*dummy_upper_xor_1_10[9] = (upper_xor_1_8[9] + upper_rot_1_9[9] + upper_xor_1_10[9]);
constraint 2*dummy_upper_xor_1_10[10] = (upper_xor_1_8[10] + upper_rot_1_9[10] + upper_xor_1_10[10]);
constraint 2*dummy_upper_xor_1_10[11] = (upper_xor_1_8[11] + upper_rot_1_9[11] + upper_xor_1_10[11]);
constraint 2*dummy_upper_xor_1_10[12] = (upper_xor_1_8[12] + upper_rot_1_9[12] + upper_xor_1_10[12]);
constraint 2*dummy_upper_xor_1_10[13] = (upper_xor_1_8[13] + upper_rot_1_9[13] + upper_xor_1_10[13]);
constraint 2*dummy_upper_xor_1_10[14] = (upper_xor_1_8[14] + upper_rot_1_9[14] + upper_xor_1_10[14]);
constraint 2*dummy_upper_xor_1_10[15] = (upper_xor_1_8[15] + upper_rot_1_9[15] + upper_xor_1_10[15]);
constraint 2*dummy_upper_xor_1_10[16] = (upper_xor_1_8[16] + upper_rot_1_9[16] + upper_xor_1_10[16]);
constraint 2*dummy_upper_xor_1_10[17] = (upper_xor_1_8[17] + upper_rot_1_9[17] + upper_xor_1_10[17]);
constraint 2*dummy_upper_xor_1_10[18] = (upper_xor_1_8[18] + upper_rot_1_9[18] + upper_xor_1_10[18]);
constraint 2*dummy_upper_xor_1_10[19] = (upper_xor_1_8[19] + upper_rot_1_9[19] + upper_xor_1_10[19]);
constraint 2*dummy_upper_xor_1_10[20] = (upper_xor_1_8[20] + upper_rot_1_9[20] + upper_xor_1_10[20]);
constraint 2*dummy_upper_xor_1_10[21] = (upper_xor_1_8[21] + upper_rot_1_9[21] + upper_xor_1_10[21]);
constraint 2*dummy_upper_xor_1_10[22] = (upper_xor_1_8[22] + upper_rot_1_9[22] + upper_xor_1_10[22]);
constraint 2*dummy_upper_xor_1_10[23] = (upper_xor_1_8[23] + upper_rot_1_9[23] + upper_xor_1_10[23]);
constraint upper_intermediate_output_1_12[0] = upper_xor_1_8[0];
constraint upper_intermediate_output_1_12[1] = upper_xor_1_8[1];
constraint upper_intermediate_output_1_12[2] = upper_xor_1_8[2];
constraint upper_intermediate_output_1_12[3] = upper_xor_1_8[3];
constraint upper_intermediate_output_1_12[4] = upper_xor_1_8[4];
constraint upper_intermediate_output_1_12[5] = upper_xor_1_8[5];
constraint upper_intermediate_output_1_12[6] = upper_xor_1_8[6];
constraint upper_intermediate_output_1_12[7] = upper_xor_1_8[7];
constraint upper_intermediate_output_1_12[8] = upper_xor_1_8[8];
constraint upper_intermediate_output_1_12[9] = upper_xor_1_8[9];
constraint upper_intermediate_output_1_12[10] = upper_xor_1_8[10];
constraint upper_intermediate_output_1_12[11] = upper_xor_1_8[11];
constraint upper_intermediate_output_1_12[12] = upper_xor_1_8[12];
constraint upper_intermediate_output_1_12[13] = upper_xor_1_8[13];
constraint upper_intermediate_output_1_12[14] = upper_xor_1_8[14];
constraint upper_intermediate_output_1_12[15] = upper_xor_1_8[15];
constraint upper_intermediate_output_1_12[16] = upper_xor_1_8[16];
constraint upper_intermediate_output_1_12[17] = upper_xor_1_8[17];
constraint upper_intermediate_output_1_12[18] = upper_xor_1_8[18];
constraint upper_intermediate_output_1_12[19] = upper_xor_1_8[19];
constraint upper_intermediate_output_1_12[20] = upper_xor_1_8[20];
constraint upper_intermediate_output_1_12[21] = upper_xor_1_8[21];
constraint upper_intermediate_output_1_12[22] = upper_xor_1_8[22];
constraint upper_intermediate_output_1_12[23] = upper_xor_1_8[23];
constraint upper_intermediate_output_1_12[24] = upper_xor_1_10[0];
constraint upper_intermediate_output_1_12[25] = upper_xor_1_10[1];
constraint upper_intermediate_output_1_12[26] = upper_xor_1_10[2];
constraint upper_intermediate_output_1_12[27] = upper_xor_1_10[3];
constraint upper_intermediate_output_1_12[28] = upper_xor_1_10[4];
constraint upper_intermediate_output_1_12[29] = upper_xor_1_10[5];
constraint upper_intermediate_output_1_12[30] = upper_xor_1_10[6];
constraint upper_intermediate_output_1_12[31] = upper_xor_1_10[7];
constraint upper_intermediate_output_1_12[32] = upper_xor_1_10[8];
constraint upper_intermediate_output_1_12[33] = upper_xor_1_10[9];
constraint upper_intermediate_output_1_12[34] = upper_xor_1_10[10];
constraint upper_intermediate_output_1_12[35] = upper_xor_1_10[11];
constraint upper_intermediate_output_1_12[36] = upper_xor_1_10[12];
constraint upper_intermediate_output_1_12[37] = upper_xor_1_10[13];
constraint upper_intermediate_output_1_12[38] = upper_xor_1_10[14];
constraint upper_intermediate_output_1_12[39] = upper_xor_1_10[15];
constraint upper_intermediate_output_1_12[40] = upper_xor_1_10[16];
constraint upper_intermediate_output_1_12[41] = upper_xor_1_10[17];
constraint upper_intermediate_output_1_12[42] = upper_xor_1_10[18];
constraint upper_intermediate_output_1_12[43] = upper_xor_1_10[19];
constraint upper_intermediate_output_1_12[44] = upper_xor_1_10[20];
constraint upper_intermediate_output_1_12[45] = upper_xor_1_10[21];
constraint upper_intermediate_output_1_12[46] = upper_xor_1_10[22];
constraint upper_intermediate_output_1_12[47] = upper_xor_1_10[23];
constraint upper_rot_2_6[0] = upper_xor_1_8[16];
constraint upper_rot_2_6[1] = upper_xor_1_8[17];
constraint upper_rot_2_6[2] = upper_xor_1_8[18];
constraint upper_rot_2_6[3] = upper_xor_1_8[19];
constraint upper_rot_2_6[4] = upper_xor_1_8[20];
constraint upper_rot_2_6[5] = upper_xor_1_8[21];
constraint upper_rot_2_6[6] = upper_xor_1_8[22];
constraint upper_rot_2_6[7] = upper_xor_1_8[23];
constraint upper_rot_2_6[8] = upper_xor_1_8[0];
constraint upper_rot_2_6[9] = upper_xor_1_8[1];
constraint upper_rot_2_6[10] = upper_xor_1_8[2];
constraint upper_rot_2_6[11] = upper_xor_1_8[3];
constraint upper_rot_2_6[12] = upper_xor_1_8[4];
constraint upper_rot_2_6[13] = upper_xor_1_8[5];
constraint upper_rot_2_6[14] = upper_xor_1_8[6];
constraint upper_rot_2_6[15] = upper_xor_1_8[7];
constraint upper_rot_2_6[16] = upper_xor_1_8[8];
constraint upper_rot_2_6[17] = upper_xor_1_8[9];
constraint upper_rot_2_6[18] = upper_xor_1_8[10];
constraint upper_rot_2_6[19] = upper_xor_1_8[11];
constraint upper_rot_2_6[20] = upper_xor_1_8[12];
constraint upper_rot_2_6[21] = upper_xor_1_8[13];
constraint upper_rot_2_6[22] = upper_xor_1_8[14];
constraint upper_rot_2_6[23] = upper_xor_1_8[15];
constraint pre_upper_modadd_2_7_0[0] = upper_rot_2_6[0];
constraint pre_upper_modadd_2_7_0[1] = upper_rot_2_6[1];
constraint pre_upper_modadd_2_7_0[2] = upper_rot_2_6[2];
constraint pre_upper_modadd_2_7_0[3] = upper_rot_2_6[3];
constraint pre_upper_modadd_2_7_0[4] = upper_rot_2_6[4];
constraint pre_upper_modadd_2_7_0[5] = upper_rot_2_6[5];
constraint pre_upper_modadd_2_7_0[6] = upper_rot_2_6[6];
constraint pre_upper_modadd_2_7_0[7] = upper_rot_2_6[7];
constraint pre_upper_modadd_2_7_0[8] = upper_rot_2_6[8];
constraint pre_upper_modadd_2_7_0[9] = upper_rot_2_6[9];
constraint pre_upper_modadd_2_7_0[10] = upper_rot_2_6[10];
constraint pre_upper_modadd_2_7_0[11] = upper_rot_2_6[11];
constraint pre_upper_modadd_2_7_0[12] = upper_rot_2_6[12];
constraint pre_upper_modadd_2_7_0[13] = upper_rot_2_6[13];
constraint pre_upper_modadd_2_7_0[14] = upper_rot_2_6[14];
constraint pre_upper_modadd_2_7_0[15] = upper_rot_2_6[15];
constraint pre_upper_modadd_2_7_0[16] = upper_rot_2_6[16];
constraint pre_upper_modadd_2_7_0[17] = upper_rot_2_6[17];
constraint pre_upper_modadd_2_7_0[18] = upper_rot_2_6[18];
constraint pre_upper_modadd_2_7_0[19] = upper_rot_2_6[19];
constraint pre_upper_modadd_2_7_0[20] = upper_rot_2_6[20];
constraint pre_upper_modadd_2_7_0[21] = upper_rot_2_6[21];
constraint pre_upper_modadd_2_7_0[22] = upper_rot_2_6[22];
constraint pre_upper_modadd_2_7_0[23] = upper_rot_2_6[23];
constraint pre_upper_modadd_2_7_1[0] = upper_xor_1_10[0];
constraint pre_upper_modadd_2_7_1[1] = upper_xor_1_10[1];
constraint pre_upper_modadd_2_7_1[2] = upper_xor_1_10[2];
constraint pre_upper_modadd_2_7_1[3] = upper_xor_1_10[3];
constraint pre_upper_modadd_2_7_1[4] = upper_xor_1_10[4];
constraint pre_upper_modadd_2_7_1[5] = upper_xor_1_10[5];
constraint pre_upper_modadd_2_7_1[6] = upper_xor_1_10[6];
constraint pre_upper_modadd_2_7_1[7] = upper_xor_1_10[7];
constraint pre_upper_modadd_2_7_1[8] = upper_xor_1_10[8];
constraint pre_upper_modadd_2_7_1[9] = upper_xor_1_10[9];
constraint pre_upper_modadd_2_7_1[10] = upper_xor_1_10[10];
constraint pre_upper_modadd_2_7_1[11] = upper_xor_1_10[11];
constraint pre_upper_modadd_2_7_1[12] = upper_xor_1_10[12];
constraint pre_upper_modadd_2_7_1[13] = upper_xor_1_10[13];
constraint pre_upper_modadd_2_7_1[14] = upper_xor_1_10[14];
constraint pre_upper_modadd_2_7_1[15] = upper_xor_1_10[15];
constraint pre_upper_modadd_2_7_1[16] = upper_xor_1_10[16];
constraint pre_upper_modadd_2_7_1[17] = upper_xor_1_10[17];
constraint pre_upper_modadd_2_7_1[18] = upper_xor_1_10[18];
constraint pre_upper_modadd_2_7_1[19] = upper_xor_1_10[19];
constraint pre_upper_modadd_2_7_1[20] = upper_xor_1_10[20];
constraint pre_upper_modadd_2_7_1[21] = upper_xor_1_10[21];
constraint pre_upper_modadd_2_7_1[22] = upper_xor_1_10[22];
constraint pre_upper_modadd_2_7_1[23] = upper_xor_1_10[23];
constraint forall(j in 0..23)(if eq_upper_modadd_2_7[j] = 1 then (sum([pre_upper_modadd_2_7_1[j], pre_upper_modadd_2_7_0[j], upper_modadd_2_7[j]]) mod 2) = Shi_pre_upper_modadd_2_7_0[j] else true endif) /\ upper_p[2] = (24-sum(eq_upper_modadd_2_7))*100;
constraint 2*dummy_upper_xor_2_8[0] = (upper_modadd_2_7[0] + upper_xor_2_5[0] + upper_xor_2_8[0]);
constraint 2*dummy_upper_xor_2_8[1] = (upper_modadd_2_7[1] + upper_xor_2_5[1] + upper_xor_2_8[1]);
constraint 2*dummy_upper_xor_2_8[2] = (upper_modadd_2_7[2] + upper_xor_2_5[2] + upper_xor_2_8[2]);
constraint 2*dummy_upper_xor_2_8[3] = (upper_modadd_2_7[3] + upper_xor_2_5[3] + upper_xor_2_8[3]);
constraint 2*dummy_upper_xor_2_8[4] = (upper_modadd_2_7[4] + upper_xor_2_5[4] + upper_xor_2_8[4]);
constraint 2*dummy_upper_xor_2_8[5] = (upper_modadd_2_7[5] + upper_xor_2_5[5] + upper_xor_2_8[5]);
constraint 2*dummy_upper_xor_2_8[6] = (upper_modadd_2_7[6] + upper_xor_2_5[6] + upper_xor_2_8[6]);
constraint 2*dummy_upper_xor_2_8[7] = (upper_modadd_2_7[7] + upper_xor_2_5[7] + upper_xor_2_8[7]);
constraint 2*dummy_upper_xor_2_8[8] = (upper_modadd_2_7[8] + upper_xor_2_5[8] + upper_xor_2_8[8]);
constraint 2*dummy_upper_xor_2_8[9] = (upper_modadd_2_7[9] + upper_xor_2_5[9] + upper_xor_2_8[9]);
constraint 2*dummy_upper_xor_2_8[10] = (upper_modadd_2_7[10] + upper_xor_2_5[10] + upper_xor_2_8[10]);
constraint 2*dummy_upper_xor_2_8[11] = (upper_modadd_2_7[11] + upper_xor_2_5[11] + upper_xor_2_8[11]);
constraint 2*dummy_upper_xor_2_8[12] = (upper_modadd_2_7[12] + upper_xor_2_5[12] + upper_xor_2_8[12]);
constraint 2*dummy_upper_xor_2_8[13] = (upper_modadd_2_7[13] + upper_xor_2_5[13] + upper_xor_2_8[13]);
constraint 2*dummy_upper_xor_2_8[14] = (upper_modadd_2_7[14] + upper_xor_2_5[14] + upper_xor_2_8[14]);
constraint 2*dummy_upper_xor_2_8[15] = (upper_modadd_2_7[15] + upper_xor_2_5[15] + upper_xor_2_8[15]);
constraint 2*dummy_upper_xor_2_8[16] = (upper_modadd_2_7[16] + upper_xor_2_5[16] + upper_xor_2_8[16]);
constraint 2*dummy_upper_xor_2_8[17] = (upper_modadd_2_7[17] + upper_xor_2_5[17] + upper_xor_2_8[17]);
constraint 2*dummy_upper_xor_2_8[18] = (upper_modadd_2_7[18] + upper_xor_2_5[18] + upper_xor_2_8[18]);
constraint 2*dummy_upper_xor_2_8[19] = (upper_modadd_2_7[19] + upper_xor_2_5[19] + upper_xor_2_8[19]);
constraint 2*dummy_upper_xor_2_8[20] = (upper_modadd_2_7[20] + upper_xor_2_5[20] + upper_xor_2_8[20]);
constraint 2*dummy_upper_xor_2_8[21] = (upper_modadd_2_7[21] + upper_xor_2_5[21] + upper_xor_2_8[21]);
constraint 2*dummy_upper_xor_2_8[22] = (upper_modadd_2_7[22] + upper_xor_2_5[22] + upper_xor_2_8[22]);
constraint 2*dummy_upper_xor_2_8[23] = (upper_modadd_2_7[23] + upper_xor_2_5[23] + upper_xor_2_8[23]);
constraint upper_rot_2_9[0] = upper_xor_1_10[3];
constraint upper_rot_2_9[1] = upper_xor_1_10[4];
constraint upper_rot_2_9[2] = upper_xor_1_10[5];
constraint upper_rot_2_9[3] = upper_xor_1_10[6];
constraint upper_rot_2_9[4] = upper_xor_1_10[7];
constraint upper_rot_2_9[5] = upper_xor_1_10[8];
constraint upper_rot_2_9[6] = upper_xor_1_10[9];
constraint upper_rot_2_9[7] = upper_xor_1_10[10];
constraint upper_rot_2_9[8] = upper_xor_1_10[11];
constraint upper_rot_2_9[9] = upper_xor_1_10[12];
constraint upper_rot_2_9[10] = upper_xor_1_10[13];
constraint upper_rot_2_9[11] = upper_xor_1_10[14];
constraint upper_rot_2_9[12] = upper_xor_1_10[15];
constraint upper_rot_2_9[13] = upper_xor_1_10[16];
constraint upper_rot_2_9[14] = upper_xor_1_10[17];
constraint upper_rot_2_9[15] = upper_xor_1_10[18];
constraint upper_rot_2_9[16] = upper_xor_1_10[19];
constraint upper_rot_2_9[17] = upper_xor_1_10[20];
constraint upper_rot_2_9[18] = upper_xor_1_10[21];
constraint upper_rot_2_9[19] = upper_xor_1_10[22];
constraint upper_rot_2_9[20] = upper_xor_1_10[23];
constraint upper_rot_2_9[21] = upper_xor_1_10[0];
constraint upper_rot_2_9[22] = upper_xor_1_10[1];
constraint upper_rot_2_9[23] = upper_xor_1_10[2];
constraint 2*dummy_upper_xor_2_10[0] = (upper_xor_2_8[0] + upper_rot_2_9[0] + upper_xor_2_10[0]);
constraint 2*dummy_upper_xor_2_10[1] = (upper_xor_2_8[1] + upper_rot_2_9[1] + upper_xor_2_10[1]);
constraint 2*dummy_upper_xor_2_10[2] = (upper_xor_2_8[2] + upper_rot_2_9[2] + upper_xor_2_10[2]);
constraint 2*dummy_upper_xor_2_10[3] = (upper_xor_2_8[3] + upper_rot_2_9[3] + upper_xor_2_10[3]);
constraint 2*dummy_upper_xor_2_10[4] = (upper_xor_2_8[4] + upper_rot_2_9[4] + upper_xor_2_10[4]);
constraint 2*dummy_upper_xor_2_10[5] = (upper_xor_2_8[5] + upper_rot_2_9[5] + upper_xor_2_10[5]);
constraint 2*dummy_upper_xor_2_10[6] = (upper_xor_2_8[6] + upper_rot_2_9[6] + upper_xor_2_10[6]);
constraint 2*dummy_upper_xor_2_10[7] = (upper_xor_2_8[7] + upper_rot_2_9[7] + upper_xor_2_10[7]);
constraint 2*dummy_upper_xor_2_10[8] = (upper_xor_2_8[8] + upper_rot_2_9[8] + upper_xor_2_10[8]);
constraint 2*dummy_upper_xor_2_10[9] = (upper_xor_2_8[9] + upper_rot_2_9[9] + upper_xor_2_10[9]);
constraint 2*dummy_upper_xor_2_10[10] = (upper_xor_2_8[10] + upper_rot_2_9[10] + upper_xor_2_10[10]);
constraint 2*dummy_upper_xor_2_10[11] = (upper_xor_2_8[11] + upper_rot_2_9[11] + upper_xor_2_10[11]);
constraint 2*dummy_upper_xor_2_10[12] = (upper_xor_2_8[12] + upper_rot_2_9[12] + upper_xor_2_10[12]);
constraint 2*dummy_upper_xor_2_10[13] = (upper_xor_2_8[13] + upper_rot_2_9[13] + upper_xor_2_10[13]);
constraint 2*dummy_upper_xor_2_10[14] = (upper_xor_2_8[14] + upper_rot_2_9[14] + upper_xor_2_10[14]);
constraint 2*dummy_upper_xor_2_10[15] = (upper_xor_2_8[15] + upper_rot_2_9[15] + upper_xor_2_10[15]);
constraint 2*dummy_upper_xor_2_10[16] = (upper_xor_2_8[16] + upper_rot_2_9[16] + upper_xor_2_10[16]);
constraint 2*dummy_upper_xor_2_10[17] = (upper_xor_2_8[17] + upper_rot_2_9[17] + upper_xor_2_10[17]);
constraint 2*dummy_upper_xor_2_10[18] = (upper_xor_2_8[18] + upper_rot_2_9[18] + upper_xor_2_10[18]);
constraint 2*dummy_upper_xor_2_10[19] = (upper_xor_2_8[19] + upper_rot_2_9[19] + upper_xor_2_10[19]);
constraint 2*dummy_upper_xor_2_10[20] = (upper_xor_2_8[20] + upper_rot_2_9[20] + upper_xor_2_10[20]);
constraint 2*dummy_upper_xor_2_10[21] = (upper_xor_2_8[21] + upper_rot_2_9[21] + upper_xor_2_10[21]);
constraint 2*dummy_upper_xor_2_10[22] = (upper_xor_2_8[22] + upper_rot_2_9[22] + upper_xor_2_10[22]);
constraint 2*dummy_upper_xor_2_10[23] = (upper_xor_2_8[23] + upper_rot_2_9[23] + upper_xor_2_10[23]);
constraint upper_intermediate_output_2_12[0] = upper_xor_2_8[0];
constraint upper_intermediate_output_2_12[1] = upper_xor_2_8[1];
constraint upper_intermediate_output_2_12[2] = upper_xor_2_8[2];
constraint upper_intermediate_output_2_12[3] = upper_xor_2_8[3];
constraint upper_intermediate_output_2_12[4] = upper_xor_2_8[4];
constraint upper_intermediate_output_2_12[5] = upper_xor_2_8[5];
constraint upper_intermediate_output_2_12[6] = upper_xor_2_8[6];
constraint upper_intermediate_output_2_12[7] = upper_xor_2_8[7];
constraint upper_intermediate_output_2_12[8] = upper_xor_2_8[8];
constraint upper_intermediate_output_2_12[9] = upper_xor_2_8[9];
constraint upper_intermediate_output_2_12[10] = upper_xor_2_8[10];
constraint upper_intermediate_output_2_12[11] = upper_xor_2_8[11];
constraint upper_intermediate_output_2_12[12] = upper_xor_2_8[12];
constraint upper_intermediate_output_2_12[13] = upper_xor_2_8[13];
constraint upper_intermediate_output_2_12[14] = upper_xor_2_8[14];
constraint upper_intermediate_output_2_12[15] = upper_xor_2_8[15];
constraint upper_intermediate_output_2_12[16] = upper_xor_2_8[16];
constraint upper_intermediate_output_2_12[17] = upper_xor_2_8[17];
constraint upper_intermediate_output_2_12[18] = upper_xor_2_8[18];
constraint upper_intermediate_output_2_12[19] = upper_xor_2_8[19];
constraint upper_intermediate_output_2_12[20] = upper_xor_2_8[20];
constraint upper_intermediate_output_2_12[21] = upper_xor_2_8[21];
constraint upper_intermediate_output_2_12[22] = upper_xor_2_8[22];
constraint upper_intermediate_output_2_12[23] = upper_xor_2_8[23];
constraint upper_intermediate_output_2_12[24] = upper_xor_2_10[0];
constraint upper_intermediate_output_2_12[25] = upper_xor_2_10[1];
constraint upper_intermediate_output_2_12[26] = upper_xor_2_10[2];
constraint upper_intermediate_output_2_12[27] = upper_xor_2_10[3];
constraint upper_intermediate_output_2_12[28] = upper_xor_2_10[4];
constraint upper_intermediate_output_2_12[29] = upper_xor_2_10[5];
constraint upper_intermediate_output_2_12[30] = upper_xor_2_10[6];
constraint upper_intermediate_output_2_12[31] = upper_xor_2_10[7];
constraint upper_intermediate_output_2_12[32] = upper_xor_2_10[8];
constraint upper_intermediate_output_2_12[33] = upper_xor_2_10[9];
constraint upper_intermediate_output_2_12[34] = upper_xor_2_10[10];
constraint upper_intermediate_output_2_12[35] = upper_xor_2_10[11];
constraint upper_intermediate_output_2_12[36] = upper_xor_2_10[12];
constraint upper_intermediate_output_2_12[37] = upper_xor_2_10[13];
constraint upper_intermediate_output_2_12[38] = upper_xor_2_10[14];
constraint upper_intermediate_output_2_12[39] = upper_xor_2_10[15];
constraint upper_intermediate_output_2_12[40] = upper_xor_2_10[16];
constraint upper_intermediate_output_2_12[41] = upper_xor_2_10[17];
constraint upper_intermediate_output_2_12[42] = upper_xor_2_10[18];
constraint upper_intermediate_output_2_12[43] = upper_xor_2_10[19];
constraint upper_intermediate_output_2_12[44] = upper_xor_2_10[20];
constraint upper_intermediate_output_2_12[45] = upper_xor_2_10[21];
constraint upper_intermediate_output_2_12[46] = upper_xor_2_10[22];
constraint upper_intermediate_output_2_12[47] = upper_xor_2_10[23];
constraint upper_rot_3_6[0] = upper_xor_2_8[16];
constraint upper_rot_3_6[1] = upper_xor_2_8[17];
constraint upper_rot_3_6[2] = upper_xor_2_8[18];
constraint upper_rot_3_6[3] = upper_xor_2_8[19];
constraint upper_rot_3_6[4] = upper_xor_2_8[20];
constraint upper_rot_3_6[5] = upper_xor_2_8[21];
constraint upper_rot_3_6[6] = upper_xor_2_8[22];
constraint upper_rot_3_6[7] = upper_xor_2_8[23];
constraint upper_rot_3_6[8] = upper_xor_2_8[0];
constraint upper_rot_3_6[9] = upper_xor_2_8[1];
constraint upper_rot_3_6[10] = upper_xor_2_8[2];
constraint upper_rot_3_6[11] = upper_xor_2_8[3];
constraint upper_rot_3_6[12] = upper_xor_2_8[4];
constraint upper_rot_3_6[13] = upper_xor_2_8[5];
constraint upper_rot_3_6[14] = upper_xor_2_8[6];
constraint upper_rot_3_6[15] = upper_xor_2_8[7];
constraint upper_rot_3_6[16] = upper_xor_2_8[8];
constraint upper_rot_3_6[17] = upper_xor_2_8[9];
constraint upper_rot_3_6[18] = upper_xor_2_8[10];
constraint upper_rot_3_6[19] = upper_xor_2_8[11];
constraint upper_rot_3_6[20] = upper_xor_2_8[12];
constraint upper_rot_3_6[21] = upper_xor_2_8[13];
constraint upper_rot_3_6[22] = upper_xor_2_8[14];
constraint upper_rot_3_6[23] = upper_xor_2_8[15];
constraint pre_upper_modadd_3_7_0[0] = upper_rot_3_6[0];
constraint pre_upper_modadd_3_7_0[1] = upper_rot_3_6[1];
constraint pre_upper_modadd_3_7_0[2] = upper_rot_3_6[2];
constraint pre_upper_modadd_3_7_0[3] = upper_rot_3_6[3];
constraint pre_upper_modadd_3_7_0[4] = upper_rot_3_6[4];
constraint pre_upper_modadd_3_7_0[5] = upper_rot_3_6[5];
constraint pre_upper_modadd_3_7_0[6] = upper_rot_3_6[6];
constraint pre_upper_modadd_3_7_0[7] = upper_rot_3_6[7];
constraint pre_upper_modadd_3_7_0[8] = upper_rot_3_6[8];
constraint pre_upper_modadd_3_7_0[9] = upper_rot_3_6[9];
constraint pre_upper_modadd_3_7_0[10] = upper_rot_3_6[10];
constraint pre_upper_modadd_3_7_0[11] = upper_rot_3_6[11];
constraint pre_upper_modadd_3_7_0[12] = upper_rot_3_6[12];
constraint pre_upper_modadd_3_7_0[13] = upper_rot_3_6[13];
constraint pre_upper_modadd_3_7_0[14] = upper_rot_3_6[14];
constraint pre_upper_modadd_3_7_0[15] = upper_rot_3_6[15];
constraint pre_upper_modadd_3_7_0[16] = upper_rot_3_6[16];
constraint pre_upper_modadd_3_7_0[17] = upper_rot_3_6[17];
constraint pre_upper_modadd_3_7_0[18] = upper_rot_3_6[18];
constraint pre_upper_modadd_3_7_0[19] = upper_rot_3_6[19];
constraint pre_upper_modadd_3_7_0[20] = upper_rot_3_6[20];
constraint pre_upper_modadd_3_7_0[21] = upper_rot_3_6[21];
constraint pre_upper_modadd_3_7_0[22] = upper_rot_3_6[22];
constraint pre_upper_modadd_3_7_0[23] = upper_rot_3_6[23];
constraint pre_upper_modadd_3_7_1[0] = upper_xor_2_10[0];
constraint pre_upper_modadd_3_7_1[1] = upper_xor_2_10[1];
constraint pre_upper_modadd_3_7_1[2] = upper_xor_2_10[2];
constraint pre_upper_modadd_3_7_1[3] = upper_xor_2_10[3];
constraint pre_upper_modadd_3_7_1[4] = upper_xor_2_10[4];
constraint pre_upper_modadd_3_7_1[5] = upper_xor_2_10[5];
constraint pre_upper_modadd_3_7_1[6] = upper_xor_2_10[6];
constraint pre_upper_modadd_3_7_1[7] = upper_xor_2_10[7];
constraint pre_upper_modadd_3_7_1[8] = upper_xor_2_10[8];
constraint pre_upper_modadd_3_7_1[9] = upper_xor_2_10[9];
constraint pre_upper_modadd_3_7_1[10] = upper_xor_2_10[10];
constraint pre_upper_modadd_3_7_1[11] = upper_xor_2_10[11];
constraint pre_upper_modadd_3_7_1[12] = upper_xor_2_10[12];
constraint pre_upper_modadd_3_7_1[13] = upper_xor_2_10[13];
constraint pre_upper_modadd_3_7_1[14] = upper_xor_2_10[14];
constraint pre_upper_modadd_3_7_1[15] = upper_xor_2_10[15];
constraint pre_upper_modadd_3_7_1[16] = upper_xor_2_10[16];
constraint pre_upper_modadd_3_7_1[17] = upper_xor_2_10[17];
constraint pre_upper_modadd_3_7_1[18] = upper_xor_2_10[18];
constraint pre_upper_modadd_3_7_1[19] = upper_xor_2_10[19];
constraint pre_upper_modadd_3_7_1[20] = upper_xor_2_10[20];
constraint pre_upper_modadd_3_7_1[21] = upper_xor_2_10[21];
constraint pre_upper_modadd_3_7_1[22] = upper_xor_2_10[22];
constraint pre_upper_modadd_3_7_1[23] = upper_xor_2_10[23];
constraint forall(j in 0..23)(if eq_upper_modadd_3_7[j] = 1 then (sum([pre_upper_modadd_3_7_1[j], pre_upper_modadd_3_7_0[j], upper_modadd_3_7[j]]) mod 2) = Shi_pre_upper_modadd_3_7_0[j] else true endif) /\ upper_p[3] = (24-sum(eq_upper_modadd_3_7))*100;
constraint 2*dummy_upper_xor_3_8[0] = (upper_modadd_3_7[0] + upper_xor_3_5[0] + upper_xor_3_8[0]);
constraint 2*dummy_upper_xor_3_8[1] = (upper_modadd_3_7[1] + upper_xor_3_5[1] + upper_xor_3_8[1]);
constraint 2*dummy_upper_xor_3_8[2] = (upper_modadd_3_7[2] + upper_xor_3_5[2] + upper_xor_3_8[2]);
constraint 2*dummy_upper_xor_3_8[3] = (upper_modadd_3_7[3] + upper_xor_3_5[3] + upper_xor_3_8[3]);
constraint 2*dummy_upper_xor_3_8[4] = (upper_modadd_3_7[4] + upper_xor_3_5[4] + upper_xor_3_8[4]);
constraint 2*dummy_upper_xor_3_8[5] = (upper_modadd_3_7[5] + upper_xor_3_5[5] + upper_xor_3_8[5]);
constraint 2*dummy_upper_xor_3_8[6] = (upper_modadd_3_7[6] + upper_xor_3_5[6] + upper_xor_3_8[6]);
constraint 2*dummy_upper_xor_3_8[7] = (upper_modadd_3_7[7] + upper_xor_3_5[7] + upper_xor_3_8[7]);
constraint 2*dummy_upper_xor_3_8[8] = (upper_modadd_3_7[8] + upper_xor_3_5[8] + upper_xor_3_8[8]);
constraint 2*dummy_upper_xor_3_8[9] = (upper_modadd_3_7[9] + upper_xor_3_5[9] + upper_xor_3_8[9]);
constraint 2*dummy_upper_xor_3_8[10] = (upper_modadd_3_7[10] + upper_xor_3_5[10] + upper_xor_3_8[10]);
constraint 2*dummy_upper_xor_3_8[11] = (upper_modadd_3_7[11] + upper_xor_3_5[11] + upper_xor_3_8[11]);
constraint 2*dummy_upper_xor_3_8[12] = (upper_modadd_3_7[12] + upper_xor_3_5[12] + upper_xor_3_8[12]);
constraint 2*dummy_upper_xor_3_8[13] = (upper_modadd_3_7[13] + upper_xor_3_5[13] + upper_xor_3_8[13]);
constraint 2*dummy_upper_xor_3_8[14] = (upper_modadd_3_7[14] + upper_xor_3_5[14] + upper_xor_3_8[14]);
constraint 2*dummy_upper_xor_3_8[15] = (upper_modadd_3_7[15] + upper_xor_3_5[15] + upper_xor_3_8[15]);
constraint 2*dummy_upper_xor_3_8[16] = (upper_modadd_3_7[16] + upper_xor_3_5[16] + upper_xor_3_8[16]);
constraint 2*dummy_upper_xor_3_8[17] = (upper_modadd_3_7[17] + upper_xor_3_5[17] + upper_xor_3_8[17]);
constraint 2*dummy_upper_xor_3_8[18] = (upper_modadd_3_7[18] + upper_xor_3_5[18] + upper_xor_3_8[18]);
constraint 2*dummy_upper_xor_3_8[19] = (upper_modadd_3_7[19] + upper_xor_3_5[19] + upper_xor_3_8[19]);
constraint 2*dummy_upper_xor_3_8[20] = (upper_modadd_3_7[20] + upper_xor_3_5[20] + upper_xor_3_8[20]);
constraint 2*dummy_upper_xor_3_8[21] = (upper_modadd_3_7[21] + upper_xor_3_5[21] + upper_xor_3_8[21]);
constraint 2*dummy_upper_xor_3_8[22] = (upper_modadd_3_7[22] + upper_xor_3_5[22] + upper_xor_3_8[22]);
constraint 2*dummy_upper_xor_3_8[23] = (upper_modadd_3_7[23] + upper_xor_3_5[23] + upper_xor_3_8[23]);
constraint upper_rot_3_9[0] = upper_xor_2_10[3];
constraint upper_rot_3_9[1] = upper_xor_2_10[4];
constraint upper_rot_3_9[2] = upper_xor_2_10[5];
constraint upper_rot_3_9[3] = upper_xor_2_10[6];
constraint upper_rot_3_9[4] = upper_xor_2_10[7];
constraint upper_rot_3_9[5] = upper_xor_2_10[8];
constraint upper_rot_3_9[6] = upper_xor_2_10[9];
constraint upper_rot_3_9[7] = upper_xor_2_10[10];
constraint upper_rot_3_9[8] = upper_xor_2_10[11];
constraint upper_rot_3_9[9] = upper_xor_2_10[12];
constraint upper_rot_3_9[10] = upper_xor_2_10[13];
constraint upper_rot_3_9[11] = upper_xor_2_10[14];
constraint upper_rot_3_9[12] = upper_xor_2_10[15];
constraint upper_rot_3_9[13] = upper_xor_2_10[16];
constraint upper_rot_3_9[14] = upper_xor_2_10[17];
constraint upper_rot_3_9[15] = upper_xor_2_10[18];
constraint upper_rot_3_9[16] = upper_xor_2_10[19];
constraint upper_rot_3_9[17] = upper_xor_2_10[20];
constraint upper_rot_3_9[18] = upper_xor_2_10[21];
constraint upper_rot_3_9[19] = upper_xor_2_10[22];
constraint upper_rot_3_9[20] = upper_xor_2_10[23];
constraint upper_rot_3_9[21] = upper_xor_2_10[0];
constraint upper_rot_3_9[22] = upper_xor_2_10[1];
constraint upper_rot_3_9[23] = upper_xor_2_10[2];
constraint 2*dummy_upper_xor_3_10[0] = (upper_xor_3_8[0] + upper_rot_3_9[0] + upper_xor_3_10[0]);
constraint 2*dummy_upper_xor_3_10[1] = (upper_xor_3_8[1] + upper_rot_3_9[1] + upper_xor_3_10[1]);
constraint 2*dummy_upper_xor_3_10[2] = (upper_xor_3_8[2] + upper_rot_3_9[2] + upper_xor_3_10[2]);
constraint 2*dummy_upper_xor_3_10[3] = (upper_xor_3_8[3] + upper_rot_3_9[3] + upper_xor_3_10[3]);
constraint 2*dummy_upper_xor_3_10[4] = (upper_xor_3_8[4] + upper_rot_3_9[4] + upper_xor_3_10[4]);
constraint 2*dummy_upper_xor_3_10[5] = (upper_xor_3_8[5] + upper_rot_3_9[5] + upper_xor_3_10[5]);
constraint 2*dummy_upper_xor_3_10[6] = (upper_xor_3_8[6] + upper_rot_3_9[6] + upper_xor_3_10[6]);
constraint 2*dummy_upper_xor_3_10[7] = (upper_xor_3_8[7] + upper_rot_3_9[7] + upper_xor_3_10[7]);
constraint 2*dummy_upper_xor_3_10[8] = (upper_xor_3_8[8] + upper_rot_3_9[8] + upper_xor_3_10[8]);
constraint 2*dummy_upper_xor_3_10[9] = (upper_xor_3_8[9] + upper_rot_3_9[9] + upper_xor_3_10[9]);
constraint 2*dummy_upper_xor_3_10[10] = (upper_xor_3_8[10] + upper_rot_3_9[10] + upper_xor_3_10[10]);
constraint 2*dummy_upper_xor_3_10[11] = (upper_xor_3_8[11] + upper_rot_3_9[11] + upper_xor_3_10[11]);
constraint 2*dummy_upper_xor_3_10[12] = (upper_xor_3_8[12] + upper_rot_3_9[12] + upper_xor_3_10[12]);
constraint 2*dummy_upper_xor_3_10[13] = (upper_xor_3_8[13] + upper_rot_3_9[13] + upper_xor_3_10[13]);
constraint 2*dummy_upper_xor_3_10[14] = (upper_xor_3_8[14] + upper_rot_3_9[14] + upper_xor_3_10[14]);
constraint 2*dummy_upper_xor_3_10[15] = (upper_xor_3_8[15] + upper_rot_3_9[15] + upper_xor_3_10[15]);
constraint 2*dummy_upper_xor_3_10[16] = (upper_xor_3_8[16] + upper_rot_3_9[16] + upper_xor_3_10[16]);
constraint 2*dummy_upper_xor_3_10[17] = (upper_xor_3_8[17] + upper_rot_3_9[17] + upper_xor_3_10[17]);
constraint 2*dummy_upper_xor_3_10[18] = (upper_xor_3_8[18] + upper_rot_3_9[18] + upper_xor_3_10[18]);
constraint 2*dummy_upper_xor_3_10[19] = (upper_xor_3_8[19] + upper_rot_3_9[19] + upper_xor_3_10[19]);
constraint 2*dummy_upper_xor_3_10[20] = (upper_xor_3_8[20] + upper_rot_3_9[20] + upper_xor_3_10[20]);
constraint 2*dummy_upper_xor_3_10[21] = (upper_xor_3_8[21] + upper_rot_3_9[21] + upper_xor_3_10[21]);
constraint 2*dummy_upper_xor_3_10[22] = (upper_xor_3_8[22] + upper_rot_3_9[22] + upper_xor_3_10[22]);
constraint 2*dummy_upper_xor_3_10[23] = (upper_xor_3_8[23] + upper_rot_3_9[23] + upper_xor_3_10[23]);
constraint upper_intermediate_output_3_12[0] = upper_xor_3_8[0];
constraint upper_intermediate_output_3_12[1] = upper_xor_3_8[1];
constraint upper_intermediate_output_3_12[2] = upper_xor_3_8[2];
constraint upper_intermediate_output_3_12[3] = upper_xor_3_8[3];
constraint upper_intermediate_output_3_12[4] = upper_xor_3_8[4];
constraint upper_intermediate_output_3_12[5] = upper_xor_3_8[5];
constraint upper_intermediate_output_3_12[6] = upper_xor_3_8[6];
constraint upper_intermediate_output_3_12[7] = upper_xor_3_8[7];
constraint upper_intermediate_output_3_12[8] = upper_xor_3_8[8];
constraint upper_intermediate_output_3_12[9] = upper_xor_3_8[9];
constraint upper_intermediate_output_3_12[10] = upper_xor_3_8[10];
constraint upper_intermediate_output_3_12[11] = upper_xor_3_8[11];
constraint upper_intermediate_output_3_12[12] = upper_xor_3_8[12];
constraint upper_intermediate_output_3_12[13] = upper_xor_3_8[13];
constraint upper_intermediate_output_3_12[14] = upper_xor_3_8[14];
constraint upper_intermediate_output_3_12[15] = upper_xor_3_8[15];
constraint upper_intermediate_output_3_12[16] = upper_xor_3_8[16];
constraint upper_intermediate_output_3_12[17] = upper_xor_3_8[17];
constraint upper_intermediate_output_3_12[18] = upper_xor_3_8[18];
constraint upper_intermediate_output_3_12[19] = upper_xor_3_8[19];
constraint upper_intermediate_output_3_12[20] = upper_xor_3_8[20];
constraint upper_intermediate_output_3_12[21] = upper_xor_3_8[21];
constraint upper_intermediate_output_3_12[22] = upper_xor_3_8[22];
constraint upper_intermediate_output_3_12[23] = upper_xor_3_8[23];
constraint upper_intermediate_output_3_12[24] = upper_xor_3_10[0];
constraint upper_intermediate_output_3_12[25] = upper_xor_3_10[1];
constraint upper_intermediate_output_3_12[26] = upper_xor_3_10[2];
constraint upper_intermediate_output_3_12[27] = upper_xor_3_10[3];
constraint upper_intermediate_output_3_12[28] = upper_xor_3_10[4];
constraint upper_intermediate_output_3_12[29] = upper_xor_3_10[5];
constraint upper_intermediate_output_3_12[30] = upper_xor_3_10[6];
constraint upper_intermediate_output_3_12[31] = upper_xor_3_10[7];
constraint upper_intermediate_output_3_12[32] = upper_xor_3_10[8];
constraint upper_intermediate_output_3_12[33] = upper_xor_3_10[9];
constraint upper_intermediate_output_3_12[34] = upper_xor_3_10[10];
constraint upper_intermediate_output_3_12[35] = upper_xor_3_10[11];
constraint upper_intermediate_output_3_12[36] = upper_xor_3_10[12];
constraint upper_intermediate_output_3_12[37] = upper_xor_3_10[13];
constraint upper_intermediate_output_3_12[38] = upper_xor_3_10[14];
constraint upper_intermediate_output_3_12[39] = upper_xor_3_10[15];
constraint upper_intermediate_output_3_12[40] = upper_xor_3_10[16];
constraint upper_intermediate_output_3_12[41] = upper_xor_3_10[17];
constraint upper_intermediate_output_3_12[42] = upper_xor_3_10[18];
constraint upper_intermediate_output_3_12[43] = upper_xor_3_10[19];
constraint upper_intermediate_output_3_12[44] = upper_xor_3_10[20];
constraint upper_intermediate_output_3_12[45] = upper_xor_3_10[21];
constraint upper_intermediate_output_3_12[46] = upper_xor_3_10[22];
constraint upper_intermediate_output_3_12[47] = upper_xor_3_10[23];
constraint upper_rot_4_6[0] = upper_xor_3_8[16];
constraint upper_rot_4_6[1] = upper_xor_3_8[17];
constraint upper_rot_4_6[2] = upper_xor_3_8[18];
constraint upper_rot_4_6[3] = upper_xor_3_8[19];
constraint upper_rot_4_6[4] = upper_xor_3_8[20];
constraint upper_rot_4_6[5] = upper_xor_3_8[21];
constraint upper_rot_4_6[6] = upper_xor_3_8[22];
constraint upper_rot_4_6[7] = upper_xor_3_8[23];
constraint upper_rot_4_6[8] = upper_xor_3_8[0];
constraint upper_rot_4_6[9] = upper_xor_3_8[1];
constraint upper_rot_4_6[10] = upper_xor_3_8[2];
constraint upper_rot_4_6[11] = upper_xor_3_8[3];
constraint upper_rot_4_6[12] = upper_xor_3_8[4];
constraint upper_rot_4_6[13] = upper_xor_3_8[5];
constraint upper_rot_4_6[14] = upper_xor_3_8[6];
constraint upper_rot_4_6[15] = upper_xor_3_8[7];
constraint upper_rot_4_6[16] = upper_xor_3_8[8];
constraint upper_rot_4_6[17] = upper_xor_3_8[9];
constraint upper_rot_4_6[18] = upper_xor_3_8[10];
constraint upper_rot_4_6[19] = upper_xor_3_8[11];
constraint upper_rot_4_6[20] = upper_xor_3_8[12];
constraint upper_rot_4_6[21] = upper_xor_3_8[13];
constraint upper_rot_4_6[22] = upper_xor_3_8[14];
constraint upper_rot_4_6[23] = upper_xor_3_8[15];
constraint pre_upper_modadd_4_7_0[0] = upper_rot_4_6[0];
constraint pre_upper_modadd_4_7_0[1] = upper_rot_4_6[1];
constraint pre_upper_modadd_4_7_0[2] = upper_rot_4_6[2];
constraint pre_upper_modadd_4_7_0[3] = upper_rot_4_6[3];
constraint pre_upper_modadd_4_7_0[4] = upper_rot_4_6[4];
constraint pre_upper_modadd_4_7_0[5] = upper_rot_4_6[5];
constraint pre_upper_modadd_4_7_0[6] = upper_rot_4_6[6];
constraint pre_upper_modadd_4_7_0[7] = upper_rot_4_6[7];
constraint pre_upper_modadd_4_7_0[8] = upper_rot_4_6[8];
constraint pre_upper_modadd_4_7_0[9] = upper_rot_4_6[9];
constraint pre_upper_modadd_4_7_0[10] = upper_rot_4_6[10];
constraint pre_upper_modadd_4_7_0[11] = upper_rot_4_6[11];
constraint pre_upper_modadd_4_7_0[12] = upper_rot_4_6[12];
constraint pre_upper_modadd_4_7_0[13] = upper_rot_4_6[13];
constraint pre_upper_modadd_4_7_0[14] = upper_rot_4_6[14];
constraint pre_upper_modadd_4_7_0[15] = upper_rot_4_6[15];
constraint pre_upper_modadd_4_7_0[16] = upper_rot_4_6[16];
constraint pre_upper_modadd_4_7_0[17] = upper_rot_4_6[17];
constraint pre_upper_modadd_4_7_0[18] = upper_rot_4_6[18];
constraint pre_upper_modadd_4_7_0[19] = upper_rot_4_6[19];
constraint pre_upper_modadd_4_7_0[20] = upper_rot_4_6[20];
constraint pre_upper_modadd_4_7_0[21] = upper_rot_4_6[21];
constraint pre_upper_modadd_4_7_0[22] = upper_rot_4_6[22];
constraint pre_upper_modadd_4_7_0[23] = upper_rot_4_6[23];
constraint pre_upper_modadd_4_7_1[0] = upper_xor_3_10[0];
constraint pre_upper_modadd_4_7_1[1] = upper_xor_3_10[1];
constraint pre_upper_modadd_4_7_1[2] = upper_xor_3_10[2];
constraint pre_upper_modadd_4_7_1[3] = upper_xor_3_10[3];
constraint pre_upper_modadd_4_7_1[4] = upper_xor_3_10[4];
constraint pre_upper_modadd_4_7_1[5] = upper_xor_3_10[5];
constraint pre_upper_modadd_4_7_1[6] = upper_xor_3_10[6];
constraint pre_upper_modadd_4_7_1[7] = upper_xor_3_10[7];
constraint pre_upper_modadd_4_7_1[8] = upper_xor_3_10[8];
constraint pre_upper_modadd_4_7_1[9] = upper_xor_3_10[9];
constraint pre_upper_modadd_4_7_1[10] = upper_xor_3_10[10];
constraint pre_upper_modadd_4_7_1[11] = upper_xor_3_10[11];
constraint pre_upper_modadd_4_7_1[12] = upper_xor_3_10[12];
constraint pre_upper_modadd_4_7_1[13] = upper_xor_3_10[13];
constraint pre_upper_modadd_4_7_1[14] = upper_xor_3_10[14];
constraint pre_upper_modadd_4_7_1[15] = upper_xor_3_10[15];
constraint pre_upper_modadd_4_7_1[16] = upper_xor_3_10[16];
constraint pre_upper_modadd_4_7_1[17] = upper_xor_3_10[17];
constraint pre_upper_modadd_4_7_1[18] = upper_xor_3_10[18];
constraint pre_upper_modadd_4_7_1[19] = upper_xor_3_10[19];
constraint pre_upper_modadd_4_7_1[20] = upper_xor_3_10[20];
constraint pre_upper_modadd_4_7_1[21] = upper_xor_3_10[21];
constraint pre_upper_modadd_4_7_1[22] = upper_xor_3_10[22];
constraint pre_upper_modadd_4_7_1[23] = upper_xor_3_10[23];
constraint forall(j in 0..23)(if eq_upper_modadd_4_7[j] = 1 then (sum([pre_upper_modadd_4_7_1[j], pre_upper_modadd_4_7_0[j], upper_modadd_4_7[j]]) mod 2) = Shi_pre_upper_modadd_4_7_0[j] else true endif) /\ upper_p[4] = (24-sum(eq_upper_modadd_4_7))*100;
constraint 2*dummy_upper_xor_4_8[0] = (upper_modadd_4_7[0] + upper_xor_4_5[0] + upper_xor_4_8[0]);
constraint 2*dummy_upper_xor_4_8[1] = (upper_modadd_4_7[1] + upper_xor_4_5[1] + upper_xor_4_8[1]);
constraint 2*dummy_upper_xor_4_8[2] = (upper_modadd_4_7[2] + upper_xor_4_5[2] + upper_xor_4_8[2]);
constraint 2*dummy_upper_xor_4_8[3] = (upper_modadd_4_7[3] + upper_xor_4_5[3] + upper_xor_4_8[3]);
constraint 2*dummy_upper_xor_4_8[4] = (upper_modadd_4_7[4] + upper_xor_4_5[4] + upper_xor_4_8[4]);
constraint 2*dummy_upper_xor_4_8[5] = (upper_modadd_4_7[5] + upper_xor_4_5[5] + upper_xor_4_8[5]);
constraint 2*dummy_upper_xor_4_8[6] = (upper_modadd_4_7[6] + upper_xor_4_5[6] + upper_xor_4_8[6]);
constraint 2*dummy_upper_xor_4_8[7] = (upper_modadd_4_7[7] + upper_xor_4_5[7] + upper_xor_4_8[7]);
constraint 2*dummy_upper_xor_4_8[8] = (upper_modadd_4_7[8] + upper_xor_4_5[8] + upper_xor_4_8[8]);
constraint 2*dummy_upper_xor_4_8[9] = (upper_modadd_4_7[9] + upper_xor_4_5[9] + upper_xor_4_8[9]);
constraint 2*dummy_upper_xor_4_8[10] = (upper_modadd_4_7[10] + upper_xor_4_5[10] + upper_xor_4_8[10]);
constraint 2*dummy_upper_xor_4_8[11] = (upper_modadd_4_7[11] + upper_xor_4_5[11] + upper_xor_4_8[11]);
constraint 2*dummy_upper_xor_4_8[12] = (upper_modadd_4_7[12] + upper_xor_4_5[12] + upper_xor_4_8[12]);
constraint 2*dummy_upper_xor_4_8[13] = (upper_modadd_4_7[13] + upper_xor_4_5[13] + upper_xor_4_8[13]);
constraint 2*dummy_upper_xor_4_8[14] = (upper_modadd_4_7[14] + upper_xor_4_5[14] + upper_xor_4_8[14]);
constraint 2*dummy_upper_xor_4_8[15] = (upper_modadd_4_7[15] + upper_xor_4_5[15] + upper_xor_4_8[15]);
constraint 2*dummy_upper_xor_4_8[16] = (upper_modadd_4_7[16] + upper_xor_4_5[16] + upper_xor_4_8[16]);
constraint 2*dummy_upper_xor_4_8[17] = (upper_modadd_4_7[17] + upper_xor_4_5[17] + upper_xor_4_8[17]);
constraint 2*dummy_upper_xor_4_8[18] = (upper_modadd_4_7[18] + upper_xor_4_5[18] + upper_xor_4_8[18]);
constraint 2*dummy_upper_xor_4_8[19] = (upper_modadd_4_7[19] + upper_xor_4_5[19] + upper_xor_4_8[19]);
constraint 2*dummy_upper_xor_4_8[20] = (upper_modadd_4_7[20] + upper_xor_4_5[20] + upper_xor_4_8[20]);
constraint 2*dummy_upper_xor_4_8[21] = (upper_modadd_4_7[21] + upper_xor_4_5[21] + upper_xor_4_8[21]);
constraint 2*dummy_upper_xor_4_8[22] = (upper_modadd_4_7[22] + upper_xor_4_5[22] + upper_xor_4_8[22]);
constraint 2*dummy_upper_xor_4_8[23] = (upper_modadd_4_7[23] + upper_xor_4_5[23] + upper_xor_4_8[23]);
constraint upper_rot_4_9[0] = upper_xor_3_10[3];
constraint upper_rot_4_9[1] = upper_xor_3_10[4];
constraint upper_rot_4_9[2] = upper_xor_3_10[5];
constraint upper_rot_4_9[3] = upper_xor_3_10[6];
constraint upper_rot_4_9[4] = upper_xor_3_10[7];
constraint upper_rot_4_9[5] = upper_xor_3_10[8];
constraint upper_rot_4_9[6] = upper_xor_3_10[9];
constraint upper_rot_4_9[7] = upper_xor_3_10[10];
constraint upper_rot_4_9[8] = upper_xor_3_10[11];
constraint upper_rot_4_9[9] = upper_xor_3_10[12];
constraint upper_rot_4_9[10] = upper_xor_3_10[13];
constraint upper_rot_4_9[11] = upper_xor_3_10[14];
constraint upper_rot_4_9[12] = upper_xor_3_10[15];
constraint upper_rot_4_9[13] = upper_xor_3_10[16];
constraint upper_rot_4_9[14] = upper_xor_3_10[17];
constraint upper_rot_4_9[15] = upper_xor_3_10[18];
constraint upper_rot_4_9[16] = upper_xor_3_10[19];
constraint upper_rot_4_9[17] = upper_xor_3_10[20];
constraint upper_rot_4_9[18] = upper_xor_3_10[21];
constraint upper_rot_4_9[19] = upper_xor_3_10[22];
constraint upper_rot_4_9[20] = upper_xor_3_10[23];
constraint upper_rot_4_9[21] = upper_xor_3_10[0];
constraint upper_rot_4_9[22] = upper_xor_3_10[1];
constraint upper_rot_4_9[23] = upper_xor_3_10[2];
constraint 2*dummy_upper_xor_4_10[0] = (upper_xor_4_8[0] + upper_rot_4_9[0] + upper_xor_4_10[0]);
constraint 2*dummy_upper_xor_4_10[1] = (upper_xor_4_8[1] + upper_rot_4_9[1] + upper_xor_4_10[1]);
constraint 2*dummy_upper_xor_4_10[2] = (upper_xor_4_8[2] + upper_rot_4_9[2] + upper_xor_4_10[2]);
constraint 2*dummy_upper_xor_4_10[3] = (upper_xor_4_8[3] + upper_rot_4_9[3] + upper_xor_4_10[3]);
constraint 2*dummy_upper_xor_4_10[4] = (upper_xor_4_8[4] + upper_rot_4_9[4] + upper_xor_4_10[4]);
constraint 2*dummy_upper_xor_4_10[5] = (upper_xor_4_8[5] + upper_rot_4_9[5] + upper_xor_4_10[5]);
constraint 2*dummy_upper_xor_4_10[6] = (upper_xor_4_8[6] + upper_rot_4_9[6] + upper_xor_4_10[6]);
constraint 2*dummy_upper_xor_4_10[7] = (upper_xor_4_8[7] + upper_rot_4_9[7] + upper_xor_4_10[7]);
constraint 2*dummy_upper_xor_4_10[8] = (upper_xor_4_8[8] + upper_rot_4_9[8] + upper_xor_4_10[8]);
constraint 2*dummy_upper_xor_4_10[9] = (upper_xor_4_8[9] + upper_rot_4_9[9] + upper_xor_4_10[9]);
constraint 2*dummy_upper_xor_4_10[10] = (upper_xor_4_8[10] + upper_rot_4_9[10] + upper_xor_4_10[10]);
constraint 2*dummy_upper_xor_4_10[11] = (upper_xor_4_8[11] + upper_rot_4_9[11] + upper_xor_4_10[11]);
constraint 2*dummy_upper_xor_4_10[12] = (upper_xor_4_8[12] + upper_rot_4_9[12] + upper_xor_4_10[12]);
constraint 2*dummy_upper_xor_4_10[13] = (upper_xor_4_8[13] + upper_rot_4_9[13] + upper_xor_4_10[13]);
constraint 2*dummy_upper_xor_4_10[14] = (upper_xor_4_8[14] + upper_rot_4_9[14] + upper_xor_4_10[14]);
constraint 2*dummy_upper_xor_4_10[15] = (upper_xor_4_8[15] + upper_rot_4_9[15] + upper_xor_4_10[15]);
constraint 2*dummy_upper_xor_4_10[16] = (upper_xor_4_8[16] + upper_rot_4_9[16] + upper_xor_4_10[16]);
constraint 2*dummy_upper_xor_4_10[17] = (upper_xor_4_8[17] + upper_rot_4_9[17] + upper_xor_4_10[17]);
constraint 2*dummy_upper_xor_4_10[18] = (upper_xor_4_8[18] + upper_rot_4_9[18] + upper_xor_4_10[18]);
constraint 2*dummy_upper_xor_4_10[19] = (upper_xor_4_8[19] + upper_rot_4_9[19] + upper_xor_4_10[19]);
constraint 2*dummy_upper_xor_4_10[20] = (upper_xor_4_8[20] + upper_rot_4_9[20] + upper_xor_4_10[20]);
constraint 2*dummy_upper_xor_4_10[21] = (upper_xor_4_8[21] + upper_rot_4_9[21] + upper_xor_4_10[21]);
constraint 2*dummy_upper_xor_4_10[22] = (upper_xor_4_8[22] + upper_rot_4_9[22] + upper_xor_4_10[22]);
constraint 2*dummy_upper_xor_4_10[23] = (upper_xor_4_8[23] + upper_rot_4_9[23] + upper_xor_4_10[23]);
constraint upper_intermediate_output_4_12[0] = upper_xor_4_8[0];
constraint upper_intermediate_output_4_12[1] = upper_xor_4_8[1];
constraint upper_intermediate_output_4_12[2] = upper_xor_4_8[2];
constraint upper_intermediate_output_4_12[3] = upper_xor_4_8[3];
constraint upper_intermediate_output_4_12[4] = upper_xor_4_8[4];
constraint upper_intermediate_output_4_12[5] = upper_xor_4_8[5];
constraint upper_intermediate_output_4_12[6] = upper_xor_4_8[6];
constraint upper_intermediate_output_4_12[7] = upper_xor_4_8[7];
constraint upper_intermediate_output_4_12[8] = upper_xor_4_8[8];
constraint upper_intermediate_output_4_12[9] = upper_xor_4_8[9];
constraint upper_intermediate_output_4_12[10] = upper_xor_4_8[10];
constraint upper_intermediate_output_4_12[11] = upper_xor_4_8[11];
constraint upper_intermediate_output_4_12[12] = upper_xor_4_8[12];
constraint upper_intermediate_output_4_12[13] = upper_xor_4_8[13];
constraint upper_intermediate_output_4_12[14] = upper_xor_4_8[14];
constraint upper_intermediate_output_4_12[15] = upper_xor_4_8[15];
constraint upper_intermediate_output_4_12[16] = upper_xor_4_8[16];
constraint upper_intermediate_output_4_12[17] = upper_xor_4_8[17];
constraint upper_intermediate_output_4_12[18] = upper_xor_4_8[18];
constraint upper_intermediate_output_4_12[19] = upper_xor_4_8[19];
constraint upper_intermediate_output_4_12[20] = upper_xor_4_8[20];
constraint upper_intermediate_output_4_12[21] = upper_xor_4_8[21];
constraint upper_intermediate_output_4_12[22] = upper_xor_4_8[22];
constraint upper_intermediate_output_4_12[23] = upper_xor_4_8[23];
constraint upper_intermediate_output_4_12[24] = upper_xor_4_10[0];
constraint upper_intermediate_output_4_12[25] = upper_xor_4_10[1];
constraint upper_intermediate_output_4_12[26] = upper_xor_4_10[2];
constraint upper_intermediate_output_4_12[27] = upper_xor_4_10[3];
constraint upper_intermediate_output_4_12[28] = upper_xor_4_10[4];
constraint upper_intermediate_output_4_12[29] = upper_xor_4_10[5];
constraint upper_intermediate_output_4_12[30] = upper_xor_4_10[6];
constraint upper_intermediate_output_4_12[31] = upper_xor_4_10[7];
constraint upper_intermediate_output_4_12[32] = upper_xor_4_10[8];
constraint upper_intermediate_output_4_12[33] = upper_xor_4_10[9];
constraint upper_intermediate_output_4_12[34] = upper_xor_4_10[10];
constraint upper_intermediate_output_4_12[35] = upper_xor_4_10[11];
constraint upper_intermediate_output_4_12[36] = upper_xor_4_10[12];
constraint upper_intermediate_output_4_12[37] = upper_xor_4_10[13];
constraint upper_intermediate_output_4_12[38] = upper_xor_4_10[14];
constraint upper_intermediate_output_4_12[39] = upper_xor_4_10[15];
constraint upper_intermediate_output_4_12[40] = upper_xor_4_10[16];
constraint upper_intermediate_output_4_12[41] = upper_xor_4_10[17];
constraint upper_intermediate_output_4_12[42] = upper_xor_4_10[18];
constraint upper_intermediate_output_4_12[43] = upper_xor_4_10[19];
constraint upper_intermediate_output_4_12[44] = upper_xor_4_10[20];
constraint upper_intermediate_output_4_12[45] = upper_xor_4_10[21];
constraint upper_intermediate_output_4_12[46] = upper_xor_4_10[22];
constraint upper_intermediate_output_4_12[47] = upper_xor_4_10[23];
constraint 2*dummy_lower_xor_4_8[0] = (lower_xor_4_5[0] + lower_rot_5_6[0] + lower_xor_4_8[0]);
constraint 2*dummy_lower_xor_4_8[1] = (lower_xor_4_5[1] + lower_rot_5_6[1] + lower_xor_4_8[1]);
constraint 2*dummy_lower_xor_4_8[2] = (lower_xor_4_5[2] + lower_rot_5_6[2] + lower_xor_4_8[2]);
constraint 2*dummy_lower_xor_4_8[3] = (lower_xor_4_5[3] + lower_rot_5_6[3] + lower_xor_4_8[3]);
constraint 2*dummy_lower_xor_4_8[4] = (lower_xor_4_5[4] + lower_rot_5_6[4] + lower_xor_4_8[4]);
constraint 2*dummy_lower_xor_4_8[5] = (lower_xor_4_5[5] + lower_rot_5_6[5] + lower_xor_4_8[5]);
constraint 2*dummy_lower_xor_4_8[6] = (lower_xor_4_5[6] + lower_rot_5_6[6] + lower_xor_4_8[6]);
constraint 2*dummy_lower_xor_4_8[7] = (lower_xor_4_5[7] + lower_rot_5_6[7] + lower_xor_4_8[7]);
constraint 2*dummy_lower_xor_4_8[8] = (lower_xor_4_5[8] + lower_rot_5_6[8] + lower_xor_4_8[8]);
constraint 2*dummy_lower_xor_4_8[9] = (lower_xor_4_5[9] + lower_rot_5_6[9] + lower_xor_4_8[9]);
constraint 2*dummy_lower_xor_4_8[10] = (lower_xor_4_5[10] + lower_rot_5_6[10] + lower_xor_4_8[10]);
constraint 2*dummy_lower_xor_4_8[11] = (lower_xor_4_5[11] + lower_rot_5_6[11] + lower_xor_4_8[11]);
constraint 2*dummy_lower_xor_4_8[12] = (lower_xor_4_5[12] + lower_rot_5_6[12] + lower_xor_4_8[12]);
constraint 2*dummy_lower_xor_4_8[13] = (lower_xor_4_5[13] + lower_rot_5_6[13] + lower_xor_4_8[13]);
constraint 2*dummy_lower_xor_4_8[14] = (lower_xor_4_5[14] + lower_rot_5_6[14] + lower_xor_4_8[14]);
constraint 2*dummy_lower_xor_4_8[15] = (lower_xor_4_5[15] + lower_rot_5_6[15] + lower_xor_4_8[15]);
constraint 2*dummy_lower_xor_4_8[16] = (lower_xor_4_5[16] + lower_rot_5_6[16] + lower_xor_4_8[16]);
constraint 2*dummy_lower_xor_4_8[17] = (lower_xor_4_5[17] + lower_rot_5_6[17] + lower_xor_4_8[17]);
constraint 2*dummy_lower_xor_4_8[18] = (lower_xor_4_5[18] + lower_rot_5_6[18] + lower_xor_4_8[18]);
constraint 2*dummy_lower_xor_4_8[19] = (lower_xor_4_5[19] + lower_rot_5_6[19] + lower_xor_4_8[19]);
constraint 2*dummy_lower_xor_4_8[20] = (lower_xor_4_5[20] + lower_rot_5_6[20] + lower_xor_4_8[20]);
constraint 2*dummy_lower_xor_4_8[21] = (lower_xor_4_5[21] + lower_rot_5_6[21] + lower_xor_4_8[21]);
constraint 2*dummy_lower_xor_4_8[22] = (lower_xor_4_5[22] + lower_rot_5_6[22] + lower_xor_4_8[22]);
constraint 2*dummy_lower_xor_4_8[23] = (lower_xor_4_5[23] + lower_rot_5_6[23] + lower_xor_4_8[23]);
constraint 2*dummy_lower_xor_4_10[0] = (lower_rot_5_6[0] + lower_rot_5_9[0] + lower_xor_4_10[0]);
constraint 2*dummy_lower_xor_4_10[1] = (lower_rot_5_6[1] + lower_rot_5_9[1] + lower_xor_4_10[1]);
constraint 2*dummy_lower_xor_4_10[2] = (lower_rot_5_6[2] + lower_rot_5_9[2] + lower_xor_4_10[2]);
constraint 2*dummy_lower_xor_4_10[3] = (lower_rot_5_6[3] + lower_rot_5_9[3] + lower_xor_4_10[3]);
constraint 2*dummy_lower_xor_4_10[4] = (lower_rot_5_6[4] + lower_rot_5_9[4] + lower_xor_4_10[4]);
constraint 2*dummy_lower_xor_4_10[5] = (lower_rot_5_6[5] + lower_rot_5_9[5] + lower_xor_4_10[5]);
constraint 2*dummy_lower_xor_4_10[6] = (lower_rot_5_6[6] + lower_rot_5_9[6] + lower_xor_4_10[6]);
constraint 2*dummy_lower_xor_4_10[7] = (lower_rot_5_6[7] + lower_rot_5_9[7] + lower_xor_4_10[7]);
constraint 2*dummy_lower_xor_4_10[8] = (lower_rot_5_6[8] + lower_rot_5_9[8] + lower_xor_4_10[8]);
constraint 2*dummy_lower_xor_4_10[9] = (lower_rot_5_6[9] + lower_rot_5_9[9] + lower_xor_4_10[9]);
constraint 2*dummy_lower_xor_4_10[10] = (lower_rot_5_6[10] + lower_rot_5_9[10] + lower_xor_4_10[10]);
constraint 2*dummy_lower_xor_4_10[11] = (lower_rot_5_6[11] + lower_rot_5_9[11] + lower_xor_4_10[11]);
constraint 2*dummy_lower_xor_4_10[12] = (lower_rot_5_6[12] + lower_rot_5_9[12] + lower_xor_4_10[12]);
constraint 2*dummy_lower_xor_4_10[13] = (lower_rot_5_6[13] + lower_rot_5_9[13] + lower_xor_4_10[13]);
constraint 2*dummy_lower_xor_4_10[14] = (lower_rot_5_6[14] + lower_rot_5_9[14] + lower_xor_4_10[14]);
constraint 2*dummy_lower_xor_4_10[15] = (lower_rot_5_6[15] + lower_rot_5_9[15] + lower_xor_4_10[15]);
constraint 2*dummy_lower_xor_4_10[16] = (lower_rot_5_6[16] + lower_rot_5_9[16] + lower_xor_4_10[16]);
constraint 2*dummy_lower_xor_4_10[17] = (lower_rot_5_6[17] + lower_rot_5_9[17] + lower_xor_4_10[17]);
constraint 2*dummy_lower_xor_4_10[18] = (lower_rot_5_6[18] + lower_rot_5_9[18] + lower_xor_4_10[18]);
constraint 2*dummy_lower_xor_4_10[19] = (lower_rot_5_6[19] + lower_rot_5_9[19] + lower_xor_4_10[19]);
constraint 2*dummy_lower_xor_4_10[20] = (lower_rot_5_6[20] + lower_rot_5_9[20] + lower_xor_4_10[20]);
constraint 2*dummy_lower_xor_4_10[21] = (lower_rot_5_6[21] + lower_rot_5_9[21] + lower_xor_4_10[21]);
constraint 2*dummy_lower_xor_4_10[22] = (lower_rot_5_6[22] + lower_rot_5_9[22] + lower_xor_4_10[22]);
constraint 2*dummy_lower_xor_4_10[23] = (lower_rot_5_6[23] + lower_rot_5_9[23] + lower_xor_4_10[23]);
constraint lower_intermediate_output_4_12[0] = lower_rot_5_6[0];
constraint lower_intermediate_output_4_12[1] = lower_rot_5_6[1];
constraint lower_intermediate_output_4_12[2] = lower_rot_5_6[2];
constraint lower_intermediate_output_4_12[3] = lower_rot_5_6[3];
constraint lower_intermediate_output_4_12[4] = lower_rot_5_6[4];
constraint lower_intermediate_output_4_12[5] = lower_rot_5_6[5];
constraint lower_intermediate_output_4_12[6] = lower_rot_5_6[6];
constraint lower_intermediate_output_4_12[7] = lower_rot_5_6[7];
constraint lower_intermediate_output_4_12[8] = lower_rot_5_6[8];
constraint lower_intermediate_output_4_12[9] = lower_rot_5_6[9];
constraint lower_intermediate_output_4_12[10] = lower_rot_5_6[10];
constraint lower_intermediate_output_4_12[11] = lower_rot_5_6[11];
constraint lower_intermediate_output_4_12[12] = lower_rot_5_6[12];
constraint lower_intermediate_output_4_12[13] = lower_rot_5_6[13];
constraint lower_intermediate_output_4_12[14] = lower_rot_5_6[14];
constraint lower_intermediate_output_4_12[15] = lower_rot_5_6[15];
constraint lower_intermediate_output_4_12[16] = lower_rot_5_6[16];
constraint lower_intermediate_output_4_12[17] = lower_rot_5_6[17];
constraint lower_intermediate_output_4_12[18] = lower_rot_5_6[18];
constraint lower_intermediate_output_4_12[19] = lower_rot_5_6[19];
constraint lower_intermediate_output_4_12[20] = lower_rot_5_6[20];
constraint lower_intermediate_output_4_12[21] = lower_rot_5_6[21];
constraint lower_intermediate_output_4_12[22] = lower_rot_5_6[22];
constraint lower_intermediate_output_4_12[23] = lower_rot_5_6[23];
constraint lower_intermediate_output_4_12[24] = lower_rot_5_9[0];
constraint lower_intermediate_output_4_12[25] = lower_rot_5_9[1];
constraint lower_intermediate_output_4_12[26] = lower_rot_5_9[2];
constraint lower_intermediate_output_4_12[27] = lower_rot_5_9[3];
constraint lower_intermediate_output_4_12[28] = lower_rot_5_9[4];
constraint lower_intermediate_output_4_12[29] = lower_rot_5_9[5];
constraint lower_intermediate_output_4_12[30] = lower_rot_5_9[6];
constraint lower_intermediate_output_4_12[31] = lower_rot_5_9[7];
constraint lower_intermediate_output_4_12[32] = lower_rot_5_9[8];
constraint lower_intermediate_output_4_12[33] = lower_rot_5_9[9];
constraint lower_intermediate_output_4_12[34] = lower_rot_5_9[10];
constraint lower_intermediate_output_4_12[35] = lower_rot_5_9[11];
constraint lower_intermediate_output_4_12[36] = lower_rot_5_9[12];
constraint lower_intermediate_output_4_12[37] = lower_rot_5_9[13];
constraint lower_intermediate_output_4_12[38] = lower_rot_5_9[14];
constraint lower_intermediate_output_4_12[39] = lower_rot_5_9[15];
constraint lower_intermediate_output_4_12[40] = lower_rot_5_9[16];
constraint lower_intermediate_output_4_12[41] = lower_rot_5_9[17];
constraint lower_intermediate_output_4_12[42] = lower_rot_5_9[18];
constraint lower_intermediate_output_4_12[43] = lower_rot_5_9[19];
constraint lower_intermediate_output_4_12[44] = lower_rot_5_9[20];
constraint lower_intermediate_output_4_12[45] = lower_rot_5_9[21];
constraint lower_intermediate_output_4_12[46] = lower_rot_5_9[22];
constraint lower_intermediate_output_4_12[47] = lower_rot_5_9[23];
constraint lower_rot_4_9[0] = lower_xor_4_10[21];
constraint lower_rot_4_9[1] = lower_xor_4_10[22];
constraint lower_rot_4_9[2] = lower_xor_4_10[23];
constraint lower_rot_4_9[3] = lower_xor_4_10[0];
constraint lower_rot_4_9[4] = lower_xor_4_10[1];
constraint lower_rot_4_9[5] = lower_xor_4_10[2];
constraint lower_rot_4_9[6] = lower_xor_4_10[3];
constraint lower_rot_4_9[7] = lower_xor_4_10[4];
constraint lower_rot_4_9[8] = lower_xor_4_10[5];
constraint lower_rot_4_9[9] = lower_xor_4_10[6];
constraint lower_rot_4_9[10] = lower_xor_4_10[7];
constraint lower_rot_4_9[11] = lower_xor_4_10[8];
constraint lower_rot_4_9[12] = lower_xor_4_10[9];
constraint lower_rot_4_9[13] = lower_xor_4_10[10];
constraint lower_rot_4_9[14] = lower_xor_4_10[11];
constraint lower_rot_4_9[15] = lower_xor_4_10[12];
constraint lower_rot_4_9[16] = lower_xor_4_10[13];
constraint lower_rot_4_9[17] = lower_xor_4_10[14];
constraint lower_rot_4_9[18] = lower_xor_4_10[15];
constraint lower_rot_4_9[19] = lower_xor_4_10[16];
constraint lower_rot_4_9[20] = lower_xor_4_10[17];
constraint lower_rot_4_9[21] = lower_xor_4_10[18];
constraint lower_rot_4_9[22] = lower_xor_4_10[19];
constraint lower_rot_4_9[23] = lower_xor_4_10[20];
constraint pre_lower_modadd_4_7_0[0] = lower_xor_4_8[0];
constraint pre_lower_modadd_4_7_0[1] = lower_xor_4_8[1];
constraint pre_lower_modadd_4_7_0[2] = lower_xor_4_8[2];
constraint pre_lower_modadd_4_7_0[3] = lower_xor_4_8[3];
constraint pre_lower_modadd_4_7_0[4] = lower_xor_4_8[4];
constraint pre_lower_modadd_4_7_0[5] = lower_xor_4_8[5];
constraint pre_lower_modadd_4_7_0[6] = lower_xor_4_8[6];
constraint pre_lower_modadd_4_7_0[7] = lower_xor_4_8[7];
constraint pre_lower_modadd_4_7_0[8] = lower_xor_4_8[8];
constraint pre_lower_modadd_4_7_0[9] = lower_xor_4_8[9];
constraint pre_lower_modadd_4_7_0[10] = lower_xor_4_8[10];
constraint pre_lower_modadd_4_7_0[11] = lower_xor_4_8[11];
constraint pre_lower_modadd_4_7_0[12] = lower_xor_4_8[12];
constraint pre_lower_modadd_4_7_0[13] = lower_xor_4_8[13];
constraint pre_lower_modadd_4_7_0[14] = lower_xor_4_8[14];
constraint pre_lower_modadd_4_7_0[15] = lower_xor_4_8[15];
constraint pre_lower_modadd_4_7_0[16] = lower_xor_4_8[16];
constraint pre_lower_modadd_4_7_0[17] = lower_xor_4_8[17];
constraint pre_lower_modadd_4_7_0[18] = lower_xor_4_8[18];
constraint pre_lower_modadd_4_7_0[19] = lower_xor_4_8[19];
constraint pre_lower_modadd_4_7_0[20] = lower_xor_4_8[20];
constraint pre_lower_modadd_4_7_0[21] = lower_xor_4_8[21];
constraint pre_lower_modadd_4_7_0[22] = lower_xor_4_8[22];
constraint pre_lower_modadd_4_7_0[23] = lower_xor_4_8[23];
constraint pre_lower_modadd_4_7_1[0] = lower_rot_4_9[0];
constraint pre_lower_modadd_4_7_1[1] = lower_rot_4_9[1];
constraint pre_lower_modadd_4_7_1[2] = lower_rot_4_9[2];
constraint pre_lower_modadd_4_7_1[3] = lower_rot_4_9[3];
constraint pre_lower_modadd_4_7_1[4] = lower_rot_4_9[4];
constraint pre_lower_modadd_4_7_1[5] = lower_rot_4_9[5];
constraint pre_lower_modadd_4_7_1[6] = lower_rot_4_9[6];
constraint pre_lower_modadd_4_7_1[7] = lower_rot_4_9[7];
constraint pre_lower_modadd_4_7_1[8] = lower_rot_4_9[8];
constraint pre_lower_modadd_4_7_1[9] = lower_rot_4_9[9];
constraint pre_lower_modadd_4_7_1[10] = lower_rot_4_9[10];
constraint pre_lower_modadd_4_7_1[11] = lower_rot_4_9[11];
constraint pre_lower_modadd_4_7_1[12] = lower_rot_4_9[12];
constraint pre_lower_modadd_4_7_1[13] = lower_rot_4_9[13];
constraint pre_lower_modadd_4_7_1[14] = lower_rot_4_9[14];
constraint pre_lower_modadd_4_7_1[15] = lower_rot_4_9[15];
constraint pre_lower_modadd_4_7_1[16] = lower_rot_4_9[16];
constraint pre_lower_modadd_4_7_1[17] = lower_rot_4_9[17];
constraint pre_lower_modadd_4_7_1[18] = lower_rot_4_9[18];
constraint pre_lower_modadd_4_7_1[19] = lower_rot_4_9[19];
constraint pre_lower_modadd_4_7_1[20] = lower_rot_4_9[20];
constraint pre_lower_modadd_4_7_1[21] = lower_rot_4_9[21];
constraint pre_lower_modadd_4_7_1[22] = lower_rot_4_9[22];
constraint pre_lower_modadd_4_7_1[23] = lower_rot_4_9[23];
constraint forall(j in 0..23)(if eq_lower_modadd_4_7[j] = 1 then (sum([pre_lower_modadd_4_7_1[j], pre_lower_modadd_4_7_0[j], lower_modadd_4_7[j]]) mod 2) = Shi_pre_lower_modadd_4_7_0[j] else true endif) /\ lower_p[0] = (24-sum(eq_lower_modadd_4_7))*100;
constraint lower_rot_4_6[0] = lower_modadd_4_7[8];
constraint lower_rot_4_6[1] = lower_modadd_4_7[9];
constraint lower_rot_4_6[2] = lower_modadd_4_7[10];
constraint lower_rot_4_6[3] = lower_modadd_4_7[11];
constraint lower_rot_4_6[4] = lower_modadd_4_7[12];
constraint lower_rot_4_6[5] = lower_modadd_4_7[13];
constraint lower_rot_4_6[6] = lower_modadd_4_7[14];
constraint lower_rot_4_6[7] = lower_modadd_4_7[15];
constraint lower_rot_4_6[8] = lower_modadd_4_7[16];
constraint lower_rot_4_6[9] = lower_modadd_4_7[17];
constraint lower_rot_4_6[10] = lower_modadd_4_7[18];
constraint lower_rot_4_6[11] = lower_modadd_4_7[19];
constraint lower_rot_4_6[12] = lower_modadd_4_7[20];
constraint lower_rot_4_6[13] = lower_modadd_4_7[21];
constraint lower_rot_4_6[14] = lower_modadd_4_7[22];
constraint lower_rot_4_6[15] = lower_modadd_4_7[23];
constraint lower_rot_4_6[16] = lower_modadd_4_7[0];
constraint lower_rot_4_6[17] = lower_modadd_4_7[1];
constraint lower_rot_4_6[18] = lower_modadd_4_7[2];
constraint lower_rot_4_6[19] = lower_modadd_4_7[3];
constraint lower_rot_4_6[20] = lower_modadd_4_7[4];
constraint lower_rot_4_6[21] = lower_modadd_4_7[5];
constraint lower_rot_4_6[22] = lower_modadd_4_7[6];
constraint lower_rot_4_6[23] = lower_modadd_4_7[7];
constraint upper_rot_5_6[0] = upper_xor_4_8[16];
constraint upper_rot_5_6[1] = upper_xor_4_8[17];
constraint upper_rot_5_6[2] = upper_xor_4_8[18];
constraint upper_rot_5_6[3] = upper_xor_4_8[19];
constraint upper_rot_5_6[4] = upper_xor_4_8[20];
constraint upper_rot_5_6[5] = upper_xor_4_8[21];
constraint upper_rot_5_6[6] = upper_xor_4_8[22];
constraint upper_rot_5_6[7] = upper_xor_4_8[23];
constraint upper_rot_5_6[8] = upper_xor_4_8[0];
constraint upper_rot_5_6[9] = upper_xor_4_8[1];
constraint upper_rot_5_6[10] = upper_xor_4_8[2];
constraint upper_rot_5_6[11] = upper_xor_4_8[3];
constraint upper_rot_5_6[12] = upper_xor_4_8[4];
constraint upper_rot_5_6[13] = upper_xor_4_8[5];
constraint upper_rot_5_6[14] = upper_xor_4_8[6];
constraint upper_rot_5_6[15] = upper_xor_4_8[7];
constraint upper_rot_5_6[16] = upper_xor_4_8[8];
constraint upper_rot_5_6[17] = upper_xor_4_8[9];
constraint upper_rot_5_6[18] = upper_xor_4_8[10];
constraint upper_rot_5_6[19] = upper_xor_4_8[11];
constraint upper_rot_5_6[20] = upper_xor_4_8[12];
constraint upper_rot_5_6[21] = upper_xor_4_8[13];
constraint upper_rot_5_6[22] = upper_xor_4_8[14];
constraint upper_rot_5_6[23] = upper_xor_4_8[15];
constraint pre_upper_modadd_5_7_0[0] = upper_rot_5_6[0];
constraint pre_upper_modadd_5_7_0[1] = upper_rot_5_6[1];
constraint pre_upper_modadd_5_7_0[2] = upper_rot_5_6[2];
constraint pre_upper_modadd_5_7_0[3] = upper_rot_5_6[3];
constraint pre_upper_modadd_5_7_0[4] = upper_rot_5_6[4];
constraint pre_upper_modadd_5_7_0[5] = upper_rot_5_6[5];
constraint pre_upper_modadd_5_7_0[6] = upper_rot_5_6[6];
constraint pre_upper_modadd_5_7_0[7] = upper_rot_5_6[7];
constraint pre_upper_modadd_5_7_0[8] = upper_rot_5_6[8];
constraint pre_upper_modadd_5_7_0[9] = upper_rot_5_6[9];
constraint pre_upper_modadd_5_7_0[10] = upper_rot_5_6[10];
constraint pre_upper_modadd_5_7_0[11] = upper_rot_5_6[11];
constraint pre_upper_modadd_5_7_0[12] = upper_rot_5_6[12];
constraint pre_upper_modadd_5_7_0[13] = upper_rot_5_6[13];
constraint pre_upper_modadd_5_7_0[14] = upper_rot_5_6[14];
constraint pre_upper_modadd_5_7_0[15] = upper_rot_5_6[15];
constraint pre_upper_modadd_5_7_0[16] = upper_rot_5_6[16];
constraint pre_upper_modadd_5_7_0[17] = upper_rot_5_6[17];
constraint pre_upper_modadd_5_7_0[18] = upper_rot_5_6[18];
constraint pre_upper_modadd_5_7_0[19] = upper_rot_5_6[19];
constraint pre_upper_modadd_5_7_0[20] = upper_rot_5_6[20];
constraint pre_upper_modadd_5_7_0[21] = upper_rot_5_6[21];
constraint pre_upper_modadd_5_7_0[22] = upper_rot_5_6[22];
constraint pre_upper_modadd_5_7_0[23] = upper_rot_5_6[23];
constraint pre_upper_modadd_5_7_1[0] = upper_xor_4_10[0];
constraint pre_upper_modadd_5_7_1[1] = upper_xor_4_10[1];
constraint pre_upper_modadd_5_7_1[2] = upper_xor_4_10[2];
constraint pre_upper_modadd_5_7_1[3] = upper_xor_4_10[3];
constraint pre_upper_modadd_5_7_1[4] = upper_xor_4_10[4];
constraint pre_upper_modadd_5_7_1[5] = upper_xor_4_10[5];
constraint pre_upper_modadd_5_7_1[6] = upper_xor_4_10[6];
constraint pre_upper_modadd_5_7_1[7] = upper_xor_4_10[7];
constraint pre_upper_modadd_5_7_1[8] = upper_xor_4_10[8];
constraint pre_upper_modadd_5_7_1[9] = upper_xor_4_10[9];
constraint pre_upper_modadd_5_7_1[10] = upper_xor_4_10[10];
constraint pre_upper_modadd_5_7_1[11] = upper_xor_4_10[11];
constraint pre_upper_modadd_5_7_1[12] = upper_xor_4_10[12];
constraint pre_upper_modadd_5_7_1[13] = upper_xor_4_10[13];
constraint pre_upper_modadd_5_7_1[14] = upper_xor_4_10[14];
constraint pre_upper_modadd_5_7_1[15] = upper_xor_4_10[15];
constraint pre_upper_modadd_5_7_1[16] = upper_xor_4_10[16];
constraint pre_upper_modadd_5_7_1[17] = upper_xor_4_10[17];
constraint pre_upper_modadd_5_7_1[18] = upper_xor_4_10[18];
constraint pre_upper_modadd_5_7_1[19] = upper_xor_4_10[19];
constraint pre_upper_modadd_5_7_1[20] = upper_xor_4_10[20];
constraint pre_upper_modadd_5_7_1[21] = upper_xor_4_10[21];
constraint pre_upper_modadd_5_7_1[22] = upper_xor_4_10[22];
constraint pre_upper_modadd_5_7_1[23] = upper_xor_4_10[23];
constraint forall(j in 0..23)(if eq_upper_modadd_5_7[j] = 1 then (sum([pre_upper_modadd_5_7_1[j], pre_upper_modadd_5_7_0[j], upper_modadd_5_7[j]]) mod 2) = Shi_pre_upper_modadd_5_7_0[j] else true endif) /\ upper_p[5] = (24-sum(eq_upper_modadd_5_7))*100;
constraint 2*dummy_upper_xor_5_8[0] = (upper_modadd_5_7[0] + upper_xor_5_5[0] + upper_xor_5_8[0]);
constraint 2*dummy_upper_xor_5_8[1] = (upper_modadd_5_7[1] + upper_xor_5_5[1] + upper_xor_5_8[1]);
constraint 2*dummy_upper_xor_5_8[2] = (upper_modadd_5_7[2] + upper_xor_5_5[2] + upper_xor_5_8[2]);
constraint 2*dummy_upper_xor_5_8[3] = (upper_modadd_5_7[3] + upper_xor_5_5[3] + upper_xor_5_8[3]);
constraint 2*dummy_upper_xor_5_8[4] = (upper_modadd_5_7[4] + upper_xor_5_5[4] + upper_xor_5_8[4]);
constraint 2*dummy_upper_xor_5_8[5] = (upper_modadd_5_7[5] + upper_xor_5_5[5] + upper_xor_5_8[5]);
constraint 2*dummy_upper_xor_5_8[6] = (upper_modadd_5_7[6] + upper_xor_5_5[6] + upper_xor_5_8[6]);
constraint 2*dummy_upper_xor_5_8[7] = (upper_modadd_5_7[7] + upper_xor_5_5[7] + upper_xor_5_8[7]);
constraint 2*dummy_upper_xor_5_8[8] = (upper_modadd_5_7[8] + upper_xor_5_5[8] + upper_xor_5_8[8]);
constraint 2*dummy_upper_xor_5_8[9] = (upper_modadd_5_7[9] + upper_xor_5_5[9] + upper_xor_5_8[9]);
constraint 2*dummy_upper_xor_5_8[10] = (upper_modadd_5_7[10] + upper_xor_5_5[10] + upper_xor_5_8[10]);
constraint 2*dummy_upper_xor_5_8[11] = (upper_modadd_5_7[11] + upper_xor_5_5[11] + upper_xor_5_8[11]);
constraint 2*dummy_upper_xor_5_8[12] = (upper_modadd_5_7[12] + upper_xor_5_5[12] + upper_xor_5_8[12]);
constraint 2*dummy_upper_xor_5_8[13] = (upper_modadd_5_7[13] + upper_xor_5_5[13] + upper_xor_5_8[13]);
constraint 2*dummy_upper_xor_5_8[14] = (upper_modadd_5_7[14] + upper_xor_5_5[14] + upper_xor_5_8[14]);
constraint 2*dummy_upper_xor_5_8[15] = (upper_modadd_5_7[15] + upper_xor_5_5[15] + upper_xor_5_8[15]);
constraint 2*dummy_upper_xor_5_8[16] = (upper_modadd_5_7[16] + upper_xor_5_5[16] + upper_xor_5_8[16]);
constraint 2*dummy_upper_xor_5_8[17] = (upper_modadd_5_7[17] + upper_xor_5_5[17] + upper_xor_5_8[17]);
constraint 2*dummy_upper_xor_5_8[18] = (upper_modadd_5_7[18] + upper_xor_5_5[18] + upper_xor_5_8[18]);
constraint 2*dummy_upper_xor_5_8[19] = (upper_modadd_5_7[19] + upper_xor_5_5[19] + upper_xor_5_8[19]);
constraint 2*dummy_upper_xor_5_8[20] = (upper_modadd_5_7[20] + upper_xor_5_5[20] + upper_xor_5_8[20]);
constraint 2*dummy_upper_xor_5_8[21] = (upper_modadd_5_7[21] + upper_xor_5_5[21] + upper_xor_5_8[21]);
constraint 2*dummy_upper_xor_5_8[22] = (upper_modadd_5_7[22] + upper_xor_5_5[22] + upper_xor_5_8[22]);
constraint 2*dummy_upper_xor_5_8[23] = (upper_modadd_5_7[23] + upper_xor_5_5[23] + upper_xor_5_8[23]);
constraint upper_rot_5_9[0] = upper_xor_4_10[3];
constraint upper_rot_5_9[1] = upper_xor_4_10[4];
constraint upper_rot_5_9[2] = upper_xor_4_10[5];
constraint upper_rot_5_9[3] = upper_xor_4_10[6];
constraint upper_rot_5_9[4] = upper_xor_4_10[7];
constraint upper_rot_5_9[5] = upper_xor_4_10[8];
constraint upper_rot_5_9[6] = upper_xor_4_10[9];
constraint upper_rot_5_9[7] = upper_xor_4_10[10];
constraint upper_rot_5_9[8] = upper_xor_4_10[11];
constraint upper_rot_5_9[9] = upper_xor_4_10[12];
constraint upper_rot_5_9[10] = upper_xor_4_10[13];
constraint upper_rot_5_9[11] = upper_xor_4_10[14];
constraint upper_rot_5_9[12] = upper_xor_4_10[15];
constraint upper_rot_5_9[13] = upper_xor_4_10[16];
constraint upper_rot_5_9[14] = upper_xor_4_10[17];
constraint upper_rot_5_9[15] = upper_xor_4_10[18];
constraint upper_rot_5_9[16] = upper_xor_4_10[19];
constraint upper_rot_5_9[17] = upper_xor_4_10[20];
constraint upper_rot_5_9[18] = upper_xor_4_10[21];
constraint upper_rot_5_9[19] = upper_xor_4_10[22];
constraint upper_rot_5_9[20] = upper_xor_4_10[23];
constraint upper_rot_5_9[21] = upper_xor_4_10[0];
constraint upper_rot_5_9[22] = upper_xor_4_10[1];
constraint upper_rot_5_9[23] = upper_xor_4_10[2];
constraint 2*dummy_upper_xor_5_10[0] = (upper_xor_5_8[0] + upper_rot_5_9[0] + upper_xor_5_10[0]);
constraint 2*dummy_upper_xor_5_10[1] = (upper_xor_5_8[1] + upper_rot_5_9[1] + upper_xor_5_10[1]);
constraint 2*dummy_upper_xor_5_10[2] = (upper_xor_5_8[2] + upper_rot_5_9[2] + upper_xor_5_10[2]);
constraint 2*dummy_upper_xor_5_10[3] = (upper_xor_5_8[3] + upper_rot_5_9[3] + upper_xor_5_10[3]);
constraint 2*dummy_upper_xor_5_10[4] = (upper_xor_5_8[4] + upper_rot_5_9[4] + upper_xor_5_10[4]);
constraint 2*dummy_upper_xor_5_10[5] = (upper_xor_5_8[5] + upper_rot_5_9[5] + upper_xor_5_10[5]);
constraint 2*dummy_upper_xor_5_10[6] = (upper_xor_5_8[6] + upper_rot_5_9[6] + upper_xor_5_10[6]);
constraint 2*dummy_upper_xor_5_10[7] = (upper_xor_5_8[7] + upper_rot_5_9[7] + upper_xor_5_10[7]);
constraint 2*dummy_upper_xor_5_10[8] = (upper_xor_5_8[8] + upper_rot_5_9[8] + upper_xor_5_10[8]);
constraint 2*dummy_upper_xor_5_10[9] = (upper_xor_5_8[9] + upper_rot_5_9[9] + upper_xor_5_10[9]);
constraint 2*dummy_upper_xor_5_10[10] = (upper_xor_5_8[10] + upper_rot_5_9[10] + upper_xor_5_10[10]);
constraint 2*dummy_upper_xor_5_10[11] = (upper_xor_5_8[11] + upper_rot_5_9[11] + upper_xor_5_10[11]);
constraint 2*dummy_upper_xor_5_10[12] = (upper_xor_5_8[12] + upper_rot_5_9[12] + upper_xor_5_10[12]);
constraint 2*dummy_upper_xor_5_10[13] = (upper_xor_5_8[13] + upper_rot_5_9[13] + upper_xor_5_10[13]);
constraint 2*dummy_upper_xor_5_10[14] = (upper_xor_5_8[14] + upper_rot_5_9[14] + upper_xor_5_10[14]);
constraint 2*dummy_upper_xor_5_10[15] = (upper_xor_5_8[15] + upper_rot_5_9[15] + upper_xor_5_10[15]);
constraint 2*dummy_upper_xor_5_10[16] = (upper_xor_5_8[16] + upper_rot_5_9[16] + upper_xor_5_10[16]);
constraint 2*dummy_upper_xor_5_10[17] = (upper_xor_5_8[17] + upper_rot_5_9[17] + upper_xor_5_10[17]);
constraint 2*dummy_upper_xor_5_10[18] = (upper_xor_5_8[18] + upper_rot_5_9[18] + upper_xor_5_10[18]);
constraint 2*dummy_upper_xor_5_10[19] = (upper_xor_5_8[19] + upper_rot_5_9[19] + upper_xor_5_10[19]);
constraint 2*dummy_upper_xor_5_10[20] = (upper_xor_5_8[20] + upper_rot_5_9[20] + upper_xor_5_10[20]);
constraint 2*dummy_upper_xor_5_10[21] = (upper_xor_5_8[21] + upper_rot_5_9[21] + upper_xor_5_10[21]);
constraint 2*dummy_upper_xor_5_10[22] = (upper_xor_5_8[22] + upper_rot_5_9[22] + upper_xor_5_10[22]);
constraint 2*dummy_upper_xor_5_10[23] = (upper_xor_5_8[23] + upper_rot_5_9[23] + upper_xor_5_10[23]);
constraint upper_intermediate_output_5_12[0] = upper_xor_5_8[0];
constraint upper_intermediate_output_5_12[1] = upper_xor_5_8[1];
constraint upper_intermediate_output_5_12[2] = upper_xor_5_8[2];
constraint upper_intermediate_output_5_12[3] = upper_xor_5_8[3];
constraint upper_intermediate_output_5_12[4] = upper_xor_5_8[4];
constraint upper_intermediate_output_5_12[5] = upper_xor_5_8[5];
constraint upper_intermediate_output_5_12[6] = upper_xor_5_8[6];
constraint upper_intermediate_output_5_12[7] = upper_xor_5_8[7];
constraint upper_intermediate_output_5_12[8] = upper_xor_5_8[8];
constraint upper_intermediate_output_5_12[9] = upper_xor_5_8[9];
constraint upper_intermediate_output_5_12[10] = upper_xor_5_8[10];
constraint upper_intermediate_output_5_12[11] = upper_xor_5_8[11];
constraint upper_intermediate_output_5_12[12] = upper_xor_5_8[12];
constraint upper_intermediate_output_5_12[13] = upper_xor_5_8[13];
constraint upper_intermediate_output_5_12[14] = upper_xor_5_8[14];
constraint upper_intermediate_output_5_12[15] = upper_xor_5_8[15];
constraint upper_intermediate_output_5_12[16] = upper_xor_5_8[16];
constraint upper_intermediate_output_5_12[17] = upper_xor_5_8[17];
constraint upper_intermediate_output_5_12[18] = upper_xor_5_8[18];
constraint upper_intermediate_output_5_12[19] = upper_xor_5_8[19];
constraint upper_intermediate_output_5_12[20] = upper_xor_5_8[20];
constraint upper_intermediate_output_5_12[21] = upper_xor_5_8[21];
constraint upper_intermediate_output_5_12[22] = upper_xor_5_8[22];
constraint upper_intermediate_output_5_12[23] = upper_xor_5_8[23];
constraint upper_intermediate_output_5_12[24] = upper_xor_5_10[0];
constraint upper_intermediate_output_5_12[25] = upper_xor_5_10[1];
constraint upper_intermediate_output_5_12[26] = upper_xor_5_10[2];
constraint upper_intermediate_output_5_12[27] = upper_xor_5_10[3];
constraint upper_intermediate_output_5_12[28] = upper_xor_5_10[4];
constraint upper_intermediate_output_5_12[29] = upper_xor_5_10[5];
constraint upper_intermediate_output_5_12[30] = upper_xor_5_10[6];
constraint upper_intermediate_output_5_12[31] = upper_xor_5_10[7];
constraint upper_intermediate_output_5_12[32] = upper_xor_5_10[8];
constraint upper_intermediate_output_5_12[33] = upper_xor_5_10[9];
constraint upper_intermediate_output_5_12[34] = upper_xor_5_10[10];
constraint upper_intermediate_output_5_12[35] = upper_xor_5_10[11];
constraint upper_intermediate_output_5_12[36] = upper_xor_5_10[12];
constraint upper_intermediate_output_5_12[37] = upper_xor_5_10[13];
constraint upper_intermediate_output_5_12[38] = upper_xor_5_10[14];
constraint upper_intermediate_output_5_12[39] = upper_xor_5_10[15];
constraint upper_intermediate_output_5_12[40] = upper_xor_5_10[16];
constraint upper_intermediate_output_5_12[41] = upper_xor_5_10[17];
constraint upper_intermediate_output_5_12[42] = upper_xor_5_10[18];
constraint upper_intermediate_output_5_12[43] = upper_xor_5_10[19];
constraint upper_intermediate_output_5_12[44] = upper_xor_5_10[20];
constraint upper_intermediate_output_5_12[45] = upper_xor_5_10[21];
constraint upper_intermediate_output_5_12[46] = upper_xor_5_10[22];
constraint upper_intermediate_output_5_12[47] = upper_xor_5_10[23];
constraint 2*dummy_lower_xor_5_8[0] = (lower_xor_5_5[0] + lower_rot_6_6[0] + lower_xor_5_8[0]);
constraint 2*dummy_lower_xor_5_8[1] = (lower_xor_5_5[1] + lower_rot_6_6[1] + lower_xor_5_8[1]);
constraint 2*dummy_lower_xor_5_8[2] = (lower_xor_5_5[2] + lower_rot_6_6[2] + lower_xor_5_8[2]);
constraint 2*dummy_lower_xor_5_8[3] = (lower_xor_5_5[3] + lower_rot_6_6[3] + lower_xor_5_8[3]);
constraint 2*dummy_lower_xor_5_8[4] = (lower_xor_5_5[4] + lower_rot_6_6[4] + lower_xor_5_8[4]);
constraint 2*dummy_lower_xor_5_8[5] = (lower_xor_5_5[5] + lower_rot_6_6[5] + lower_xor_5_8[5]);
constraint 2*dummy_lower_xor_5_8[6] = (lower_xor_5_5[6] + lower_rot_6_6[6] + lower_xor_5_8[6]);
constraint 2*dummy_lower_xor_5_8[7] = (lower_xor_5_5[7] + lower_rot_6_6[7] + lower_xor_5_8[7]);
constraint 2*dummy_lower_xor_5_8[8] = (lower_xor_5_5[8] + lower_rot_6_6[8] + lower_xor_5_8[8]);
constraint 2*dummy_lower_xor_5_8[9] = (lower_xor_5_5[9] + lower_rot_6_6[9] + lower_xor_5_8[9]);
constraint 2*dummy_lower_xor_5_8[10] = (lower_xor_5_5[10] + lower_rot_6_6[10] + lower_xor_5_8[10]);
constraint 2*dummy_lower_xor_5_8[11] = (lower_xor_5_5[11] + lower_rot_6_6[11] + lower_xor_5_8[11]);
constraint 2*dummy_lower_xor_5_8[12] = (lower_xor_5_5[12] + lower_rot_6_6[12] + lower_xor_5_8[12]);
constraint 2*dummy_lower_xor_5_8[13] = (lower_xor_5_5[13] + lower_rot_6_6[13] + lower_xor_5_8[13]);
constraint 2*dummy_lower_xor_5_8[14] = (lower_xor_5_5[14] + lower_rot_6_6[14] + lower_xor_5_8[14]);
constraint 2*dummy_lower_xor_5_8[15] = (lower_xor_5_5[15] + lower_rot_6_6[15] + lower_xor_5_8[15]);
constraint 2*dummy_lower_xor_5_8[16] = (lower_xor_5_5[16] + lower_rot_6_6[16] + lower_xor_5_8[16]);
constraint 2*dummy_lower_xor_5_8[17] = (lower_xor_5_5[17] + lower_rot_6_6[17] + lower_xor_5_8[17]);
constraint 2*dummy_lower_xor_5_8[18] = (lower_xor_5_5[18] + lower_rot_6_6[18] + lower_xor_5_8[18]);
constraint 2*dummy_lower_xor_5_8[19] = (lower_xor_5_5[19] + lower_rot_6_6[19] + lower_xor_5_8[19]);
constraint 2*dummy_lower_xor_5_8[20] = (lower_xor_5_5[20] + lower_rot_6_6[20] + lower_xor_5_8[20]);
constraint 2*dummy_lower_xor_5_8[21] = (lower_xor_5_5[21] + lower_rot_6_6[21] + lower_xor_5_8[21]);
constraint 2*dummy_lower_xor_5_8[22] = (lower_xor_5_5[22] + lower_rot_6_6[22] + lower_xor_5_8[22]);
constraint 2*dummy_lower_xor_5_8[23] = (lower_xor_5_5[23] + lower_rot_6_6[23] + lower_xor_5_8[23]);
constraint 2*dummy_lower_xor_5_10[0] = (lower_rot_6_6[0] + lower_rot_6_9[0] + lower_xor_5_10[0]);
constraint 2*dummy_lower_xor_5_10[1] = (lower_rot_6_6[1] + lower_rot_6_9[1] + lower_xor_5_10[1]);
constraint 2*dummy_lower_xor_5_10[2] = (lower_rot_6_6[2] + lower_rot_6_9[2] + lower_xor_5_10[2]);
constraint 2*dummy_lower_xor_5_10[3] = (lower_rot_6_6[3] + lower_rot_6_9[3] + lower_xor_5_10[3]);
constraint 2*dummy_lower_xor_5_10[4] = (lower_rot_6_6[4] + lower_rot_6_9[4] + lower_xor_5_10[4]);
constraint 2*dummy_lower_xor_5_10[5] = (lower_rot_6_6[5] + lower_rot_6_9[5] + lower_xor_5_10[5]);
constraint 2*dummy_lower_xor_5_10[6] = (lower_rot_6_6[6] + lower_rot_6_9[6] + lower_xor_5_10[6]);
constraint 2*dummy_lower_xor_5_10[7] = (lower_rot_6_6[7] + lower_rot_6_9[7] + lower_xor_5_10[7]);
constraint 2*dummy_lower_xor_5_10[8] = (lower_rot_6_6[8] + lower_rot_6_9[8] + lower_xor_5_10[8]);
constraint 2*dummy_lower_xor_5_10[9] = (lower_rot_6_6[9] + lower_rot_6_9[9] + lower_xor_5_10[9]);
constraint 2*dummy_lower_xor_5_10[10] = (lower_rot_6_6[10] + lower_rot_6_9[10] + lower_xor_5_10[10]);
constraint 2*dummy_lower_xor_5_10[11] = (lower_rot_6_6[11] + lower_rot_6_9[11] + lower_xor_5_10[11]);
constraint 2*dummy_lower_xor_5_10[12] = (lower_rot_6_6[12] + lower_rot_6_9[12] + lower_xor_5_10[12]);
constraint 2*dummy_lower_xor_5_10[13] = (lower_rot_6_6[13] + lower_rot_6_9[13] + lower_xor_5_10[13]);
constraint 2*dummy_lower_xor_5_10[14] = (lower_rot_6_6[14] + lower_rot_6_9[14] + lower_xor_5_10[14]);
constraint 2*dummy_lower_xor_5_10[15] = (lower_rot_6_6[15] + lower_rot_6_9[15] + lower_xor_5_10[15]);
constraint 2*dummy_lower_xor_5_10[16] = (lower_rot_6_6[16] + lower_rot_6_9[16] + lower_xor_5_10[16]);
constraint 2*dummy_lower_xor_5_10[17] = (lower_rot_6_6[17] + lower_rot_6_9[17] + lower_xor_5_10[17]);
constraint 2*dummy_lower_xor_5_10[18] = (lower_rot_6_6[18] + lower_rot_6_9[18] + lower_xor_5_10[18]);
constraint 2*dummy_lower_xor_5_10[19] = (lower_rot_6_6[19] + lower_rot_6_9[19] + lower_xor_5_10[19]);
constraint 2*dummy_lower_xor_5_10[20] = (lower_rot_6_6[20] + lower_rot_6_9[20] + lower_xor_5_10[20]);
constraint 2*dummy_lower_xor_5_10[21] = (lower_rot_6_6[21] + lower_rot_6_9[21] + lower_xor_5_10[21]);
constraint 2*dummy_lower_xor_5_10[22] = (lower_rot_6_6[22] + lower_rot_6_9[22] + lower_xor_5_10[22]);
constraint 2*dummy_lower_xor_5_10[23] = (lower_rot_6_6[23] + lower_rot_6_9[23] + lower_xor_5_10[23]);
constraint lower_intermediate_output_5_12[0] = lower_rot_6_6[0];
constraint lower_intermediate_output_5_12[1] = lower_rot_6_6[1];
constraint lower_intermediate_output_5_12[2] = lower_rot_6_6[2];
constraint lower_intermediate_output_5_12[3] = lower_rot_6_6[3];
constraint lower_intermediate_output_5_12[4] = lower_rot_6_6[4];
constraint lower_intermediate_output_5_12[5] = lower_rot_6_6[5];
constraint lower_intermediate_output_5_12[6] = lower_rot_6_6[6];
constraint lower_intermediate_output_5_12[7] = lower_rot_6_6[7];
constraint lower_intermediate_output_5_12[8] = lower_rot_6_6[8];
constraint lower_intermediate_output_5_12[9] = lower_rot_6_6[9];
constraint lower_intermediate_output_5_12[10] = lower_rot_6_6[10];
constraint lower_intermediate_output_5_12[11] = lower_rot_6_6[11];
constraint lower_intermediate_output_5_12[12] = lower_rot_6_6[12];
constraint lower_intermediate_output_5_12[13] = lower_rot_6_6[13];
constraint lower_intermediate_output_5_12[14] = lower_rot_6_6[14];
constraint lower_intermediate_output_5_12[15] = lower_rot_6_6[15];
constraint lower_intermediate_output_5_12[16] = lower_rot_6_6[16];
constraint lower_intermediate_output_5_12[17] = lower_rot_6_6[17];
constraint lower_intermediate_output_5_12[18] = lower_rot_6_6[18];
constraint lower_intermediate_output_5_12[19] = lower_rot_6_6[19];
constraint lower_intermediate_output_5_12[20] = lower_rot_6_6[20];
constraint lower_intermediate_output_5_12[21] = lower_rot_6_6[21];
constraint lower_intermediate_output_5_12[22] = lower_rot_6_6[22];
constraint lower_intermediate_output_5_12[23] = lower_rot_6_6[23];
constraint lower_intermediate_output_5_12[24] = lower_rot_6_9[0];
constraint lower_intermediate_output_5_12[25] = lower_rot_6_9[1];
constraint lower_intermediate_output_5_12[26] = lower_rot_6_9[2];
constraint lower_intermediate_output_5_12[27] = lower_rot_6_9[3];
constraint lower_intermediate_output_5_12[28] = lower_rot_6_9[4];
constraint lower_intermediate_output_5_12[29] = lower_rot_6_9[5];
constraint lower_intermediate_output_5_12[30] = lower_rot_6_9[6];
constraint lower_intermediate_output_5_12[31] = lower_rot_6_9[7];
constraint lower_intermediate_output_5_12[32] = lower_rot_6_9[8];
constraint lower_intermediate_output_5_12[33] = lower_rot_6_9[9];
constraint lower_intermediate_output_5_12[34] = lower_rot_6_9[10];
constraint lower_intermediate_output_5_12[35] = lower_rot_6_9[11];
constraint lower_intermediate_output_5_12[36] = lower_rot_6_9[12];
constraint lower_intermediate_output_5_12[37] = lower_rot_6_9[13];
constraint lower_intermediate_output_5_12[38] = lower_rot_6_9[14];
constraint lower_intermediate_output_5_12[39] = lower_rot_6_9[15];
constraint lower_intermediate_output_5_12[40] = lower_rot_6_9[16];
constraint lower_intermediate_output_5_12[41] = lower_rot_6_9[17];
constraint lower_intermediate_output_5_12[42] = lower_rot_6_9[18];
constraint lower_intermediate_output_5_12[43] = lower_rot_6_9[19];
constraint lower_intermediate_output_5_12[44] = lower_rot_6_9[20];
constraint lower_intermediate_output_5_12[45] = lower_rot_6_9[21];
constraint lower_intermediate_output_5_12[46] = lower_rot_6_9[22];
constraint lower_intermediate_output_5_12[47] = lower_rot_6_9[23];
constraint lower_rot_5_9[0] = lower_xor_5_10[21];
constraint lower_rot_5_9[1] = lower_xor_5_10[22];
constraint lower_rot_5_9[2] = lower_xor_5_10[23];
constraint lower_rot_5_9[3] = lower_xor_5_10[0];
constraint lower_rot_5_9[4] = lower_xor_5_10[1];
constraint lower_rot_5_9[5] = lower_xor_5_10[2];
constraint lower_rot_5_9[6] = lower_xor_5_10[3];
constraint lower_rot_5_9[7] = lower_xor_5_10[4];
constraint lower_rot_5_9[8] = lower_xor_5_10[5];
constraint lower_rot_5_9[9] = lower_xor_5_10[6];
constraint lower_rot_5_9[10] = lower_xor_5_10[7];
constraint lower_rot_5_9[11] = lower_xor_5_10[8];
constraint lower_rot_5_9[12] = lower_xor_5_10[9];
constraint lower_rot_5_9[13] = lower_xor_5_10[10];
constraint lower_rot_5_9[14] = lower_xor_5_10[11];
constraint lower_rot_5_9[15] = lower_xor_5_10[12];
constraint lower_rot_5_9[16] = lower_xor_5_10[13];
constraint lower_rot_5_9[17] = lower_xor_5_10[14];
constraint lower_rot_5_9[18] = lower_xor_5_10[15];
constraint lower_rot_5_9[19] = lower_xor_5_10[16];
constraint lower_rot_5_9[20] = lower_xor_5_10[17];
constraint lower_rot_5_9[21] = lower_xor_5_10[18];
constraint lower_rot_5_9[22] = lower_xor_5_10[19];
constraint lower_rot_5_9[23] = lower_xor_5_10[20];
constraint pre_lower_modadd_5_7_0[0] = lower_xor_5_8[0];
constraint pre_lower_modadd_5_7_0[1] = lower_xor_5_8[1];
constraint pre_lower_modadd_5_7_0[2] = lower_xor_5_8[2];
constraint pre_lower_modadd_5_7_0[3] = lower_xor_5_8[3];
constraint pre_lower_modadd_5_7_0[4] = lower_xor_5_8[4];
constraint pre_lower_modadd_5_7_0[5] = lower_xor_5_8[5];
constraint pre_lower_modadd_5_7_0[6] = lower_xor_5_8[6];
constraint pre_lower_modadd_5_7_0[7] = lower_xor_5_8[7];
constraint pre_lower_modadd_5_7_0[8] = lower_xor_5_8[8];
constraint pre_lower_modadd_5_7_0[9] = lower_xor_5_8[9];
constraint pre_lower_modadd_5_7_0[10] = lower_xor_5_8[10];
constraint pre_lower_modadd_5_7_0[11] = lower_xor_5_8[11];
constraint pre_lower_modadd_5_7_0[12] = lower_xor_5_8[12];
constraint pre_lower_modadd_5_7_0[13] = lower_xor_5_8[13];
constraint pre_lower_modadd_5_7_0[14] = lower_xor_5_8[14];
constraint pre_lower_modadd_5_7_0[15] = lower_xor_5_8[15];
constraint pre_lower_modadd_5_7_0[16] = lower_xor_5_8[16];
constraint pre_lower_modadd_5_7_0[17] = lower_xor_5_8[17];
constraint pre_lower_modadd_5_7_0[18] = lower_xor_5_8[18];
constraint pre_lower_modadd_5_7_0[19] = lower_xor_5_8[19];
constraint pre_lower_modadd_5_7_0[20] = lower_xor_5_8[20];
constraint pre_lower_modadd_5_7_0[21] = lower_xor_5_8[21];
constraint pre_lower_modadd_5_7_0[22] = lower_xor_5_8[22];
constraint pre_lower_modadd_5_7_0[23] = lower_xor_5_8[23];
constraint pre_lower_modadd_5_7_1[0] = lower_rot_5_9[0];
constraint pre_lower_modadd_5_7_1[1] = lower_rot_5_9[1];
constraint pre_lower_modadd_5_7_1[2] = lower_rot_5_9[2];
constraint pre_lower_modadd_5_7_1[3] = lower_rot_5_9[3];
constraint pre_lower_modadd_5_7_1[4] = lower_rot_5_9[4];
constraint pre_lower_modadd_5_7_1[5] = lower_rot_5_9[5];
constraint pre_lower_modadd_5_7_1[6] = lower_rot_5_9[6];
constraint pre_lower_modadd_5_7_1[7] = lower_rot_5_9[7];
constraint pre_lower_modadd_5_7_1[8] = lower_rot_5_9[8];
constraint pre_lower_modadd_5_7_1[9] = lower_rot_5_9[9];
constraint pre_lower_modadd_5_7_1[10] = lower_rot_5_9[10];
constraint pre_lower_modadd_5_7_1[11] = lower_rot_5_9[11];
constraint pre_lower_modadd_5_7_1[12] = lower_rot_5_9[12];
constraint pre_lower_modadd_5_7_1[13] = lower_rot_5_9[13];
constraint pre_lower_modadd_5_7_1[14] = lower_rot_5_9[14];
constraint pre_lower_modadd_5_7_1[15] = lower_rot_5_9[15];
constraint pre_lower_modadd_5_7_1[16] = lower_rot_5_9[16];
constraint pre_lower_modadd_5_7_1[17] = lower_rot_5_9[17];
constraint pre_lower_modadd_5_7_1[18] = lower_rot_5_9[18];
constraint pre_lower_modadd_5_7_1[19] = lower_rot_5_9[19];
constraint pre_lower_modadd_5_7_1[20] = lower_rot_5_9[20];
constraint pre_lower_modadd_5_7_1[21] = lower_rot_5_9[21];
constraint pre_lower_modadd_5_7_1[22] = lower_rot_5_9[22];
constraint pre_lower_modadd_5_7_1[23] = lower_rot_5_9[23];
constraint forall(j in 0..23)(if eq_lower_modadd_5_7[j] = 1 then (sum([pre_lower_modadd_5_7_1[j], pre_lower_modadd_5_7_0[j], lower_modadd_5_7[j]]) mod 2) = Shi_pre_lower_modadd_5_7_0[j] else true endif) /\ lower_p[1] = (24-sum(eq_lower_modadd_5_7))*100;
constraint lower_rot_5_6[0] = lower_modadd_5_7[8];
constraint lower_rot_5_6[1] = lower_modadd_5_7[9];
constraint lower_rot_5_6[2] = lower_modadd_5_7[10];
constraint lower_rot_5_6[3] = lower_modadd_5_7[11];
constraint lower_rot_5_6[4] = lower_modadd_5_7[12];
constraint lower_rot_5_6[5] = lower_modadd_5_7[13];
constraint lower_rot_5_6[6] = lower_modadd_5_7[14];
constraint lower_rot_5_6[7] = lower_modadd_5_7[15];
constraint lower_rot_5_6[8] = lower_modadd_5_7[16];
constraint lower_rot_5_6[9] = lower_modadd_5_7[17];
constraint lower_rot_5_6[10] = lower_modadd_5_7[18];
constraint lower_rot_5_6[11] = lower_modadd_5_7[19];
constraint lower_rot_5_6[12] = lower_modadd_5_7[20];
constraint lower_rot_5_6[13] = lower_modadd_5_7[21];
constraint lower_rot_5_6[14] = lower_modadd_5_7[22];
constraint lower_rot_5_6[15] = lower_modadd_5_7[23];
constraint lower_rot_5_6[16] = lower_modadd_5_7[0];
constraint lower_rot_5_6[17] = lower_modadd_5_7[1];
constraint lower_rot_5_6[18] = lower_modadd_5_7[2];
constraint lower_rot_5_6[19] = lower_modadd_5_7[3];
constraint lower_rot_5_6[20] = lower_modadd_5_7[4];
constraint lower_rot_5_6[21] = lower_modadd_5_7[5];
constraint lower_rot_5_6[22] = lower_modadd_5_7[6];
constraint lower_rot_5_6[23] = lower_modadd_5_7[7];
constraint 2*dummy_lower_xor_6_8[0] = (lower_xor_6_5[0] + lower_rot_7_6[0] + lower_xor_6_8[0]);
constraint 2*dummy_lower_xor_6_8[1] = (lower_xor_6_5[1] + lower_rot_7_6[1] + lower_xor_6_8[1]);
constraint 2*dummy_lower_xor_6_8[2] = (lower_xor_6_5[2] + lower_rot_7_6[2] + lower_xor_6_8[2]);
constraint 2*dummy_lower_xor_6_8[3] = (lower_xor_6_5[3] + lower_rot_7_6[3] + lower_xor_6_8[3]);
constraint 2*dummy_lower_xor_6_8[4] = (lower_xor_6_5[4] + lower_rot_7_6[4] + lower_xor_6_8[4]);
constraint 2*dummy_lower_xor_6_8[5] = (lower_xor_6_5[5] + lower_rot_7_6[5] + lower_xor_6_8[5]);
constraint 2*dummy_lower_xor_6_8[6] = (lower_xor_6_5[6] + lower_rot_7_6[6] + lower_xor_6_8[6]);
constraint 2*dummy_lower_xor_6_8[7] = (lower_xor_6_5[7] + lower_rot_7_6[7] + lower_xor_6_8[7]);
constraint 2*dummy_lower_xor_6_8[8] = (lower_xor_6_5[8] + lower_rot_7_6[8] + lower_xor_6_8[8]);
constraint 2*dummy_lower_xor_6_8[9] = (lower_xor_6_5[9] + lower_rot_7_6[9] + lower_xor_6_8[9]);
constraint 2*dummy_lower_xor_6_8[10] = (lower_xor_6_5[10] + lower_rot_7_6[10] + lower_xor_6_8[10]);
constraint 2*dummy_lower_xor_6_8[11] = (lower_xor_6_5[11] + lower_rot_7_6[11] + lower_xor_6_8[11]);
constraint 2*dummy_lower_xor_6_8[12] = (lower_xor_6_5[12] + lower_rot_7_6[12] + lower_xor_6_8[12]);
constraint 2*dummy_lower_xor_6_8[13] = (lower_xor_6_5[13] + lower_rot_7_6[13] + lower_xor_6_8[13]);
constraint 2*dummy_lower_xor_6_8[14] = (lower_xor_6_5[14] + lower_rot_7_6[14] + lower_xor_6_8[14]);
constraint 2*dummy_lower_xor_6_8[15] = (lower_xor_6_5[15] + lower_rot_7_6[15] + lower_xor_6_8[15]);
constraint 2*dummy_lower_xor_6_8[16] = (lower_xor_6_5[16] + lower_rot_7_6[16] + lower_xor_6_8[16]);
constraint 2*dummy_lower_xor_6_8[17] = (lower_xor_6_5[17] + lower_rot_7_6[17] + lower_xor_6_8[17]);
constraint 2*dummy_lower_xor_6_8[18] = (lower_xor_6_5[18] + lower_rot_7_6[18] + lower_xor_6_8[18]);
constraint 2*dummy_lower_xor_6_8[19] = (lower_xor_6_5[19] + lower_rot_7_6[19] + lower_xor_6_8[19]);
constraint 2*dummy_lower_xor_6_8[20] = (lower_xor_6_5[20] + lower_rot_7_6[20] + lower_xor_6_8[20]);
constraint 2*dummy_lower_xor_6_8[21] = (lower_xor_6_5[21] + lower_rot_7_6[21] + lower_xor_6_8[21]);
constraint 2*dummy_lower_xor_6_8[22] = (lower_xor_6_5[22] + lower_rot_7_6[22] + lower_xor_6_8[22]);
constraint 2*dummy_lower_xor_6_8[23] = (lower_xor_6_5[23] + lower_rot_7_6[23] + lower_xor_6_8[23]);
constraint 2*dummy_lower_xor_6_10[0] = (lower_rot_7_6[0] + lower_rot_7_9[0] + lower_xor_6_10[0]);
constraint 2*dummy_lower_xor_6_10[1] = (lower_rot_7_6[1] + lower_rot_7_9[1] + lower_xor_6_10[1]);
constraint 2*dummy_lower_xor_6_10[2] = (lower_rot_7_6[2] + lower_rot_7_9[2] + lower_xor_6_10[2]);
constraint 2*dummy_lower_xor_6_10[3] = (lower_rot_7_6[3] + lower_rot_7_9[3] + lower_xor_6_10[3]);
constraint 2*dummy_lower_xor_6_10[4] = (lower_rot_7_6[4] + lower_rot_7_9[4] + lower_xor_6_10[4]);
constraint 2*dummy_lower_xor_6_10[5] = (lower_rot_7_6[5] + lower_rot_7_9[5] + lower_xor_6_10[5]);
constraint 2*dummy_lower_xor_6_10[6] = (lower_rot_7_6[6] + lower_rot_7_9[6] + lower_xor_6_10[6]);
constraint 2*dummy_lower_xor_6_10[7] = (lower_rot_7_6[7] + lower_rot_7_9[7] + lower_xor_6_10[7]);
constraint 2*dummy_lower_xor_6_10[8] = (lower_rot_7_6[8] + lower_rot_7_9[8] + lower_xor_6_10[8]);
constraint 2*dummy_lower_xor_6_10[9] = (lower_rot_7_6[9] + lower_rot_7_9[9] + lower_xor_6_10[9]);
constraint 2*dummy_lower_xor_6_10[10] = (lower_rot_7_6[10] + lower_rot_7_9[10] + lower_xor_6_10[10]);
constraint 2*dummy_lower_xor_6_10[11] = (lower_rot_7_6[11] + lower_rot_7_9[11] + lower_xor_6_10[11]);
constraint 2*dummy_lower_xor_6_10[12] = (lower_rot_7_6[12] + lower_rot_7_9[12] + lower_xor_6_10[12]);
constraint 2*dummy_lower_xor_6_10[13] = (lower_rot_7_6[13] + lower_rot_7_9[13] + lower_xor_6_10[13]);
constraint 2*dummy_lower_xor_6_10[14] = (lower_rot_7_6[14] + lower_rot_7_9[14] + lower_xor_6_10[14]);
constraint 2*dummy_lower_xor_6_10[15] = (lower_rot_7_6[15] + lower_rot_7_9[15] + lower_xor_6_10[15]);
constraint 2*dummy_lower_xor_6_10[16] = (lower_rot_7_6[16] + lower_rot_7_9[16] + lower_xor_6_10[16]);
constraint 2*dummy_lower_xor_6_10[17] = (lower_rot_7_6[17] + lower_rot_7_9[17] + lower_xor_6_10[17]);
constraint 2*dummy_lower_xor_6_10[18] = (lower_rot_7_6[18] + lower_rot_7_9[18] + lower_xor_6_10[18]);
constraint 2*dummy_lower_xor_6_10[19] = (lower_rot_7_6[19] + lower_rot_7_9[19] + lower_xor_6_10[19]);
constraint 2*dummy_lower_xor_6_10[20] = (lower_rot_7_6[20] + lower_rot_7_9[20] + lower_xor_6_10[20]);
constraint 2*dummy_lower_xor_6_10[21] = (lower_rot_7_6[21] + lower_rot_7_9[21] + lower_xor_6_10[21]);
constraint 2*dummy_lower_xor_6_10[22] = (lower_rot_7_6[22] + lower_rot_7_9[22] + lower_xor_6_10[22]);
constraint 2*dummy_lower_xor_6_10[23] = (lower_rot_7_6[23] + lower_rot_7_9[23] + lower_xor_6_10[23]);
constraint lower_intermediate_output_6_12[0] = lower_rot_7_6[0];
constraint lower_intermediate_output_6_12[1] = lower_rot_7_6[1];
constraint lower_intermediate_output_6_12[2] = lower_rot_7_6[2];
constraint lower_intermediate_output_6_12[3] = lower_rot_7_6[3];
constraint lower_intermediate_output_6_12[4] = lower_rot_7_6[4];
constraint lower_intermediate_output_6_12[5] = lower_rot_7_6[5];
constraint lower_intermediate_output_6_12[6] = lower_rot_7_6[6];
constraint lower_intermediate_output_6_12[7] = lower_rot_7_6[7];
constraint lower_intermediate_output_6_12[8] = lower_rot_7_6[8];
constraint lower_intermediate_output_6_12[9] = lower_rot_7_6[9];
constraint lower_intermediate_output_6_12[10] = lower_rot_7_6[10];
constraint lower_intermediate_output_6_12[11] = lower_rot_7_6[11];
constraint lower_intermediate_output_6_12[12] = lower_rot_7_6[12];
constraint lower_intermediate_output_6_12[13] = lower_rot_7_6[13];
constraint lower_intermediate_output_6_12[14] = lower_rot_7_6[14];
constraint lower_intermediate_output_6_12[15] = lower_rot_7_6[15];
constraint lower_intermediate_output_6_12[16] = lower_rot_7_6[16];
constraint lower_intermediate_output_6_12[17] = lower_rot_7_6[17];
constraint lower_intermediate_output_6_12[18] = lower_rot_7_6[18];
constraint lower_intermediate_output_6_12[19] = lower_rot_7_6[19];
constraint lower_intermediate_output_6_12[20] = lower_rot_7_6[20];
constraint lower_intermediate_output_6_12[21] = lower_rot_7_6[21];
constraint lower_intermediate_output_6_12[22] = lower_rot_7_6[22];
constraint lower_intermediate_output_6_12[23] = lower_rot_7_6[23];
constraint lower_intermediate_output_6_12[24] = lower_rot_7_9[0];
constraint lower_intermediate_output_6_12[25] = lower_rot_7_9[1];
constraint lower_intermediate_output_6_12[26] = lower_rot_7_9[2];
constraint lower_intermediate_output_6_12[27] = lower_rot_7_9[3];
constraint lower_intermediate_output_6_12[28] = lower_rot_7_9[4];
constraint lower_intermediate_output_6_12[29] = lower_rot_7_9[5];
constraint lower_intermediate_output_6_12[30] = lower_rot_7_9[6];
constraint lower_intermediate_output_6_12[31] = lower_rot_7_9[7];
constraint lower_intermediate_output_6_12[32] = lower_rot_7_9[8];
constraint lower_intermediate_output_6_12[33] = lower_rot_7_9[9];
constraint lower_intermediate_output_6_12[34] = lower_rot_7_9[10];
constraint lower_intermediate_output_6_12[35] = lower_rot_7_9[11];
constraint lower_intermediate_output_6_12[36] = lower_rot_7_9[12];
constraint lower_intermediate_output_6_12[37] = lower_rot_7_9[13];
constraint lower_intermediate_output_6_12[38] = lower_rot_7_9[14];
constraint lower_intermediate_output_6_12[39] = lower_rot_7_9[15];
constraint lower_intermediate_output_6_12[40] = lower_rot_7_9[16];
constraint lower_intermediate_output_6_12[41] = lower_rot_7_9[17];
constraint lower_intermediate_output_6_12[42] = lower_rot_7_9[18];
constraint lower_intermediate_output_6_12[43] = lower_rot_7_9[19];
constraint lower_intermediate_output_6_12[44] = lower_rot_7_9[20];
constraint lower_intermediate_output_6_12[45] = lower_rot_7_9[21];
constraint lower_intermediate_output_6_12[46] = lower_rot_7_9[22];
constraint lower_intermediate_output_6_12[47] = lower_rot_7_9[23];
constraint lower_rot_6_9[0] = lower_xor_6_10[21];
constraint lower_rot_6_9[1] = lower_xor_6_10[22];
constraint lower_rot_6_9[2] = lower_xor_6_10[23];
constraint lower_rot_6_9[3] = lower_xor_6_10[0];
constraint lower_rot_6_9[4] = lower_xor_6_10[1];
constraint lower_rot_6_9[5] = lower_xor_6_10[2];
constraint lower_rot_6_9[6] = lower_xor_6_10[3];
constraint lower_rot_6_9[7] = lower_xor_6_10[4];
constraint lower_rot_6_9[8] = lower_xor_6_10[5];
constraint lower_rot_6_9[9] = lower_xor_6_10[6];
constraint lower_rot_6_9[10] = lower_xor_6_10[7];
constraint lower_rot_6_9[11] = lower_xor_6_10[8];
constraint lower_rot_6_9[12] = lower_xor_6_10[9];
constraint lower_rot_6_9[13] = lower_xor_6_10[10];
constraint lower_rot_6_9[14] = lower_xor_6_10[11];
constraint lower_rot_6_9[15] = lower_xor_6_10[12];
constraint lower_rot_6_9[16] = lower_xor_6_10[13];
constraint lower_rot_6_9[17] = lower_xor_6_10[14];
constraint lower_rot_6_9[18] = lower_xor_6_10[15];
constraint lower_rot_6_9[19] = lower_xor_6_10[16];
constraint lower_rot_6_9[20] = lower_xor_6_10[17];
constraint lower_rot_6_9[21] = lower_xor_6_10[18];
constraint lower_rot_6_9[22] = lower_xor_6_10[19];
constraint lower_rot_6_9[23] = lower_xor_6_10[20];
constraint pre_lower_modadd_6_7_0[0] = lower_xor_6_8[0];
constraint pre_lower_modadd_6_7_0[1] = lower_xor_6_8[1];
constraint pre_lower_modadd_6_7_0[2] = lower_xor_6_8[2];
constraint pre_lower_modadd_6_7_0[3] = lower_xor_6_8[3];
constraint pre_lower_modadd_6_7_0[4] = lower_xor_6_8[4];
constraint pre_lower_modadd_6_7_0[5] = lower_xor_6_8[5];
constraint pre_lower_modadd_6_7_0[6] = lower_xor_6_8[6];
constraint pre_lower_modadd_6_7_0[7] = lower_xor_6_8[7];
constraint pre_lower_modadd_6_7_0[8] = lower_xor_6_8[8];
constraint pre_lower_modadd_6_7_0[9] = lower_xor_6_8[9];
constraint pre_lower_modadd_6_7_0[10] = lower_xor_6_8[10];
constraint pre_lower_modadd_6_7_0[11] = lower_xor_6_8[11];
constraint pre_lower_modadd_6_7_0[12] = lower_xor_6_8[12];
constraint pre_lower_modadd_6_7_0[13] = lower_xor_6_8[13];
constraint pre_lower_modadd_6_7_0[14] = lower_xor_6_8[14];
constraint pre_lower_modadd_6_7_0[15] = lower_xor_6_8[15];
constraint pre_lower_modadd_6_7_0[16] = lower_xor_6_8[16];
constraint pre_lower_modadd_6_7_0[17] = lower_xor_6_8[17];
constraint pre_lower_modadd_6_7_0[18] = lower_xor_6_8[18];
constraint pre_lower_modadd_6_7_0[19] = lower_xor_6_8[19];
constraint pre_lower_modadd_6_7_0[20] = lower_xor_6_8[20];
constraint pre_lower_modadd_6_7_0[21] = lower_xor_6_8[21];
constraint pre_lower_modadd_6_7_0[22] = lower_xor_6_8[22];
constraint pre_lower_modadd_6_7_0[23] = lower_xor_6_8[23];
constraint pre_lower_modadd_6_7_1[0] = lower_rot_6_9[0];
constraint pre_lower_modadd_6_7_1[1] = lower_rot_6_9[1];
constraint pre_lower_modadd_6_7_1[2] = lower_rot_6_9[2];
constraint pre_lower_modadd_6_7_1[3] = lower_rot_6_9[3];
constraint pre_lower_modadd_6_7_1[4] = lower_rot_6_9[4];
constraint pre_lower_modadd_6_7_1[5] = lower_rot_6_9[5];
constraint pre_lower_modadd_6_7_1[6] = lower_rot_6_9[6];
constraint pre_lower_modadd_6_7_1[7] = lower_rot_6_9[7];
constraint pre_lower_modadd_6_7_1[8] = lower_rot_6_9[8];
constraint pre_lower_modadd_6_7_1[9] = lower_rot_6_9[9];
constraint pre_lower_modadd_6_7_1[10] = lower_rot_6_9[10];
constraint pre_lower_modadd_6_7_1[11] = lower_rot_6_9[11];
constraint pre_lower_modadd_6_7_1[12] = lower_rot_6_9[12];
constraint pre_lower_modadd_6_7_1[13] = lower_rot_6_9[13];
constraint pre_lower_modadd_6_7_1[14] = lower_rot_6_9[14];
constraint pre_lower_modadd_6_7_1[15] = lower_rot_6_9[15];
constraint pre_lower_modadd_6_7_1[16] = lower_rot_6_9[16];
constraint pre_lower_modadd_6_7_1[17] = lower_rot_6_9[17];
constraint pre_lower_modadd_6_7_1[18] = lower_rot_6_9[18];
constraint pre_lower_modadd_6_7_1[19] = lower_rot_6_9[19];
constraint pre_lower_modadd_6_7_1[20] = lower_rot_6_9[20];
constraint pre_lower_modadd_6_7_1[21] = lower_rot_6_9[21];
constraint pre_lower_modadd_6_7_1[22] = lower_rot_6_9[22];
constraint pre_lower_modadd_6_7_1[23] = lower_rot_6_9[23];
constraint forall(j in 0..23)(if eq_lower_modadd_6_7[j] = 1 then (sum([pre_lower_modadd_6_7_1[j], pre_lower_modadd_6_7_0[j], lower_modadd_6_7[j]]) mod 2) = Shi_pre_lower_modadd_6_7_0[j] else true endif) /\ lower_p[2] = (24-sum(eq_lower_modadd_6_7))*100;
constraint lower_rot_6_6[0] = lower_modadd_6_7[8];
constraint lower_rot_6_6[1] = lower_modadd_6_7[9];
constraint lower_rot_6_6[2] = lower_modadd_6_7[10];
constraint lower_rot_6_6[3] = lower_modadd_6_7[11];
constraint lower_rot_6_6[4] = lower_modadd_6_7[12];
constraint lower_rot_6_6[5] = lower_modadd_6_7[13];
constraint lower_rot_6_6[6] = lower_modadd_6_7[14];
constraint lower_rot_6_6[7] = lower_modadd_6_7[15];
constraint lower_rot_6_6[8] = lower_modadd_6_7[16];
constraint lower_rot_6_6[9] = lower_modadd_6_7[17];
constraint lower_rot_6_6[10] = lower_modadd_6_7[18];
constraint lower_rot_6_6[11] = lower_modadd_6_7[19];
constraint lower_rot_6_6[12] = lower_modadd_6_7[20];
constraint lower_rot_6_6[13] = lower_modadd_6_7[21];
constraint lower_rot_6_6[14] = lower_modadd_6_7[22];
constraint lower_rot_6_6[15] = lower_modadd_6_7[23];
constraint lower_rot_6_6[16] = lower_modadd_6_7[0];
constraint lower_rot_6_6[17] = lower_modadd_6_7[1];
constraint lower_rot_6_6[18] = lower_modadd_6_7[2];
constraint lower_rot_6_6[19] = lower_modadd_6_7[3];
constraint lower_rot_6_6[20] = lower_modadd_6_7[4];
constraint lower_rot_6_6[21] = lower_modadd_6_7[5];
constraint lower_rot_6_6[22] = lower_modadd_6_7[6];
constraint lower_rot_6_6[23] = lower_modadd_6_7[7];
constraint 2*dummy_lower_xor_7_8[0] = (lower_xor_7_5[0] + lower_rot_8_6[0] + lower_xor_7_8[0]);
constraint 2*dummy_lower_xor_7_8[1] = (lower_xor_7_5[1] + lower_rot_8_6[1] + lower_xor_7_8[1]);
constraint 2*dummy_lower_xor_7_8[2] = (lower_xor_7_5[2] + lower_rot_8_6[2] + lower_xor_7_8[2]);
constraint 2*dummy_lower_xor_7_8[3] = (lower_xor_7_5[3] + lower_rot_8_6[3] + lower_xor_7_8[3]);
constraint 2*dummy_lower_xor_7_8[4] = (lower_xor_7_5[4] + lower_rot_8_6[4] + lower_xor_7_8[4]);
constraint 2*dummy_lower_xor_7_8[5] = (lower_xor_7_5[5] + lower_rot_8_6[5] + lower_xor_7_8[5]);
constraint 2*dummy_lower_xor_7_8[6] = (lower_xor_7_5[6] + lower_rot_8_6[6] + lower_xor_7_8[6]);
constraint 2*dummy_lower_xor_7_8[7] = (lower_xor_7_5[7] + lower_rot_8_6[7] + lower_xor_7_8[7]);
constraint 2*dummy_lower_xor_7_8[8] = (lower_xor_7_5[8] + lower_rot_8_6[8] + lower_xor_7_8[8]);
constraint 2*dummy_lower_xor_7_8[9] = (lower_xor_7_5[9] + lower_rot_8_6[9] + lower_xor_7_8[9]);
constraint 2*dummy_lower_xor_7_8[10] = (lower_xor_7_5[10] + lower_rot_8_6[10] + lower_xor_7_8[10]);
constraint 2*dummy_lower_xor_7_8[11] = (lower_xor_7_5[11] + lower_rot_8_6[11] + lower_xor_7_8[11]);
constraint 2*dummy_lower_xor_7_8[12] = (lower_xor_7_5[12] + lower_rot_8_6[12] + lower_xor_7_8[12]);
constraint 2*dummy_lower_xor_7_8[13] = (lower_xor_7_5[13] + lower_rot_8_6[13] + lower_xor_7_8[13]);
constraint 2*dummy_lower_xor_7_8[14] = (lower_xor_7_5[14] + lower_rot_8_6[14] + lower_xor_7_8[14]);
constraint 2*dummy_lower_xor_7_8[15] = (lower_xor_7_5[15] + lower_rot_8_6[15] + lower_xor_7_8[15]);
constraint 2*dummy_lower_xor_7_8[16] = (lower_xor_7_5[16] + lower_rot_8_6[16] + lower_xor_7_8[16]);
constraint 2*dummy_lower_xor_7_8[17] = (lower_xor_7_5[17] + lower_rot_8_6[17] + lower_xor_7_8[17]);
constraint 2*dummy_lower_xor_7_8[18] = (lower_xor_7_5[18] + lower_rot_8_6[18] + lower_xor_7_8[18]);
constraint 2*dummy_lower_xor_7_8[19] = (lower_xor_7_5[19] + lower_rot_8_6[19] + lower_xor_7_8[19]);
constraint 2*dummy_lower_xor_7_8[20] = (lower_xor_7_5[20] + lower_rot_8_6[20] + lower_xor_7_8[20]);
constraint 2*dummy_lower_xor_7_8[21] = (lower_xor_7_5[21] + lower_rot_8_6[21] + lower_xor_7_8[21]);
constraint 2*dummy_lower_xor_7_8[22] = (lower_xor_7_5[22] + lower_rot_8_6[22] + lower_xor_7_8[22]);
constraint 2*dummy_lower_xor_7_8[23] = (lower_xor_7_5[23] + lower_rot_8_6[23] + lower_xor_7_8[23]);
constraint 2*dummy_lower_xor_7_10[0] = (lower_rot_8_6[0] + lower_rot_8_9[0] + lower_xor_7_10[0]);
constraint 2*dummy_lower_xor_7_10[1] = (lower_rot_8_6[1] + lower_rot_8_9[1] + lower_xor_7_10[1]);
constraint 2*dummy_lower_xor_7_10[2] = (lower_rot_8_6[2] + lower_rot_8_9[2] + lower_xor_7_10[2]);
constraint 2*dummy_lower_xor_7_10[3] = (lower_rot_8_6[3] + lower_rot_8_9[3] + lower_xor_7_10[3]);
constraint 2*dummy_lower_xor_7_10[4] = (lower_rot_8_6[4] + lower_rot_8_9[4] + lower_xor_7_10[4]);
constraint 2*dummy_lower_xor_7_10[5] = (lower_rot_8_6[5] + lower_rot_8_9[5] + lower_xor_7_10[5]);
constraint 2*dummy_lower_xor_7_10[6] = (lower_rot_8_6[6] + lower_rot_8_9[6] + lower_xor_7_10[6]);
constraint 2*dummy_lower_xor_7_10[7] = (lower_rot_8_6[7] + lower_rot_8_9[7] + lower_xor_7_10[7]);
constraint 2*dummy_lower_xor_7_10[8] = (lower_rot_8_6[8] + lower_rot_8_9[8] + lower_xor_7_10[8]);
constraint 2*dummy_lower_xor_7_10[9] = (lower_rot_8_6[9] + lower_rot_8_9[9] + lower_xor_7_10[9]);
constraint 2*dummy_lower_xor_7_10[10] = (lower_rot_8_6[10] + lower_rot_8_9[10] + lower_xor_7_10[10]);
constraint 2*dummy_lower_xor_7_10[11] = (lower_rot_8_6[11] + lower_rot_8_9[11] + lower_xor_7_10[11]);
constraint 2*dummy_lower_xor_7_10[12] = (lower_rot_8_6[12] + lower_rot_8_9[12] + lower_xor_7_10[12]);
constraint 2*dummy_lower_xor_7_10[13] = (lower_rot_8_6[13] + lower_rot_8_9[13] + lower_xor_7_10[13]);
constraint 2*dummy_lower_xor_7_10[14] = (lower_rot_8_6[14] + lower_rot_8_9[14] + lower_xor_7_10[14]);
constraint 2*dummy_lower_xor_7_10[15] = (lower_rot_8_6[15] + lower_rot_8_9[15] + lower_xor_7_10[15]);
constraint 2*dummy_lower_xor_7_10[16] = (lower_rot_8_6[16] + lower_rot_8_9[16] + lower_xor_7_10[16]);
constraint 2*dummy_lower_xor_7_10[17] = (lower_rot_8_6[17] + lower_rot_8_9[17] + lower_xor_7_10[17]);
constraint 2*dummy_lower_xor_7_10[18] = (lower_rot_8_6[18] + lower_rot_8_9[18] + lower_xor_7_10[18]);
constraint 2*dummy_lower_xor_7_10[19] = (lower_rot_8_6[19] + lower_rot_8_9[19] + lower_xor_7_10[19]);
constraint 2*dummy_lower_xor_7_10[20] = (lower_rot_8_6[20] + lower_rot_8_9[20] + lower_xor_7_10[20]);
constraint 2*dummy_lower_xor_7_10[21] = (lower_rot_8_6[21] + lower_rot_8_9[21] + lower_xor_7_10[21]);
constraint 2*dummy_lower_xor_7_10[22] = (lower_rot_8_6[22] + lower_rot_8_9[22] + lower_xor_7_10[22]);
constraint 2*dummy_lower_xor_7_10[23] = (lower_rot_8_6[23] + lower_rot_8_9[23] + lower_xor_7_10[23]);
constraint lower_intermediate_output_7_12[0] = lower_rot_8_6[0];
constraint lower_intermediate_output_7_12[1] = lower_rot_8_6[1];
constraint lower_intermediate_output_7_12[2] = lower_rot_8_6[2];
constraint lower_intermediate_output_7_12[3] = lower_rot_8_6[3];
constraint lower_intermediate_output_7_12[4] = lower_rot_8_6[4];
constraint lower_intermediate_output_7_12[5] = lower_rot_8_6[5];
constraint lower_intermediate_output_7_12[6] = lower_rot_8_6[6];
constraint lower_intermediate_output_7_12[7] = lower_rot_8_6[7];
constraint lower_intermediate_output_7_12[8] = lower_rot_8_6[8];
constraint lower_intermediate_output_7_12[9] = lower_rot_8_6[9];
constraint lower_intermediate_output_7_12[10] = lower_rot_8_6[10];
constraint lower_intermediate_output_7_12[11] = lower_rot_8_6[11];
constraint lower_intermediate_output_7_12[12] = lower_rot_8_6[12];
constraint lower_intermediate_output_7_12[13] = lower_rot_8_6[13];
constraint lower_intermediate_output_7_12[14] = lower_rot_8_6[14];
constraint lower_intermediate_output_7_12[15] = lower_rot_8_6[15];
constraint lower_intermediate_output_7_12[16] = lower_rot_8_6[16];
constraint lower_intermediate_output_7_12[17] = lower_rot_8_6[17];
constraint lower_intermediate_output_7_12[18] = lower_rot_8_6[18];
constraint lower_intermediate_output_7_12[19] = lower_rot_8_6[19];
constraint lower_intermediate_output_7_12[20] = lower_rot_8_6[20];
constraint lower_intermediate_output_7_12[21] = lower_rot_8_6[21];
constraint lower_intermediate_output_7_12[22] = lower_rot_8_6[22];
constraint lower_intermediate_output_7_12[23] = lower_rot_8_6[23];
constraint lower_intermediate_output_7_12[24] = lower_rot_8_9[0];
constraint lower_intermediate_output_7_12[25] = lower_rot_8_9[1];
constraint lower_intermediate_output_7_12[26] = lower_rot_8_9[2];
constraint lower_intermediate_output_7_12[27] = lower_rot_8_9[3];
constraint lower_intermediate_output_7_12[28] = lower_rot_8_9[4];
constraint lower_intermediate_output_7_12[29] = lower_rot_8_9[5];
constraint lower_intermediate_output_7_12[30] = lower_rot_8_9[6];
constraint lower_intermediate_output_7_12[31] = lower_rot_8_9[7];
constraint lower_intermediate_output_7_12[32] = lower_rot_8_9[8];
constraint lower_intermediate_output_7_12[33] = lower_rot_8_9[9];
constraint lower_intermediate_output_7_12[34] = lower_rot_8_9[10];
constraint lower_intermediate_output_7_12[35] = lower_rot_8_9[11];
constraint lower_intermediate_output_7_12[36] = lower_rot_8_9[12];
constraint lower_intermediate_output_7_12[37] = lower_rot_8_9[13];
constraint lower_intermediate_output_7_12[38] = lower_rot_8_9[14];
constraint lower_intermediate_output_7_12[39] = lower_rot_8_9[15];
constraint lower_intermediate_output_7_12[40] = lower_rot_8_9[16];
constraint lower_intermediate_output_7_12[41] = lower_rot_8_9[17];
constraint lower_intermediate_output_7_12[42] = lower_rot_8_9[18];
constraint lower_intermediate_output_7_12[43] = lower_rot_8_9[19];
constraint lower_intermediate_output_7_12[44] = lower_rot_8_9[20];
constraint lower_intermediate_output_7_12[45] = lower_rot_8_9[21];
constraint lower_intermediate_output_7_12[46] = lower_rot_8_9[22];
constraint lower_intermediate_output_7_12[47] = lower_rot_8_9[23];
constraint lower_rot_7_9[0] = lower_xor_7_10[21];
constraint lower_rot_7_9[1] = lower_xor_7_10[22];
constraint lower_rot_7_9[2] = lower_xor_7_10[23];
constraint lower_rot_7_9[3] = lower_xor_7_10[0];
constraint lower_rot_7_9[4] = lower_xor_7_10[1];
constraint lower_rot_7_9[5] = lower_xor_7_10[2];
constraint lower_rot_7_9[6] = lower_xor_7_10[3];
constraint lower_rot_7_9[7] = lower_xor_7_10[4];
constraint lower_rot_7_9[8] = lower_xor_7_10[5];
constraint lower_rot_7_9[9] = lower_xor_7_10[6];
constraint lower_rot_7_9[10] = lower_xor_7_10[7];
constraint lower_rot_7_9[11] = lower_xor_7_10[8];
constraint lower_rot_7_9[12] = lower_xor_7_10[9];
constraint lower_rot_7_9[13] = lower_xor_7_10[10];
constraint lower_rot_7_9[14] = lower_xor_7_10[11];
constraint lower_rot_7_9[15] = lower_xor_7_10[12];
constraint lower_rot_7_9[16] = lower_xor_7_10[13];
constraint lower_rot_7_9[17] = lower_xor_7_10[14];
constraint lower_rot_7_9[18] = lower_xor_7_10[15];
constraint lower_rot_7_9[19] = lower_xor_7_10[16];
constraint lower_rot_7_9[20] = lower_xor_7_10[17];
constraint lower_rot_7_9[21] = lower_xor_7_10[18];
constraint lower_rot_7_9[22] = lower_xor_7_10[19];
constraint lower_rot_7_9[23] = lower_xor_7_10[20];
constraint pre_lower_modadd_7_7_0[0] = lower_xor_7_8[0];
constraint pre_lower_modadd_7_7_0[1] = lower_xor_7_8[1];
constraint pre_lower_modadd_7_7_0[2] = lower_xor_7_8[2];
constraint pre_lower_modadd_7_7_0[3] = lower_xor_7_8[3];
constraint pre_lower_modadd_7_7_0[4] = lower_xor_7_8[4];
constraint pre_lower_modadd_7_7_0[5] = lower_xor_7_8[5];
constraint pre_lower_modadd_7_7_0[6] = lower_xor_7_8[6];
constraint pre_lower_modadd_7_7_0[7] = lower_xor_7_8[7];
constraint pre_lower_modadd_7_7_0[8] = lower_xor_7_8[8];
constraint pre_lower_modadd_7_7_0[9] = lower_xor_7_8[9];
constraint pre_lower_modadd_7_7_0[10] = lower_xor_7_8[10];
constraint pre_lower_modadd_7_7_0[11] = lower_xor_7_8[11];
constraint pre_lower_modadd_7_7_0[12] = lower_xor_7_8[12];
constraint pre_lower_modadd_7_7_0[13] = lower_xor_7_8[13];
constraint pre_lower_modadd_7_7_0[14] = lower_xor_7_8[14];
constraint pre_lower_modadd_7_7_0[15] = lower_xor_7_8[15];
constraint pre_lower_modadd_7_7_0[16] = lower_xor_7_8[16];
constraint pre_lower_modadd_7_7_0[17] = lower_xor_7_8[17];
constraint pre_lower_modadd_7_7_0[18] = lower_xor_7_8[18];
constraint pre_lower_modadd_7_7_0[19] = lower_xor_7_8[19];
constraint pre_lower_modadd_7_7_0[20] = lower_xor_7_8[20];
constraint pre_lower_modadd_7_7_0[21] = lower_xor_7_8[21];
constraint pre_lower_modadd_7_7_0[22] = lower_xor_7_8[22];
constraint pre_lower_modadd_7_7_0[23] = lower_xor_7_8[23];
constraint pre_lower_modadd_7_7_1[0] = lower_rot_7_9[0];
constraint pre_lower_modadd_7_7_1[1] = lower_rot_7_9[1];
constraint pre_lower_modadd_7_7_1[2] = lower_rot_7_9[2];
constraint pre_lower_modadd_7_7_1[3] = lower_rot_7_9[3];
constraint pre_lower_modadd_7_7_1[4] = lower_rot_7_9[4];
constraint pre_lower_modadd_7_7_1[5] = lower_rot_7_9[5];
constraint pre_lower_modadd_7_7_1[6] = lower_rot_7_9[6];
constraint pre_lower_modadd_7_7_1[7] = lower_rot_7_9[7];
constraint pre_lower_modadd_7_7_1[8] = lower_rot_7_9[8];
constraint pre_lower_modadd_7_7_1[9] = lower_rot_7_9[9];
constraint pre_lower_modadd_7_7_1[10] = lower_rot_7_9[10];
constraint pre_lower_modadd_7_7_1[11] = lower_rot_7_9[11];
constraint pre_lower_modadd_7_7_1[12] = lower_rot_7_9[12];
constraint pre_lower_modadd_7_7_1[13] = lower_rot_7_9[13];
constraint pre_lower_modadd_7_7_1[14] = lower_rot_7_9[14];
constraint pre_lower_modadd_7_7_1[15] = lower_rot_7_9[15];
constraint pre_lower_modadd_7_7_1[16] = lower_rot_7_9[16];
constraint pre_lower_modadd_7_7_1[17] = lower_rot_7_9[17];
constraint pre_lower_modadd_7_7_1[18] = lower_rot_7_9[18];
constraint pre_lower_modadd_7_7_1[19] = lower_rot_7_9[19];
constraint pre_lower_modadd_7_7_1[20] = lower_rot_7_9[20];
constraint pre_lower_modadd_7_7_1[21] = lower_rot_7_9[21];
constraint pre_lower_modadd_7_7_1[22] = lower_rot_7_9[22];
constraint pre_lower_modadd_7_7_1[23] = lower_rot_7_9[23];
constraint forall(j in 0..23)(if eq_lower_modadd_7_7[j] = 1 then (sum([pre_lower_modadd_7_7_1[j], pre_lower_modadd_7_7_0[j], lower_modadd_7_7[j]]) mod 2) = Shi_pre_lower_modadd_7_7_0[j] else true endif) /\ lower_p[3] = (24-sum(eq_lower_modadd_7_7))*100;
constraint lower_rot_7_6[0] = lower_modadd_7_7[8];
constraint lower_rot_7_6[1] = lower_modadd_7_7[9];
constraint lower_rot_7_6[2] = lower_modadd_7_7[10];
constraint lower_rot_7_6[3] = lower_modadd_7_7[11];
constraint lower_rot_7_6[4] = lower_modadd_7_7[12];
constraint lower_rot_7_6[5] = lower_modadd_7_7[13];
constraint lower_rot_7_6[6] = lower_modadd_7_7[14];
constraint lower_rot_7_6[7] = lower_modadd_7_7[15];
constraint lower_rot_7_6[8] = lower_modadd_7_7[16];
constraint lower_rot_7_6[9] = lower_modadd_7_7[17];
constraint lower_rot_7_6[10] = lower_modadd_7_7[18];
constraint lower_rot_7_6[11] = lower_modadd_7_7[19];
constraint lower_rot_7_6[12] = lower_modadd_7_7[20];
constraint lower_rot_7_6[13] = lower_modadd_7_7[21];
constraint lower_rot_7_6[14] = lower_modadd_7_7[22];
constraint lower_rot_7_6[15] = lower_modadd_7_7[23];
constraint lower_rot_7_6[16] = lower_modadd_7_7[0];
constraint lower_rot_7_6[17] = lower_modadd_7_7[1];
constraint lower_rot_7_6[18] = lower_modadd_7_7[2];
constraint lower_rot_7_6[19] = lower_modadd_7_7[3];
constraint lower_rot_7_6[20] = lower_modadd_7_7[4];
constraint lower_rot_7_6[21] = lower_modadd_7_7[5];
constraint lower_rot_7_6[22] = lower_modadd_7_7[6];
constraint lower_rot_7_6[23] = lower_modadd_7_7[7];
constraint 2*dummy_lower_xor_8_8[0] = (lower_xor_8_5[0] + lower_rot_9_6[0] + lower_xor_8_8[0]);
constraint 2*dummy_lower_xor_8_8[1] = (lower_xor_8_5[1] + lower_rot_9_6[1] + lower_xor_8_8[1]);
constraint 2*dummy_lower_xor_8_8[2] = (lower_xor_8_5[2] + lower_rot_9_6[2] + lower_xor_8_8[2]);
constraint 2*dummy_lower_xor_8_8[3] = (lower_xor_8_5[3] + lower_rot_9_6[3] + lower_xor_8_8[3]);
constraint 2*dummy_lower_xor_8_8[4] = (lower_xor_8_5[4] + lower_rot_9_6[4] + lower_xor_8_8[4]);
constraint 2*dummy_lower_xor_8_8[5] = (lower_xor_8_5[5] + lower_rot_9_6[5] + lower_xor_8_8[5]);
constraint 2*dummy_lower_xor_8_8[6] = (lower_xor_8_5[6] + lower_rot_9_6[6] + lower_xor_8_8[6]);
constraint 2*dummy_lower_xor_8_8[7] = (lower_xor_8_5[7] + lower_rot_9_6[7] + lower_xor_8_8[7]);
constraint 2*dummy_lower_xor_8_8[8] = (lower_xor_8_5[8] + lower_rot_9_6[8] + lower_xor_8_8[8]);
constraint 2*dummy_lower_xor_8_8[9] = (lower_xor_8_5[9] + lower_rot_9_6[9] + lower_xor_8_8[9]);
constraint 2*dummy_lower_xor_8_8[10] = (lower_xor_8_5[10] + lower_rot_9_6[10] + lower_xor_8_8[10]);
constraint 2*dummy_lower_xor_8_8[11] = (lower_xor_8_5[11] + lower_rot_9_6[11] + lower_xor_8_8[11]);
constraint 2*dummy_lower_xor_8_8[12] = (lower_xor_8_5[12] + lower_rot_9_6[12] + lower_xor_8_8[12]);
constraint 2*dummy_lower_xor_8_8[13] = (lower_xor_8_5[13] + lower_rot_9_6[13] + lower_xor_8_8[13]);
constraint 2*dummy_lower_xor_8_8[14] = (lower_xor_8_5[14] + lower_rot_9_6[14] + lower_xor_8_8[14]);
constraint 2*dummy_lower_xor_8_8[15] = (lower_xor_8_5[15] + lower_rot_9_6[15] + lower_xor_8_8[15]);
constraint 2*dummy_lower_xor_8_8[16] = (lower_xor_8_5[16] + lower_rot_9_6[16] + lower_xor_8_8[16]);
constraint 2*dummy_lower_xor_8_8[17] = (lower_xor_8_5[17] + lower_rot_9_6[17] + lower_xor_8_8[17]);
constraint 2*dummy_lower_xor_8_8[18] = (lower_xor_8_5[18] + lower_rot_9_6[18] + lower_xor_8_8[18]);
constraint 2*dummy_lower_xor_8_8[19] = (lower_xor_8_5[19] + lower_rot_9_6[19] + lower_xor_8_8[19]);
constraint 2*dummy_lower_xor_8_8[20] = (lower_xor_8_5[20] + lower_rot_9_6[20] + lower_xor_8_8[20]);
constraint 2*dummy_lower_xor_8_8[21] = (lower_xor_8_5[21] + lower_rot_9_6[21] + lower_xor_8_8[21]);
constraint 2*dummy_lower_xor_8_8[22] = (lower_xor_8_5[22] + lower_rot_9_6[22] + lower_xor_8_8[22]);
constraint 2*dummy_lower_xor_8_8[23] = (lower_xor_8_5[23] + lower_rot_9_6[23] + lower_xor_8_8[23]);
constraint 2*dummy_lower_xor_8_10[0] = (lower_rot_9_6[0] + lower_rot_9_9[0] + lower_xor_8_10[0]);
constraint 2*dummy_lower_xor_8_10[1] = (lower_rot_9_6[1] + lower_rot_9_9[1] + lower_xor_8_10[1]);
constraint 2*dummy_lower_xor_8_10[2] = (lower_rot_9_6[2] + lower_rot_9_9[2] + lower_xor_8_10[2]);
constraint 2*dummy_lower_xor_8_10[3] = (lower_rot_9_6[3] + lower_rot_9_9[3] + lower_xor_8_10[3]);
constraint 2*dummy_lower_xor_8_10[4] = (lower_rot_9_6[4] + lower_rot_9_9[4] + lower_xor_8_10[4]);
constraint 2*dummy_lower_xor_8_10[5] = (lower_rot_9_6[5] + lower_rot_9_9[5] + lower_xor_8_10[5]);
constraint 2*dummy_lower_xor_8_10[6] = (lower_rot_9_6[6] + lower_rot_9_9[6] + lower_xor_8_10[6]);
constraint 2*dummy_lower_xor_8_10[7] = (lower_rot_9_6[7] + lower_rot_9_9[7] + lower_xor_8_10[7]);
constraint 2*dummy_lower_xor_8_10[8] = (lower_rot_9_6[8] + lower_rot_9_9[8] + lower_xor_8_10[8]);
constraint 2*dummy_lower_xor_8_10[9] = (lower_rot_9_6[9] + lower_rot_9_9[9] + lower_xor_8_10[9]);
constraint 2*dummy_lower_xor_8_10[10] = (lower_rot_9_6[10] + lower_rot_9_9[10] + lower_xor_8_10[10]);
constraint 2*dummy_lower_xor_8_10[11] = (lower_rot_9_6[11] + lower_rot_9_9[11] + lower_xor_8_10[11]);
constraint 2*dummy_lower_xor_8_10[12] = (lower_rot_9_6[12] + lower_rot_9_9[12] + lower_xor_8_10[12]);
constraint 2*dummy_lower_xor_8_10[13] = (lower_rot_9_6[13] + lower_rot_9_9[13] + lower_xor_8_10[13]);
constraint 2*dummy_lower_xor_8_10[14] = (lower_rot_9_6[14] + lower_rot_9_9[14] + lower_xor_8_10[14]);
constraint 2*dummy_lower_xor_8_10[15] = (lower_rot_9_6[15] + lower_rot_9_9[15] + lower_xor_8_10[15]);
constraint 2*dummy_lower_xor_8_10[16] = (lower_rot_9_6[16] + lower_rot_9_9[16] + lower_xor_8_10[16]);
constraint 2*dummy_lower_xor_8_10[17] = (lower_rot_9_6[17] + lower_rot_9_9[17] + lower_xor_8_10[17]);
constraint 2*dummy_lower_xor_8_10[18] = (lower_rot_9_6[18] + lower_rot_9_9[18] + lower_xor_8_10[18]);
constraint 2*dummy_lower_xor_8_10[19] = (lower_rot_9_6[19] + lower_rot_9_9[19] + lower_xor_8_10[19]);
constraint 2*dummy_lower_xor_8_10[20] = (lower_rot_9_6[20] + lower_rot_9_9[20] + lower_xor_8_10[20]);
constraint 2*dummy_lower_xor_8_10[21] = (lower_rot_9_6[21] + lower_rot_9_9[21] + lower_xor_8_10[21]);
constraint 2*dummy_lower_xor_8_10[22] = (lower_rot_9_6[22] + lower_rot_9_9[22] + lower_xor_8_10[22]);
constraint 2*dummy_lower_xor_8_10[23] = (lower_rot_9_6[23] + lower_rot_9_9[23] + lower_xor_8_10[23]);
constraint lower_intermediate_output_8_12[0] = lower_rot_9_6[0];
constraint lower_intermediate_output_8_12[1] = lower_rot_9_6[1];
constraint lower_intermediate_output_8_12[2] = lower_rot_9_6[2];
constraint lower_intermediate_output_8_12[3] = lower_rot_9_6[3];
constraint lower_intermediate_output_8_12[4] = lower_rot_9_6[4];
constraint lower_intermediate_output_8_12[5] = lower_rot_9_6[5];
constraint lower_intermediate_output_8_12[6] = lower_rot_9_6[6];
constraint lower_intermediate_output_8_12[7] = lower_rot_9_6[7];
constraint lower_intermediate_output_8_12[8] = lower_rot_9_6[8];
constraint lower_intermediate_output_8_12[9] = lower_rot_9_6[9];
constraint lower_intermediate_output_8_12[10] = lower_rot_9_6[10];
constraint lower_intermediate_output_8_12[11] = lower_rot_9_6[11];
constraint lower_intermediate_output_8_12[12] = lower_rot_9_6[12];
constraint lower_intermediate_output_8_12[13] = lower_rot_9_6[13];
constraint lower_intermediate_output_8_12[14] = lower_rot_9_6[14];
constraint lower_intermediate_output_8_12[15] = lower_rot_9_6[15];
constraint lower_intermediate_output_8_12[16] = lower_rot_9_6[16];
constraint lower_intermediate_output_8_12[17] = lower_rot_9_6[17];
constraint lower_intermediate_output_8_12[18] = lower_rot_9_6[18];
constraint lower_intermediate_output_8_12[19] = lower_rot_9_6[19];
constraint lower_intermediate_output_8_12[20] = lower_rot_9_6[20];
constraint lower_intermediate_output_8_12[21] = lower_rot_9_6[21];
constraint lower_intermediate_output_8_12[22] = lower_rot_9_6[22];
constraint lower_intermediate_output_8_12[23] = lower_rot_9_6[23];
constraint lower_intermediate_output_8_12[24] = lower_rot_9_9[0];
constraint lower_intermediate_output_8_12[25] = lower_rot_9_9[1];
constraint lower_intermediate_output_8_12[26] = lower_rot_9_9[2];
constraint lower_intermediate_output_8_12[27] = lower_rot_9_9[3];
constraint lower_intermediate_output_8_12[28] = lower_rot_9_9[4];
constraint lower_intermediate_output_8_12[29] = lower_rot_9_9[5];
constraint lower_intermediate_output_8_12[30] = lower_rot_9_9[6];
constraint lower_intermediate_output_8_12[31] = lower_rot_9_9[7];
constraint lower_intermediate_output_8_12[32] = lower_rot_9_9[8];
constraint lower_intermediate_output_8_12[33] = lower_rot_9_9[9];
constraint lower_intermediate_output_8_12[34] = lower_rot_9_9[10];
constraint lower_intermediate_output_8_12[35] = lower_rot_9_9[11];
constraint lower_intermediate_output_8_12[36] = lower_rot_9_9[12];
constraint lower_intermediate_output_8_12[37] = lower_rot_9_9[13];
constraint lower_intermediate_output_8_12[38] = lower_rot_9_9[14];
constraint lower_intermediate_output_8_12[39] = lower_rot_9_9[15];
constraint lower_intermediate_output_8_12[40] = lower_rot_9_9[16];
constraint lower_intermediate_output_8_12[41] = lower_rot_9_9[17];
constraint lower_intermediate_output_8_12[42] = lower_rot_9_9[18];
constraint lower_intermediate_output_8_12[43] = lower_rot_9_9[19];
constraint lower_intermediate_output_8_12[44] = lower_rot_9_9[20];
constraint lower_intermediate_output_8_12[45] = lower_rot_9_9[21];
constraint lower_intermediate_output_8_12[46] = lower_rot_9_9[22];
constraint lower_intermediate_output_8_12[47] = lower_rot_9_9[23];
constraint lower_rot_8_9[0] = lower_xor_8_10[21];
constraint lower_rot_8_9[1] = lower_xor_8_10[22];
constraint lower_rot_8_9[2] = lower_xor_8_10[23];
constraint lower_rot_8_9[3] = lower_xor_8_10[0];
constraint lower_rot_8_9[4] = lower_xor_8_10[1];
constraint lower_rot_8_9[5] = lower_xor_8_10[2];
constraint lower_rot_8_9[6] = lower_xor_8_10[3];
constraint lower_rot_8_9[7] = lower_xor_8_10[4];
constraint lower_rot_8_9[8] = lower_xor_8_10[5];
constraint lower_rot_8_9[9] = lower_xor_8_10[6];
constraint lower_rot_8_9[10] = lower_xor_8_10[7];
constraint lower_rot_8_9[11] = lower_xor_8_10[8];
constraint lower_rot_8_9[12] = lower_xor_8_10[9];
constraint lower_rot_8_9[13] = lower_xor_8_10[10];
constraint lower_rot_8_9[14] = lower_xor_8_10[11];
constraint lower_rot_8_9[15] = lower_xor_8_10[12];
constraint lower_rot_8_9[16] = lower_xor_8_10[13];
constraint lower_rot_8_9[17] = lower_xor_8_10[14];
constraint lower_rot_8_9[18] = lower_xor_8_10[15];
constraint lower_rot_8_9[19] = lower_xor_8_10[16];
constraint lower_rot_8_9[20] = lower_xor_8_10[17];
constraint lower_rot_8_9[21] = lower_xor_8_10[18];
constraint lower_rot_8_9[22] = lower_xor_8_10[19];
constraint lower_rot_8_9[23] = lower_xor_8_10[20];
constraint pre_lower_modadd_8_7_0[0] = lower_xor_8_8[0];
constraint pre_lower_modadd_8_7_0[1] = lower_xor_8_8[1];
constraint pre_lower_modadd_8_7_0[2] = lower_xor_8_8[2];
constraint pre_lower_modadd_8_7_0[3] = lower_xor_8_8[3];
constraint pre_lower_modadd_8_7_0[4] = lower_xor_8_8[4];
constraint pre_lower_modadd_8_7_0[5] = lower_xor_8_8[5];
constraint pre_lower_modadd_8_7_0[6] = lower_xor_8_8[6];
constraint pre_lower_modadd_8_7_0[7] = lower_xor_8_8[7];
constraint pre_lower_modadd_8_7_0[8] = lower_xor_8_8[8];
constraint pre_lower_modadd_8_7_0[9] = lower_xor_8_8[9];
constraint pre_lower_modadd_8_7_0[10] = lower_xor_8_8[10];
constraint pre_lower_modadd_8_7_0[11] = lower_xor_8_8[11];
constraint pre_lower_modadd_8_7_0[12] = lower_xor_8_8[12];
constraint pre_lower_modadd_8_7_0[13] = lower_xor_8_8[13];
constraint pre_lower_modadd_8_7_0[14] = lower_xor_8_8[14];
constraint pre_lower_modadd_8_7_0[15] = lower_xor_8_8[15];
constraint pre_lower_modadd_8_7_0[16] = lower_xor_8_8[16];
constraint pre_lower_modadd_8_7_0[17] = lower_xor_8_8[17];
constraint pre_lower_modadd_8_7_0[18] = lower_xor_8_8[18];
constraint pre_lower_modadd_8_7_0[19] = lower_xor_8_8[19];
constraint pre_lower_modadd_8_7_0[20] = lower_xor_8_8[20];
constraint pre_lower_modadd_8_7_0[21] = lower_xor_8_8[21];
constraint pre_lower_modadd_8_7_0[22] = lower_xor_8_8[22];
constraint pre_lower_modadd_8_7_0[23] = lower_xor_8_8[23];
constraint pre_lower_modadd_8_7_1[0] = lower_rot_8_9[0];
constraint pre_lower_modadd_8_7_1[1] = lower_rot_8_9[1];
constraint pre_lower_modadd_8_7_1[2] = lower_rot_8_9[2];
constraint pre_lower_modadd_8_7_1[3] = lower_rot_8_9[3];
constraint pre_lower_modadd_8_7_1[4] = lower_rot_8_9[4];
constraint pre_lower_modadd_8_7_1[5] = lower_rot_8_9[5];
constraint pre_lower_modadd_8_7_1[6] = lower_rot_8_9[6];
constraint pre_lower_modadd_8_7_1[7] = lower_rot_8_9[7];
constraint pre_lower_modadd_8_7_1[8] = lower_rot_8_9[8];
constraint pre_lower_modadd_8_7_1[9] = lower_rot_8_9[9];
constraint pre_lower_modadd_8_7_1[10] = lower_rot_8_9[10];
constraint pre_lower_modadd_8_7_1[11] = lower_rot_8_9[11];
constraint pre_lower_modadd_8_7_1[12] = lower_rot_8_9[12];
constraint pre_lower_modadd_8_7_1[13] = lower_rot_8_9[13];
constraint pre_lower_modadd_8_7_1[14] = lower_rot_8_9[14];
constraint pre_lower_modadd_8_7_1[15] = lower_rot_8_9[15];
constraint pre_lower_modadd_8_7_1[16] = lower_rot_8_9[16];
constraint pre_lower_modadd_8_7_1[17] = lower_rot_8_9[17];
constraint pre_lower_modadd_8_7_1[18] = lower_rot_8_9[18];
constraint pre_lower_modadd_8_7_1[19] = lower_rot_8_9[19];
constraint pre_lower_modadd_8_7_1[20] = lower_rot_8_9[20];
constraint pre_lower_modadd_8_7_1[21] = lower_rot_8_9[21];
constraint pre_lower_modadd_8_7_1[22] = lower_rot_8_9[22];
constraint pre_lower_modadd_8_7_1[23] = lower_rot_8_9[23];
constraint forall(j in 0..23)(if eq_lower_modadd_8_7[j] = 1 then (sum([pre_lower_modadd_8_7_1[j], pre_lower_modadd_8_7_0[j], lower_modadd_8_7[j]]) mod 2) = Shi_pre_lower_modadd_8_7_0[j] else true endif) /\ lower_p[4] = (24-sum(eq_lower_modadd_8_7))*100;
constraint lower_rot_8_6[0] = lower_modadd_8_7[8];
constraint lower_rot_8_6[1] = lower_modadd_8_7[9];
constraint lower_rot_8_6[2] = lower_modadd_8_7[10];
constraint lower_rot_8_6[3] = lower_modadd_8_7[11];
constraint lower_rot_8_6[4] = lower_modadd_8_7[12];
constraint lower_rot_8_6[5] = lower_modadd_8_7[13];
constraint lower_rot_8_6[6] = lower_modadd_8_7[14];
constraint lower_rot_8_6[7] = lower_modadd_8_7[15];
constraint lower_rot_8_6[8] = lower_modadd_8_7[16];
constraint lower_rot_8_6[9] = lower_modadd_8_7[17];
constraint lower_rot_8_6[10] = lower_modadd_8_7[18];
constraint lower_rot_8_6[11] = lower_modadd_8_7[19];
constraint lower_rot_8_6[12] = lower_modadd_8_7[20];
constraint lower_rot_8_6[13] = lower_modadd_8_7[21];
constraint lower_rot_8_6[14] = lower_modadd_8_7[22];
constraint lower_rot_8_6[15] = lower_modadd_8_7[23];
constraint lower_rot_8_6[16] = lower_modadd_8_7[0];
constraint lower_rot_8_6[17] = lower_modadd_8_7[1];
constraint lower_rot_8_6[18] = lower_modadd_8_7[2];
constraint lower_rot_8_6[19] = lower_modadd_8_7[3];
constraint lower_rot_8_6[20] = lower_modadd_8_7[4];
constraint lower_rot_8_6[21] = lower_modadd_8_7[5];
constraint lower_rot_8_6[22] = lower_modadd_8_7[6];
constraint lower_rot_8_6[23] = lower_modadd_8_7[7];
constraint 2*dummy_lower_xor_9_8[0] = (lower_xor_9_5[0] + lower_rot_10_6[0] + lower_xor_9_8[0]);
constraint 2*dummy_lower_xor_9_8[1] = (lower_xor_9_5[1] + lower_rot_10_6[1] + lower_xor_9_8[1]);
constraint 2*dummy_lower_xor_9_8[2] = (lower_xor_9_5[2] + lower_rot_10_6[2] + lower_xor_9_8[2]);
constraint 2*dummy_lower_xor_9_8[3] = (lower_xor_9_5[3] + lower_rot_10_6[3] + lower_xor_9_8[3]);
constraint 2*dummy_lower_xor_9_8[4] = (lower_xor_9_5[4] + lower_rot_10_6[4] + lower_xor_9_8[4]);
constraint 2*dummy_lower_xor_9_8[5] = (lower_xor_9_5[5] + lower_rot_10_6[5] + lower_xor_9_8[5]);
constraint 2*dummy_lower_xor_9_8[6] = (lower_xor_9_5[6] + lower_rot_10_6[6] + lower_xor_9_8[6]);
constraint 2*dummy_lower_xor_9_8[7] = (lower_xor_9_5[7] + lower_rot_10_6[7] + lower_xor_9_8[7]);
constraint 2*dummy_lower_xor_9_8[8] = (lower_xor_9_5[8] + lower_rot_10_6[8] + lower_xor_9_8[8]);
constraint 2*dummy_lower_xor_9_8[9] = (lower_xor_9_5[9] + lower_rot_10_6[9] + lower_xor_9_8[9]);
constraint 2*dummy_lower_xor_9_8[10] = (lower_xor_9_5[10] + lower_rot_10_6[10] + lower_xor_9_8[10]);
constraint 2*dummy_lower_xor_9_8[11] = (lower_xor_9_5[11] + lower_rot_10_6[11] + lower_xor_9_8[11]);
constraint 2*dummy_lower_xor_9_8[12] = (lower_xor_9_5[12] + lower_rot_10_6[12] + lower_xor_9_8[12]);
constraint 2*dummy_lower_xor_9_8[13] = (lower_xor_9_5[13] + lower_rot_10_6[13] + lower_xor_9_8[13]);
constraint 2*dummy_lower_xor_9_8[14] = (lower_xor_9_5[14] + lower_rot_10_6[14] + lower_xor_9_8[14]);
constraint 2*dummy_lower_xor_9_8[15] = (lower_xor_9_5[15] + lower_rot_10_6[15] + lower_xor_9_8[15]);
constraint 2*dummy_lower_xor_9_8[16] = (lower_xor_9_5[16] + lower_rot_10_6[16] + lower_xor_9_8[16]);
constraint 2*dummy_lower_xor_9_8[17] = (lower_xor_9_5[17] + lower_rot_10_6[17] + lower_xor_9_8[17]);
constraint 2*dummy_lower_xor_9_8[18] = (lower_xor_9_5[18] + lower_rot_10_6[18] + lower_xor_9_8[18]);
constraint 2*dummy_lower_xor_9_8[19] = (lower_xor_9_5[19] + lower_rot_10_6[19] + lower_xor_9_8[19]);
constraint 2*dummy_lower_xor_9_8[20] = (lower_xor_9_5[20] + lower_rot_10_6[20] + lower_xor_9_8[20]);
constraint 2*dummy_lower_xor_9_8[21] = (lower_xor_9_5[21] + lower_rot_10_6[21] + lower_xor_9_8[21]);
constraint 2*dummy_lower_xor_9_8[22] = (lower_xor_9_5[22] + lower_rot_10_6[22] + lower_xor_9_8[22]);
constraint 2*dummy_lower_xor_9_8[23] = (lower_xor_9_5[23] + lower_rot_10_6[23] + lower_xor_9_8[23]);
constraint 2*dummy_lower_xor_9_10[0] = (lower_rot_10_6[0] + lower_rot_10_9[0] + lower_xor_9_10[0]);
constraint 2*dummy_lower_xor_9_10[1] = (lower_rot_10_6[1] + lower_rot_10_9[1] + lower_xor_9_10[1]);
constraint 2*dummy_lower_xor_9_10[2] = (lower_rot_10_6[2] + lower_rot_10_9[2] + lower_xor_9_10[2]);
constraint 2*dummy_lower_xor_9_10[3] = (lower_rot_10_6[3] + lower_rot_10_9[3] + lower_xor_9_10[3]);
constraint 2*dummy_lower_xor_9_10[4] = (lower_rot_10_6[4] + lower_rot_10_9[4] + lower_xor_9_10[4]);
constraint 2*dummy_lower_xor_9_10[5] = (lower_rot_10_6[5] + lower_rot_10_9[5] + lower_xor_9_10[5]);
constraint 2*dummy_lower_xor_9_10[6] = (lower_rot_10_6[6] + lower_rot_10_9[6] + lower_xor_9_10[6]);
constraint 2*dummy_lower_xor_9_10[7] = (lower_rot_10_6[7] + lower_rot_10_9[7] + lower_xor_9_10[7]);
constraint 2*dummy_lower_xor_9_10[8] = (lower_rot_10_6[8] + lower_rot_10_9[8] + lower_xor_9_10[8]);
constraint 2*dummy_lower_xor_9_10[9] = (lower_rot_10_6[9] + lower_rot_10_9[9] + lower_xor_9_10[9]);
constraint 2*dummy_lower_xor_9_10[10] = (lower_rot_10_6[10] + lower_rot_10_9[10] + lower_xor_9_10[10]);
constraint 2*dummy_lower_xor_9_10[11] = (lower_rot_10_6[11] + lower_rot_10_9[11] + lower_xor_9_10[11]);
constraint 2*dummy_lower_xor_9_10[12] = (lower_rot_10_6[12] + lower_rot_10_9[12] + lower_xor_9_10[12]);
constraint 2*dummy_lower_xor_9_10[13] = (lower_rot_10_6[13] + lower_rot_10_9[13] + lower_xor_9_10[13]);
constraint 2*dummy_lower_xor_9_10[14] = (lower_rot_10_6[14] + lower_rot_10_9[14] + lower_xor_9_10[14]);
constraint 2*dummy_lower_xor_9_10[15] = (lower_rot_10_6[15] + lower_rot_10_9[15] + lower_xor_9_10[15]);
constraint 2*dummy_lower_xor_9_10[16] = (lower_rot_10_6[16] + lower_rot_10_9[16] + lower_xor_9_10[16]);
constraint 2*dummy_lower_xor_9_10[17] = (lower_rot_10_6[17] + lower_rot_10_9[17] + lower_xor_9_10[17]);
constraint 2*dummy_lower_xor_9_10[18] = (lower_rot_10_6[18] + lower_rot_10_9[18] + lower_xor_9_10[18]);
constraint 2*dummy_lower_xor_9_10[19] = (lower_rot_10_6[19] + lower_rot_10_9[19] + lower_xor_9_10[19]);
constraint 2*dummy_lower_xor_9_10[20] = (lower_rot_10_6[20] + lower_rot_10_9[20] + lower_xor_9_10[20]);
constraint 2*dummy_lower_xor_9_10[21] = (lower_rot_10_6[21] + lower_rot_10_9[21] + lower_xor_9_10[21]);
constraint 2*dummy_lower_xor_9_10[22] = (lower_rot_10_6[22] + lower_rot_10_9[22] + lower_xor_9_10[22]);
constraint 2*dummy_lower_xor_9_10[23] = (lower_rot_10_6[23] + lower_rot_10_9[23] + lower_xor_9_10[23]);
constraint lower_intermediate_output_9_12[0] = lower_rot_10_6[0];
constraint lower_intermediate_output_9_12[1] = lower_rot_10_6[1];
constraint lower_intermediate_output_9_12[2] = lower_rot_10_6[2];
constraint lower_intermediate_output_9_12[3] = lower_rot_10_6[3];
constraint lower_intermediate_output_9_12[4] = lower_rot_10_6[4];
constraint lower_intermediate_output_9_12[5] = lower_rot_10_6[5];
constraint lower_intermediate_output_9_12[6] = lower_rot_10_6[6];
constraint lower_intermediate_output_9_12[7] = lower_rot_10_6[7];
constraint lower_intermediate_output_9_12[8] = lower_rot_10_6[8];
constraint lower_intermediate_output_9_12[9] = lower_rot_10_6[9];
constraint lower_intermediate_output_9_12[10] = lower_rot_10_6[10];
constraint lower_intermediate_output_9_12[11] = lower_rot_10_6[11];
constraint lower_intermediate_output_9_12[12] = lower_rot_10_6[12];
constraint lower_intermediate_output_9_12[13] = lower_rot_10_6[13];
constraint lower_intermediate_output_9_12[14] = lower_rot_10_6[14];
constraint lower_intermediate_output_9_12[15] = lower_rot_10_6[15];
constraint lower_intermediate_output_9_12[16] = lower_rot_10_6[16];
constraint lower_intermediate_output_9_12[17] = lower_rot_10_6[17];
constraint lower_intermediate_output_9_12[18] = lower_rot_10_6[18];
constraint lower_intermediate_output_9_12[19] = lower_rot_10_6[19];
constraint lower_intermediate_output_9_12[20] = lower_rot_10_6[20];
constraint lower_intermediate_output_9_12[21] = lower_rot_10_6[21];
constraint lower_intermediate_output_9_12[22] = lower_rot_10_6[22];
constraint lower_intermediate_output_9_12[23] = lower_rot_10_6[23];
constraint lower_intermediate_output_9_12[24] = lower_rot_10_9[0];
constraint lower_intermediate_output_9_12[25] = lower_rot_10_9[1];
constraint lower_intermediate_output_9_12[26] = lower_rot_10_9[2];
constraint lower_intermediate_output_9_12[27] = lower_rot_10_9[3];
constraint lower_intermediate_output_9_12[28] = lower_rot_10_9[4];
constraint lower_intermediate_output_9_12[29] = lower_rot_10_9[5];
constraint lower_intermediate_output_9_12[30] = lower_rot_10_9[6];
constraint lower_intermediate_output_9_12[31] = lower_rot_10_9[7];
constraint lower_intermediate_output_9_12[32] = lower_rot_10_9[8];
constraint lower_intermediate_output_9_12[33] = lower_rot_10_9[9];
constraint lower_intermediate_output_9_12[34] = lower_rot_10_9[10];
constraint lower_intermediate_output_9_12[35] = lower_rot_10_9[11];
constraint lower_intermediate_output_9_12[36] = lower_rot_10_9[12];
constraint lower_intermediate_output_9_12[37] = lower_rot_10_9[13];
constraint lower_intermediate_output_9_12[38] = lower_rot_10_9[14];
constraint lower_intermediate_output_9_12[39] = lower_rot_10_9[15];
constraint lower_intermediate_output_9_12[40] = lower_rot_10_9[16];
constraint lower_intermediate_output_9_12[41] = lower_rot_10_9[17];
constraint lower_intermediate_output_9_12[42] = lower_rot_10_9[18];
constraint lower_intermediate_output_9_12[43] = lower_rot_10_9[19];
constraint lower_intermediate_output_9_12[44] = lower_rot_10_9[20];
constraint lower_intermediate_output_9_12[45] = lower_rot_10_9[21];
constraint lower_intermediate_output_9_12[46] = lower_rot_10_9[22];
constraint lower_intermediate_output_9_12[47] = lower_rot_10_9[23];
constraint lower_rot_9_9[0] = lower_xor_9_10[21];
constraint lower_rot_9_9[1] = lower_xor_9_10[22];
constraint lower_rot_9_9[2] = lower_xor_9_10[23];
constraint lower_rot_9_9[3] = lower_xor_9_10[0];
constraint lower_rot_9_9[4] = lower_xor_9_10[1];
constraint lower_rot_9_9[5] = lower_xor_9_10[2];
constraint lower_rot_9_9[6] = lower_xor_9_10[3];
constraint lower_rot_9_9[7] = lower_xor_9_10[4];
constraint lower_rot_9_9[8] = lower_xor_9_10[5];
constraint lower_rot_9_9[9] = lower_xor_9_10[6];
constraint lower_rot_9_9[10] = lower_xor_9_10[7];
constraint lower_rot_9_9[11] = lower_xor_9_10[8];
constraint lower_rot_9_9[12] = lower_xor_9_10[9];
constraint lower_rot_9_9[13] = lower_xor_9_10[10];
constraint lower_rot_9_9[14] = lower_xor_9_10[11];
constraint lower_rot_9_9[15] = lower_xor_9_10[12];
constraint lower_rot_9_9[16] = lower_xor_9_10[13];
constraint lower_rot_9_9[17] = lower_xor_9_10[14];
constraint lower_rot_9_9[18] = lower_xor_9_10[15];
constraint lower_rot_9_9[19] = lower_xor_9_10[16];
constraint lower_rot_9_9[20] = lower_xor_9_10[17];
constraint lower_rot_9_9[21] = lower_xor_9_10[18];
constraint lower_rot_9_9[22] = lower_xor_9_10[19];
constraint lower_rot_9_9[23] = lower_xor_9_10[20];
constraint pre_lower_modadd_9_7_0[0] = lower_xor_9_8[0];
constraint pre_lower_modadd_9_7_0[1] = lower_xor_9_8[1];
constraint pre_lower_modadd_9_7_0[2] = lower_xor_9_8[2];
constraint pre_lower_modadd_9_7_0[3] = lower_xor_9_8[3];
constraint pre_lower_modadd_9_7_0[4] = lower_xor_9_8[4];
constraint pre_lower_modadd_9_7_0[5] = lower_xor_9_8[5];
constraint pre_lower_modadd_9_7_0[6] = lower_xor_9_8[6];
constraint pre_lower_modadd_9_7_0[7] = lower_xor_9_8[7];
constraint pre_lower_modadd_9_7_0[8] = lower_xor_9_8[8];
constraint pre_lower_modadd_9_7_0[9] = lower_xor_9_8[9];
constraint pre_lower_modadd_9_7_0[10] = lower_xor_9_8[10];
constraint pre_lower_modadd_9_7_0[11] = lower_xor_9_8[11];
constraint pre_lower_modadd_9_7_0[12] = lower_xor_9_8[12];
constraint pre_lower_modadd_9_7_0[13] = lower_xor_9_8[13];
constraint pre_lower_modadd_9_7_0[14] = lower_xor_9_8[14];
constraint pre_lower_modadd_9_7_0[15] = lower_xor_9_8[15];
constraint pre_lower_modadd_9_7_0[16] = lower_xor_9_8[16];
constraint pre_lower_modadd_9_7_0[17] = lower_xor_9_8[17];
constraint pre_lower_modadd_9_7_0[18] = lower_xor_9_8[18];
constraint pre_lower_modadd_9_7_0[19] = lower_xor_9_8[19];
constraint pre_lower_modadd_9_7_0[20] = lower_xor_9_8[20];
constraint pre_lower_modadd_9_7_0[21] = lower_xor_9_8[21];
constraint pre_lower_modadd_9_7_0[22] = lower_xor_9_8[22];
constraint pre_lower_modadd_9_7_0[23] = lower_xor_9_8[23];
constraint pre_lower_modadd_9_7_1[0] = lower_rot_9_9[0];
constraint pre_lower_modadd_9_7_1[1] = lower_rot_9_9[1];
constraint pre_lower_modadd_9_7_1[2] = lower_rot_9_9[2];
constraint pre_lower_modadd_9_7_1[3] = lower_rot_9_9[3];
constraint pre_lower_modadd_9_7_1[4] = lower_rot_9_9[4];
constraint pre_lower_modadd_9_7_1[5] = lower_rot_9_9[5];
constraint pre_lower_modadd_9_7_1[6] = lower_rot_9_9[6];
constraint pre_lower_modadd_9_7_1[7] = lower_rot_9_9[7];
constraint pre_lower_modadd_9_7_1[8] = lower_rot_9_9[8];
constraint pre_lower_modadd_9_7_1[9] = lower_rot_9_9[9];
constraint pre_lower_modadd_9_7_1[10] = lower_rot_9_9[10];
constraint pre_lower_modadd_9_7_1[11] = lower_rot_9_9[11];
constraint pre_lower_modadd_9_7_1[12] = lower_rot_9_9[12];
constraint pre_lower_modadd_9_7_1[13] = lower_rot_9_9[13];
constraint pre_lower_modadd_9_7_1[14] = lower_rot_9_9[14];
constraint pre_lower_modadd_9_7_1[15] = lower_rot_9_9[15];
constraint pre_lower_modadd_9_7_1[16] = lower_rot_9_9[16];
constraint pre_lower_modadd_9_7_1[17] = lower_rot_9_9[17];
constraint pre_lower_modadd_9_7_1[18] = lower_rot_9_9[18];
constraint pre_lower_modadd_9_7_1[19] = lower_rot_9_9[19];
constraint pre_lower_modadd_9_7_1[20] = lower_rot_9_9[20];
constraint pre_lower_modadd_9_7_1[21] = lower_rot_9_9[21];
constraint pre_lower_modadd_9_7_1[22] = lower_rot_9_9[22];
constraint pre_lower_modadd_9_7_1[23] = lower_rot_9_9[23];
constraint forall(j in 0..23)(if eq_lower_modadd_9_7[j] = 1 then (sum([pre_lower_modadd_9_7_1[j], pre_lower_modadd_9_7_0[j], lower_modadd_9_7[j]]) mod 2) = Shi_pre_lower_modadd_9_7_0[j] else true endif) /\ lower_p[5] = (24-sum(eq_lower_modadd_9_7))*100;
constraint lower_rot_9_6[0] = lower_modadd_9_7[8];
constraint lower_rot_9_6[1] = lower_modadd_9_7[9];
constraint lower_rot_9_6[2] = lower_modadd_9_7[10];
constraint lower_rot_9_6[3] = lower_modadd_9_7[11];
constraint lower_rot_9_6[4] = lower_modadd_9_7[12];
constraint lower_rot_9_6[5] = lower_modadd_9_7[13];
constraint lower_rot_9_6[6] = lower_modadd_9_7[14];
constraint lower_rot_9_6[7] = lower_modadd_9_7[15];
constraint lower_rot_9_6[8] = lower_modadd_9_7[16];
constraint lower_rot_9_6[9] = lower_modadd_9_7[17];
constraint lower_rot_9_6[10] = lower_modadd_9_7[18];
constraint lower_rot_9_6[11] = lower_modadd_9_7[19];
constraint lower_rot_9_6[12] = lower_modadd_9_7[20];
constraint lower_rot_9_6[13] = lower_modadd_9_7[21];
constraint lower_rot_9_6[14] = lower_modadd_9_7[22];
constraint lower_rot_9_6[15] = lower_modadd_9_7[23];
constraint lower_rot_9_6[16] = lower_modadd_9_7[0];
constraint lower_rot_9_6[17] = lower_modadd_9_7[1];
constraint lower_rot_9_6[18] = lower_modadd_9_7[2];
constraint lower_rot_9_6[19] = lower_modadd_9_7[3];
constraint lower_rot_9_6[20] = lower_modadd_9_7[4];
constraint lower_rot_9_6[21] = lower_modadd_9_7[5];
constraint lower_rot_9_6[22] = lower_modadd_9_7[6];
constraint lower_rot_9_6[23] = lower_modadd_9_7[7];
constraint 2*dummy_lower_xor_10_8[0] = (lower_xor_10_5[0] + lower_cipher_output_10_12[0] + lower_xor_10_8[0]);
constraint 2*dummy_lower_xor_10_8[1] = (lower_xor_10_5[1] + lower_cipher_output_10_12[1] + lower_xor_10_8[1]);
constraint 2*dummy_lower_xor_10_8[2] = (lower_xor_10_5[2] + lower_cipher_output_10_12[2] + lower_xor_10_8[2]);
constraint 2*dummy_lower_xor_10_8[3] = (lower_xor_10_5[3] + lower_cipher_output_10_12[3] + lower_xor_10_8[3]);
constraint 2*dummy_lower_xor_10_8[4] = (lower_xor_10_5[4] + lower_cipher_output_10_12[4] + lower_xor_10_8[4]);
constraint 2*dummy_lower_xor_10_8[5] = (lower_xor_10_5[5] + lower_cipher_output_10_12[5] + lower_xor_10_8[5]);
constraint 2*dummy_lower_xor_10_8[6] = (lower_xor_10_5[6] + lower_cipher_output_10_12[6] + lower_xor_10_8[6]);
constraint 2*dummy_lower_xor_10_8[7] = (lower_xor_10_5[7] + lower_cipher_output_10_12[7] + lower_xor_10_8[7]);
constraint 2*dummy_lower_xor_10_8[8] = (lower_xor_10_5[8] + lower_cipher_output_10_12[8] + lower_xor_10_8[8]);
constraint 2*dummy_lower_xor_10_8[9] = (lower_xor_10_5[9] + lower_cipher_output_10_12[9] + lower_xor_10_8[9]);
constraint 2*dummy_lower_xor_10_8[10] = (lower_xor_10_5[10] + lower_cipher_output_10_12[10] + lower_xor_10_8[10]);
constraint 2*dummy_lower_xor_10_8[11] = (lower_xor_10_5[11] + lower_cipher_output_10_12[11] + lower_xor_10_8[11]);
constraint 2*dummy_lower_xor_10_8[12] = (lower_xor_10_5[12] + lower_cipher_output_10_12[12] + lower_xor_10_8[12]);
constraint 2*dummy_lower_xor_10_8[13] = (lower_xor_10_5[13] + lower_cipher_output_10_12[13] + lower_xor_10_8[13]);
constraint 2*dummy_lower_xor_10_8[14] = (lower_xor_10_5[14] + lower_cipher_output_10_12[14] + lower_xor_10_8[14]);
constraint 2*dummy_lower_xor_10_8[15] = (lower_xor_10_5[15] + lower_cipher_output_10_12[15] + lower_xor_10_8[15]);
constraint 2*dummy_lower_xor_10_8[16] = (lower_xor_10_5[16] + lower_cipher_output_10_12[16] + lower_xor_10_8[16]);
constraint 2*dummy_lower_xor_10_8[17] = (lower_xor_10_5[17] + lower_cipher_output_10_12[17] + lower_xor_10_8[17]);
constraint 2*dummy_lower_xor_10_8[18] = (lower_xor_10_5[18] + lower_cipher_output_10_12[18] + lower_xor_10_8[18]);
constraint 2*dummy_lower_xor_10_8[19] = (lower_xor_10_5[19] + lower_cipher_output_10_12[19] + lower_xor_10_8[19]);
constraint 2*dummy_lower_xor_10_8[20] = (lower_xor_10_5[20] + lower_cipher_output_10_12[20] + lower_xor_10_8[20]);
constraint 2*dummy_lower_xor_10_8[21] = (lower_xor_10_5[21] + lower_cipher_output_10_12[21] + lower_xor_10_8[21]);
constraint 2*dummy_lower_xor_10_8[22] = (lower_xor_10_5[22] + lower_cipher_output_10_12[22] + lower_xor_10_8[22]);
constraint 2*dummy_lower_xor_10_8[23] = (lower_xor_10_5[23] + lower_cipher_output_10_12[23] + lower_xor_10_8[23]);
constraint 2*dummy_lower_xor_10_10[0] = (lower_cipher_output_10_12[0] + lower_cipher_output_10_12[24] + lower_xor_10_10[0]);
constraint 2*dummy_lower_xor_10_10[1] = (lower_cipher_output_10_12[1] + lower_cipher_output_10_12[25] + lower_xor_10_10[1]);
constraint 2*dummy_lower_xor_10_10[2] = (lower_cipher_output_10_12[2] + lower_cipher_output_10_12[26] + lower_xor_10_10[2]);
constraint 2*dummy_lower_xor_10_10[3] = (lower_cipher_output_10_12[3] + lower_cipher_output_10_12[27] + lower_xor_10_10[3]);
constraint 2*dummy_lower_xor_10_10[4] = (lower_cipher_output_10_12[4] + lower_cipher_output_10_12[28] + lower_xor_10_10[4]);
constraint 2*dummy_lower_xor_10_10[5] = (lower_cipher_output_10_12[5] + lower_cipher_output_10_12[29] + lower_xor_10_10[5]);
constraint 2*dummy_lower_xor_10_10[6] = (lower_cipher_output_10_12[6] + lower_cipher_output_10_12[30] + lower_xor_10_10[6]);
constraint 2*dummy_lower_xor_10_10[7] = (lower_cipher_output_10_12[7] + lower_cipher_output_10_12[31] + lower_xor_10_10[7]);
constraint 2*dummy_lower_xor_10_10[8] = (lower_cipher_output_10_12[8] + lower_cipher_output_10_12[32] + lower_xor_10_10[8]);
constraint 2*dummy_lower_xor_10_10[9] = (lower_cipher_output_10_12[9] + lower_cipher_output_10_12[33] + lower_xor_10_10[9]);
constraint 2*dummy_lower_xor_10_10[10] = (lower_cipher_output_10_12[10] + lower_cipher_output_10_12[34] + lower_xor_10_10[10]);
constraint 2*dummy_lower_xor_10_10[11] = (lower_cipher_output_10_12[11] + lower_cipher_output_10_12[35] + lower_xor_10_10[11]);
constraint 2*dummy_lower_xor_10_10[12] = (lower_cipher_output_10_12[12] + lower_cipher_output_10_12[36] + lower_xor_10_10[12]);
constraint 2*dummy_lower_xor_10_10[13] = (lower_cipher_output_10_12[13] + lower_cipher_output_10_12[37] + lower_xor_10_10[13]);
constraint 2*dummy_lower_xor_10_10[14] = (lower_cipher_output_10_12[14] + lower_cipher_output_10_12[38] + lower_xor_10_10[14]);
constraint 2*dummy_lower_xor_10_10[15] = (lower_cipher_output_10_12[15] + lower_cipher_output_10_12[39] + lower_xor_10_10[15]);
constraint 2*dummy_lower_xor_10_10[16] = (lower_cipher_output_10_12[16] + lower_cipher_output_10_12[40] + lower_xor_10_10[16]);
constraint 2*dummy_lower_xor_10_10[17] = (lower_cipher_output_10_12[17] + lower_cipher_output_10_12[41] + lower_xor_10_10[17]);
constraint 2*dummy_lower_xor_10_10[18] = (lower_cipher_output_10_12[18] + lower_cipher_output_10_12[42] + lower_xor_10_10[18]);
constraint 2*dummy_lower_xor_10_10[19] = (lower_cipher_output_10_12[19] + lower_cipher_output_10_12[43] + lower_xor_10_10[19]);
constraint 2*dummy_lower_xor_10_10[20] = (lower_cipher_output_10_12[20] + lower_cipher_output_10_12[44] + lower_xor_10_10[20]);
constraint 2*dummy_lower_xor_10_10[21] = (lower_cipher_output_10_12[21] + lower_cipher_output_10_12[45] + lower_xor_10_10[21]);
constraint 2*dummy_lower_xor_10_10[22] = (lower_cipher_output_10_12[22] + lower_cipher_output_10_12[46] + lower_xor_10_10[22]);
constraint 2*dummy_lower_xor_10_10[23] = (lower_cipher_output_10_12[23] + lower_cipher_output_10_12[47] + lower_xor_10_10[23]);
constraint lower_rot_10_9[0] = lower_xor_10_10[21];
constraint lower_rot_10_9[1] = lower_xor_10_10[22];
constraint lower_rot_10_9[2] = lower_xor_10_10[23];
constraint lower_rot_10_9[3] = lower_xor_10_10[0];
constraint lower_rot_10_9[4] = lower_xor_10_10[1];
constraint lower_rot_10_9[5] = lower_xor_10_10[2];
constraint lower_rot_10_9[6] = lower_xor_10_10[3];
constraint lower_rot_10_9[7] = lower_xor_10_10[4];
constraint lower_rot_10_9[8] = lower_xor_10_10[5];
constraint lower_rot_10_9[9] = lower_xor_10_10[6];
constraint lower_rot_10_9[10] = lower_xor_10_10[7];
constraint lower_rot_10_9[11] = lower_xor_10_10[8];
constraint lower_rot_10_9[12] = lower_xor_10_10[9];
constraint lower_rot_10_9[13] = lower_xor_10_10[10];
constraint lower_rot_10_9[14] = lower_xor_10_10[11];
constraint lower_rot_10_9[15] = lower_xor_10_10[12];
constraint lower_rot_10_9[16] = lower_xor_10_10[13];
constraint lower_rot_10_9[17] = lower_xor_10_10[14];
constraint lower_rot_10_9[18] = lower_xor_10_10[15];
constraint lower_rot_10_9[19] = lower_xor_10_10[16];
constraint lower_rot_10_9[20] = lower_xor_10_10[17];
constraint lower_rot_10_9[21] = lower_xor_10_10[18];
constraint lower_rot_10_9[22] = lower_xor_10_10[19];
constraint lower_rot_10_9[23] = lower_xor_10_10[20];
constraint pre_lower_modadd_10_7_0[0] = lower_xor_10_8[0];
constraint pre_lower_modadd_10_7_0[1] = lower_xor_10_8[1];
constraint pre_lower_modadd_10_7_0[2] = lower_xor_10_8[2];
constraint pre_lower_modadd_10_7_0[3] = lower_xor_10_8[3];
constraint pre_lower_modadd_10_7_0[4] = lower_xor_10_8[4];
constraint pre_lower_modadd_10_7_0[5] = lower_xor_10_8[5];
constraint pre_lower_modadd_10_7_0[6] = lower_xor_10_8[6];
constraint pre_lower_modadd_10_7_0[7] = lower_xor_10_8[7];
constraint pre_lower_modadd_10_7_0[8] = lower_xor_10_8[8];
constraint pre_lower_modadd_10_7_0[9] = lower_xor_10_8[9];
constraint pre_lower_modadd_10_7_0[10] = lower_xor_10_8[10];
constraint pre_lower_modadd_10_7_0[11] = lower_xor_10_8[11];
constraint pre_lower_modadd_10_7_0[12] = lower_xor_10_8[12];
constraint pre_lower_modadd_10_7_0[13] = lower_xor_10_8[13];
constraint pre_lower_modadd_10_7_0[14] = lower_xor_10_8[14];
constraint pre_lower_modadd_10_7_0[15] = lower_xor_10_8[15];
constraint pre_lower_modadd_10_7_0[16] = lower_xor_10_8[16];
constraint pre_lower_modadd_10_7_0[17] = lower_xor_10_8[17];
constraint pre_lower_modadd_10_7_0[18] = lower_xor_10_8[18];
constraint pre_lower_modadd_10_7_0[19] = lower_xor_10_8[19];
constraint pre_lower_modadd_10_7_0[20] = lower_xor_10_8[20];
constraint pre_lower_modadd_10_7_0[21] = lower_xor_10_8[21];
constraint pre_lower_modadd_10_7_0[22] = lower_xor_10_8[22];
constraint pre_lower_modadd_10_7_0[23] = lower_xor_10_8[23];
constraint pre_lower_modadd_10_7_1[0] = lower_rot_10_9[0];
constraint pre_lower_modadd_10_7_1[1] = lower_rot_10_9[1];
constraint pre_lower_modadd_10_7_1[2] = lower_rot_10_9[2];
constraint pre_lower_modadd_10_7_1[3] = lower_rot_10_9[3];
constraint pre_lower_modadd_10_7_1[4] = lower_rot_10_9[4];
constraint pre_lower_modadd_10_7_1[5] = lower_rot_10_9[5];
constraint pre_lower_modadd_10_7_1[6] = lower_rot_10_9[6];
constraint pre_lower_modadd_10_7_1[7] = lower_rot_10_9[7];
constraint pre_lower_modadd_10_7_1[8] = lower_rot_10_9[8];
constraint pre_lower_modadd_10_7_1[9] = lower_rot_10_9[9];
constraint pre_lower_modadd_10_7_1[10] = lower_rot_10_9[10];
constraint pre_lower_modadd_10_7_1[11] = lower_rot_10_9[11];
constraint pre_lower_modadd_10_7_1[12] = lower_rot_10_9[12];
constraint pre_lower_modadd_10_7_1[13] = lower_rot_10_9[13];
constraint pre_lower_modadd_10_7_1[14] = lower_rot_10_9[14];
constraint pre_lower_modadd_10_7_1[15] = lower_rot_10_9[15];
constraint pre_lower_modadd_10_7_1[16] = lower_rot_10_9[16];
constraint pre_lower_modadd_10_7_1[17] = lower_rot_10_9[17];
constraint pre_lower_modadd_10_7_1[18] = lower_rot_10_9[18];
constraint pre_lower_modadd_10_7_1[19] = lower_rot_10_9[19];
constraint pre_lower_modadd_10_7_1[20] = lower_rot_10_9[20];
constraint pre_lower_modadd_10_7_1[21] = lower_rot_10_9[21];
constraint pre_lower_modadd_10_7_1[22] = lower_rot_10_9[22];
constraint pre_lower_modadd_10_7_1[23] = lower_rot_10_9[23];
constraint forall(j in 0..23)(if eq_lower_modadd_10_7[j] = 1 then (sum([pre_lower_modadd_10_7_1[j], pre_lower_modadd_10_7_0[j], lower_modadd_10_7[j]]) mod 2) = Shi_pre_lower_modadd_10_7_0[j] else true endif) /\ lower_p[6] = (24-sum(eq_lower_modadd_10_7))*100;
constraint lower_rot_10_6[0] = lower_modadd_10_7[8];
constraint lower_rot_10_6[1] = lower_modadd_10_7[9];
constraint lower_rot_10_6[2] = lower_modadd_10_7[10];
constraint lower_rot_10_6[3] = lower_modadd_10_7[11];
constraint lower_rot_10_6[4] = lower_modadd_10_7[12];
constraint lower_rot_10_6[5] = lower_modadd_10_7[13];
constraint lower_rot_10_6[6] = lower_modadd_10_7[14];
constraint lower_rot_10_6[7] = lower_modadd_10_7[15];
constraint lower_rot_10_6[8] = lower_modadd_10_7[16];
constraint lower_rot_10_6[9] = lower_modadd_10_7[17];
constraint lower_rot_10_6[10] = lower_modadd_10_7[18];
constraint lower_rot_10_6[11] = lower_modadd_10_7[19];
constraint lower_rot_10_6[12] = lower_modadd_10_7[20];
constraint lower_rot_10_6[13] = lower_modadd_10_7[21];
constraint lower_rot_10_6[14] = lower_modadd_10_7[22];
constraint lower_rot_10_6[15] = lower_modadd_10_7[23];
constraint lower_rot_10_6[16] = lower_modadd_10_7[0];
constraint lower_rot_10_6[17] = lower_modadd_10_7[1];
constraint lower_rot_10_6[18] = lower_modadd_10_7[2];
constraint lower_rot_10_6[19] = lower_modadd_10_7[3];
constraint lower_rot_10_6[20] = lower_modadd_10_7[4];
constraint lower_rot_10_6[21] = lower_modadd_10_7[5];
constraint lower_rot_10_6[22] = lower_modadd_10_7[6];
constraint lower_rot_10_6[23] = lower_modadd_10_7[7];
constraint onlyLargeSwitch_UBCT_enum(array1d(0..24-1, [pre_upper_modadd_4_7_0[23],pre_upper_modadd_4_7_0[22],pre_upper_modadd_4_7_0[21],pre_upper_modadd_4_7_0[20],pre_upper_modadd_4_7_0[19],pre_upper_modadd_4_7_0[18],pre_upper_modadd_4_7_0[17],pre_upper_modadd_4_7_0[16],pre_upper_modadd_4_7_0[15],pre_upper_modadd_4_7_0[14],pre_upper_modadd_4_7_0[13],pre_upper_modadd_4_7_0[12],pre_upper_modadd_4_7_0[11],pre_upper_modadd_4_7_0[10],pre_upper_modadd_4_7_0[9],pre_upper_modadd_4_7_0[8],pre_upper_modadd_4_7_0[7],pre_upper_modadd_4_7_0[6],pre_upper_modadd_4_7_0[5],pre_upper_modadd_4_7_0[4],pre_upper_modadd_4_7_0[3],pre_upper_modadd_4_7_0[2],pre_upper_modadd_4_7_0[1],pre_upper_modadd_4_7_0[0]]), array1d(0..24-1, [pre_upper_modadd_4_7_1[23],pre_upper_modadd_4_7_1[22],pre_upper_modadd_4_7_1[21],pre_upper_modadd_4_7_1[20],pre_upper_modadd_4_7_1[19],pre_upper_modadd_4_7_1[18],pre_upper_modadd_4_7_1[17],pre_upper_modadd_4_7_1[16],pre_upper_modadd_4_7_1[15],pre_upper_modadd_4_7_1[14],pre_upper_modadd_4_7_1[13],pre_upper_modadd_4_7_1[12],pre_upper_modadd_4_7_1[11],pre_upper_modadd_4_7_1[10],pre_upper_modadd_4_7_1[9],pre_upper_modadd_4_7_1[8],pre_upper_modadd_4_7_1[7],pre_upper_modadd_4_7_1[6],pre_upper_modadd_4_7_1[5],pre_upper_modadd_4_7_1[4],pre_upper_modadd_4_7_1[3],pre_upper_modadd_4_7_1[2],pre_upper_modadd_4_7_1[1],pre_upper_modadd_4_7_1[0]]), array1d(0..24-1, [pre_lower_modadd_4_7_0[23],pre_lower_modadd_4_7_0[22],pre_lower_modadd_4_7_0[21],pre_lower_modadd_4_7_0[20],pre_lower_modadd_4_7_0[19],pre_lower_modadd_4_7_0[18],pre_lower_modadd_4_7_0[17],pre_lower_modadd_4_7_0[16],pre_lower_modadd_4_7_0[15],pre_lower_modadd_4_7_0[14],pre_lower_modadd_4_7_0[13],pre_lower_modadd_4_7_0[12],pre_lower_modadd_4_7_0[11],pre_lower_modadd_4_7_0[10],pre_lower_modadd_4_7_0[9],pre_lower_modadd_4_7_0[8],pre_lower_modadd_4_7_0[7],pre_lower_modadd_4_7_0[6],pre_lower_modadd_4_7_0[5],pre_lower_modadd_4_7_0[4],pre_lower_modadd_4_7_0[3],pre_lower_modadd_4_7_0[2],pre_lower_modadd_4_7_0[1],pre_lower_modadd_4_7_0[0]]), array1d(0..24-1, [pre_lower_modadd_4_7_1[23],pre_lower_modadd_4_7_1[22],pre_lower_modadd_4_7_1[21],pre_lower_modadd_4_7_1[20],pre_lower_modadd_4_7_1[19],pre_lower_modadd_4_7_1[18],pre_lower_modadd_4_7_1[17],pre_lower_modadd_4_7_1[16],pre_lower_modadd_4_7_1[15],pre_lower_modadd_4_7_1[14],pre_lower_modadd_4_7_1[13],pre_lower_modadd_4_7_1[12],pre_lower_modadd_4_7_1[11],pre_lower_modadd_4_7_1[10],pre_lower_modadd_4_7_1[9],pre_lower_modadd_4_7_1[8],pre_lower_modadd_4_7_1[7],pre_lower_modadd_4_7_1[6],pre_lower_modadd_4_7_1[5],pre_lower_modadd_4_7_1[4],pre_lower_modadd_4_7_1[3],pre_lower_modadd_4_7_1[2],pre_lower_modadd_4_7_1[1],pre_lower_modadd_4_7_1[0]]), array1d(0..24-1, [upper_modadd_4_7[23],upper_modadd_4_7[22],upper_modadd_4_7[21],upper_modadd_4_7[20],upper_modadd_4_7[19],upper_modadd_4_7[18],upper_modadd_4_7[17],upper_modadd_4_7[16],upper_modadd_4_7[15],upper_modadd_4_7[14],upper_modadd_4_7[13],upper_modadd_4_7[12],upper_modadd_4_7[11],upper_modadd_4_7[10],upper_modadd_4_7[9],upper_modadd_4_7[8],upper_modadd_4_7[7],upper_modadd_4_7[6],upper_modadd_4_7[5],upper_modadd_4_7[4],upper_modadd_4_7[3],upper_modadd_4_7[2],upper_modadd_4_7[1],upper_modadd_4_7[0]]), 12, 24) = true;

constraint ubct_compute(array1d(0..24-1, [pre_upper_modadd_4_7_0[0],pre_upper_modadd_4_7_0[1],pre_upper_modadd_4_7_0[2],pre_upper_modadd_4_7_0[3],pre_upper_modadd_4_7_0[4],pre_upper_modadd_4_7_0[5],pre_upper_modadd_4_7_0[6],pre_upper_modadd_4_7_0[7],pre_upper_modadd_4_7_0[8],pre_upper_modadd_4_7_0[9],pre_upper_modadd_4_7_0[10],pre_upper_modadd_4_7_0[11],pre_upper_modadd_4_7_0[12],pre_upper_modadd_4_7_0[13],pre_upper_modadd_4_7_0[14],pre_upper_modadd_4_7_0[15],pre_upper_modadd_4_7_0[16],pre_upper_modadd_4_7_0[17],pre_upper_modadd_4_7_0[18],pre_upper_modadd_4_7_0[19],pre_upper_modadd_4_7_0[20],pre_upper_modadd_4_7_0[21],pre_upper_modadd_4_7_0[22],pre_upper_modadd_4_7_0[23]]), array1d(0..24-1, [pre_upper_modadd_4_7_1[0],pre_upper_modadd_4_7_1[1],pre_upper_modadd_4_7_1[2],pre_upper_modadd_4_7_1[3],pre_upper_modadd_4_7_1[4],pre_upper_modadd_4_7_1[5],pre_upper_modadd_4_7_1[6],pre_upper_modadd_4_7_1[7],pre_upper_modadd_4_7_1[8],pre_upper_modadd_4_7_1[9],pre_upper_modadd_4_7_1[10],pre_upper_modadd_4_7_1[11],pre_upper_modadd_4_7_1[12],pre_upper_modadd_4_7_1[13],pre_upper_modadd_4_7_1[14],pre_upper_modadd_4_7_1[15],pre_upper_modadd_4_7_1[16],pre_upper_modadd_4_7_1[17],pre_upper_modadd_4_7_1[18],pre_upper_modadd_4_7_1[19],pre_upper_modadd_4_7_1[20],pre_upper_modadd_4_7_1[21],pre_upper_modadd_4_7_1[22],pre_upper_modadd_4_7_1[23]]), array1d(0..24-1, [pre_lower_modadd_4_7_0[0],pre_lower_modadd_4_7_0[1],pre_lower_modadd_4_7_0[2],pre_lower_modadd_4_7_0[3],pre_lower_modadd_4_7_0[4],pre_lower_modadd_4_7_0[5],pre_lower_modadd_4_7_0[6],pre_lower_modadd_4_7_0[7],pre_lower_modadd_4_7_0[8],pre_lower_modadd_4_7_0[9],pre_lower_modadd_4_7_0[10],pre_lower_modadd_4_7_0[11],pre_lower_modadd_4_7_0[12],pre_lower_modadd_4_7_0[13],pre_lower_modadd_4_7_0[14],pre_lower_modadd_4_7_0[15],pre_lower_modadd_4_7_0[16],pre_lower_modadd_4_7_0[17],pre_lower_modadd_4_7_0[18],pre_lower_modadd_4_7_0[19],pre_lower_modadd_4_7_0[20],pre_lower_modadd_4_7_0[21],pre_lower_modadd_4_7_0[22],pre_lower_modadd_4_7_0[23]]), array1d(0..24-1, [pre_lower_modadd_4_7_1[0],pre_lower_modadd_4_7_1[1],pre_lower_modadd_4_7_1[2],pre_lower_modadd_4_7_1[3],pre_lower_modadd_4_7_1[4],pre_lower_modadd_4_7_1[5],pre_lower_modadd_4_7_1[6],pre_lower_modadd_4_7_1[7],pre_lower_modadd_4_7_1[8],pre_lower_modadd_4_7_1[9],pre_lower_modadd_4_7_1[10],pre_lower_modadd_4_7_1[11],pre_lower_modadd_4_7_1[12],pre_lower_modadd_4_7_1[13],pre_lower_modadd_4_7_1[14],pre_lower_modadd_4_7_1[15],pre_lower_modadd_4_7_1[16],pre_lower_modadd_4_7_1[17],pre_lower_modadd_4_7_1[18],pre_lower_modadd_4_7_1[19],pre_lower_modadd_4_7_1[20],pre_lower_modadd_4_7_1[21],pre_lower_modadd_4_7_1[22],pre_lower_modadd_4_7_1[23]]), array1d(0..24-1, [upper_modadd_4_7[0],upper_modadd_4_7[1],upper_modadd_4_7[2],upper_modadd_4_7[3],upper_modadd_4_7[4],upper_modadd_4_7[5],upper_modadd_4_7[6],upper_modadd_4_7[7],upper_modadd_4_7[8],upper_modadd_4_7[9],upper_modadd_4_7[10],upper_modadd_4_7[11],upper_modadd_4_7[12],upper_modadd_4_7[13],upper_modadd_4_7[14],upper_modadd_4_7[15],upper_modadd_4_7[16],upper_modadd_4_7[17],upper_modadd_4_7[18],upper_modadd_4_7[19],upper_modadd_4_7[20],upper_modadd_4_7[21],upper_modadd_4_7[22],upper_modadd_4_7[23]]), 24, middle_p[0]);

constraint onlyLargeSwitch_LBCT_enum(array1d(0..24-1, [pre_upper_modadd_5_7_0[23],pre_upper_modadd_5_7_0[22],pre_upper_modadd_5_7_0[21],pre_upper_modadd_5_7_0[20],pre_upper_modadd_5_7_0[19],pre_upper_modadd_5_7_0[18],pre_upper_modadd_5_7_0[17],pre_upper_modadd_5_7_0[16],pre_upper_modadd_5_7_0[15],pre_upper_modadd_5_7_0[14],pre_upper_modadd_5_7_0[13],pre_upper_modadd_5_7_0[12],pre_upper_modadd_5_7_0[11],pre_upper_modadd_5_7_0[10],pre_upper_modadd_5_7_0[9],pre_upper_modadd_5_7_0[8],pre_upper_modadd_5_7_0[7],pre_upper_modadd_5_7_0[6],pre_upper_modadd_5_7_0[5],pre_upper_modadd_5_7_0[4],pre_upper_modadd_5_7_0[3],pre_upper_modadd_5_7_0[2],pre_upper_modadd_5_7_0[1],pre_upper_modadd_5_7_0[0]]), array1d(0..24-1, [pre_upper_modadd_5_7_1[23],pre_upper_modadd_5_7_1[22],pre_upper_modadd_5_7_1[21],pre_upper_modadd_5_7_1[20],pre_upper_modadd_5_7_1[19],pre_upper_modadd_5_7_1[18],pre_upper_modadd_5_7_1[17],pre_upper_modadd_5_7_1[16],pre_upper_modadd_5_7_1[15],pre_upper_modadd_5_7_1[14],pre_upper_modadd_5_7_1[13],pre_upper_modadd_5_7_1[12],pre_upper_modadd_5_7_1[11],pre_upper_modadd_5_7_1[10],pre_upper_modadd_5_7_1[9],pre_upper_modadd_5_7_1[8],pre_upper_modadd_5_7_1[7],pre_upper_modadd_5_7_1[6],pre_upper_modadd_5_7_1[5],pre_upper_modadd_5_7_1[4],pre_upper_modadd_5_7_1[3],pre_upper_modadd_5_7_1[2],pre_upper_modadd_5_7_1[1],pre_upper_modadd_5_7_1[0]]), array1d(0..24-1, [pre_lower_modadd_5_7_0[23],pre_lower_modadd_5_7_0[22],pre_lower_modadd_5_7_0[21],pre_lower_modadd_5_7_0[20],pre_lower_modadd_5_7_0[19],pre_lower_modadd_5_7_0[18],pre_lower_modadd_5_7_0[17],pre_lower_modadd_5_7_0[16],pre_lower_modadd_5_7_0[15],pre_lower_modadd_5_7_0[14],pre_lower_modadd_5_7_0[13],pre_lower_modadd_5_7_0[12],pre_lower_modadd_5_7_0[11],pre_lower_modadd_5_7_0[10],pre_lower_modadd_5_7_0[9],pre_lower_modadd_5_7_0[8],pre_lower_modadd_5_7_0[7],pre_lower_modadd_5_7_0[6],pre_lower_modadd_5_7_0[5],pre_lower_modadd_5_7_0[4],pre_lower_modadd_5_7_0[3],pre_lower_modadd_5_7_0[2],pre_lower_modadd_5_7_0[1],pre_lower_modadd_5_7_0[0]]), array1d(0..24-1, [pre_lower_modadd_5_7_1[23],pre_lower_modadd_5_7_1[22],pre_lower_modadd_5_7_1[21],pre_lower_modadd_5_7_1[20],pre_lower_modadd_5_7_1[19],pre_lower_modadd_5_7_1[18],pre_lower_modadd_5_7_1[17],pre_lower_modadd_5_7_1[16],pre_lower_modadd_5_7_1[15],pre_lower_modadd_5_7_1[14],pre_lower_modadd_5_7_1[13],pre_lower_modadd_5_7_1[12],pre_lower_modadd_5_7_1[11],pre_lower_modadd_5_7_1[10],pre_lower_modadd_5_7_1[9],pre_lower_modadd_5_7_1[8],pre_lower_modadd_5_7_1[7],pre_lower_modadd_5_7_1[6],pre_lower_modadd_5_7_1[5],pre_lower_modadd_5_7_1[4],pre_lower_modadd_5_7_1[3],pre_lower_modadd_5_7_1[2],pre_lower_modadd_5_7_1[1],pre_lower_modadd_5_7_1[0]]), array1d(0..24-1, [lower_modadd_5_7[23],lower_modadd_5_7[22],lower_modadd_5_7[21],lower_modadd_5_7[20],lower_modadd_5_7[19],lower_modadd_5_7[18],lower_modadd_5_7[17],lower_modadd_5_7[16],lower_modadd_5_7[15],lower_modadd_5_7[14],lower_modadd_5_7[13],lower_modadd_5_7[12],lower_modadd_5_7[11],lower_modadd_5_7[10],lower_modadd_5_7[9],lower_modadd_5_7[8],lower_modadd_5_7[7],lower_modadd_5_7[6],lower_modadd_5_7[5],lower_modadd_5_7[4],lower_modadd_5_7[3],lower_modadd_5_7[2],lower_modadd_5_7[1],lower_modadd_5_7[0]]), 12, 24) = true;

constraint lbct_compute(array1d(0..24-1, [pre_upper_modadd_5_7_0[0],pre_upper_modadd_5_7_0[1],pre_upper_modadd_5_7_0[2],pre_upper_modadd_5_7_0[3],pre_upper_modadd_5_7_0[4],pre_upper_modadd_5_7_0[5],pre_upper_modadd_5_7_0[6],pre_upper_modadd_5_7_0[7],pre_upper_modadd_5_7_0[8],pre_upper_modadd_5_7_0[9],pre_upper_modadd_5_7_0[10],pre_upper_modadd_5_7_0[11],pre_upper_modadd_5_7_0[12],pre_upper_modadd_5_7_0[13],pre_upper_modadd_5_7_0[14],pre_upper_modadd_5_7_0[15],pre_upper_modadd_5_7_0[16],pre_upper_modadd_5_7_0[17],pre_upper_modadd_5_7_0[18],pre_upper_modadd_5_7_0[19],pre_upper_modadd_5_7_0[20],pre_upper_modadd_5_7_0[21],pre_upper_modadd_5_7_0[22],pre_upper_modadd_5_7_0[23]]), array1d(0..24-1, [pre_upper_modadd_5_7_1[0],pre_upper_modadd_5_7_1[1],pre_upper_modadd_5_7_1[2],pre_upper_modadd_5_7_1[3],pre_upper_modadd_5_7_1[4],pre_upper_modadd_5_7_1[5],pre_upper_modadd_5_7_1[6],pre_upper_modadd_5_7_1[7],pre_upper_modadd_5_7_1[8],pre_upper_modadd_5_7_1[9],pre_upper_modadd_5_7_1[10],pre_upper_modadd_5_7_1[11],pre_upper_modadd_5_7_1[12],pre_upper_modadd_5_7_1[13],pre_upper_modadd_5_7_1[14],pre_upper_modadd_5_7_1[15],pre_upper_modadd_5_7_1[16],pre_upper_modadd_5_7_1[17],pre_upper_modadd_5_7_1[18],pre_upper_modadd_5_7_1[19],pre_upper_modadd_5_7_1[20],pre_upper_modadd_5_7_1[21],pre_upper_modadd_5_7_1[22],pre_upper_modadd_5_7_1[23]]), array1d(0..24-1, [pre_lower_modadd_5_7_0[0],pre_lower_modadd_5_7_0[1],pre_lower_modadd_5_7_0[2],pre_lower_modadd_5_7_0[3],pre_lower_modadd_5_7_0[4],pre_lower_modadd_5_7_0[5],pre_lower_modadd_5_7_0[6],pre_lower_modadd_5_7_0[7],pre_lower_modadd_5_7_0[8],pre_lower_modadd_5_7_0[9],pre_lower_modadd_5_7_0[10],pre_lower_modadd_5_7_0[11],pre_lower_modadd_5_7_0[12],pre_lower_modadd_5_7_0[13],pre_lower_modadd_5_7_0[14],pre_lower_modadd_5_7_0[15],pre_lower_modadd_5_7_0[16],pre_lower_modadd_5_7_0[17],pre_lower_modadd_5_7_0[18],pre_lower_modadd_5_7_0[19],pre_lower_modadd_5_7_0[20],pre_lower_modadd_5_7_0[21],pre_lower_modadd_5_7_0[22],pre_lower_modadd_5_7_0[23]]), array1d(0..24-1, [pre_lower_modadd_5_7_1[0],pre_lower_modadd_5_7_1[1],pre_lower_modadd_5_7_1[2],pre_lower_modadd_5_7_1[3],pre_lower_modadd_5_7_1[4],pre_lower_modadd_5_7_1[5],pre_lower_modadd_5_7_1[6],pre_lower_modadd_5_7_1[7],pre_lower_modadd_5_7_1[8],pre_lower_modadd_5_7_1[9],pre_lower_modadd_5_7_1[10],pre_lower_modadd_5_7_1[11],pre_lower_modadd_5_7_1[12],pre_lower_modadd_5_7_1[13],pre_lower_modadd_5_7_1[14],pre_lower_modadd_5_7_1[15],pre_lower_modadd_5_7_1[16],pre_lower_modadd_5_7_1[17],pre_lower_modadd_5_7_1[18],pre_lower_modadd_5_7_1[19],pre_lower_modadd_5_7_1[20],pre_lower_modadd_5_7_1[21],pre_lower_modadd_5_7_1[22],pre_lower_modadd_5_7_1[23]]), array1d(0..24-1, [lower_modadd_5_7[0],lower_modadd_5_7[1],lower_modadd_5_7[2],lower_modadd_5_7[3],lower_modadd_5_7[4],lower_modadd_5_7[5],lower_modadd_5_7[6],lower_modadd_5_7[7],lower_modadd_5_7[8],lower_modadd_5_7[9],lower_modadd_5_7[10],lower_modadd_5_7[11],lower_modadd_5_7[12],lower_modadd_5_7[13],lower_modadd_5_7[14],lower_modadd_5_7[15],lower_modadd_5_7[16],lower_modadd_5_7[17],lower_modadd_5_7[18],lower_modadd_5_7[19],lower_modadd_5_7[20],lower_modadd_5_7[21],lower_modadd_5_7[22],lower_modadd_5_7[23]]), 24, middle_p[1]);

array[0..47] of var 0..1: upper_plaintext;
array[0..71] of var 0..1: upper_key;
array[0..23] of var 0..1: upper_xor_1_5;
array[0..23] of var 0..1: upper_xor_2_5;
array[0..23] of var 0..1: upper_xor_3_5;
array[0..23] of var 0..1: upper_xor_4_5;
array[0..23] of var 0..1: upper_xor_5_5;
array[0..47] of var 0..1: lower_cipher_output_10_12;
array[0..71] of var 0..1: lower_key;
array[0..23] of var 0..1: lower_xor_10_5;
array[0..23] of var 0..1: lower_xor_9_5;
array[0..23] of var 0..1: lower_xor_8_5;
array[0..23] of var 0..1: lower_xor_7_5;
array[0..23] of var 0..1: lower_xor_6_5;
array[0..23] of var 0..1: lower_xor_5_5;
array[0..23] of var 0..1: lower_xor_4_5;
array[0..23] of var 0..1: upper_rot_0_0;
array[0..23] of var 0..1: upper_modadd_0_1;
array[0..23] of var 0..1: upper_xor_0_2;
array[0..23] of var 0..1: upper_rot_0_3;
array[0..23] of var 0..1: upper_xor_0_4;
array[0..47] of var 0..1: upper_intermediate_output_0_6;
array[0..23] of var 0..1: upper_rot_1_6;
array[0..23] of var 0..1: upper_modadd_1_7;
array[0..23] of var 0..1: upper_xor_1_8;
array[0..23] of var 0..1: upper_rot_1_9;
array[0..23] of var 0..1: upper_xor_1_10;
array[0..47] of var 0..1: upper_intermediate_output_1_12;
array[0..23] of var 0..1: upper_rot_2_6;
array[0..23] of var 0..1: upper_modadd_2_7;
array[0..23] of var 0..1: upper_xor_2_8;
array[0..23] of var 0..1: upper_rot_2_9;
array[0..23] of var 0..1: upper_xor_2_10;
array[0..47] of var 0..1: upper_intermediate_output_2_12;
array[0..23] of var 0..1: upper_rot_3_6;
array[0..23] of var 0..1: upper_modadd_3_7;
array[0..23] of var 0..1: upper_xor_3_8;
array[0..23] of var 0..1: upper_rot_3_9;
array[0..23] of var 0..1: upper_xor_3_10;
array[0..47] of var 0..1: upper_intermediate_output_3_12;
array[0..23] of var 0..1: upper_rot_4_6;
array[0..23] of var 0..1: upper_modadd_4_7;
array[0..23] of var 0..1: upper_xor_4_8;
array[0..23] of var 0..1: upper_rot_4_9;
array[0..23] of var 0..1: upper_xor_4_10;
array[0..47] of var 0..1: upper_intermediate_output_4_12;
array[0..23] of var 0..1: lower_xor_4_8;
array[0..23] of var 0..1: lower_xor_4_10;
array[0..47] of var 0..1: lower_intermediate_output_4_12;
array[0..23] of var 0..1: lower_rot_4_9;
array[0..23] of var 0..1: lower_modadd_4_7;
array[0..23] of var 0..1: lower_rot_4_6;
array[0..23] of var 0..1: upper_rot_5_6;
array[0..23] of var 0..1: upper_modadd_5_7;
array[0..23] of var 0..1: upper_xor_5_8;
array[0..23] of var 0..1: upper_rot_5_9;
array[0..23] of var 0..1: upper_xor_5_10;
array[0..47] of var 0..1: upper_intermediate_output_5_12;
array[0..23] of var 0..1: lower_xor_5_8;
array[0..23] of var 0..1: lower_xor_5_10;
array[0..47] of var 0..1: lower_intermediate_output_5_12;
array[0..23] of var 0..1: lower_rot_5_9;
array[0..23] of var 0..1: lower_modadd_5_7;
array[0..23] of var 0..1: lower_rot_5_6;
array[0..23] of var 0..1: lower_xor_6_8;
array[0..23] of var 0..1: lower_xor_6_10;
array[0..47] of var 0..1: lower_intermediate_output_6_12;
array[0..23] of var 0..1: lower_rot_6_9;
array[0..23] of var 0..1: lower_modadd_6_7;
array[0..23] of var 0..1: lower_rot_6_6;
array[0..23] of var 0..1: lower_xor_7_8;
array[0..23] of var 0..1: lower_xor_7_10;
array[0..47] of var 0..1: lower_intermediate_output_7_12;
array[0..23] of var 0..1: lower_rot_7_9;
array[0..23] of var 0..1: lower_modadd_7_7;
array[0..23] of var 0..1: lower_rot_7_6;
array[0..23] of var 0..1: lower_xor_8_8;
array[0..23] of var 0..1: lower_xor_8_10;
array[0..47] of var 0..1: lower_intermediate_output_8_12;
array[0..23] of var 0..1: lower_rot_8_9;
array[0..23] of var 0..1: lower_modadd_8_7;
array[0..23] of var 0..1: lower_rot_8_6;
array[0..23] of var 0..1: lower_xor_9_8;
array[0..23] of var 0..1: lower_xor_9_10;
array[0..47] of var 0..1: lower_intermediate_output_9_12;
array[0..23] of var 0..1: lower_rot_9_9;
array[0..23] of var 0..1: lower_modadd_9_7;
array[0..23] of var 0..1: lower_rot_9_6;
array[0..23] of var 0..1: lower_xor_10_8;
array[0..23] of var 0..1: lower_xor_10_10;
array[0..23] of var 0..1: lower_rot_10_9;
array[0..23] of var 0..1: lower_modadd_10_7;
array[0..23] of var 0..1: lower_rot_10_6;
array[0..11-1] of var int: p;
array[0..6-1] of var {0, 900, 1800, 400, 1300, 2200, 800, 1700, 300, 1200, 2100, 700, 1600, 200, 1100, 2000, 600, 1500, 100, 1000, 1900, 500, 1400, 2300}: upper_p;
constraint p[0] = upper_p[0];
constraint p[1] = upper_p[1];
constraint p[2] = upper_p[2];
constraint p[3] = upper_p[3];
var int: upper_weight = upper_p[0] + upper_p[1] + upper_p[2] + upper_p[3];
array[0..7-1] of var {0, 900, 1800, 400, 1300, 2200, 800, 1700, 300, 1200, 2100, 700, 1600, 200, 1100, 2000, 600, 1500, 100, 1000, 1900, 500, 1400, 2300}: lower_p;
constraint p[4] = lower_p[2];
constraint p[5] = lower_p[3];
constraint p[6] = lower_p[4];
constraint p[7] = lower_p[5];
constraint p[8] = lower_p[6];
var int: lower_weight = lower_p[2] + lower_p[3] + lower_p[4] + lower_p[5] + lower_p[6];
array[0..2-1] of var 0..3200: middle_p;
var int: middle_weight = sum(middle_p);
constraint p[9] = middle_p[0];
constraint p[10] = middle_p[1];
var int: weight = (2 * upper_weight) + (2 * lower_weight) + middle_weight;
constraint sum(upper_key) = 0;
constraint sum(upper_xor_1_5) = 0;
constraint sum(upper_xor_2_5) = 0;
constraint sum(upper_xor_3_5) = 0;
constraint sum(upper_xor_4_5) = 0;
constraint sum(upper_xor_5_5) = 0;
constraint sum(lower_key) = 0;
constraint sum(lower_xor_10_5) = 0;
constraint sum(lower_xor_9_5) = 0;
constraint sum(lower_xor_8_5) = 0;
constraint sum(lower_xor_7_5) = 0;
constraint sum(lower_xor_6_5) = 0;
constraint sum(lower_xor_5_5) = 0;
constraint sum(lower_xor_4_5) = 0;
solve:: int_search(p, smallest, indomain_min, complete) minimize weight;
output["upper_plaintext = "++ show(upper_plaintext) ++ "\n" ++"upper_key = "++ show(upper_key) ++ "\n" ++"upper_xor_1_5 = "++ show(upper_xor_1_5) ++ "\n" ++"upper_xor_2_5 = "++ show(upper_xor_2_5) ++ "\n" ++"upper_xor_3_5 = "++ show(upper_xor_3_5) ++ "\n" ++"upper_xor_4_5 = "++ show(upper_xor_4_5) ++ "\n" ++"upper_xor_5_5 = "++ show(upper_xor_5_5) ++ "\n" ++"lower_cipher_output_10_12 = "++ show(lower_cipher_output_10_12) ++ "\n" ++"lower_key = "++ show(lower_key) ++ "\n" ++"lower_xor_10_5 = "++ show(lower_xor_10_5) ++ "\n" ++"lower_xor_9_5 = "++ show(lower_xor_9_5) ++ "\n" ++"lower_xor_8_5 = "++ show(lower_xor_8_5) ++ "\n" ++"lower_xor_7_5 = "++ show(lower_xor_7_5) ++ "\n" ++"lower_xor_6_5 = "++ show(lower_xor_6_5) ++ "\n" ++"lower_xor_5_5 = "++ show(lower_xor_5_5) ++ "\n" ++"lower_xor_4_5 = "++ show(lower_xor_4_5) ++ "\n" ++"upper_rot_0_0 = "++ show(upper_rot_0_0)++ "\n" ++"upper_modadd_0_1 = "++ show(upper_modadd_0_1)++ "\n" ++ "upper probability = "++ show(upper_p[0]/100) ++ "\n" ++"upper_xor_0_2 = "++ show(upper_xor_0_2)++ "\n" ++"upper_rot_0_3 = "++ show(upper_rot_0_3)++ "\n" ++"upper_xor_0_4 = "++ show(upper_xor_0_4)++ "\n" ++"upper_intermediate_output_0_6 = "++ show(upper_intermediate_output_0_6)++ "\n" ++"upper_rot_1_6 = "++ show(upper_rot_1_6)++ "\n" ++"upper_modadd_1_7 = "++ show(upper_modadd_1_7)++ "\n" ++ "upper probability = "++ show(upper_p[1]/100) ++ "\n" ++"upper_xor_1_8 = "++ show(upper_xor_1_8)++ "\n" ++"upper_rot_1_9 = "++ show(upper_rot_1_9)++ "\n" ++"upper_xor_1_10 = "++ show(upper_xor_1_10)++ "\n" ++"upper_intermediate_output_1_12 = "++ show(upper_intermediate_output_1_12)++ "\n" ++"upper_rot_2_6 = "++ show(upper_rot_2_6)++ "\n" ++"upper_modadd_2_7 = "++ show(upper_modadd_2_7)++ "\n" ++ "upper probability = "++ show(upper_p[2]/100) ++ "\n" ++"upper_xor_2_8 = "++ show(upper_xor_2_8)++ "\n" ++"upper_rot_2_9 = "++ show(upper_rot_2_9)++ "\n" ++"upper_xor_2_10 = "++ show(upper_xor_2_10)++ "\n" ++"upper_intermediate_output_2_12 = "++ show(upper_intermediate_output_2_12)++ "\n" ++"upper_rot_3_6 = "++ show(upper_rot_3_6)++ "\n" ++"upper_modadd_3_7 = "++ show(upper_modadd_3_7)++ "\n" ++ "upper probability = "++ show(upper_p[3]/100) ++ "\n" ++"upper_xor_3_8 = "++ show(upper_xor_3_8)++ "\n" ++"upper_rot_3_9 = "++ show(upper_rot_3_9)++ "\n" ++"upper_xor_3_10 = "++ show(upper_xor_3_10)++ "\n" ++"upper_intermediate_output_3_12 = "++ show(upper_intermediate_output_3_12)++ "\n" ++"upper_rot_4_6 = "++ show(upper_rot_4_6)++ "\n" ++"upper_modadd_4_7 = "++ show(upper_modadd_4_7)++ "\n" ++ "middle probability = "++ show(middle_p[0]/100) ++ "\n" ++"upper_xor_4_8 = "++ show(upper_xor_4_8)++ "\n" ++"upper_rot_4_9 = "++ show(upper_rot_4_9)++ "\n" ++"upper_xor_4_10 = "++ show(upper_xor_4_10)++ "\n" ++"upper_intermediate_output_4_12 = "++ show(upper_intermediate_output_4_12)++ "\n" ++"lower_xor_4_8 = "++ show(lower_xor_4_8)++ "\n" ++"lower_xor_4_10 = "++ show(lower_xor_4_10)++ "\n" ++"lower_intermediate_output_4_12 = "++ show(lower_intermediate_output_4_12)++ "\n" ++"lower_rot_4_9 = "++ show(lower_rot_4_9)++ "\n" ++"lower_modadd_4_7 = "++ show(lower_modadd_4_7)++ "\n" ++ "lower_rot_4_6 = "++ show(lower_rot_4_6)++ "\n" ++"upper_rot_5_6 = "++ show(upper_rot_5_6)++ "\n" ++"upper_modadd_5_7 = "++ show(upper_modadd_5_7)++ "\n" ++ "middle probability = "++ show(middle_p[1]/100) ++ "\n" ++"upper_xor_5_8 = "++ show(upper_xor_5_8)++ "\n" ++"upper_rot_5_9 = "++ show(upper_rot_5_9)++ "\n" ++"upper_xor_5_10 = "++ show(upper_xor_5_10)++ "\n" ++"upper_intermediate_output_5_12 = "++ show(upper_intermediate_output_5_12)++ "\n" ++"lower_xor_5_8 = "++ show(lower_xor_5_8)++ "\n" ++"lower_xor_5_10 = "++ show(lower_xor_5_10)++ "\n" ++"lower_intermediate_output_5_12 = "++ show(lower_intermediate_output_5_12)++ "\n" ++"lower_rot_5_9 = "++ show(lower_rot_5_9)++ "\n" ++"lower_modadd_5_7 = "++ show(lower_modadd_5_7)++ "\n" ++ "lower_rot_5_6 = "++ show(lower_rot_5_6)++ "\n" ++"lower_xor_6_8 = "++ show(lower_xor_6_8)++ "\n" ++"lower_xor_6_10 = "++ show(lower_xor_6_10)++ "\n" ++"lower_intermediate_output_6_12 = "++ show(lower_intermediate_output_6_12)++ "\n" ++"lower_rot_6_9 = "++ show(lower_rot_6_9)++ "\n" ++"lower_modadd_6_7 = "++ show(lower_modadd_6_7)++ "\n" ++ "lower probability = "++ show(lower_p[2]/100) ++ "\n" ++"lower_rot_6_6 = "++ show(lower_rot_6_6)++ "\n" ++"lower_xor_7_8 = "++ show(lower_xor_7_8)++ "\n" ++"lower_xor_7_10 = "++ show(lower_xor_7_10)++ "\n" ++"lower_intermediate_output_7_12 = "++ show(lower_intermediate_output_7_12)++ "\n" ++"lower_rot_7_9 = "++ show(lower_rot_7_9)++ "\n" ++"lower_modadd_7_7 = "++ show(lower_modadd_7_7)++ "\n" ++ "lower probability = "++ show(lower_p[3]/100) ++ "\n" ++"lower_rot_7_6 = "++ show(lower_rot_7_6)++ "\n" ++"lower_xor_8_8 = "++ show(lower_xor_8_8)++ "\n" ++"lower_xor_8_10 = "++ show(lower_xor_8_10)++ "\n" ++"lower_intermediate_output_8_12 = "++ show(lower_intermediate_output_8_12)++ "\n" ++"lower_rot_8_9 = "++ show(lower_rot_8_9)++ "\n" ++"lower_modadd_8_7 = "++ show(lower_modadd_8_7)++ "\n" ++ "lower probability = "++ show(lower_p[4]/100) ++ "\n" ++"lower_rot_8_6 = "++ show(lower_rot_8_6)++ "\n" ++"lower_xor_9_8 = "++ show(lower_xor_9_8)++ "\n" ++"lower_xor_9_10 = "++ show(lower_xor_9_10)++ "\n" ++"lower_intermediate_output_9_12 = "++ show(lower_intermediate_output_9_12)++ "\n" ++"lower_rot_9_9 = "++ show(lower_rot_9_9)++ "\n" ++"lower_modadd_9_7 = "++ show(lower_modadd_9_7)++ "\n" ++ "lower probability = "++ show(lower_p[5]/100) ++ "\n" ++"lower_rot_9_6 = "++ show(lower_rot_9_6)++ "\n" ++"lower_xor_10_8 = "++ show(lower_xor_10_8)++ "\n" ++"lower_xor_10_10 = "++ show(lower_xor_10_10)++ "\n" ++"lower_rot_10_9 = "++ show(lower_rot_10_9)++ "\n" ++"lower_modadd_10_7 = "++ show(lower_modadd_10_7)++ "\n" ++ "lower probability = "++ show(lower_p[6]/100) ++ "\n" ++"lower_rot_10_6 = "++ show(lower_rot_10_6)++ "\n" ++"Upper weight = " ++ show(upper_weight/100) ++ "\n" ++"Lower weight = " ++ show(lower_weight/100) ++ "\n" ++"Middle weight = " ++ show(middle_weight/100) ++ "\n" ++"Trail weight = " ++ show(weight/100)  ];

    include "table.mzn";
    int: num_workers_lbct = 8;
    int: num_rows_lbct = 32;
    int: num_cols_last_table_lbct = 11;
    int: num_cols_lbct = 15;
    array[0..num_cols_lbct-1] of var 0..1: b_lbct;
    array[0..num_workers_lbct-1,0..num_rows_lbct-1,0..num_cols_lbct-1] of 0..1: lbct_table =
         array3d(0..num_workers_lbct-1,0..num_rows_lbct-1,0..num_cols_lbct-1,
      [
         0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
         0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
         1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
         0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
         1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
         1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
         1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
         0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
         1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
         0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1,
         1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1,
         0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1,
         1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1,
         0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
         1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0,
         0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
         1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
         0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0,
         0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
         1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
         0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
         1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
         0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
         1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
         1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
         0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
         1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0,
         0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0,
         0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1,
         1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0,
         0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1,
         1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0,
         0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
         1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1,
         0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
         1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1,
         0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
         1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
         0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
         1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
         0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
         0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
         0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
         1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
         0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
         1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0,
         1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0,
         1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0,
         1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1,
         0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0,
         1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1,
         0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1,
         1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1,
         0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1,
         1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1,
         0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
         1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
         0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
         1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
         0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
         0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
         0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
         1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
         0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
         1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
         0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1,
         1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
         0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1,
         1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
         0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0,
         1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
         0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0,
         1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
         0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0,
         1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0,
         1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
     
    ]);
    
    array[0..7,0..num_cols_last_table_lbct-1] of 0..1: last_table_lbct =
         array2d(0..7,0..num_cols_last_table_lbct-1,
      [
        0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0,
        0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1,
        1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1
      
      ]);
    
    
    predicate onlyLargeSwitch_LBCT_enum(
      array[int] of var 0..1: dL,
      array[int] of var 0..1:dR,
      array[int] of var 0..1: nL,
      array[int] of var 0..1:nR,
      array[int] of var 0..1:nLL,
      int: halfNum,
      int: branchSize,
    ) = 
        let {
            array[0..branchSize - 1, 0..7] of var bool: dp ,
            array[0..branchSize - 2] of var bool: isHalf ;
            array[0..branchSize-2, 0..63] of var bool: matrix;
            array[0..branchSize-2, 0..7] of var bool: halfSize0;
            array[0..branchSize-2, 0..7] of var bool: halfSize1;
            array[0..branchSize-2] of var bool: ifEnforced;
            array[0..branchSize-2, 0..7] of var bool: enforcedLiterals;
            array[0..branchSize-2, 0..63] of var bool: literals;
            array[0..7] of var bool: lastLiterals;
            array[0..10] of var bool: isValid;
        } in
        (sum(isHalf) <= halfNum) /\
        (dp[0, 0] == true) /\
        (dp[0, 1] == false) /\
        (dp[0, 2] == false) /\
        (dp[0, 3] == false) /\
        (dp[0, 4] == false) /\
        (dp[0, 5] == false) /\
        (dp[0, 6] == false) /\
        (dp[0, 7] == false) /\
        forall(i in 0..branchSize-2) (
            forall(cn in 0..7) (
                 let {
                    array[0..14] of var 0..1: column = array1d(0..14, [dL[i], dR[i], nL[i], nR[i], nLL[i], matrix[i, 0*8+cn], matrix[i, 1*8+cn], matrix[i, 2*8+cn], matrix[i, 3*8+cn], matrix[i, 4*8+cn], matrix[i, 5*8+cn], matrix[i, 6*8+cn], matrix[i, 7*8+cn], halfSize0[i, cn], halfSize1[i, cn]])
                } in
                BVAssign_lbct(column, cn)
            ) /\
            (
                dp[i + 1, 0] \/ dp[i + 1, 1] \/ dp[i + 1, 2] \/ dp[i + 1, 3] \/ dp[i + 1, 4] \/ dp[i + 1, 5] \/ dp[i + 1, 6] \/ dp[i + 1, 7]
            ) /\
            (ifEnforced[i] == not(isHalf[i])) /\
            forall(j in 0..7) (
                (not(ifEnforced[i]) \/ not(dp[i,j]) \/ matrix[i, j*8+j]) /\
                (not(ifEnforced[i]) \/ not(dp[i,j]) \/ dp[i+1,j]) /\
                sum([not(ifEnforced[i]), not(dp[i,j]), matrix[i, j * 8 + j]]) >= 1 /\
                sum([not(ifEnforced[i]), not(dp[i,j]), dp[i + 1,j]]) >= 1
            ) /\
            forall(j in 0..7) (
                (enforcedLiterals[i,j] -> (not(matrix[i,j * 8 + j]) /\ dp[i,j])) /\
                (not(enforcedLiterals[i,j]) -> (matrix[i,j * 8 + j] \/ not(dp[i,j])))
            ) /\ 
            (
                ifEnforced[i] \/ enforcedLiterals[i,0] \/ enforcedLiterals[i,1] \/ enforcedLiterals[i,2] \/ enforcedLiterals[i,3] \/ enforcedLiterals[i,4] \/ enforcedLiterals[i,5] \/ enforcedLiterals[i,6] \/ enforcedLiterals[i,7]
            ) /\
            forall(r in 0..7) (
                forall(cc in 0..7) (
                    (literals[i, r * 8 + cc] -> (matrix[i, r * 8 + cc] /\ dp[i, cc])) /\
                    (not(literals[i, r * 8 + cc]) -> (not(matrix[i,r * 8 + cc]) \/ not(dp[i,cc]))) /\
                    (matrix[i,r * 8 + cc] >=  literals[i,r * 8 + cc]) /\
                    (dp[i,cc] >=           literals[i,r * 8 + cc])  /\
                    sum([ literals[i, r * 8 + cc], true ]) >= sum([ matrix[i, r * 8 + cc], dp[i,cc] ])
                ) /\
                (
                    dp[i + 1,r] -> (literals[i,r * 8 + 0] \/ literals[i,r * 8 + 1] \/ literals[i,r * 8 + 2] \/ literals[i,r * 8 + 3] \/ literals[i,r * 8 + 4] \/ literals[i,r * 8 + 5] \/ literals[i,r * 8 + 6] \/ literals[i,r * 8 + 7])
                ) /\
                (
                    not(dp[i + 1,r]) -> (not(literals[i,r * 8 + 0]) /\ not(literals[i,r * 8 + 1]) /\ not(literals[i,r * 8 + 2]) /\ not(literals[i,r * 8 + 3]) /\ not(literals[i,r * 8 + 4]) /\ not(literals[i,r * 8 + 5]) /\ not(literals[i,r * 8 + 6]) /\ not(literals[i,r * 8 + 7]))
                ) /\
                forall(li in 0..7) (
                    dp[i + 1,r] >= literals[i, r * 8 + li] 
                ) /\
                (
                    sum([ literals[i,r * 8 + 0], literals[i,r * 8 + 1], literals[i,r * 8 + 2], literals[i,r * 8 + 3], literals[i,r * 8 + 4], literals[i,r * 8 + 5], literals[i,r * 8 + 6], literals[i,r * 8 + 7] ]) >= dp[i + 1,r]
                )
            )
        ) /\
        (
            isValid[0] == nL[branchSize - 1] /\
            isValid[1] == nR[branchSize - 1] /\
            isValid[2] == nLL[branchSize -1] 
        ) /\
            (BVAssign_last_table_lbct(isValid))
        /\
        forall(i in 0..7) (
            (
                lastLiterals[i] -> (dp[branchSize-1,i] /\ isValid[3 + i])
            ) /\
            (
                not(lastLiterals[i]) -> (not(dp[branchSize-1,i]) \/ not(isValid[3 + i]))
            )
        ) /\
        (
            lastLiterals[0] \/ lastLiterals[1] \/ lastLiterals[2] \/ lastLiterals[3] \/ lastLiterals[4] \/ lastLiterals[5] \/ lastLiterals[6] \/ lastLiterals[7]
        );         

        predicate BVAssign_lbct(array[0..num_cols_lbct-1] of var 0..1: column, int: index) =
        let {
            array[int] of set of int: indices = [index..index, 0..num_rows_lbct-1, 0..num_cols_lbct-1];
            array[int,int] of int: extractedFromTable = slice_2d(lbct_table, indices, 0..num_rows_lbct-1, 0..num_cols_lbct-1);
        } in
        table(column, extractedFromTable);

        predicate BVAssign_last_table_lbct(
            array[0..num_cols_last_table_lbct-1] of var bool: isValid
        ) =  table(isValid, last_table_lbct);  
    

    include "table.mzn";
    int: num_workers_ubct = 4;
    int: num_rows_ubct = 32;
    int: num_cols_last_table_ubct = 7;
    int: num_cols_ubct = 10;
    array[0..num_cols_ubct-1] of var 0..1: b_ubct;
    array[0..num_workers_ubct-1,0..num_rows_ubct-1,0..num_cols_ubct-1] of 0..1: ubct_table =
         array3d(0..num_workers_ubct-1,0..num_rows_ubct-1,0..num_cols_ubct-1,
      [
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 0, 0, 0, 1, 1, 0, 0, 1,
        0, 0, 1, 0, 0, 1, 0, 1, 0, 1,
        1, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 1, 0, 1, 0, 1,
        1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        1, 1, 0, 1, 0, 1, 0, 0, 1, 1,
        0, 0, 1, 1, 0, 1, 0, 1, 0, 1,
        1, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 1, 1, 1, 0, 0, 1,
        0, 1, 0, 0, 1, 1, 1, 0, 0, 1,
        1, 1, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 1, 0, 0, 0, 0, 0,
        1, 0, 1, 0, 1, 1, 0, 0, 1, 1,
        0, 1, 1, 0, 1, 0, 0, 0, 0, 0,
        1, 1, 1, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 1, 0, 0, 0, 0, 0,
        1, 0, 0, 1, 1, 0, 0, 0, 0, 0,
        0, 1, 0, 1, 1, 0, 0, 0, 0, 0,
        1, 1, 0, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 1, 0, 0, 0, 0, 0,
        1, 0, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
        1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 1, 1, 0, 0, 1,
        0, 1, 0, 0, 0, 1, 1, 0, 0, 1,
        1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 0, 0, 0, 1, 1, 0, 1,
        1, 1, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        1, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        1, 0, 1, 1, 0, 0, 1, 1, 0, 1,
        0, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 1, 1, 0, 0, 1,
        1, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 1, 0, 0, 0, 0, 0,
        1, 1, 0, 0, 1, 0, 1, 0, 0, 0,
        0, 0, 1, 0, 1, 0, 0, 0, 0, 0,
        1, 0, 1, 0, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 0, 1, 0, 0, 0, 0, 0,
        1, 1, 1, 0, 1, 0, 1, 0, 1, 1,
        0, 0, 0, 1, 1, 0, 1, 1, 0, 1,
        1, 0, 0, 1, 1, 0, 0, 0, 0, 0,
        0, 1, 0, 1, 1, 0, 0, 0, 0, 0,
        1, 1, 0, 1, 1, 0, 1, 0, 1, 1,
        0, 0, 1, 1, 1, 0, 0, 0, 0, 0,
        1, 0, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 0, 1, 0, 1, 1,
        0, 0, 0, 0, 0, 1, 0, 1, 0, 1,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 1, 0, 1, 0, 1,
        1, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 0, 0, 0, 1, 1, 0, 1,
        0, 0, 0, 1, 0, 1, 0, 1, 0, 1,
        1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        1, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 0, 0, 0, 1, 0, 0,
        1, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
        0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 1, 0, 1, 1, 0, 1,
        1, 1, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 1, 0, 0, 0, 0, 0,
        1, 0, 1, 0, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 0, 1, 0, 0, 0, 0, 0,
        1, 1, 1, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 1, 0, 0, 0, 0, 0,
        1, 0, 0, 1, 1, 0, 1, 1, 0, 1,
        0, 1, 0, 1, 1, 0, 0, 0, 0, 0,
        1, 1, 0, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 1, 0, 0, 0, 0, 0,
        1, 0, 1, 1, 1, 0, 0, 1, 1, 1,
        0, 1, 1, 1, 1, 0, 0, 1, 1, 1,
        1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 1, 0, 0, 1, 1,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 1, 0, 1, 0, 0, 1, 1,
        1, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        1, 0, 1, 1, 0, 0, 0, 1, 1, 1,
        0, 1, 1, 1, 0, 0, 0, 1, 1, 1,
        1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 1, 0, 0, 0, 0, 0,
        1, 1, 0, 0, 1, 0, 1, 0, 1, 1,
        0, 0, 1, 0, 1, 1, 0, 0, 1, 1,
        1, 0, 1, 0, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 0, 1, 0, 0, 0, 0, 0,
        1, 1, 1, 0, 1, 0, 1, 0, 1, 1,
        0, 0, 0, 1, 1, 0, 0, 0, 0, 0,
        1, 0, 0, 1, 1, 0, 0, 0, 0, 0,
        0, 1, 0, 1, 1, 0, 0, 0, 0, 0,
        1, 1, 0, 1, 1, 0, 1, 0, 1, 1,
        0, 0, 1, 1, 1, 0, 0, 1, 1, 1,
        1, 0, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 0, 0, 0, 1, 0
    ]);
    
    array[0..7,0..num_cols_last_table_ubct-1] of 0..1: last_table_ubct =
         array2d(0..7,0..num_cols_last_table_ubct-1,
      [
         0, 0, 0, 1, 0, 1, 0,
         1, 0, 0, 0, 1, 0, 1,
         0, 1, 0, 0, 1, 0, 1,
         1, 1, 0, 1, 0, 1, 0,
         0, 0, 1, 0, 1, 0, 1,
         1, 0, 1, 1, 0, 1, 0,
         0, 1, 1, 1, 0, 1, 0,
         1, 1, 1, 0, 1, 0, 1
      ]);
    
    
    predicate onlyLargeSwitch_UBCT_enum(
      array[int] of var 0..1: dL,
      array[int] of var 0..1:dR,
      array[int] of var 0..1: nL,
      array[int] of var 0..1:nR,
      array[int] of var 0..1:dLL,
      int: halfNum,
      int: branchSize,
    ) = 
        let {
            array[0..branchSize - 1, 0..3] of var bool: dp ,
            array[0..branchSize - 2] of var bool: isHalf ;
            array[0..branchSize-2, 0..15] of var bool: matrix;
            array[0..branchSize-2, 0..3] of var bool: halfSize;
            array[0..branchSize-2] of var bool: ifEnforced;
            array[0..branchSize-2, 0..3] of var bool: enforcedLiterals;
            array[0..branchSize-2, 0..15] of var bool: literals;
            array[0..3] of var bool: lastLiterals;
            array[0..6] of var bool: isValid;
        } in
        (sum(isHalf) <= halfNum) /\
        (dp[0, 0] == true) /\
        (dp[0, 1] == false) /\
        (dp[0, 2] == false) /\
        (dp[0, 3] == false) /\
        forall(i in 0..branchSize-2) (
            forall(cn in 0..3) (
                 let {
                    array[0..9] of var 0..1: column = array1d(0..9, [dL[i], dR[i], nL[i], nR[i], dLL[i], matrix[i, 0*4+cn], matrix[i, 1*4+cn], matrix[i,2*4+cn], matrix[i, 3*4+cn], halfSize[i, cn]])
                } in
                BVAssign_ubct(column, cn)
            ) /\
            (
                dp[i + 1, 0] \/ dp[i + 1, 1] \/ dp[i + 1, 2] \/ dp[i + 1, 3]
            ) /\
            (ifEnforced[i] == not(isHalf[i])) /\
            forall(j in 0..3) (
                (not(ifEnforced[i]) \/ not(dp[i,j]) \/ matrix[i, j*4+j]) /\
                (not(ifEnforced[i]) \/ not(dp[i,j]) \/ dp[i+1,j]) /\
                sum([not(ifEnforced[i]), not(dp[i,j]), matrix[i, j * 4 + j]]) >= 1 /\
                sum([not(ifEnforced[i]), not(dp[i,j]), dp[i + 1,j]]) >= 1
            ) /\
            forall(j in 0..3) (
                (enforcedLiterals[i,j] -> (not(matrix[i,j * 4 + j]) /\ dp[i,j])) /\
                (not(enforcedLiterals[i,j]) -> (matrix[i,j * 4 + j] \/ not(dp[i,j])))
            ) /\ 
            (
                ifEnforced[i] \/ enforcedLiterals[i,0] \/ enforcedLiterals[i,1] \/ enforcedLiterals[i,2] \/ enforcedLiterals[i,3]
            ) /\
            forall(r in 0..3) (
                forall(cc in 0..3) (
                    (literals[i, r * 4 + cc] -> (matrix[i, r * 4 + cc] /\ dp[i, cc])) /\
                    (not(literals[i, r * 4 + cc]) -> (not(matrix[i,r * 4 + cc]) \/ not(dp[i,cc]))) /\
                    (matrix[i,r * 4 + cc] >=  literals[i,r * 4 + cc]) /\
                    (dp[i,cc] >=           literals[i,r * 4 + cc])  /\
                    sum([ literals[i, r * 4 + cc], true ]) >= sum([ matrix[i, r * 4 + cc], dp[i,cc] ])
                ) /\
                (
                    dp[i + 1,r] -> (literals[i,r * 4 + 0] \/ literals[i,r * 4 + 1] \/ literals[i,r * 4 + 2] \/ literals[i,r * 4 + 3])
                ) /\
                (
                    not(dp[i + 1,r]) -> (not(literals[i,r * 4 + 0]) /\ not(literals[i,r * 4 + 1]) /\ not(literals[i,r * 4 + 2]) /\ not(literals[i,r * 4 + 3]))
                ) /\
                forall(li in 0..3) (
                    dp[i + 1,r] >= literals[i, r * 4 + li] 
                ) /\
                (
                    sum([ literals[i,r * 4 + 0], literals[i,r * 4 + 1], literals[i,r * 4 + 2], literals[i,r * 4 + 3] ]) >= dp[i + 1,r]
                )
            )
        ) /\
        (
            isValid[0] == dL[branchSize - 1] /\
            isValid[1] == dR[branchSize - 1] /\
            isValid[2] == dLL[branchSize -1] 
        ) /\
            (BVAssign_last_table_ubct(isValid))
        /\
        forall(i in 0..3) (
            (
                lastLiterals[i] -> (dp[branchSize-1,i] /\ isValid[3 + i])
            ) /\
            (
                not(lastLiterals[i]) -> (not(dp[branchSize-1,i]) \/ not(isValid[3 + i]))
            )
        ) /\
        (
            lastLiterals[0] \/ lastLiterals[1] \/ lastLiterals[2] \/ lastLiterals[3]
        );         

        predicate BVAssign_ubct(array[0..num_cols_ubct-1] of var 0..1: column, int: index) =
        let {
            array[int] of set of int: indices = [index..index, 0..num_rows_ubct-1, 0..num_cols_ubct-1];
            array[int,int] of int: extractedFromTable = slice_2d(ubct_table, indices, 0..num_rows_ubct-1, 0..num_cols_ubct-1);
        } in
        table(column, extractedFromTable);

        predicate BVAssign_last_table_ubct(
            array[0..num_cols_last_table_ubct-1] of var bool: isValid
        ) =  table(isValid, last_table_ubct);  
    

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
    array[0..23] of var 0..1: dL,
    array[0..23] of var 0..1: dR,
    array[0..23] of var 0..1: nL,
    array[0..23] of var 0..1: nR,
    array[0..23] of var 0..1: dLL,
    int: branchSize,
    var 0..3200: ubct_minus_log_2
) =
let {
    array[1..branchSize-1,0..3] of var 0.0..1.0: dp_ubct;
    array[1..branchSize-1] of var 0..31: tmp0;
    var 0.0..1.0: ubct_value;
} in
(
    ( 
        tmp0[1] == dLL[branchSize-1]*16 + nR[branchSize-1]*8 + nL[branchSize-1]*4 + dR[branchSize-1]*2 + dL[branchSize-1]*1
    ) /\
    forall(j in 0..3)(
        dp_ubct[1,j] == int2float(tables_ubct[tmp0[1],j,0]) / 4.0
    ) /\
    forall(i in 2..branchSize-1)(
        tmp0[i] == dLL[branchSize-i]*16 + nR[branchSize-i]*8 + nL[branchSize-i]*4 + dR[branchSize-i]*2 + dL[branchSize-i]*1
    ) /\
    forall(i in 2..branchSize-1, j in 0..3)(
            dp_ubct[i,j] == sum(k in 0..3)(
                 dp_ubct[i-1,k] * int2float(tables_ubct[tmp0[i],j,k]) 
            ) / 4.0
    ) /\
    (
        ubct_value == sum(state in 0..3)( 
                                if (((valid_state_ubct[state,0] + valid_state_ubct[state,1] + dLL[1] + nR[1] + nL[1]) mod 2) == 0)
                                    then dp_ubct[branchSize-1,state]
                                else 0
                                endif
        )
    ) /\
    (
        approx_prob_log(ubct_value,ubct_minus_log_2)
    )
);
    
 
    array[0..31, 0..7, 0..7] of 0..4: tables_lbct = array3d(0..31, 0..7, 0..7, 
[
 4, 0, 0, 0, 0, 2, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 2, 0, 0,
 0, 0, 0, 0, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 2, 0, 0, 2, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 2, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 2, 0, 0, 0, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 2, 0, 0, 0, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 2, 0, 0,
 2, 0, 0, 0, 0, 2, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 2, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 2, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 2, 0, 0, 2, 0, 0, 4, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 2, 0, 2, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 2, 0, 0, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 1,


 0, 0, 0, 0, 0, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 1,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 0, 2, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 1, 2, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 2, 0, 0, 0, 0, 1,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 1, 2, 0, 0, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 1,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 1,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 2, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 2, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 0, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 0, 0, 0, 0, 0, 1,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 1,
 0, 1, 0, 0, 2, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 1,


 2, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 2, 0, 0, 1, 0, 2, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 2, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 2, 0, 1, 2, 0,
 0, 0, 0, 2, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 2, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 2, 0, 0, 1, 0, 2, 0, 0,
 0, 0, 0, 1, 0, 2, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 2, 0, 1, 0, 0,
 0, 0, 0, 2, 0, 1, 2, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 1, 2, 0, 0, 0, 0, 2,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 0, 2, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 2,


 0, 2, 0, 0, 2, 0, 0, 1,
 0, 2, 0, 0, 0, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 1,


 0, 1, 0, 0, 0, 0, 0, 0,
 0, 1, 0, 0, 0, 0, 0, 0,
 0, 0, 2, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 1, 2, 0, 0, 0, 0, 2,
 0, 1, 0, 0, 0, 0, 0, 2,


 0, 0, 0, 0, 0, 0, 0, 1,
 0, 2, 0, 0, 0, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 2, 0, 0, 2, 0, 0, 1,
 0, 0, 0, 0, 0, 0, 0, 1,


 2, 0, 0, 1, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 2, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 1, 0, 0,


 2, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 2, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 1, 0, 1, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 2, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 2, 0, 0, 0, 0, 1, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 1, 0, 0,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 1, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 0, 1, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,


 2, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 0, 0,
 2, 0, 0, 1, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 0, 2, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 4, 0, 2, 0, 0, 2,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 2,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 2, 0, 0, 0, 0, 0, 0,
 0, 2, 2, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 2, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 2, 0, 2, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 2, 0, 2, 0, 0, 2,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 2,


 0, 0, 0, 0, 0, 0, 0, 0,
 0, 2, 0, 0, 0, 0, 0, 0,
 0, 0, 2, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 2, 2, 0, 4, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0]);
 
array[0..7,0..1] of 0..1: valid_state_lbct = array2d(0..7,0..1,
[
0,0,%lsb is the first one, msb the last one
1,0,
1,0,
0,0,
1,0,
0,0,
0,0,
1,0
]);

predicate lbct_compute(
    array[0..23] of var 0..1: dL,
    array[0..23] of var 0..1: dR,
    array[0..23] of var 0..1: nL,
    array[0..23] of var 0..1: nR,
    array[0..23] of var 0..1: nLL,
    int: branchSize,
    var 0..3200: lbct_minus_log_2
) =
let {
    array[1..branchSize-1,0..7] of var 0.0..1.0: dp_lbct;
    array[1..branchSize-1] of var 0..31: tmp0;
    var 0.0..1.0: lbct_value;
} in
(
    (
        tmp0[1] == nLL[branchSize-1]*16 + nR[branchSize-1]*8 + nL[branchSize-1]*4 + dR[branchSize-1]*2 + dL[branchSize-1]
    ) /\
    forall(j in 0..7)(
        dp_lbct[1,j] == int2float(tables_lbct[tmp0[1],j,0]) / 4.0
    ) /\
    forall(i in 2..branchSize-1)(
        tmp0[i] == nLL[branchSize-i]*16 + nR[branchSize-i]*8 + nL[branchSize-i]*4 + dR[branchSize-i]*2 + dL[branchSize-i]
    ) /\
    forall(i in 2..branchSize-1, j in 0..7)(
            dp_lbct[i,j] == sum(k in 0..7)(
                 dp_lbct[i-1,k] * int2float(tables_lbct[tmp0[i],j,k]) 
            ) / 4.0
    ) /\
    (
        lbct_value == sum(state in 0..7)(
                                        if ((valid_state_lbct[state,0] + valid_state_lbct[state,1] + nLL[1] + nR[1] + nL[1]) mod 2 == 0)
                                            then dp_lbct[branchSize-1,state]
                                        else
                                            0
                                        endif
        )
    ) /\
    (
        approx_prob_log(lbct_value,lbct_minus_log_2)
    )
);
    

predicate approx_prob_log(
        var 0.0..1.0: prob,
        var 0..3200: minus_log2_prob
) = (
    minus_log2_prob == if prob <= 0.001021453702391378 then
                          3200
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
    
constraint sum(upper_plaintext)>0;
constraint sum(lower_cipher_output_10_12)>0;
