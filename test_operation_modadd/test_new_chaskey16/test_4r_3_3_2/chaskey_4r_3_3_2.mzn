
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

array[0..15] of var 0..1: pre_upper_modadd_0_0_0;
array[0..15] of var 0..1: pre_upper_modadd_0_0_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_0_0_1 = LShift(pre_upper_modadd_0_0_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_0_0_0 = LShift(pre_upper_modadd_0_0_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_0_0 = LShift(upper_modadd_0_0,1);
array[0..15] of var 0..1: eq_upper_modadd_0_0 = Eq(Shi_pre_upper_modadd_0_0_1, Shi_pre_upper_modadd_0_0_0, Shi_upper_modadd_0_0);
array[0..16-1] of var 0..1: dummy_upper_xor_0_2;
array[0..15] of var 0..1: pre_upper_modadd_0_4_0;
array[0..15] of var 0..1: pre_upper_modadd_0_4_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_0_4_1 = LShift(pre_upper_modadd_0_4_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_0_4_0 = LShift(pre_upper_modadd_0_4_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_0_4 = LShift(upper_modadd_0_4,1);
array[0..15] of var 0..1: eq_upper_modadd_0_4 = Eq(Shi_pre_upper_modadd_0_4_1, Shi_pre_upper_modadd_0_4_0, Shi_upper_modadd_0_4);
array[0..16-1] of var 0..1: dummy_upper_xor_0_6;
array[0..15] of var 0..1: pre_upper_modadd_1_0_0;
array[0..15] of var 0..1: pre_upper_modadd_1_0_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_0_1 = LShift(pre_upper_modadd_1_0_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_0_0 = LShift(pre_upper_modadd_1_0_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_1_0 = LShift(upper_modadd_1_0,1);
array[0..15] of var 0..1: eq_upper_modadd_1_0 = Eq(Shi_pre_upper_modadd_1_0_1, Shi_pre_upper_modadd_1_0_0, Shi_upper_modadd_1_0);
array[0..16-1] of var 0..1: dummy_upper_xor_1_2;
array[0..15] of var 0..1: pre_upper_modadd_1_3_0;
array[0..15] of var 0..1: pre_upper_modadd_1_3_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_3_1 = LShift(pre_upper_modadd_1_3_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_3_0 = LShift(pre_upper_modadd_1_3_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_1_3 = LShift(upper_modadd_1_3,1);
array[0..15] of var 0..1: eq_upper_modadd_1_3 = Eq(Shi_pre_upper_modadd_1_3_1, Shi_pre_upper_modadd_1_3_0, Shi_upper_modadd_1_3);
array[0..16-1] of var 0..1: dummy_upper_xor_1_5;
array[0..15] of var 0..1: pre_upper_modadd_2_0_0;
array[0..15] of var 0..1: pre_upper_modadd_2_0_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_2_0_1 = LShift(pre_upper_modadd_2_0_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_2_0_0 = LShift(pre_upper_modadd_2_0_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_2_0 = LShift(upper_modadd_2_0,1);
array[0..15] of var 0..1: eq_upper_modadd_2_0 = Eq(Shi_pre_upper_modadd_2_0_1, Shi_pre_upper_modadd_2_0_0, Shi_upper_modadd_2_0);
array[0..16-1] of var 0..1: dummy_upper_xor_2_2;
array[0..15] of var 0..1: pre_upper_modadd_2_4_0;
array[0..15] of var 0..1: pre_upper_modadd_2_4_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_2_4_1 = LShift(pre_upper_modadd_2_4_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_2_4_0 = LShift(pre_upper_modadd_2_4_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_2_4 = LShift(upper_modadd_2_4,1);
array[0..15] of var 0..1: eq_upper_modadd_2_4 = Eq(Shi_pre_upper_modadd_2_4_1, Shi_pre_upper_modadd_2_4_0, Shi_upper_modadd_2_4);
array[0..16-1] of var 0..1: dummy_upper_xor_2_6;
array[0..15] of var 0..1: pre_upper_modadd_3_0_0;
array[0..15] of var 0..1: pre_upper_modadd_3_0_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_0_1 = LShift(pre_upper_modadd_3_0_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_0_0 = LShift(pre_upper_modadd_3_0_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_3_0 = LShift(upper_modadd_3_0,1);
array[0..15] of var 0..1: eq_upper_modadd_3_0 = Eq(Shi_pre_upper_modadd_3_0_1, Shi_pre_upper_modadd_3_0_0, Shi_upper_modadd_3_0);
array[0..16-1] of var 0..1: dummy_upper_xor_3_2;
array[0..15] of var 0..1: pre_upper_modadd_3_3_0;
array[0..15] of var 0..1: pre_upper_modadd_3_3_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_3_1 = LShift(pre_upper_modadd_3_3_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_3_0 = LShift(pre_upper_modadd_3_3_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_3_3 = LShift(upper_modadd_3_3,1);
array[0..15] of var 0..1: eq_upper_modadd_3_3 = Eq(Shi_pre_upper_modadd_3_3_1, Shi_pre_upper_modadd_3_3_0, Shi_upper_modadd_3_3);
array[0..16-1] of var 0..1: dummy_upper_xor_3_5;
array[0..16-1] of var 0..1: dummy_lower_xor_3_2;
array[0..16-1] of var 0..1: dummy_lower_xor_3_5;
array[0..15] of var 0..1: pre_lower_modadd_3_0_0;
array[0..15] of var 0..1: pre_lower_modadd_3_0_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_0_1 = LShift(pre_lower_modadd_3_0_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_0_0 = LShift(pre_lower_modadd_3_0_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_3_0 = LShift(lower_modadd_3_0,1);
array[0..15] of var 0..1: eq_lower_modadd_3_0 = Eq(Shi_pre_lower_modadd_3_0_1, Shi_pre_lower_modadd_3_0_0, Shi_lower_modadd_3_0);
array[0..15] of var 0..1: pre_lower_modadd_3_3_0;
array[0..15] of var 0..1: pre_lower_modadd_3_3_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_3_1 = LShift(pre_lower_modadd_3_3_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_3_0 = LShift(pre_lower_modadd_3_3_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_3_3 = LShift(lower_modadd_3_3,1);
array[0..15] of var 0..1: eq_lower_modadd_3_3 = Eq(Shi_pre_lower_modadd_3_3_1, Shi_pre_lower_modadd_3_3_0, Shi_lower_modadd_3_3);
array[0..15] of var 0..1: pre_upper_modadd_4_0_0;
array[0..15] of var 0..1: pre_upper_modadd_4_0_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_4_0_1 = LShift(pre_upper_modadd_4_0_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_4_0_0 = LShift(pre_upper_modadd_4_0_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_4_0 = LShift(upper_modadd_4_0,1);
array[0..15] of var 0..1: eq_upper_modadd_4_0 = Eq(Shi_pre_upper_modadd_4_0_1, Shi_pre_upper_modadd_4_0_0, Shi_upper_modadd_4_0);
array[0..16-1] of var 0..1: dummy_upper_xor_4_2;
array[0..15] of var 0..1: pre_upper_modadd_4_4_0;
array[0..15] of var 0..1: pre_upper_modadd_4_4_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_4_4_1 = LShift(pre_upper_modadd_4_4_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_4_4_0 = LShift(pre_upper_modadd_4_4_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_4_4 = LShift(upper_modadd_4_4,1);
array[0..15] of var 0..1: eq_upper_modadd_4_4 = Eq(Shi_pre_upper_modadd_4_4_1, Shi_pre_upper_modadd_4_4_0, Shi_upper_modadd_4_4);
array[0..16-1] of var 0..1: dummy_upper_xor_4_6;
array[0..16-1] of var 0..1: dummy_lower_xor_4_2;
array[0..16-1] of var 0..1: dummy_lower_xor_4_6;
array[0..15] of var 0..1: pre_lower_modadd_4_0_0;
array[0..15] of var 0..1: pre_lower_modadd_4_0_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_4_0_1 = LShift(pre_lower_modadd_4_0_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_4_0_0 = LShift(pre_lower_modadd_4_0_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_4_0 = LShift(lower_modadd_4_0,1);
array[0..15] of var 0..1: eq_lower_modadd_4_0 = Eq(Shi_pre_lower_modadd_4_0_1, Shi_pre_lower_modadd_4_0_0, Shi_lower_modadd_4_0);
array[0..15] of var 0..1: pre_lower_modadd_4_4_0;
array[0..15] of var 0..1: pre_lower_modadd_4_4_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_4_4_1 = LShift(pre_lower_modadd_4_4_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_4_4_0 = LShift(pre_lower_modadd_4_4_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_4_4 = LShift(lower_modadd_4_4,1);
array[0..15] of var 0..1: eq_lower_modadd_4_4 = Eq(Shi_pre_lower_modadd_4_4_1, Shi_pre_lower_modadd_4_4_0, Shi_lower_modadd_4_4);
array[0..15] of var 0..1: pre_upper_modadd_5_0_0;
array[0..15] of var 0..1: pre_upper_modadd_5_0_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_5_0_1 = LShift(pre_upper_modadd_5_0_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_5_0_0 = LShift(pre_upper_modadd_5_0_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_5_0 = LShift(upper_modadd_5_0,1);
array[0..15] of var 0..1: eq_upper_modadd_5_0 = Eq(Shi_pre_upper_modadd_5_0_1, Shi_pre_upper_modadd_5_0_0, Shi_upper_modadd_5_0);
array[0..16-1] of var 0..1: dummy_upper_xor_5_2;
array[0..15] of var 0..1: pre_upper_modadd_5_3_0;
array[0..15] of var 0..1: pre_upper_modadd_5_3_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_5_3_1 = LShift(pre_upper_modadd_5_3_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_5_3_0 = LShift(pre_upper_modadd_5_3_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_5_3 = LShift(upper_modadd_5_3,1);
array[0..15] of var 0..1: eq_upper_modadd_5_3 = Eq(Shi_pre_upper_modadd_5_3_1, Shi_pre_upper_modadd_5_3_0, Shi_upper_modadd_5_3);
array[0..16-1] of var 0..1: dummy_upper_xor_5_5;
array[0..16-1] of var 0..1: dummy_lower_xor_5_2;
array[0..16-1] of var 0..1: dummy_lower_xor_5_5;
array[0..15] of var 0..1: pre_lower_modadd_5_0_0;
array[0..15] of var 0..1: pre_lower_modadd_5_0_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_0_1 = LShift(pre_lower_modadd_5_0_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_0_0 = LShift(pre_lower_modadd_5_0_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_5_0 = LShift(lower_modadd_5_0,1);
array[0..15] of var 0..1: eq_lower_modadd_5_0 = Eq(Shi_pre_lower_modadd_5_0_1, Shi_pre_lower_modadd_5_0_0, Shi_lower_modadd_5_0);
array[0..15] of var 0..1: pre_lower_modadd_5_3_0;
array[0..15] of var 0..1: pre_lower_modadd_5_3_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_3_1 = LShift(pre_lower_modadd_5_3_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_3_0 = LShift(pre_lower_modadd_5_3_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_5_3 = LShift(lower_modadd_5_3,1);
array[0..15] of var 0..1: eq_lower_modadd_5_3 = Eq(Shi_pre_lower_modadd_5_3_1, Shi_pre_lower_modadd_5_3_0, Shi_lower_modadd_5_3);
array[0..16-1] of var 0..1: dummy_lower_xor_6_2;
array[0..16-1] of var 0..1: dummy_lower_xor_6_6;
array[0..15] of var 0..1: pre_lower_modadd_6_0_0;
array[0..15] of var 0..1: pre_lower_modadd_6_0_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_6_0_1 = LShift(pre_lower_modadd_6_0_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_6_0_0 = LShift(pre_lower_modadd_6_0_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_6_0 = LShift(lower_modadd_6_0,1);
array[0..15] of var 0..1: eq_lower_modadd_6_0 = Eq(Shi_pre_lower_modadd_6_0_1, Shi_pre_lower_modadd_6_0_0, Shi_lower_modadd_6_0);
array[0..15] of var 0..1: pre_lower_modadd_6_4_0;
array[0..15] of var 0..1: pre_lower_modadd_6_4_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_6_4_1 = LShift(pre_lower_modadd_6_4_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_6_4_0 = LShift(pre_lower_modadd_6_4_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_6_4 = LShift(lower_modadd_6_4,1);
array[0..15] of var 0..1: eq_lower_modadd_6_4 = Eq(Shi_pre_lower_modadd_6_4_1, Shi_pre_lower_modadd_6_4_0, Shi_lower_modadd_6_4);
array[0..16-1] of var 0..1: dummy_lower_xor_7_2;
array[0..16-1] of var 0..1: dummy_lower_xor_7_5;
array[0..15] of var 0..1: pre_lower_modadd_7_0_0;
array[0..15] of var 0..1: pre_lower_modadd_7_0_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_7_0_1 = LShift(pre_lower_modadd_7_0_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_7_0_0 = LShift(pre_lower_modadd_7_0_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_7_0 = LShift(lower_modadd_7_0,1);
array[0..15] of var 0..1: eq_lower_modadd_7_0 = Eq(Shi_pre_lower_modadd_7_0_1, Shi_pre_lower_modadd_7_0_0, Shi_lower_modadd_7_0);
array[0..15] of var 0..1: pre_lower_modadd_7_3_0;
array[0..15] of var 0..1: pre_lower_modadd_7_3_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_7_3_1 = LShift(pre_lower_modadd_7_3_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_7_3_0 = LShift(pre_lower_modadd_7_3_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_7_3 = LShift(lower_modadd_7_3,1);
array[0..15] of var 0..1: eq_lower_modadd_7_3 = Eq(Shi_pre_lower_modadd_7_3_1, Shi_pre_lower_modadd_7_3_0, Shi_lower_modadd_7_3);
constraint pre_upper_modadd_0_0_0[0] = upper_plaintext[0];
constraint pre_upper_modadd_0_0_0[1] = upper_plaintext[1];
constraint pre_upper_modadd_0_0_0[2] = upper_plaintext[2];
constraint pre_upper_modadd_0_0_0[3] = upper_plaintext[3];
constraint pre_upper_modadd_0_0_0[4] = upper_plaintext[4];
constraint pre_upper_modadd_0_0_0[5] = upper_plaintext[5];
constraint pre_upper_modadd_0_0_0[6] = upper_plaintext[6];
constraint pre_upper_modadd_0_0_0[7] = upper_plaintext[7];
constraint pre_upper_modadd_0_0_0[8] = upper_plaintext[8];
constraint pre_upper_modadd_0_0_0[9] = upper_plaintext[9];
constraint pre_upper_modadd_0_0_0[10] = upper_plaintext[10];
constraint pre_upper_modadd_0_0_0[11] = upper_plaintext[11];
constraint pre_upper_modadd_0_0_0[12] = upper_plaintext[12];
constraint pre_upper_modadd_0_0_0[13] = upper_plaintext[13];
constraint pre_upper_modadd_0_0_0[14] = upper_plaintext[14];
constraint pre_upper_modadd_0_0_0[15] = upper_plaintext[15];
constraint pre_upper_modadd_0_0_1[0] = upper_plaintext[16];
constraint pre_upper_modadd_0_0_1[1] = upper_plaintext[17];
constraint pre_upper_modadd_0_0_1[2] = upper_plaintext[18];
constraint pre_upper_modadd_0_0_1[3] = upper_plaintext[19];
constraint pre_upper_modadd_0_0_1[4] = upper_plaintext[20];
constraint pre_upper_modadd_0_0_1[5] = upper_plaintext[21];
constraint pre_upper_modadd_0_0_1[6] = upper_plaintext[22];
constraint pre_upper_modadd_0_0_1[7] = upper_plaintext[23];
constraint pre_upper_modadd_0_0_1[8] = upper_plaintext[24];
constraint pre_upper_modadd_0_0_1[9] = upper_plaintext[25];
constraint pre_upper_modadd_0_0_1[10] = upper_plaintext[26];
constraint pre_upper_modadd_0_0_1[11] = upper_plaintext[27];
constraint pre_upper_modadd_0_0_1[12] = upper_plaintext[28];
constraint pre_upper_modadd_0_0_1[13] = upper_plaintext[29];
constraint pre_upper_modadd_0_0_1[14] = upper_plaintext[30];
constraint pre_upper_modadd_0_0_1[15] = upper_plaintext[31];
constraint forall(j in 0..15)(if eq_upper_modadd_0_0[j] = 1 then (sum([pre_upper_modadd_0_0_1[j], pre_upper_modadd_0_0_0[j], upper_modadd_0_0[j]]) mod 2) = Shi_pre_upper_modadd_0_0_0[j] else true endif) /\ upper_p[0] = (16-sum(eq_upper_modadd_0_0))*100;
constraint upper_rot_0_1[0] = upper_plaintext[21];
constraint upper_rot_0_1[1] = upper_plaintext[22];
constraint upper_rot_0_1[2] = upper_plaintext[23];
constraint upper_rot_0_1[3] = upper_plaintext[24];
constraint upper_rot_0_1[4] = upper_plaintext[25];
constraint upper_rot_0_1[5] = upper_plaintext[26];
constraint upper_rot_0_1[6] = upper_plaintext[27];
constraint upper_rot_0_1[7] = upper_plaintext[28];
constraint upper_rot_0_1[8] = upper_plaintext[29];
constraint upper_rot_0_1[9] = upper_plaintext[30];
constraint upper_rot_0_1[10] = upper_plaintext[31];
constraint upper_rot_0_1[11] = upper_plaintext[16];
constraint upper_rot_0_1[12] = upper_plaintext[17];
constraint upper_rot_0_1[13] = upper_plaintext[18];
constraint upper_rot_0_1[14] = upper_plaintext[19];
constraint upper_rot_0_1[15] = upper_plaintext[20];
constraint 2*dummy_upper_xor_0_2[0] = (upper_rot_0_1[0] + upper_modadd_0_0[0] + upper_xor_0_2[0]);
constraint 2*dummy_upper_xor_0_2[1] = (upper_rot_0_1[1] + upper_modadd_0_0[1] + upper_xor_0_2[1]);
constraint 2*dummy_upper_xor_0_2[2] = (upper_rot_0_1[2] + upper_modadd_0_0[2] + upper_xor_0_2[2]);
constraint 2*dummy_upper_xor_0_2[3] = (upper_rot_0_1[3] + upper_modadd_0_0[3] + upper_xor_0_2[3]);
constraint 2*dummy_upper_xor_0_2[4] = (upper_rot_0_1[4] + upper_modadd_0_0[4] + upper_xor_0_2[4]);
constraint 2*dummy_upper_xor_0_2[5] = (upper_rot_0_1[5] + upper_modadd_0_0[5] + upper_xor_0_2[5]);
constraint 2*dummy_upper_xor_0_2[6] = (upper_rot_0_1[6] + upper_modadd_0_0[6] + upper_xor_0_2[6]);
constraint 2*dummy_upper_xor_0_2[7] = (upper_rot_0_1[7] + upper_modadd_0_0[7] + upper_xor_0_2[7]);
constraint 2*dummy_upper_xor_0_2[8] = (upper_rot_0_1[8] + upper_modadd_0_0[8] + upper_xor_0_2[8]);
constraint 2*dummy_upper_xor_0_2[9] = (upper_rot_0_1[9] + upper_modadd_0_0[9] + upper_xor_0_2[9]);
constraint 2*dummy_upper_xor_0_2[10] = (upper_rot_0_1[10] + upper_modadd_0_0[10] + upper_xor_0_2[10]);
constraint 2*dummy_upper_xor_0_2[11] = (upper_rot_0_1[11] + upper_modadd_0_0[11] + upper_xor_0_2[11]);
constraint 2*dummy_upper_xor_0_2[12] = (upper_rot_0_1[12] + upper_modadd_0_0[12] + upper_xor_0_2[12]);
constraint 2*dummy_upper_xor_0_2[13] = (upper_rot_0_1[13] + upper_modadd_0_0[13] + upper_xor_0_2[13]);
constraint 2*dummy_upper_xor_0_2[14] = (upper_rot_0_1[14] + upper_modadd_0_0[14] + upper_xor_0_2[14]);
constraint 2*dummy_upper_xor_0_2[15] = (upper_rot_0_1[15] + upper_modadd_0_0[15] + upper_xor_0_2[15]);
constraint upper_rot_0_3[0] = upper_modadd_0_0[0];
constraint upper_rot_0_3[1] = upper_modadd_0_0[1];
constraint upper_rot_0_3[2] = upper_modadd_0_0[2];
constraint upper_rot_0_3[3] = upper_modadd_0_0[3];
constraint upper_rot_0_3[4] = upper_modadd_0_0[4];
constraint upper_rot_0_3[5] = upper_modadd_0_0[5];
constraint upper_rot_0_3[6] = upper_modadd_0_0[6];
constraint upper_rot_0_3[7] = upper_modadd_0_0[7];
constraint upper_rot_0_3[8] = upper_modadd_0_0[8];
constraint upper_rot_0_3[9] = upper_modadd_0_0[9];
constraint upper_rot_0_3[10] = upper_modadd_0_0[10];
constraint upper_rot_0_3[11] = upper_modadd_0_0[11];
constraint upper_rot_0_3[12] = upper_modadd_0_0[12];
constraint upper_rot_0_3[13] = upper_modadd_0_0[13];
constraint upper_rot_0_3[14] = upper_modadd_0_0[14];
constraint upper_rot_0_3[15] = upper_modadd_0_0[15];
constraint pre_upper_modadd_0_4_0[0] = upper_plaintext[32];
constraint pre_upper_modadd_0_4_0[1] = upper_plaintext[33];
constraint pre_upper_modadd_0_4_0[2] = upper_plaintext[34];
constraint pre_upper_modadd_0_4_0[3] = upper_plaintext[35];
constraint pre_upper_modadd_0_4_0[4] = upper_plaintext[36];
constraint pre_upper_modadd_0_4_0[5] = upper_plaintext[37];
constraint pre_upper_modadd_0_4_0[6] = upper_plaintext[38];
constraint pre_upper_modadd_0_4_0[7] = upper_plaintext[39];
constraint pre_upper_modadd_0_4_0[8] = upper_plaintext[40];
constraint pre_upper_modadd_0_4_0[9] = upper_plaintext[41];
constraint pre_upper_modadd_0_4_0[10] = upper_plaintext[42];
constraint pre_upper_modadd_0_4_0[11] = upper_plaintext[43];
constraint pre_upper_modadd_0_4_0[12] = upper_plaintext[44];
constraint pre_upper_modadd_0_4_0[13] = upper_plaintext[45];
constraint pre_upper_modadd_0_4_0[14] = upper_plaintext[46];
constraint pre_upper_modadd_0_4_0[15] = upper_plaintext[47];
constraint pre_upper_modadd_0_4_1[0] = upper_plaintext[48];
constraint pre_upper_modadd_0_4_1[1] = upper_plaintext[49];
constraint pre_upper_modadd_0_4_1[2] = upper_plaintext[50];
constraint pre_upper_modadd_0_4_1[3] = upper_plaintext[51];
constraint pre_upper_modadd_0_4_1[4] = upper_plaintext[52];
constraint pre_upper_modadd_0_4_1[5] = upper_plaintext[53];
constraint pre_upper_modadd_0_4_1[6] = upper_plaintext[54];
constraint pre_upper_modadd_0_4_1[7] = upper_plaintext[55];
constraint pre_upper_modadd_0_4_1[8] = upper_plaintext[56];
constraint pre_upper_modadd_0_4_1[9] = upper_plaintext[57];
constraint pre_upper_modadd_0_4_1[10] = upper_plaintext[58];
constraint pre_upper_modadd_0_4_1[11] = upper_plaintext[59];
constraint pre_upper_modadd_0_4_1[12] = upper_plaintext[60];
constraint pre_upper_modadd_0_4_1[13] = upper_plaintext[61];
constraint pre_upper_modadd_0_4_1[14] = upper_plaintext[62];
constraint pre_upper_modadd_0_4_1[15] = upper_plaintext[63];
constraint forall(j in 0..15)(if eq_upper_modadd_0_4[j] = 1 then (sum([pre_upper_modadd_0_4_1[j], pre_upper_modadd_0_4_0[j], upper_modadd_0_4[j]]) mod 2) = Shi_pre_upper_modadd_0_4_0[j] else true endif) /\ upper_p[1] = (16-sum(eq_upper_modadd_0_4))*100;
constraint upper_rot_0_5[0] = upper_plaintext[56];
constraint upper_rot_0_5[1] = upper_plaintext[57];
constraint upper_rot_0_5[2] = upper_plaintext[58];
constraint upper_rot_0_5[3] = upper_plaintext[59];
constraint upper_rot_0_5[4] = upper_plaintext[60];
constraint upper_rot_0_5[5] = upper_plaintext[61];
constraint upper_rot_0_5[6] = upper_plaintext[62];
constraint upper_rot_0_5[7] = upper_plaintext[63];
constraint upper_rot_0_5[8] = upper_plaintext[48];
constraint upper_rot_0_5[9] = upper_plaintext[49];
constraint upper_rot_0_5[10] = upper_plaintext[50];
constraint upper_rot_0_5[11] = upper_plaintext[51];
constraint upper_rot_0_5[12] = upper_plaintext[52];
constraint upper_rot_0_5[13] = upper_plaintext[53];
constraint upper_rot_0_5[14] = upper_plaintext[54];
constraint upper_rot_0_5[15] = upper_plaintext[55];
constraint 2*dummy_upper_xor_0_6[0] = (upper_rot_0_5[0] + upper_modadd_0_4[0] + upper_xor_0_6[0]);
constraint 2*dummy_upper_xor_0_6[1] = (upper_rot_0_5[1] + upper_modadd_0_4[1] + upper_xor_0_6[1]);
constraint 2*dummy_upper_xor_0_6[2] = (upper_rot_0_5[2] + upper_modadd_0_4[2] + upper_xor_0_6[2]);
constraint 2*dummy_upper_xor_0_6[3] = (upper_rot_0_5[3] + upper_modadd_0_4[3] + upper_xor_0_6[3]);
constraint 2*dummy_upper_xor_0_6[4] = (upper_rot_0_5[4] + upper_modadd_0_4[4] + upper_xor_0_6[4]);
constraint 2*dummy_upper_xor_0_6[5] = (upper_rot_0_5[5] + upper_modadd_0_4[5] + upper_xor_0_6[5]);
constraint 2*dummy_upper_xor_0_6[6] = (upper_rot_0_5[6] + upper_modadd_0_4[6] + upper_xor_0_6[6]);
constraint 2*dummy_upper_xor_0_6[7] = (upper_rot_0_5[7] + upper_modadd_0_4[7] + upper_xor_0_6[7]);
constraint 2*dummy_upper_xor_0_6[8] = (upper_rot_0_5[8] + upper_modadd_0_4[8] + upper_xor_0_6[8]);
constraint 2*dummy_upper_xor_0_6[9] = (upper_rot_0_5[9] + upper_modadd_0_4[9] + upper_xor_0_6[9]);
constraint 2*dummy_upper_xor_0_6[10] = (upper_rot_0_5[10] + upper_modadd_0_4[10] + upper_xor_0_6[10]);
constraint 2*dummy_upper_xor_0_6[11] = (upper_rot_0_5[11] + upper_modadd_0_4[11] + upper_xor_0_6[11]);
constraint 2*dummy_upper_xor_0_6[12] = (upper_rot_0_5[12] + upper_modadd_0_4[12] + upper_xor_0_6[12]);
constraint 2*dummy_upper_xor_0_6[13] = (upper_rot_0_5[13] + upper_modadd_0_4[13] + upper_xor_0_6[13]);
constraint 2*dummy_upper_xor_0_6[14] = (upper_rot_0_5[14] + upper_modadd_0_4[14] + upper_xor_0_6[14]);
constraint 2*dummy_upper_xor_0_6[15] = (upper_rot_0_5[15] + upper_modadd_0_4[15] + upper_xor_0_6[15]);
constraint upper_intermediate_output_0_7[0] = upper_rot_0_3[0];
constraint upper_intermediate_output_0_7[1] = upper_rot_0_3[1];
constraint upper_intermediate_output_0_7[2] = upper_rot_0_3[2];
constraint upper_intermediate_output_0_7[3] = upper_rot_0_3[3];
constraint upper_intermediate_output_0_7[4] = upper_rot_0_3[4];
constraint upper_intermediate_output_0_7[5] = upper_rot_0_3[5];
constraint upper_intermediate_output_0_7[6] = upper_rot_0_3[6];
constraint upper_intermediate_output_0_7[7] = upper_rot_0_3[7];
constraint upper_intermediate_output_0_7[8] = upper_rot_0_3[8];
constraint upper_intermediate_output_0_7[9] = upper_rot_0_3[9];
constraint upper_intermediate_output_0_7[10] = upper_rot_0_3[10];
constraint upper_intermediate_output_0_7[11] = upper_rot_0_3[11];
constraint upper_intermediate_output_0_7[12] = upper_rot_0_3[12];
constraint upper_intermediate_output_0_7[13] = upper_rot_0_3[13];
constraint upper_intermediate_output_0_7[14] = upper_rot_0_3[14];
constraint upper_intermediate_output_0_7[15] = upper_rot_0_3[15];
constraint upper_intermediate_output_0_7[16] = upper_xor_0_2[0];
constraint upper_intermediate_output_0_7[17] = upper_xor_0_2[1];
constraint upper_intermediate_output_0_7[18] = upper_xor_0_2[2];
constraint upper_intermediate_output_0_7[19] = upper_xor_0_2[3];
constraint upper_intermediate_output_0_7[20] = upper_xor_0_2[4];
constraint upper_intermediate_output_0_7[21] = upper_xor_0_2[5];
constraint upper_intermediate_output_0_7[22] = upper_xor_0_2[6];
constraint upper_intermediate_output_0_7[23] = upper_xor_0_2[7];
constraint upper_intermediate_output_0_7[24] = upper_xor_0_2[8];
constraint upper_intermediate_output_0_7[25] = upper_xor_0_2[9];
constraint upper_intermediate_output_0_7[26] = upper_xor_0_2[10];
constraint upper_intermediate_output_0_7[27] = upper_xor_0_2[11];
constraint upper_intermediate_output_0_7[28] = upper_xor_0_2[12];
constraint upper_intermediate_output_0_7[29] = upper_xor_0_2[13];
constraint upper_intermediate_output_0_7[30] = upper_xor_0_2[14];
constraint upper_intermediate_output_0_7[31] = upper_xor_0_2[15];
constraint upper_intermediate_output_0_7[32] = upper_modadd_0_4[0];
constraint upper_intermediate_output_0_7[33] = upper_modadd_0_4[1];
constraint upper_intermediate_output_0_7[34] = upper_modadd_0_4[2];
constraint upper_intermediate_output_0_7[35] = upper_modadd_0_4[3];
constraint upper_intermediate_output_0_7[36] = upper_modadd_0_4[4];
constraint upper_intermediate_output_0_7[37] = upper_modadd_0_4[5];
constraint upper_intermediate_output_0_7[38] = upper_modadd_0_4[6];
constraint upper_intermediate_output_0_7[39] = upper_modadd_0_4[7];
constraint upper_intermediate_output_0_7[40] = upper_modadd_0_4[8];
constraint upper_intermediate_output_0_7[41] = upper_modadd_0_4[9];
constraint upper_intermediate_output_0_7[42] = upper_modadd_0_4[10];
constraint upper_intermediate_output_0_7[43] = upper_modadd_0_4[11];
constraint upper_intermediate_output_0_7[44] = upper_modadd_0_4[12];
constraint upper_intermediate_output_0_7[45] = upper_modadd_0_4[13];
constraint upper_intermediate_output_0_7[46] = upper_modadd_0_4[14];
constraint upper_intermediate_output_0_7[47] = upper_modadd_0_4[15];
constraint upper_intermediate_output_0_7[48] = upper_xor_0_6[0];
constraint upper_intermediate_output_0_7[49] = upper_xor_0_6[1];
constraint upper_intermediate_output_0_7[50] = upper_xor_0_6[2];
constraint upper_intermediate_output_0_7[51] = upper_xor_0_6[3];
constraint upper_intermediate_output_0_7[52] = upper_xor_0_6[4];
constraint upper_intermediate_output_0_7[53] = upper_xor_0_6[5];
constraint upper_intermediate_output_0_7[54] = upper_xor_0_6[6];
constraint upper_intermediate_output_0_7[55] = upper_xor_0_6[7];
constraint upper_intermediate_output_0_7[56] = upper_xor_0_6[8];
constraint upper_intermediate_output_0_7[57] = upper_xor_0_6[9];
constraint upper_intermediate_output_0_7[58] = upper_xor_0_6[10];
constraint upper_intermediate_output_0_7[59] = upper_xor_0_6[11];
constraint upper_intermediate_output_0_7[60] = upper_xor_0_6[12];
constraint upper_intermediate_output_0_7[61] = upper_xor_0_6[13];
constraint upper_intermediate_output_0_7[62] = upper_xor_0_6[14];
constraint upper_intermediate_output_0_7[63] = upper_xor_0_6[15];
constraint pre_upper_modadd_1_0_0[0] = upper_rot_0_3[0];
constraint pre_upper_modadd_1_0_0[1] = upper_rot_0_3[1];
constraint pre_upper_modadd_1_0_0[2] = upper_rot_0_3[2];
constraint pre_upper_modadd_1_0_0[3] = upper_rot_0_3[3];
constraint pre_upper_modadd_1_0_0[4] = upper_rot_0_3[4];
constraint pre_upper_modadd_1_0_0[5] = upper_rot_0_3[5];
constraint pre_upper_modadd_1_0_0[6] = upper_rot_0_3[6];
constraint pre_upper_modadd_1_0_0[7] = upper_rot_0_3[7];
constraint pre_upper_modadd_1_0_0[8] = upper_rot_0_3[8];
constraint pre_upper_modadd_1_0_0[9] = upper_rot_0_3[9];
constraint pre_upper_modadd_1_0_0[10] = upper_rot_0_3[10];
constraint pre_upper_modadd_1_0_0[11] = upper_rot_0_3[11];
constraint pre_upper_modadd_1_0_0[12] = upper_rot_0_3[12];
constraint pre_upper_modadd_1_0_0[13] = upper_rot_0_3[13];
constraint pre_upper_modadd_1_0_0[14] = upper_rot_0_3[14];
constraint pre_upper_modadd_1_0_0[15] = upper_rot_0_3[15];
constraint pre_upper_modadd_1_0_1[0] = upper_xor_0_6[0];
constraint pre_upper_modadd_1_0_1[1] = upper_xor_0_6[1];
constraint pre_upper_modadd_1_0_1[2] = upper_xor_0_6[2];
constraint pre_upper_modadd_1_0_1[3] = upper_xor_0_6[3];
constraint pre_upper_modadd_1_0_1[4] = upper_xor_0_6[4];
constraint pre_upper_modadd_1_0_1[5] = upper_xor_0_6[5];
constraint pre_upper_modadd_1_0_1[6] = upper_xor_0_6[6];
constraint pre_upper_modadd_1_0_1[7] = upper_xor_0_6[7];
constraint pre_upper_modadd_1_0_1[8] = upper_xor_0_6[8];
constraint pre_upper_modadd_1_0_1[9] = upper_xor_0_6[9];
constraint pre_upper_modadd_1_0_1[10] = upper_xor_0_6[10];
constraint pre_upper_modadd_1_0_1[11] = upper_xor_0_6[11];
constraint pre_upper_modadd_1_0_1[12] = upper_xor_0_6[12];
constraint pre_upper_modadd_1_0_1[13] = upper_xor_0_6[13];
constraint pre_upper_modadd_1_0_1[14] = upper_xor_0_6[14];
constraint pre_upper_modadd_1_0_1[15] = upper_xor_0_6[15];
constraint forall(j in 0..15)(if eq_upper_modadd_1_0[j] = 1 then (sum([pre_upper_modadd_1_0_1[j], pre_upper_modadd_1_0_0[j], upper_modadd_1_0[j]]) mod 2) = Shi_pre_upper_modadd_1_0_0[j] else true endif) /\ upper_p[2] = (16-sum(eq_upper_modadd_1_0))*100;
constraint upper_rot_1_1[0] = upper_xor_0_6[13];
constraint upper_rot_1_1[1] = upper_xor_0_6[14];
constraint upper_rot_1_1[2] = upper_xor_0_6[15];
constraint upper_rot_1_1[3] = upper_xor_0_6[0];
constraint upper_rot_1_1[4] = upper_xor_0_6[1];
constraint upper_rot_1_1[5] = upper_xor_0_6[2];
constraint upper_rot_1_1[6] = upper_xor_0_6[3];
constraint upper_rot_1_1[7] = upper_xor_0_6[4];
constraint upper_rot_1_1[8] = upper_xor_0_6[5];
constraint upper_rot_1_1[9] = upper_xor_0_6[6];
constraint upper_rot_1_1[10] = upper_xor_0_6[7];
constraint upper_rot_1_1[11] = upper_xor_0_6[8];
constraint upper_rot_1_1[12] = upper_xor_0_6[9];
constraint upper_rot_1_1[13] = upper_xor_0_6[10];
constraint upper_rot_1_1[14] = upper_xor_0_6[11];
constraint upper_rot_1_1[15] = upper_xor_0_6[12];
constraint 2*dummy_upper_xor_1_2[0] = (upper_rot_1_1[0] + upper_modadd_1_0[0] + upper_xor_1_2[0]);
constraint 2*dummy_upper_xor_1_2[1] = (upper_rot_1_1[1] + upper_modadd_1_0[1] + upper_xor_1_2[1]);
constraint 2*dummy_upper_xor_1_2[2] = (upper_rot_1_1[2] + upper_modadd_1_0[2] + upper_xor_1_2[2]);
constraint 2*dummy_upper_xor_1_2[3] = (upper_rot_1_1[3] + upper_modadd_1_0[3] + upper_xor_1_2[3]);
constraint 2*dummy_upper_xor_1_2[4] = (upper_rot_1_1[4] + upper_modadd_1_0[4] + upper_xor_1_2[4]);
constraint 2*dummy_upper_xor_1_2[5] = (upper_rot_1_1[5] + upper_modadd_1_0[5] + upper_xor_1_2[5]);
constraint 2*dummy_upper_xor_1_2[6] = (upper_rot_1_1[6] + upper_modadd_1_0[6] + upper_xor_1_2[6]);
constraint 2*dummy_upper_xor_1_2[7] = (upper_rot_1_1[7] + upper_modadd_1_0[7] + upper_xor_1_2[7]);
constraint 2*dummy_upper_xor_1_2[8] = (upper_rot_1_1[8] + upper_modadd_1_0[8] + upper_xor_1_2[8]);
constraint 2*dummy_upper_xor_1_2[9] = (upper_rot_1_1[9] + upper_modadd_1_0[9] + upper_xor_1_2[9]);
constraint 2*dummy_upper_xor_1_2[10] = (upper_rot_1_1[10] + upper_modadd_1_0[10] + upper_xor_1_2[10]);
constraint 2*dummy_upper_xor_1_2[11] = (upper_rot_1_1[11] + upper_modadd_1_0[11] + upper_xor_1_2[11]);
constraint 2*dummy_upper_xor_1_2[12] = (upper_rot_1_1[12] + upper_modadd_1_0[12] + upper_xor_1_2[12]);
constraint 2*dummy_upper_xor_1_2[13] = (upper_rot_1_1[13] + upper_modadd_1_0[13] + upper_xor_1_2[13]);
constraint 2*dummy_upper_xor_1_2[14] = (upper_rot_1_1[14] + upper_modadd_1_0[14] + upper_xor_1_2[14]);
constraint 2*dummy_upper_xor_1_2[15] = (upper_rot_1_1[15] + upper_modadd_1_0[15] + upper_xor_1_2[15]);
constraint pre_upper_modadd_1_3_0[0] = upper_modadd_0_4[0];
constraint pre_upper_modadd_1_3_0[1] = upper_modadd_0_4[1];
constraint pre_upper_modadd_1_3_0[2] = upper_modadd_0_4[2];
constraint pre_upper_modadd_1_3_0[3] = upper_modadd_0_4[3];
constraint pre_upper_modadd_1_3_0[4] = upper_modadd_0_4[4];
constraint pre_upper_modadd_1_3_0[5] = upper_modadd_0_4[5];
constraint pre_upper_modadd_1_3_0[6] = upper_modadd_0_4[6];
constraint pre_upper_modadd_1_3_0[7] = upper_modadd_0_4[7];
constraint pre_upper_modadd_1_3_0[8] = upper_modadd_0_4[8];
constraint pre_upper_modadd_1_3_0[9] = upper_modadd_0_4[9];
constraint pre_upper_modadd_1_3_0[10] = upper_modadd_0_4[10];
constraint pre_upper_modadd_1_3_0[11] = upper_modadd_0_4[11];
constraint pre_upper_modadd_1_3_0[12] = upper_modadd_0_4[12];
constraint pre_upper_modadd_1_3_0[13] = upper_modadd_0_4[13];
constraint pre_upper_modadd_1_3_0[14] = upper_modadd_0_4[14];
constraint pre_upper_modadd_1_3_0[15] = upper_modadd_0_4[15];
constraint pre_upper_modadd_1_3_1[0] = upper_xor_0_2[0];
constraint pre_upper_modadd_1_3_1[1] = upper_xor_0_2[1];
constraint pre_upper_modadd_1_3_1[2] = upper_xor_0_2[2];
constraint pre_upper_modadd_1_3_1[3] = upper_xor_0_2[3];
constraint pre_upper_modadd_1_3_1[4] = upper_xor_0_2[4];
constraint pre_upper_modadd_1_3_1[5] = upper_xor_0_2[5];
constraint pre_upper_modadd_1_3_1[6] = upper_xor_0_2[6];
constraint pre_upper_modadd_1_3_1[7] = upper_xor_0_2[7];
constraint pre_upper_modadd_1_3_1[8] = upper_xor_0_2[8];
constraint pre_upper_modadd_1_3_1[9] = upper_xor_0_2[9];
constraint pre_upper_modadd_1_3_1[10] = upper_xor_0_2[10];
constraint pre_upper_modadd_1_3_1[11] = upper_xor_0_2[11];
constraint pre_upper_modadd_1_3_1[12] = upper_xor_0_2[12];
constraint pre_upper_modadd_1_3_1[13] = upper_xor_0_2[13];
constraint pre_upper_modadd_1_3_1[14] = upper_xor_0_2[14];
constraint pre_upper_modadd_1_3_1[15] = upper_xor_0_2[15];
constraint forall(j in 0..15)(if eq_upper_modadd_1_3[j] = 1 then (sum([pre_upper_modadd_1_3_1[j], pre_upper_modadd_1_3_0[j], upper_modadd_1_3[j]]) mod 2) = Shi_pre_upper_modadd_1_3_0[j] else true endif) /\ upper_p[3] = (16-sum(eq_upper_modadd_1_3))*100;
constraint upper_rot_1_4[0] = upper_xor_0_2[7];
constraint upper_rot_1_4[1] = upper_xor_0_2[8];
constraint upper_rot_1_4[2] = upper_xor_0_2[9];
constraint upper_rot_1_4[3] = upper_xor_0_2[10];
constraint upper_rot_1_4[4] = upper_xor_0_2[11];
constraint upper_rot_1_4[5] = upper_xor_0_2[12];
constraint upper_rot_1_4[6] = upper_xor_0_2[13];
constraint upper_rot_1_4[7] = upper_xor_0_2[14];
constraint upper_rot_1_4[8] = upper_xor_0_2[15];
constraint upper_rot_1_4[9] = upper_xor_0_2[0];
constraint upper_rot_1_4[10] = upper_xor_0_2[1];
constraint upper_rot_1_4[11] = upper_xor_0_2[2];
constraint upper_rot_1_4[12] = upper_xor_0_2[3];
constraint upper_rot_1_4[13] = upper_xor_0_2[4];
constraint upper_rot_1_4[14] = upper_xor_0_2[5];
constraint upper_rot_1_4[15] = upper_xor_0_2[6];
constraint 2*dummy_upper_xor_1_5[0] = (upper_rot_1_4[0] + upper_modadd_1_3[0] + upper_xor_1_5[0]);
constraint 2*dummy_upper_xor_1_5[1] = (upper_rot_1_4[1] + upper_modadd_1_3[1] + upper_xor_1_5[1]);
constraint 2*dummy_upper_xor_1_5[2] = (upper_rot_1_4[2] + upper_modadd_1_3[2] + upper_xor_1_5[2]);
constraint 2*dummy_upper_xor_1_5[3] = (upper_rot_1_4[3] + upper_modadd_1_3[3] + upper_xor_1_5[3]);
constraint 2*dummy_upper_xor_1_5[4] = (upper_rot_1_4[4] + upper_modadd_1_3[4] + upper_xor_1_5[4]);
constraint 2*dummy_upper_xor_1_5[5] = (upper_rot_1_4[5] + upper_modadd_1_3[5] + upper_xor_1_5[5]);
constraint 2*dummy_upper_xor_1_5[6] = (upper_rot_1_4[6] + upper_modadd_1_3[6] + upper_xor_1_5[6]);
constraint 2*dummy_upper_xor_1_5[7] = (upper_rot_1_4[7] + upper_modadd_1_3[7] + upper_xor_1_5[7]);
constraint 2*dummy_upper_xor_1_5[8] = (upper_rot_1_4[8] + upper_modadd_1_3[8] + upper_xor_1_5[8]);
constraint 2*dummy_upper_xor_1_5[9] = (upper_rot_1_4[9] + upper_modadd_1_3[9] + upper_xor_1_5[9]);
constraint 2*dummy_upper_xor_1_5[10] = (upper_rot_1_4[10] + upper_modadd_1_3[10] + upper_xor_1_5[10]);
constraint 2*dummy_upper_xor_1_5[11] = (upper_rot_1_4[11] + upper_modadd_1_3[11] + upper_xor_1_5[11]);
constraint 2*dummy_upper_xor_1_5[12] = (upper_rot_1_4[12] + upper_modadd_1_3[12] + upper_xor_1_5[12]);
constraint 2*dummy_upper_xor_1_5[13] = (upper_rot_1_4[13] + upper_modadd_1_3[13] + upper_xor_1_5[13]);
constraint 2*dummy_upper_xor_1_5[14] = (upper_rot_1_4[14] + upper_modadd_1_3[14] + upper_xor_1_5[14]);
constraint 2*dummy_upper_xor_1_5[15] = (upper_rot_1_4[15] + upper_modadd_1_3[15] + upper_xor_1_5[15]);
constraint upper_rot_1_6[0] = upper_modadd_1_3[0];
constraint upper_rot_1_6[1] = upper_modadd_1_3[1];
constraint upper_rot_1_6[2] = upper_modadd_1_3[2];
constraint upper_rot_1_6[3] = upper_modadd_1_3[3];
constraint upper_rot_1_6[4] = upper_modadd_1_3[4];
constraint upper_rot_1_6[5] = upper_modadd_1_3[5];
constraint upper_rot_1_6[6] = upper_modadd_1_3[6];
constraint upper_rot_1_6[7] = upper_modadd_1_3[7];
constraint upper_rot_1_6[8] = upper_modadd_1_3[8];
constraint upper_rot_1_6[9] = upper_modadd_1_3[9];
constraint upper_rot_1_6[10] = upper_modadd_1_3[10];
constraint upper_rot_1_6[11] = upper_modadd_1_3[11];
constraint upper_rot_1_6[12] = upper_modadd_1_3[12];
constraint upper_rot_1_6[13] = upper_modadd_1_3[13];
constraint upper_rot_1_6[14] = upper_modadd_1_3[14];
constraint upper_rot_1_6[15] = upper_modadd_1_3[15];
constraint upper_intermediate_output_1_7[0] = upper_modadd_1_0[0];
constraint upper_intermediate_output_1_7[1] = upper_modadd_1_0[1];
constraint upper_intermediate_output_1_7[2] = upper_modadd_1_0[2];
constraint upper_intermediate_output_1_7[3] = upper_modadd_1_0[3];
constraint upper_intermediate_output_1_7[4] = upper_modadd_1_0[4];
constraint upper_intermediate_output_1_7[5] = upper_modadd_1_0[5];
constraint upper_intermediate_output_1_7[6] = upper_modadd_1_0[6];
constraint upper_intermediate_output_1_7[7] = upper_modadd_1_0[7];
constraint upper_intermediate_output_1_7[8] = upper_modadd_1_0[8];
constraint upper_intermediate_output_1_7[9] = upper_modadd_1_0[9];
constraint upper_intermediate_output_1_7[10] = upper_modadd_1_0[10];
constraint upper_intermediate_output_1_7[11] = upper_modadd_1_0[11];
constraint upper_intermediate_output_1_7[12] = upper_modadd_1_0[12];
constraint upper_intermediate_output_1_7[13] = upper_modadd_1_0[13];
constraint upper_intermediate_output_1_7[14] = upper_modadd_1_0[14];
constraint upper_intermediate_output_1_7[15] = upper_modadd_1_0[15];
constraint upper_intermediate_output_1_7[16] = upper_xor_1_5[0];
constraint upper_intermediate_output_1_7[17] = upper_xor_1_5[1];
constraint upper_intermediate_output_1_7[18] = upper_xor_1_5[2];
constraint upper_intermediate_output_1_7[19] = upper_xor_1_5[3];
constraint upper_intermediate_output_1_7[20] = upper_xor_1_5[4];
constraint upper_intermediate_output_1_7[21] = upper_xor_1_5[5];
constraint upper_intermediate_output_1_7[22] = upper_xor_1_5[6];
constraint upper_intermediate_output_1_7[23] = upper_xor_1_5[7];
constraint upper_intermediate_output_1_7[24] = upper_xor_1_5[8];
constraint upper_intermediate_output_1_7[25] = upper_xor_1_5[9];
constraint upper_intermediate_output_1_7[26] = upper_xor_1_5[10];
constraint upper_intermediate_output_1_7[27] = upper_xor_1_5[11];
constraint upper_intermediate_output_1_7[28] = upper_xor_1_5[12];
constraint upper_intermediate_output_1_7[29] = upper_xor_1_5[13];
constraint upper_intermediate_output_1_7[30] = upper_xor_1_5[14];
constraint upper_intermediate_output_1_7[31] = upper_xor_1_5[15];
constraint upper_intermediate_output_1_7[32] = upper_rot_1_6[0];
constraint upper_intermediate_output_1_7[33] = upper_rot_1_6[1];
constraint upper_intermediate_output_1_7[34] = upper_rot_1_6[2];
constraint upper_intermediate_output_1_7[35] = upper_rot_1_6[3];
constraint upper_intermediate_output_1_7[36] = upper_rot_1_6[4];
constraint upper_intermediate_output_1_7[37] = upper_rot_1_6[5];
constraint upper_intermediate_output_1_7[38] = upper_rot_1_6[6];
constraint upper_intermediate_output_1_7[39] = upper_rot_1_6[7];
constraint upper_intermediate_output_1_7[40] = upper_rot_1_6[8];
constraint upper_intermediate_output_1_7[41] = upper_rot_1_6[9];
constraint upper_intermediate_output_1_7[42] = upper_rot_1_6[10];
constraint upper_intermediate_output_1_7[43] = upper_rot_1_6[11];
constraint upper_intermediate_output_1_7[44] = upper_rot_1_6[12];
constraint upper_intermediate_output_1_7[45] = upper_rot_1_6[13];
constraint upper_intermediate_output_1_7[46] = upper_rot_1_6[14];
constraint upper_intermediate_output_1_7[47] = upper_rot_1_6[15];
constraint upper_intermediate_output_1_7[48] = upper_xor_1_2[0];
constraint upper_intermediate_output_1_7[49] = upper_xor_1_2[1];
constraint upper_intermediate_output_1_7[50] = upper_xor_1_2[2];
constraint upper_intermediate_output_1_7[51] = upper_xor_1_2[3];
constraint upper_intermediate_output_1_7[52] = upper_xor_1_2[4];
constraint upper_intermediate_output_1_7[53] = upper_xor_1_2[5];
constraint upper_intermediate_output_1_7[54] = upper_xor_1_2[6];
constraint upper_intermediate_output_1_7[55] = upper_xor_1_2[7];
constraint upper_intermediate_output_1_7[56] = upper_xor_1_2[8];
constraint upper_intermediate_output_1_7[57] = upper_xor_1_2[9];
constraint upper_intermediate_output_1_7[58] = upper_xor_1_2[10];
constraint upper_intermediate_output_1_7[59] = upper_xor_1_2[11];
constraint upper_intermediate_output_1_7[60] = upper_xor_1_2[12];
constraint upper_intermediate_output_1_7[61] = upper_xor_1_2[13];
constraint upper_intermediate_output_1_7[62] = upper_xor_1_2[14];
constraint upper_intermediate_output_1_7[63] = upper_xor_1_2[15];
constraint pre_upper_modadd_2_0_0[0] = upper_modadd_1_0[0];
constraint pre_upper_modadd_2_0_0[1] = upper_modadd_1_0[1];
constraint pre_upper_modadd_2_0_0[2] = upper_modadd_1_0[2];
constraint pre_upper_modadd_2_0_0[3] = upper_modadd_1_0[3];
constraint pre_upper_modadd_2_0_0[4] = upper_modadd_1_0[4];
constraint pre_upper_modadd_2_0_0[5] = upper_modadd_1_0[5];
constraint pre_upper_modadd_2_0_0[6] = upper_modadd_1_0[6];
constraint pre_upper_modadd_2_0_0[7] = upper_modadd_1_0[7];
constraint pre_upper_modadd_2_0_0[8] = upper_modadd_1_0[8];
constraint pre_upper_modadd_2_0_0[9] = upper_modadd_1_0[9];
constraint pre_upper_modadd_2_0_0[10] = upper_modadd_1_0[10];
constraint pre_upper_modadd_2_0_0[11] = upper_modadd_1_0[11];
constraint pre_upper_modadd_2_0_0[12] = upper_modadd_1_0[12];
constraint pre_upper_modadd_2_0_0[13] = upper_modadd_1_0[13];
constraint pre_upper_modadd_2_0_0[14] = upper_modadd_1_0[14];
constraint pre_upper_modadd_2_0_0[15] = upper_modadd_1_0[15];
constraint pre_upper_modadd_2_0_1[0] = upper_xor_1_5[0];
constraint pre_upper_modadd_2_0_1[1] = upper_xor_1_5[1];
constraint pre_upper_modadd_2_0_1[2] = upper_xor_1_5[2];
constraint pre_upper_modadd_2_0_1[3] = upper_xor_1_5[3];
constraint pre_upper_modadd_2_0_1[4] = upper_xor_1_5[4];
constraint pre_upper_modadd_2_0_1[5] = upper_xor_1_5[5];
constraint pre_upper_modadd_2_0_1[6] = upper_xor_1_5[6];
constraint pre_upper_modadd_2_0_1[7] = upper_xor_1_5[7];
constraint pre_upper_modadd_2_0_1[8] = upper_xor_1_5[8];
constraint pre_upper_modadd_2_0_1[9] = upper_xor_1_5[9];
constraint pre_upper_modadd_2_0_1[10] = upper_xor_1_5[10];
constraint pre_upper_modadd_2_0_1[11] = upper_xor_1_5[11];
constraint pre_upper_modadd_2_0_1[12] = upper_xor_1_5[12];
constraint pre_upper_modadd_2_0_1[13] = upper_xor_1_5[13];
constraint pre_upper_modadd_2_0_1[14] = upper_xor_1_5[14];
constraint pre_upper_modadd_2_0_1[15] = upper_xor_1_5[15];
constraint forall(j in 0..15)(if eq_upper_modadd_2_0[j] = 1 then (sum([pre_upper_modadd_2_0_1[j], pre_upper_modadd_2_0_0[j], upper_modadd_2_0[j]]) mod 2) = Shi_pre_upper_modadd_2_0_0[j] else true endif) /\ upper_p[4] = (16-sum(eq_upper_modadd_2_0))*100;
constraint upper_rot_2_1[0] = upper_xor_1_5[5];
constraint upper_rot_2_1[1] = upper_xor_1_5[6];
constraint upper_rot_2_1[2] = upper_xor_1_5[7];
constraint upper_rot_2_1[3] = upper_xor_1_5[8];
constraint upper_rot_2_1[4] = upper_xor_1_5[9];
constraint upper_rot_2_1[5] = upper_xor_1_5[10];
constraint upper_rot_2_1[6] = upper_xor_1_5[11];
constraint upper_rot_2_1[7] = upper_xor_1_5[12];
constraint upper_rot_2_1[8] = upper_xor_1_5[13];
constraint upper_rot_2_1[9] = upper_xor_1_5[14];
constraint upper_rot_2_1[10] = upper_xor_1_5[15];
constraint upper_rot_2_1[11] = upper_xor_1_5[0];
constraint upper_rot_2_1[12] = upper_xor_1_5[1];
constraint upper_rot_2_1[13] = upper_xor_1_5[2];
constraint upper_rot_2_1[14] = upper_xor_1_5[3];
constraint upper_rot_2_1[15] = upper_xor_1_5[4];
constraint 2*dummy_upper_xor_2_2[0] = (upper_rot_2_1[0] + upper_modadd_2_0[0] + upper_xor_2_2[0]);
constraint 2*dummy_upper_xor_2_2[1] = (upper_rot_2_1[1] + upper_modadd_2_0[1] + upper_xor_2_2[1]);
constraint 2*dummy_upper_xor_2_2[2] = (upper_rot_2_1[2] + upper_modadd_2_0[2] + upper_xor_2_2[2]);
constraint 2*dummy_upper_xor_2_2[3] = (upper_rot_2_1[3] + upper_modadd_2_0[3] + upper_xor_2_2[3]);
constraint 2*dummy_upper_xor_2_2[4] = (upper_rot_2_1[4] + upper_modadd_2_0[4] + upper_xor_2_2[4]);
constraint 2*dummy_upper_xor_2_2[5] = (upper_rot_2_1[5] + upper_modadd_2_0[5] + upper_xor_2_2[5]);
constraint 2*dummy_upper_xor_2_2[6] = (upper_rot_2_1[6] + upper_modadd_2_0[6] + upper_xor_2_2[6]);
constraint 2*dummy_upper_xor_2_2[7] = (upper_rot_2_1[7] + upper_modadd_2_0[7] + upper_xor_2_2[7]);
constraint 2*dummy_upper_xor_2_2[8] = (upper_rot_2_1[8] + upper_modadd_2_0[8] + upper_xor_2_2[8]);
constraint 2*dummy_upper_xor_2_2[9] = (upper_rot_2_1[9] + upper_modadd_2_0[9] + upper_xor_2_2[9]);
constraint 2*dummy_upper_xor_2_2[10] = (upper_rot_2_1[10] + upper_modadd_2_0[10] + upper_xor_2_2[10]);
constraint 2*dummy_upper_xor_2_2[11] = (upper_rot_2_1[11] + upper_modadd_2_0[11] + upper_xor_2_2[11]);
constraint 2*dummy_upper_xor_2_2[12] = (upper_rot_2_1[12] + upper_modadd_2_0[12] + upper_xor_2_2[12]);
constraint 2*dummy_upper_xor_2_2[13] = (upper_rot_2_1[13] + upper_modadd_2_0[13] + upper_xor_2_2[13]);
constraint 2*dummy_upper_xor_2_2[14] = (upper_rot_2_1[14] + upper_modadd_2_0[14] + upper_xor_2_2[14]);
constraint 2*dummy_upper_xor_2_2[15] = (upper_rot_2_1[15] + upper_modadd_2_0[15] + upper_xor_2_2[15]);
constraint upper_rot_2_3[0] = upper_modadd_2_0[0];
constraint upper_rot_2_3[1] = upper_modadd_2_0[1];
constraint upper_rot_2_3[2] = upper_modadd_2_0[2];
constraint upper_rot_2_3[3] = upper_modadd_2_0[3];
constraint upper_rot_2_3[4] = upper_modadd_2_0[4];
constraint upper_rot_2_3[5] = upper_modadd_2_0[5];
constraint upper_rot_2_3[6] = upper_modadd_2_0[6];
constraint upper_rot_2_3[7] = upper_modadd_2_0[7];
constraint upper_rot_2_3[8] = upper_modadd_2_0[8];
constraint upper_rot_2_3[9] = upper_modadd_2_0[9];
constraint upper_rot_2_3[10] = upper_modadd_2_0[10];
constraint upper_rot_2_3[11] = upper_modadd_2_0[11];
constraint upper_rot_2_3[12] = upper_modadd_2_0[12];
constraint upper_rot_2_3[13] = upper_modadd_2_0[13];
constraint upper_rot_2_3[14] = upper_modadd_2_0[14];
constraint upper_rot_2_3[15] = upper_modadd_2_0[15];
constraint pre_upper_modadd_2_4_0[0] = upper_rot_1_6[0];
constraint pre_upper_modadd_2_4_0[1] = upper_rot_1_6[1];
constraint pre_upper_modadd_2_4_0[2] = upper_rot_1_6[2];
constraint pre_upper_modadd_2_4_0[3] = upper_rot_1_6[3];
constraint pre_upper_modadd_2_4_0[4] = upper_rot_1_6[4];
constraint pre_upper_modadd_2_4_0[5] = upper_rot_1_6[5];
constraint pre_upper_modadd_2_4_0[6] = upper_rot_1_6[6];
constraint pre_upper_modadd_2_4_0[7] = upper_rot_1_6[7];
constraint pre_upper_modadd_2_4_0[8] = upper_rot_1_6[8];
constraint pre_upper_modadd_2_4_0[9] = upper_rot_1_6[9];
constraint pre_upper_modadd_2_4_0[10] = upper_rot_1_6[10];
constraint pre_upper_modadd_2_4_0[11] = upper_rot_1_6[11];
constraint pre_upper_modadd_2_4_0[12] = upper_rot_1_6[12];
constraint pre_upper_modadd_2_4_0[13] = upper_rot_1_6[13];
constraint pre_upper_modadd_2_4_0[14] = upper_rot_1_6[14];
constraint pre_upper_modadd_2_4_0[15] = upper_rot_1_6[15];
constraint pre_upper_modadd_2_4_1[0] = upper_xor_1_2[0];
constraint pre_upper_modadd_2_4_1[1] = upper_xor_1_2[1];
constraint pre_upper_modadd_2_4_1[2] = upper_xor_1_2[2];
constraint pre_upper_modadd_2_4_1[3] = upper_xor_1_2[3];
constraint pre_upper_modadd_2_4_1[4] = upper_xor_1_2[4];
constraint pre_upper_modadd_2_4_1[5] = upper_xor_1_2[5];
constraint pre_upper_modadd_2_4_1[6] = upper_xor_1_2[6];
constraint pre_upper_modadd_2_4_1[7] = upper_xor_1_2[7];
constraint pre_upper_modadd_2_4_1[8] = upper_xor_1_2[8];
constraint pre_upper_modadd_2_4_1[9] = upper_xor_1_2[9];
constraint pre_upper_modadd_2_4_1[10] = upper_xor_1_2[10];
constraint pre_upper_modadd_2_4_1[11] = upper_xor_1_2[11];
constraint pre_upper_modadd_2_4_1[12] = upper_xor_1_2[12];
constraint pre_upper_modadd_2_4_1[13] = upper_xor_1_2[13];
constraint pre_upper_modadd_2_4_1[14] = upper_xor_1_2[14];
constraint pre_upper_modadd_2_4_1[15] = upper_xor_1_2[15];
constraint forall(j in 0..15)(if eq_upper_modadd_2_4[j] = 1 then (sum([pre_upper_modadd_2_4_1[j], pre_upper_modadd_2_4_0[j], upper_modadd_2_4[j]]) mod 2) = Shi_pre_upper_modadd_2_4_0[j] else true endif) /\ upper_p[5] = (16-sum(eq_upper_modadd_2_4))*100;
constraint upper_rot_2_5[0] = upper_xor_1_2[8];
constraint upper_rot_2_5[1] = upper_xor_1_2[9];
constraint upper_rot_2_5[2] = upper_xor_1_2[10];
constraint upper_rot_2_5[3] = upper_xor_1_2[11];
constraint upper_rot_2_5[4] = upper_xor_1_2[12];
constraint upper_rot_2_5[5] = upper_xor_1_2[13];
constraint upper_rot_2_5[6] = upper_xor_1_2[14];
constraint upper_rot_2_5[7] = upper_xor_1_2[15];
constraint upper_rot_2_5[8] = upper_xor_1_2[0];
constraint upper_rot_2_5[9] = upper_xor_1_2[1];
constraint upper_rot_2_5[10] = upper_xor_1_2[2];
constraint upper_rot_2_5[11] = upper_xor_1_2[3];
constraint upper_rot_2_5[12] = upper_xor_1_2[4];
constraint upper_rot_2_5[13] = upper_xor_1_2[5];
constraint upper_rot_2_5[14] = upper_xor_1_2[6];
constraint upper_rot_2_5[15] = upper_xor_1_2[7];
constraint 2*dummy_upper_xor_2_6[0] = (upper_rot_2_5[0] + upper_modadd_2_4[0] + upper_xor_2_6[0]);
constraint 2*dummy_upper_xor_2_6[1] = (upper_rot_2_5[1] + upper_modadd_2_4[1] + upper_xor_2_6[1]);
constraint 2*dummy_upper_xor_2_6[2] = (upper_rot_2_5[2] + upper_modadd_2_4[2] + upper_xor_2_6[2]);
constraint 2*dummy_upper_xor_2_6[3] = (upper_rot_2_5[3] + upper_modadd_2_4[3] + upper_xor_2_6[3]);
constraint 2*dummy_upper_xor_2_6[4] = (upper_rot_2_5[4] + upper_modadd_2_4[4] + upper_xor_2_6[4]);
constraint 2*dummy_upper_xor_2_6[5] = (upper_rot_2_5[5] + upper_modadd_2_4[5] + upper_xor_2_6[5]);
constraint 2*dummy_upper_xor_2_6[6] = (upper_rot_2_5[6] + upper_modadd_2_4[6] + upper_xor_2_6[6]);
constraint 2*dummy_upper_xor_2_6[7] = (upper_rot_2_5[7] + upper_modadd_2_4[7] + upper_xor_2_6[7]);
constraint 2*dummy_upper_xor_2_6[8] = (upper_rot_2_5[8] + upper_modadd_2_4[8] + upper_xor_2_6[8]);
constraint 2*dummy_upper_xor_2_6[9] = (upper_rot_2_5[9] + upper_modadd_2_4[9] + upper_xor_2_6[9]);
constraint 2*dummy_upper_xor_2_6[10] = (upper_rot_2_5[10] + upper_modadd_2_4[10] + upper_xor_2_6[10]);
constraint 2*dummy_upper_xor_2_6[11] = (upper_rot_2_5[11] + upper_modadd_2_4[11] + upper_xor_2_6[11]);
constraint 2*dummy_upper_xor_2_6[12] = (upper_rot_2_5[12] + upper_modadd_2_4[12] + upper_xor_2_6[12]);
constraint 2*dummy_upper_xor_2_6[13] = (upper_rot_2_5[13] + upper_modadd_2_4[13] + upper_xor_2_6[13]);
constraint 2*dummy_upper_xor_2_6[14] = (upper_rot_2_5[14] + upper_modadd_2_4[14] + upper_xor_2_6[14]);
constraint 2*dummy_upper_xor_2_6[15] = (upper_rot_2_5[15] + upper_modadd_2_4[15] + upper_xor_2_6[15]);
constraint upper_intermediate_output_2_7[0] = upper_rot_2_3[0];
constraint upper_intermediate_output_2_7[1] = upper_rot_2_3[1];
constraint upper_intermediate_output_2_7[2] = upper_rot_2_3[2];
constraint upper_intermediate_output_2_7[3] = upper_rot_2_3[3];
constraint upper_intermediate_output_2_7[4] = upper_rot_2_3[4];
constraint upper_intermediate_output_2_7[5] = upper_rot_2_3[5];
constraint upper_intermediate_output_2_7[6] = upper_rot_2_3[6];
constraint upper_intermediate_output_2_7[7] = upper_rot_2_3[7];
constraint upper_intermediate_output_2_7[8] = upper_rot_2_3[8];
constraint upper_intermediate_output_2_7[9] = upper_rot_2_3[9];
constraint upper_intermediate_output_2_7[10] = upper_rot_2_3[10];
constraint upper_intermediate_output_2_7[11] = upper_rot_2_3[11];
constraint upper_intermediate_output_2_7[12] = upper_rot_2_3[12];
constraint upper_intermediate_output_2_7[13] = upper_rot_2_3[13];
constraint upper_intermediate_output_2_7[14] = upper_rot_2_3[14];
constraint upper_intermediate_output_2_7[15] = upper_rot_2_3[15];
constraint upper_intermediate_output_2_7[16] = upper_xor_2_2[0];
constraint upper_intermediate_output_2_7[17] = upper_xor_2_2[1];
constraint upper_intermediate_output_2_7[18] = upper_xor_2_2[2];
constraint upper_intermediate_output_2_7[19] = upper_xor_2_2[3];
constraint upper_intermediate_output_2_7[20] = upper_xor_2_2[4];
constraint upper_intermediate_output_2_7[21] = upper_xor_2_2[5];
constraint upper_intermediate_output_2_7[22] = upper_xor_2_2[6];
constraint upper_intermediate_output_2_7[23] = upper_xor_2_2[7];
constraint upper_intermediate_output_2_7[24] = upper_xor_2_2[8];
constraint upper_intermediate_output_2_7[25] = upper_xor_2_2[9];
constraint upper_intermediate_output_2_7[26] = upper_xor_2_2[10];
constraint upper_intermediate_output_2_7[27] = upper_xor_2_2[11];
constraint upper_intermediate_output_2_7[28] = upper_xor_2_2[12];
constraint upper_intermediate_output_2_7[29] = upper_xor_2_2[13];
constraint upper_intermediate_output_2_7[30] = upper_xor_2_2[14];
constraint upper_intermediate_output_2_7[31] = upper_xor_2_2[15];
constraint upper_intermediate_output_2_7[32] = upper_modadd_2_4[0];
constraint upper_intermediate_output_2_7[33] = upper_modadd_2_4[1];
constraint upper_intermediate_output_2_7[34] = upper_modadd_2_4[2];
constraint upper_intermediate_output_2_7[35] = upper_modadd_2_4[3];
constraint upper_intermediate_output_2_7[36] = upper_modadd_2_4[4];
constraint upper_intermediate_output_2_7[37] = upper_modadd_2_4[5];
constraint upper_intermediate_output_2_7[38] = upper_modadd_2_4[6];
constraint upper_intermediate_output_2_7[39] = upper_modadd_2_4[7];
constraint upper_intermediate_output_2_7[40] = upper_modadd_2_4[8];
constraint upper_intermediate_output_2_7[41] = upper_modadd_2_4[9];
constraint upper_intermediate_output_2_7[42] = upper_modadd_2_4[10];
constraint upper_intermediate_output_2_7[43] = upper_modadd_2_4[11];
constraint upper_intermediate_output_2_7[44] = upper_modadd_2_4[12];
constraint upper_intermediate_output_2_7[45] = upper_modadd_2_4[13];
constraint upper_intermediate_output_2_7[46] = upper_modadd_2_4[14];
constraint upper_intermediate_output_2_7[47] = upper_modadd_2_4[15];
constraint upper_intermediate_output_2_7[48] = upper_xor_2_6[0];
constraint upper_intermediate_output_2_7[49] = upper_xor_2_6[1];
constraint upper_intermediate_output_2_7[50] = upper_xor_2_6[2];
constraint upper_intermediate_output_2_7[51] = upper_xor_2_6[3];
constraint upper_intermediate_output_2_7[52] = upper_xor_2_6[4];
constraint upper_intermediate_output_2_7[53] = upper_xor_2_6[5];
constraint upper_intermediate_output_2_7[54] = upper_xor_2_6[6];
constraint upper_intermediate_output_2_7[55] = upper_xor_2_6[7];
constraint upper_intermediate_output_2_7[56] = upper_xor_2_6[8];
constraint upper_intermediate_output_2_7[57] = upper_xor_2_6[9];
constraint upper_intermediate_output_2_7[58] = upper_xor_2_6[10];
constraint upper_intermediate_output_2_7[59] = upper_xor_2_6[11];
constraint upper_intermediate_output_2_7[60] = upper_xor_2_6[12];
constraint upper_intermediate_output_2_7[61] = upper_xor_2_6[13];
constraint upper_intermediate_output_2_7[62] = upper_xor_2_6[14];
constraint upper_intermediate_output_2_7[63] = upper_xor_2_6[15];
constraint pre_upper_modadd_3_0_0[0] = upper_rot_2_3[0];
constraint pre_upper_modadd_3_0_0[1] = upper_rot_2_3[1];
constraint pre_upper_modadd_3_0_0[2] = upper_rot_2_3[2];
constraint pre_upper_modadd_3_0_0[3] = upper_rot_2_3[3];
constraint pre_upper_modadd_3_0_0[4] = upper_rot_2_3[4];
constraint pre_upper_modadd_3_0_0[5] = upper_rot_2_3[5];
constraint pre_upper_modadd_3_0_0[6] = upper_rot_2_3[6];
constraint pre_upper_modadd_3_0_0[7] = upper_rot_2_3[7];
constraint pre_upper_modadd_3_0_0[8] = upper_rot_2_3[8];
constraint pre_upper_modadd_3_0_0[9] = upper_rot_2_3[9];
constraint pre_upper_modadd_3_0_0[10] = upper_rot_2_3[10];
constraint pre_upper_modadd_3_0_0[11] = upper_rot_2_3[11];
constraint pre_upper_modadd_3_0_0[12] = upper_rot_2_3[12];
constraint pre_upper_modadd_3_0_0[13] = upper_rot_2_3[13];
constraint pre_upper_modadd_3_0_0[14] = upper_rot_2_3[14];
constraint pre_upper_modadd_3_0_0[15] = upper_rot_2_3[15];
constraint pre_upper_modadd_3_0_1[0] = upper_xor_2_6[0];
constraint pre_upper_modadd_3_0_1[1] = upper_xor_2_6[1];
constraint pre_upper_modadd_3_0_1[2] = upper_xor_2_6[2];
constraint pre_upper_modadd_3_0_1[3] = upper_xor_2_6[3];
constraint pre_upper_modadd_3_0_1[4] = upper_xor_2_6[4];
constraint pre_upper_modadd_3_0_1[5] = upper_xor_2_6[5];
constraint pre_upper_modadd_3_0_1[6] = upper_xor_2_6[6];
constraint pre_upper_modadd_3_0_1[7] = upper_xor_2_6[7];
constraint pre_upper_modadd_3_0_1[8] = upper_xor_2_6[8];
constraint pre_upper_modadd_3_0_1[9] = upper_xor_2_6[9];
constraint pre_upper_modadd_3_0_1[10] = upper_xor_2_6[10];
constraint pre_upper_modadd_3_0_1[11] = upper_xor_2_6[11];
constraint pre_upper_modadd_3_0_1[12] = upper_xor_2_6[12];
constraint pre_upper_modadd_3_0_1[13] = upper_xor_2_6[13];
constraint pre_upper_modadd_3_0_1[14] = upper_xor_2_6[14];
constraint pre_upper_modadd_3_0_1[15] = upper_xor_2_6[15];
constraint forall(j in 0..15)(if eq_upper_modadd_3_0[j] = 1 then (sum([pre_upper_modadd_3_0_1[j], pre_upper_modadd_3_0_0[j], upper_modadd_3_0[j]]) mod 2) = Shi_pre_upper_modadd_3_0_0[j] else true endif) /\ upper_p[6] = (16-sum(eq_upper_modadd_3_0))*100;
constraint upper_rot_3_1[0] = upper_xor_2_6[13];
constraint upper_rot_3_1[1] = upper_xor_2_6[14];
constraint upper_rot_3_1[2] = upper_xor_2_6[15];
constraint upper_rot_3_1[3] = upper_xor_2_6[0];
constraint upper_rot_3_1[4] = upper_xor_2_6[1];
constraint upper_rot_3_1[5] = upper_xor_2_6[2];
constraint upper_rot_3_1[6] = upper_xor_2_6[3];
constraint upper_rot_3_1[7] = upper_xor_2_6[4];
constraint upper_rot_3_1[8] = upper_xor_2_6[5];
constraint upper_rot_3_1[9] = upper_xor_2_6[6];
constraint upper_rot_3_1[10] = upper_xor_2_6[7];
constraint upper_rot_3_1[11] = upper_xor_2_6[8];
constraint upper_rot_3_1[12] = upper_xor_2_6[9];
constraint upper_rot_3_1[13] = upper_xor_2_6[10];
constraint upper_rot_3_1[14] = upper_xor_2_6[11];
constraint upper_rot_3_1[15] = upper_xor_2_6[12];
constraint 2*dummy_upper_xor_3_2[0] = (upper_rot_3_1[0] + upper_modadd_3_0[0] + upper_xor_3_2[0]);
constraint 2*dummy_upper_xor_3_2[1] = (upper_rot_3_1[1] + upper_modadd_3_0[1] + upper_xor_3_2[1]);
constraint 2*dummy_upper_xor_3_2[2] = (upper_rot_3_1[2] + upper_modadd_3_0[2] + upper_xor_3_2[2]);
constraint 2*dummy_upper_xor_3_2[3] = (upper_rot_3_1[3] + upper_modadd_3_0[3] + upper_xor_3_2[3]);
constraint 2*dummy_upper_xor_3_2[4] = (upper_rot_3_1[4] + upper_modadd_3_0[4] + upper_xor_3_2[4]);
constraint 2*dummy_upper_xor_3_2[5] = (upper_rot_3_1[5] + upper_modadd_3_0[5] + upper_xor_3_2[5]);
constraint 2*dummy_upper_xor_3_2[6] = (upper_rot_3_1[6] + upper_modadd_3_0[6] + upper_xor_3_2[6]);
constraint 2*dummy_upper_xor_3_2[7] = (upper_rot_3_1[7] + upper_modadd_3_0[7] + upper_xor_3_2[7]);
constraint 2*dummy_upper_xor_3_2[8] = (upper_rot_3_1[8] + upper_modadd_3_0[8] + upper_xor_3_2[8]);
constraint 2*dummy_upper_xor_3_2[9] = (upper_rot_3_1[9] + upper_modadd_3_0[9] + upper_xor_3_2[9]);
constraint 2*dummy_upper_xor_3_2[10] = (upper_rot_3_1[10] + upper_modadd_3_0[10] + upper_xor_3_2[10]);
constraint 2*dummy_upper_xor_3_2[11] = (upper_rot_3_1[11] + upper_modadd_3_0[11] + upper_xor_3_2[11]);
constraint 2*dummy_upper_xor_3_2[12] = (upper_rot_3_1[12] + upper_modadd_3_0[12] + upper_xor_3_2[12]);
constraint 2*dummy_upper_xor_3_2[13] = (upper_rot_3_1[13] + upper_modadd_3_0[13] + upper_xor_3_2[13]);
constraint 2*dummy_upper_xor_3_2[14] = (upper_rot_3_1[14] + upper_modadd_3_0[14] + upper_xor_3_2[14]);
constraint 2*dummy_upper_xor_3_2[15] = (upper_rot_3_1[15] + upper_modadd_3_0[15] + upper_xor_3_2[15]);
constraint pre_upper_modadd_3_3_0[0] = upper_modadd_2_4[0];
constraint pre_upper_modadd_3_3_0[1] = upper_modadd_2_4[1];
constraint pre_upper_modadd_3_3_0[2] = upper_modadd_2_4[2];
constraint pre_upper_modadd_3_3_0[3] = upper_modadd_2_4[3];
constraint pre_upper_modadd_3_3_0[4] = upper_modadd_2_4[4];
constraint pre_upper_modadd_3_3_0[5] = upper_modadd_2_4[5];
constraint pre_upper_modadd_3_3_0[6] = upper_modadd_2_4[6];
constraint pre_upper_modadd_3_3_0[7] = upper_modadd_2_4[7];
constraint pre_upper_modadd_3_3_0[8] = upper_modadd_2_4[8];
constraint pre_upper_modadd_3_3_0[9] = upper_modadd_2_4[9];
constraint pre_upper_modadd_3_3_0[10] = upper_modadd_2_4[10];
constraint pre_upper_modadd_3_3_0[11] = upper_modadd_2_4[11];
constraint pre_upper_modadd_3_3_0[12] = upper_modadd_2_4[12];
constraint pre_upper_modadd_3_3_0[13] = upper_modadd_2_4[13];
constraint pre_upper_modadd_3_3_0[14] = upper_modadd_2_4[14];
constraint pre_upper_modadd_3_3_0[15] = upper_modadd_2_4[15];
constraint pre_upper_modadd_3_3_1[0] = upper_xor_2_2[0];
constraint pre_upper_modadd_3_3_1[1] = upper_xor_2_2[1];
constraint pre_upper_modadd_3_3_1[2] = upper_xor_2_2[2];
constraint pre_upper_modadd_3_3_1[3] = upper_xor_2_2[3];
constraint pre_upper_modadd_3_3_1[4] = upper_xor_2_2[4];
constraint pre_upper_modadd_3_3_1[5] = upper_xor_2_2[5];
constraint pre_upper_modadd_3_3_1[6] = upper_xor_2_2[6];
constraint pre_upper_modadd_3_3_1[7] = upper_xor_2_2[7];
constraint pre_upper_modadd_3_3_1[8] = upper_xor_2_2[8];
constraint pre_upper_modadd_3_3_1[9] = upper_xor_2_2[9];
constraint pre_upper_modadd_3_3_1[10] = upper_xor_2_2[10];
constraint pre_upper_modadd_3_3_1[11] = upper_xor_2_2[11];
constraint pre_upper_modadd_3_3_1[12] = upper_xor_2_2[12];
constraint pre_upper_modadd_3_3_1[13] = upper_xor_2_2[13];
constraint pre_upper_modadd_3_3_1[14] = upper_xor_2_2[14];
constraint pre_upper_modadd_3_3_1[15] = upper_xor_2_2[15];
constraint forall(j in 0..15)(if eq_upper_modadd_3_3[j] = 1 then (sum([pre_upper_modadd_3_3_1[j], pre_upper_modadd_3_3_0[j], upper_modadd_3_3[j]]) mod 2) = Shi_pre_upper_modadd_3_3_0[j] else true endif) /\ upper_p[7] = (16-sum(eq_upper_modadd_3_3))*100;
constraint upper_rot_3_4[0] = upper_xor_2_2[7];
constraint upper_rot_3_4[1] = upper_xor_2_2[8];
constraint upper_rot_3_4[2] = upper_xor_2_2[9];
constraint upper_rot_3_4[3] = upper_xor_2_2[10];
constraint upper_rot_3_4[4] = upper_xor_2_2[11];
constraint upper_rot_3_4[5] = upper_xor_2_2[12];
constraint upper_rot_3_4[6] = upper_xor_2_2[13];
constraint upper_rot_3_4[7] = upper_xor_2_2[14];
constraint upper_rot_3_4[8] = upper_xor_2_2[15];
constraint upper_rot_3_4[9] = upper_xor_2_2[0];
constraint upper_rot_3_4[10] = upper_xor_2_2[1];
constraint upper_rot_3_4[11] = upper_xor_2_2[2];
constraint upper_rot_3_4[12] = upper_xor_2_2[3];
constraint upper_rot_3_4[13] = upper_xor_2_2[4];
constraint upper_rot_3_4[14] = upper_xor_2_2[5];
constraint upper_rot_3_4[15] = upper_xor_2_2[6];
constraint 2*dummy_upper_xor_3_5[0] = (upper_rot_3_4[0] + upper_modadd_3_3[0] + upper_xor_3_5[0]);
constraint 2*dummy_upper_xor_3_5[1] = (upper_rot_3_4[1] + upper_modadd_3_3[1] + upper_xor_3_5[1]);
constraint 2*dummy_upper_xor_3_5[2] = (upper_rot_3_4[2] + upper_modadd_3_3[2] + upper_xor_3_5[2]);
constraint 2*dummy_upper_xor_3_5[3] = (upper_rot_3_4[3] + upper_modadd_3_3[3] + upper_xor_3_5[3]);
constraint 2*dummy_upper_xor_3_5[4] = (upper_rot_3_4[4] + upper_modadd_3_3[4] + upper_xor_3_5[4]);
constraint 2*dummy_upper_xor_3_5[5] = (upper_rot_3_4[5] + upper_modadd_3_3[5] + upper_xor_3_5[5]);
constraint 2*dummy_upper_xor_3_5[6] = (upper_rot_3_4[6] + upper_modadd_3_3[6] + upper_xor_3_5[6]);
constraint 2*dummy_upper_xor_3_5[7] = (upper_rot_3_4[7] + upper_modadd_3_3[7] + upper_xor_3_5[7]);
constraint 2*dummy_upper_xor_3_5[8] = (upper_rot_3_4[8] + upper_modadd_3_3[8] + upper_xor_3_5[8]);
constraint 2*dummy_upper_xor_3_5[9] = (upper_rot_3_4[9] + upper_modadd_3_3[9] + upper_xor_3_5[9]);
constraint 2*dummy_upper_xor_3_5[10] = (upper_rot_3_4[10] + upper_modadd_3_3[10] + upper_xor_3_5[10]);
constraint 2*dummy_upper_xor_3_5[11] = (upper_rot_3_4[11] + upper_modadd_3_3[11] + upper_xor_3_5[11]);
constraint 2*dummy_upper_xor_3_5[12] = (upper_rot_3_4[12] + upper_modadd_3_3[12] + upper_xor_3_5[12]);
constraint 2*dummy_upper_xor_3_5[13] = (upper_rot_3_4[13] + upper_modadd_3_3[13] + upper_xor_3_5[13]);
constraint 2*dummy_upper_xor_3_5[14] = (upper_rot_3_4[14] + upper_modadd_3_3[14] + upper_xor_3_5[14]);
constraint 2*dummy_upper_xor_3_5[15] = (upper_rot_3_4[15] + upper_modadd_3_3[15] + upper_xor_3_5[15]);
constraint upper_rot_3_6[0] = upper_modadd_3_3[0];
constraint upper_rot_3_6[1] = upper_modadd_3_3[1];
constraint upper_rot_3_6[2] = upper_modadd_3_3[2];
constraint upper_rot_3_6[3] = upper_modadd_3_3[3];
constraint upper_rot_3_6[4] = upper_modadd_3_3[4];
constraint upper_rot_3_6[5] = upper_modadd_3_3[5];
constraint upper_rot_3_6[6] = upper_modadd_3_3[6];
constraint upper_rot_3_6[7] = upper_modadd_3_3[7];
constraint upper_rot_3_6[8] = upper_modadd_3_3[8];
constraint upper_rot_3_6[9] = upper_modadd_3_3[9];
constraint upper_rot_3_6[10] = upper_modadd_3_3[10];
constraint upper_rot_3_6[11] = upper_modadd_3_3[11];
constraint upper_rot_3_6[12] = upper_modadd_3_3[12];
constraint upper_rot_3_6[13] = upper_modadd_3_3[13];
constraint upper_rot_3_6[14] = upper_modadd_3_3[14];
constraint upper_rot_3_6[15] = upper_modadd_3_3[15];
constraint upper_intermediate_output_3_7[0] = upper_modadd_3_0[0];
constraint upper_intermediate_output_3_7[1] = upper_modadd_3_0[1];
constraint upper_intermediate_output_3_7[2] = upper_modadd_3_0[2];
constraint upper_intermediate_output_3_7[3] = upper_modadd_3_0[3];
constraint upper_intermediate_output_3_7[4] = upper_modadd_3_0[4];
constraint upper_intermediate_output_3_7[5] = upper_modadd_3_0[5];
constraint upper_intermediate_output_3_7[6] = upper_modadd_3_0[6];
constraint upper_intermediate_output_3_7[7] = upper_modadd_3_0[7];
constraint upper_intermediate_output_3_7[8] = upper_modadd_3_0[8];
constraint upper_intermediate_output_3_7[9] = upper_modadd_3_0[9];
constraint upper_intermediate_output_3_7[10] = upper_modadd_3_0[10];
constraint upper_intermediate_output_3_7[11] = upper_modadd_3_0[11];
constraint upper_intermediate_output_3_7[12] = upper_modadd_3_0[12];
constraint upper_intermediate_output_3_7[13] = upper_modadd_3_0[13];
constraint upper_intermediate_output_3_7[14] = upper_modadd_3_0[14];
constraint upper_intermediate_output_3_7[15] = upper_modadd_3_0[15];
constraint upper_intermediate_output_3_7[16] = upper_xor_3_5[0];
constraint upper_intermediate_output_3_7[17] = upper_xor_3_5[1];
constraint upper_intermediate_output_3_7[18] = upper_xor_3_5[2];
constraint upper_intermediate_output_3_7[19] = upper_xor_3_5[3];
constraint upper_intermediate_output_3_7[20] = upper_xor_3_5[4];
constraint upper_intermediate_output_3_7[21] = upper_xor_3_5[5];
constraint upper_intermediate_output_3_7[22] = upper_xor_3_5[6];
constraint upper_intermediate_output_3_7[23] = upper_xor_3_5[7];
constraint upper_intermediate_output_3_7[24] = upper_xor_3_5[8];
constraint upper_intermediate_output_3_7[25] = upper_xor_3_5[9];
constraint upper_intermediate_output_3_7[26] = upper_xor_3_5[10];
constraint upper_intermediate_output_3_7[27] = upper_xor_3_5[11];
constraint upper_intermediate_output_3_7[28] = upper_xor_3_5[12];
constraint upper_intermediate_output_3_7[29] = upper_xor_3_5[13];
constraint upper_intermediate_output_3_7[30] = upper_xor_3_5[14];
constraint upper_intermediate_output_3_7[31] = upper_xor_3_5[15];
constraint upper_intermediate_output_3_7[32] = upper_rot_3_6[0];
constraint upper_intermediate_output_3_7[33] = upper_rot_3_6[1];
constraint upper_intermediate_output_3_7[34] = upper_rot_3_6[2];
constraint upper_intermediate_output_3_7[35] = upper_rot_3_6[3];
constraint upper_intermediate_output_3_7[36] = upper_rot_3_6[4];
constraint upper_intermediate_output_3_7[37] = upper_rot_3_6[5];
constraint upper_intermediate_output_3_7[38] = upper_rot_3_6[6];
constraint upper_intermediate_output_3_7[39] = upper_rot_3_6[7];
constraint upper_intermediate_output_3_7[40] = upper_rot_3_6[8];
constraint upper_intermediate_output_3_7[41] = upper_rot_3_6[9];
constraint upper_intermediate_output_3_7[42] = upper_rot_3_6[10];
constraint upper_intermediate_output_3_7[43] = upper_rot_3_6[11];
constraint upper_intermediate_output_3_7[44] = upper_rot_3_6[12];
constraint upper_intermediate_output_3_7[45] = upper_rot_3_6[13];
constraint upper_intermediate_output_3_7[46] = upper_rot_3_6[14];
constraint upper_intermediate_output_3_7[47] = upper_rot_3_6[15];
constraint upper_intermediate_output_3_7[48] = upper_xor_3_2[0];
constraint upper_intermediate_output_3_7[49] = upper_xor_3_2[1];
constraint upper_intermediate_output_3_7[50] = upper_xor_3_2[2];
constraint upper_intermediate_output_3_7[51] = upper_xor_3_2[3];
constraint upper_intermediate_output_3_7[52] = upper_xor_3_2[4];
constraint upper_intermediate_output_3_7[53] = upper_xor_3_2[5];
constraint upper_intermediate_output_3_7[54] = upper_xor_3_2[6];
constraint upper_intermediate_output_3_7[55] = upper_xor_3_2[7];
constraint upper_intermediate_output_3_7[56] = upper_xor_3_2[8];
constraint upper_intermediate_output_3_7[57] = upper_xor_3_2[9];
constraint upper_intermediate_output_3_7[58] = upper_xor_3_2[10];
constraint upper_intermediate_output_3_7[59] = upper_xor_3_2[11];
constraint upper_intermediate_output_3_7[60] = upper_xor_3_2[12];
constraint upper_intermediate_output_3_7[61] = upper_xor_3_2[13];
constraint upper_intermediate_output_3_7[62] = upper_xor_3_2[14];
constraint upper_intermediate_output_3_7[63] = upper_xor_3_2[15];
constraint 2*dummy_lower_xor_3_2[0] = (lower_modadd_4_0[0] + lower_rot_4_5[0] + lower_xor_3_2[0]);
constraint 2*dummy_lower_xor_3_2[1] = (lower_modadd_4_0[1] + lower_rot_4_5[1] + lower_xor_3_2[1]);
constraint 2*dummy_lower_xor_3_2[2] = (lower_modadd_4_0[2] + lower_rot_4_5[2] + lower_xor_3_2[2]);
constraint 2*dummy_lower_xor_3_2[3] = (lower_modadd_4_0[3] + lower_rot_4_5[3] + lower_xor_3_2[3]);
constraint 2*dummy_lower_xor_3_2[4] = (lower_modadd_4_0[4] + lower_rot_4_5[4] + lower_xor_3_2[4]);
constraint 2*dummy_lower_xor_3_2[5] = (lower_modadd_4_0[5] + lower_rot_4_5[5] + lower_xor_3_2[5]);
constraint 2*dummy_lower_xor_3_2[6] = (lower_modadd_4_0[6] + lower_rot_4_5[6] + lower_xor_3_2[6]);
constraint 2*dummy_lower_xor_3_2[7] = (lower_modadd_4_0[7] + lower_rot_4_5[7] + lower_xor_3_2[7]);
constraint 2*dummy_lower_xor_3_2[8] = (lower_modadd_4_0[8] + lower_rot_4_5[8] + lower_xor_3_2[8]);
constraint 2*dummy_lower_xor_3_2[9] = (lower_modadd_4_0[9] + lower_rot_4_5[9] + lower_xor_3_2[9]);
constraint 2*dummy_lower_xor_3_2[10] = (lower_modadd_4_0[10] + lower_rot_4_5[10] + lower_xor_3_2[10]);
constraint 2*dummy_lower_xor_3_2[11] = (lower_modadd_4_0[11] + lower_rot_4_5[11] + lower_xor_3_2[11]);
constraint 2*dummy_lower_xor_3_2[12] = (lower_modadd_4_0[12] + lower_rot_4_5[12] + lower_xor_3_2[12]);
constraint 2*dummy_lower_xor_3_2[13] = (lower_modadd_4_0[13] + lower_rot_4_5[13] + lower_xor_3_2[13]);
constraint 2*dummy_lower_xor_3_2[14] = (lower_modadd_4_0[14] + lower_rot_4_5[14] + lower_xor_3_2[14]);
constraint 2*dummy_lower_xor_3_2[15] = (lower_modadd_4_0[15] + lower_rot_4_5[15] + lower_xor_3_2[15]);
constraint lower_rot_3_6[0] = lower_modadd_4_4[0];
constraint lower_rot_3_6[1] = lower_modadd_4_4[1];
constraint lower_rot_3_6[2] = lower_modadd_4_4[2];
constraint lower_rot_3_6[3] = lower_modadd_4_4[3];
constraint lower_rot_3_6[4] = lower_modadd_4_4[4];
constraint lower_rot_3_6[5] = lower_modadd_4_4[5];
constraint lower_rot_3_6[6] = lower_modadd_4_4[6];
constraint lower_rot_3_6[7] = lower_modadd_4_4[7];
constraint lower_rot_3_6[8] = lower_modadd_4_4[8];
constraint lower_rot_3_6[9] = lower_modadd_4_4[9];
constraint lower_rot_3_6[10] = lower_modadd_4_4[10];
constraint lower_rot_3_6[11] = lower_modadd_4_4[11];
constraint lower_rot_3_6[12] = lower_modadd_4_4[12];
constraint lower_rot_3_6[13] = lower_modadd_4_4[13];
constraint lower_rot_3_6[14] = lower_modadd_4_4[14];
constraint lower_rot_3_6[15] = lower_modadd_4_4[15];
constraint lower_intermediate_output_3_7[0] = lower_modadd_4_0[0];
constraint lower_intermediate_output_3_7[1] = lower_modadd_4_0[1];
constraint lower_intermediate_output_3_7[2] = lower_modadd_4_0[2];
constraint lower_intermediate_output_3_7[3] = lower_modadd_4_0[3];
constraint lower_intermediate_output_3_7[4] = lower_modadd_4_0[4];
constraint lower_intermediate_output_3_7[5] = lower_modadd_4_0[5];
constraint lower_intermediate_output_3_7[6] = lower_modadd_4_0[6];
constraint lower_intermediate_output_3_7[7] = lower_modadd_4_0[7];
constraint lower_intermediate_output_3_7[8] = lower_modadd_4_0[8];
constraint lower_intermediate_output_3_7[9] = lower_modadd_4_0[9];
constraint lower_intermediate_output_3_7[10] = lower_modadd_4_0[10];
constraint lower_intermediate_output_3_7[11] = lower_modadd_4_0[11];
constraint lower_intermediate_output_3_7[12] = lower_modadd_4_0[12];
constraint lower_intermediate_output_3_7[13] = lower_modadd_4_0[13];
constraint lower_intermediate_output_3_7[14] = lower_modadd_4_0[14];
constraint lower_intermediate_output_3_7[15] = lower_modadd_4_0[15];
constraint lower_intermediate_output_3_7[16] = lower_rot_4_1[0];
constraint lower_intermediate_output_3_7[17] = lower_rot_4_1[1];
constraint lower_intermediate_output_3_7[18] = lower_rot_4_1[2];
constraint lower_intermediate_output_3_7[19] = lower_rot_4_1[3];
constraint lower_intermediate_output_3_7[20] = lower_rot_4_1[4];
constraint lower_intermediate_output_3_7[21] = lower_rot_4_1[5];
constraint lower_intermediate_output_3_7[22] = lower_rot_4_1[6];
constraint lower_intermediate_output_3_7[23] = lower_rot_4_1[7];
constraint lower_intermediate_output_3_7[24] = lower_rot_4_1[8];
constraint lower_intermediate_output_3_7[25] = lower_rot_4_1[9];
constraint lower_intermediate_output_3_7[26] = lower_rot_4_1[10];
constraint lower_intermediate_output_3_7[27] = lower_rot_4_1[11];
constraint lower_intermediate_output_3_7[28] = lower_rot_4_1[12];
constraint lower_intermediate_output_3_7[29] = lower_rot_4_1[13];
constraint lower_intermediate_output_3_7[30] = lower_rot_4_1[14];
constraint lower_intermediate_output_3_7[31] = lower_rot_4_1[15];
constraint lower_intermediate_output_3_7[32] = lower_modadd_4_4[0];
constraint lower_intermediate_output_3_7[33] = lower_modadd_4_4[1];
constraint lower_intermediate_output_3_7[34] = lower_modadd_4_4[2];
constraint lower_intermediate_output_3_7[35] = lower_modadd_4_4[3];
constraint lower_intermediate_output_3_7[36] = lower_modadd_4_4[4];
constraint lower_intermediate_output_3_7[37] = lower_modadd_4_4[5];
constraint lower_intermediate_output_3_7[38] = lower_modadd_4_4[6];
constraint lower_intermediate_output_3_7[39] = lower_modadd_4_4[7];
constraint lower_intermediate_output_3_7[40] = lower_modadd_4_4[8];
constraint lower_intermediate_output_3_7[41] = lower_modadd_4_4[9];
constraint lower_intermediate_output_3_7[42] = lower_modadd_4_4[10];
constraint lower_intermediate_output_3_7[43] = lower_modadd_4_4[11];
constraint lower_intermediate_output_3_7[44] = lower_modadd_4_4[12];
constraint lower_intermediate_output_3_7[45] = lower_modadd_4_4[13];
constraint lower_intermediate_output_3_7[46] = lower_modadd_4_4[14];
constraint lower_intermediate_output_3_7[47] = lower_modadd_4_4[15];
constraint lower_intermediate_output_3_7[48] = lower_rot_4_5[0];
constraint lower_intermediate_output_3_7[49] = lower_rot_4_5[1];
constraint lower_intermediate_output_3_7[50] = lower_rot_4_5[2];
constraint lower_intermediate_output_3_7[51] = lower_rot_4_5[3];
constraint lower_intermediate_output_3_7[52] = lower_rot_4_5[4];
constraint lower_intermediate_output_3_7[53] = lower_rot_4_5[5];
constraint lower_intermediate_output_3_7[54] = lower_rot_4_5[6];
constraint lower_intermediate_output_3_7[55] = lower_rot_4_5[7];
constraint lower_intermediate_output_3_7[56] = lower_rot_4_5[8];
constraint lower_intermediate_output_3_7[57] = lower_rot_4_5[9];
constraint lower_intermediate_output_3_7[58] = lower_rot_4_5[10];
constraint lower_intermediate_output_3_7[59] = lower_rot_4_5[11];
constraint lower_intermediate_output_3_7[60] = lower_rot_4_5[12];
constraint lower_intermediate_output_3_7[61] = lower_rot_4_5[13];
constraint lower_intermediate_output_3_7[62] = lower_rot_4_5[14];
constraint lower_intermediate_output_3_7[63] = lower_rot_4_5[15];
constraint lower_rot_3_1[0] = lower_xor_3_2[3];
constraint lower_rot_3_1[1] = lower_xor_3_2[4];
constraint lower_rot_3_1[2] = lower_xor_3_2[5];
constraint lower_rot_3_1[3] = lower_xor_3_2[6];
constraint lower_rot_3_1[4] = lower_xor_3_2[7];
constraint lower_rot_3_1[5] = lower_xor_3_2[8];
constraint lower_rot_3_1[6] = lower_xor_3_2[9];
constraint lower_rot_3_1[7] = lower_xor_3_2[10];
constraint lower_rot_3_1[8] = lower_xor_3_2[11];
constraint lower_rot_3_1[9] = lower_xor_3_2[12];
constraint lower_rot_3_1[10] = lower_xor_3_2[13];
constraint lower_rot_3_1[11] = lower_xor_3_2[14];
constraint lower_rot_3_1[12] = lower_xor_3_2[15];
constraint lower_rot_3_1[13] = lower_xor_3_2[0];
constraint lower_rot_3_1[14] = lower_xor_3_2[1];
constraint lower_rot_3_1[15] = lower_xor_3_2[2];
constraint 2*dummy_lower_xor_3_5[0] = (lower_rot_3_6[0] + lower_rot_4_1[0] + lower_xor_3_5[0]);
constraint 2*dummy_lower_xor_3_5[1] = (lower_rot_3_6[1] + lower_rot_4_1[1] + lower_xor_3_5[1]);
constraint 2*dummy_lower_xor_3_5[2] = (lower_rot_3_6[2] + lower_rot_4_1[2] + lower_xor_3_5[2]);
constraint 2*dummy_lower_xor_3_5[3] = (lower_rot_3_6[3] + lower_rot_4_1[3] + lower_xor_3_5[3]);
constraint 2*dummy_lower_xor_3_5[4] = (lower_rot_3_6[4] + lower_rot_4_1[4] + lower_xor_3_5[4]);
constraint 2*dummy_lower_xor_3_5[5] = (lower_rot_3_6[5] + lower_rot_4_1[5] + lower_xor_3_5[5]);
constraint 2*dummy_lower_xor_3_5[6] = (lower_rot_3_6[6] + lower_rot_4_1[6] + lower_xor_3_5[6]);
constraint 2*dummy_lower_xor_3_5[7] = (lower_rot_3_6[7] + lower_rot_4_1[7] + lower_xor_3_5[7]);
constraint 2*dummy_lower_xor_3_5[8] = (lower_rot_3_6[8] + lower_rot_4_1[8] + lower_xor_3_5[8]);
constraint 2*dummy_lower_xor_3_5[9] = (lower_rot_3_6[9] + lower_rot_4_1[9] + lower_xor_3_5[9]);
constraint 2*dummy_lower_xor_3_5[10] = (lower_rot_3_6[10] + lower_rot_4_1[10] + lower_xor_3_5[10]);
constraint 2*dummy_lower_xor_3_5[11] = (lower_rot_3_6[11] + lower_rot_4_1[11] + lower_xor_3_5[11]);
constraint 2*dummy_lower_xor_3_5[12] = (lower_rot_3_6[12] + lower_rot_4_1[12] + lower_xor_3_5[12]);
constraint 2*dummy_lower_xor_3_5[13] = (lower_rot_3_6[13] + lower_rot_4_1[13] + lower_xor_3_5[13]);
constraint 2*dummy_lower_xor_3_5[14] = (lower_rot_3_6[14] + lower_rot_4_1[14] + lower_xor_3_5[14]);
constraint 2*dummy_lower_xor_3_5[15] = (lower_rot_3_6[15] + lower_rot_4_1[15] + lower_xor_3_5[15]);
constraint pre_lower_modadd_3_0_0[0] = lower_modadd_4_0[0];
constraint pre_lower_modadd_3_0_0[1] = lower_modadd_4_0[1];
constraint pre_lower_modadd_3_0_0[2] = lower_modadd_4_0[2];
constraint pre_lower_modadd_3_0_0[3] = lower_modadd_4_0[3];
constraint pre_lower_modadd_3_0_0[4] = lower_modadd_4_0[4];
constraint pre_lower_modadd_3_0_0[5] = lower_modadd_4_0[5];
constraint pre_lower_modadd_3_0_0[6] = lower_modadd_4_0[6];
constraint pre_lower_modadd_3_0_0[7] = lower_modadd_4_0[7];
constraint pre_lower_modadd_3_0_0[8] = lower_modadd_4_0[8];
constraint pre_lower_modadd_3_0_0[9] = lower_modadd_4_0[9];
constraint pre_lower_modadd_3_0_0[10] = lower_modadd_4_0[10];
constraint pre_lower_modadd_3_0_0[11] = lower_modadd_4_0[11];
constraint pre_lower_modadd_3_0_0[12] = lower_modadd_4_0[12];
constraint pre_lower_modadd_3_0_0[13] = lower_modadd_4_0[13];
constraint pre_lower_modadd_3_0_0[14] = lower_modadd_4_0[14];
constraint pre_lower_modadd_3_0_0[15] = lower_modadd_4_0[15];
constraint pre_lower_modadd_3_0_1[0] = lower_rot_3_1[0];
constraint pre_lower_modadd_3_0_1[1] = lower_rot_3_1[1];
constraint pre_lower_modadd_3_0_1[2] = lower_rot_3_1[2];
constraint pre_lower_modadd_3_0_1[3] = lower_rot_3_1[3];
constraint pre_lower_modadd_3_0_1[4] = lower_rot_3_1[4];
constraint pre_lower_modadd_3_0_1[5] = lower_rot_3_1[5];
constraint pre_lower_modadd_3_0_1[6] = lower_rot_3_1[6];
constraint pre_lower_modadd_3_0_1[7] = lower_rot_3_1[7];
constraint pre_lower_modadd_3_0_1[8] = lower_rot_3_1[8];
constraint pre_lower_modadd_3_0_1[9] = lower_rot_3_1[9];
constraint pre_lower_modadd_3_0_1[10] = lower_rot_3_1[10];
constraint pre_lower_modadd_3_0_1[11] = lower_rot_3_1[11];
constraint pre_lower_modadd_3_0_1[12] = lower_rot_3_1[12];
constraint pre_lower_modadd_3_0_1[13] = lower_rot_3_1[13];
constraint pre_lower_modadd_3_0_1[14] = lower_rot_3_1[14];
constraint pre_lower_modadd_3_0_1[15] = lower_rot_3_1[15];
constraint forall(j in 0..15)(if eq_lower_modadd_3_0[j] = 1 then (sum([pre_lower_modadd_3_0_1[j], pre_lower_modadd_3_0_0[j], lower_modadd_3_0[j]]) mod 2) = Shi_pre_lower_modadd_3_0_0[j] else true endif) /\ lower_p[0] = (16-sum(eq_lower_modadd_3_0))*100;
constraint lower_rot_3_4[0] = lower_xor_3_5[9];
constraint lower_rot_3_4[1] = lower_xor_3_5[10];
constraint lower_rot_3_4[2] = lower_xor_3_5[11];
constraint lower_rot_3_4[3] = lower_xor_3_5[12];
constraint lower_rot_3_4[4] = lower_xor_3_5[13];
constraint lower_rot_3_4[5] = lower_xor_3_5[14];
constraint lower_rot_3_4[6] = lower_xor_3_5[15];
constraint lower_rot_3_4[7] = lower_xor_3_5[0];
constraint lower_rot_3_4[8] = lower_xor_3_5[1];
constraint lower_rot_3_4[9] = lower_xor_3_5[2];
constraint lower_rot_3_4[10] = lower_xor_3_5[3];
constraint lower_rot_3_4[11] = lower_xor_3_5[4];
constraint lower_rot_3_4[12] = lower_xor_3_5[5];
constraint lower_rot_3_4[13] = lower_xor_3_5[6];
constraint lower_rot_3_4[14] = lower_xor_3_5[7];
constraint lower_rot_3_4[15] = lower_xor_3_5[8];
constraint pre_lower_modadd_3_3_0[0] = lower_rot_3_6[0];
constraint pre_lower_modadd_3_3_0[1] = lower_rot_3_6[1];
constraint pre_lower_modadd_3_3_0[2] = lower_rot_3_6[2];
constraint pre_lower_modadd_3_3_0[3] = lower_rot_3_6[3];
constraint pre_lower_modadd_3_3_0[4] = lower_rot_3_6[4];
constraint pre_lower_modadd_3_3_0[5] = lower_rot_3_6[5];
constraint pre_lower_modadd_3_3_0[6] = lower_rot_3_6[6];
constraint pre_lower_modadd_3_3_0[7] = lower_rot_3_6[7];
constraint pre_lower_modadd_3_3_0[8] = lower_rot_3_6[8];
constraint pre_lower_modadd_3_3_0[9] = lower_rot_3_6[9];
constraint pre_lower_modadd_3_3_0[10] = lower_rot_3_6[10];
constraint pre_lower_modadd_3_3_0[11] = lower_rot_3_6[11];
constraint pre_lower_modadd_3_3_0[12] = lower_rot_3_6[12];
constraint pre_lower_modadd_3_3_0[13] = lower_rot_3_6[13];
constraint pre_lower_modadd_3_3_0[14] = lower_rot_3_6[14];
constraint pre_lower_modadd_3_3_0[15] = lower_rot_3_6[15];
constraint pre_lower_modadd_3_3_1[0] = lower_rot_3_4[0];
constraint pre_lower_modadd_3_3_1[1] = lower_rot_3_4[1];
constraint pre_lower_modadd_3_3_1[2] = lower_rot_3_4[2];
constraint pre_lower_modadd_3_3_1[3] = lower_rot_3_4[3];
constraint pre_lower_modadd_3_3_1[4] = lower_rot_3_4[4];
constraint pre_lower_modadd_3_3_1[5] = lower_rot_3_4[5];
constraint pre_lower_modadd_3_3_1[6] = lower_rot_3_4[6];
constraint pre_lower_modadd_3_3_1[7] = lower_rot_3_4[7];
constraint pre_lower_modadd_3_3_1[8] = lower_rot_3_4[8];
constraint pre_lower_modadd_3_3_1[9] = lower_rot_3_4[9];
constraint pre_lower_modadd_3_3_1[10] = lower_rot_3_4[10];
constraint pre_lower_modadd_3_3_1[11] = lower_rot_3_4[11];
constraint pre_lower_modadd_3_3_1[12] = lower_rot_3_4[12];
constraint pre_lower_modadd_3_3_1[13] = lower_rot_3_4[13];
constraint pre_lower_modadd_3_3_1[14] = lower_rot_3_4[14];
constraint pre_lower_modadd_3_3_1[15] = lower_rot_3_4[15];
constraint forall(j in 0..15)(if eq_lower_modadd_3_3[j] = 1 then (sum([pre_lower_modadd_3_3_1[j], pre_lower_modadd_3_3_0[j], lower_modadd_3_3[j]]) mod 2) = Shi_pre_lower_modadd_3_3_0[j] else true endif) /\ lower_p[1] = (16-sum(eq_lower_modadd_3_3))*100;
constraint pre_upper_modadd_4_0_0[0] = upper_modadd_3_0[0];
constraint pre_upper_modadd_4_0_0[1] = upper_modadd_3_0[1];
constraint pre_upper_modadd_4_0_0[2] = upper_modadd_3_0[2];
constraint pre_upper_modadd_4_0_0[3] = upper_modadd_3_0[3];
constraint pre_upper_modadd_4_0_0[4] = upper_modadd_3_0[4];
constraint pre_upper_modadd_4_0_0[5] = upper_modadd_3_0[5];
constraint pre_upper_modadd_4_0_0[6] = upper_modadd_3_0[6];
constraint pre_upper_modadd_4_0_0[7] = upper_modadd_3_0[7];
constraint pre_upper_modadd_4_0_0[8] = upper_modadd_3_0[8];
constraint pre_upper_modadd_4_0_0[9] = upper_modadd_3_0[9];
constraint pre_upper_modadd_4_0_0[10] = upper_modadd_3_0[10];
constraint pre_upper_modadd_4_0_0[11] = upper_modadd_3_0[11];
constraint pre_upper_modadd_4_0_0[12] = upper_modadd_3_0[12];
constraint pre_upper_modadd_4_0_0[13] = upper_modadd_3_0[13];
constraint pre_upper_modadd_4_0_0[14] = upper_modadd_3_0[14];
constraint pre_upper_modadd_4_0_0[15] = upper_modadd_3_0[15];
constraint pre_upper_modadd_4_0_1[0] = upper_xor_3_5[0];
constraint pre_upper_modadd_4_0_1[1] = upper_xor_3_5[1];
constraint pre_upper_modadd_4_0_1[2] = upper_xor_3_5[2];
constraint pre_upper_modadd_4_0_1[3] = upper_xor_3_5[3];
constraint pre_upper_modadd_4_0_1[4] = upper_xor_3_5[4];
constraint pre_upper_modadd_4_0_1[5] = upper_xor_3_5[5];
constraint pre_upper_modadd_4_0_1[6] = upper_xor_3_5[6];
constraint pre_upper_modadd_4_0_1[7] = upper_xor_3_5[7];
constraint pre_upper_modadd_4_0_1[8] = upper_xor_3_5[8];
constraint pre_upper_modadd_4_0_1[9] = upper_xor_3_5[9];
constraint pre_upper_modadd_4_0_1[10] = upper_xor_3_5[10];
constraint pre_upper_modadd_4_0_1[11] = upper_xor_3_5[11];
constraint pre_upper_modadd_4_0_1[12] = upper_xor_3_5[12];
constraint pre_upper_modadd_4_0_1[13] = upper_xor_3_5[13];
constraint pre_upper_modadd_4_0_1[14] = upper_xor_3_5[14];
constraint pre_upper_modadd_4_0_1[15] = upper_xor_3_5[15];
constraint forall(j in 0..15)(if eq_upper_modadd_4_0[j] = 1 then (sum([pre_upper_modadd_4_0_1[j], pre_upper_modadd_4_0_0[j], upper_modadd_4_0[j]]) mod 2) = Shi_pre_upper_modadd_4_0_0[j] else true endif) /\ upper_p[8] = (16-sum(eq_upper_modadd_4_0))*100;
constraint upper_rot_4_1[0] = upper_xor_3_5[5];
constraint upper_rot_4_1[1] = upper_xor_3_5[6];
constraint upper_rot_4_1[2] = upper_xor_3_5[7];
constraint upper_rot_4_1[3] = upper_xor_3_5[8];
constraint upper_rot_4_1[4] = upper_xor_3_5[9];
constraint upper_rot_4_1[5] = upper_xor_3_5[10];
constraint upper_rot_4_1[6] = upper_xor_3_5[11];
constraint upper_rot_4_1[7] = upper_xor_3_5[12];
constraint upper_rot_4_1[8] = upper_xor_3_5[13];
constraint upper_rot_4_1[9] = upper_xor_3_5[14];
constraint upper_rot_4_1[10] = upper_xor_3_5[15];
constraint upper_rot_4_1[11] = upper_xor_3_5[0];
constraint upper_rot_4_1[12] = upper_xor_3_5[1];
constraint upper_rot_4_1[13] = upper_xor_3_5[2];
constraint upper_rot_4_1[14] = upper_xor_3_5[3];
constraint upper_rot_4_1[15] = upper_xor_3_5[4];
constraint 2*dummy_upper_xor_4_2[0] = (upper_rot_4_1[0] + upper_modadd_4_0[0] + upper_xor_4_2[0]);
constraint 2*dummy_upper_xor_4_2[1] = (upper_rot_4_1[1] + upper_modadd_4_0[1] + upper_xor_4_2[1]);
constraint 2*dummy_upper_xor_4_2[2] = (upper_rot_4_1[2] + upper_modadd_4_0[2] + upper_xor_4_2[2]);
constraint 2*dummy_upper_xor_4_2[3] = (upper_rot_4_1[3] + upper_modadd_4_0[3] + upper_xor_4_2[3]);
constraint 2*dummy_upper_xor_4_2[4] = (upper_rot_4_1[4] + upper_modadd_4_0[4] + upper_xor_4_2[4]);
constraint 2*dummy_upper_xor_4_2[5] = (upper_rot_4_1[5] + upper_modadd_4_0[5] + upper_xor_4_2[5]);
constraint 2*dummy_upper_xor_4_2[6] = (upper_rot_4_1[6] + upper_modadd_4_0[6] + upper_xor_4_2[6]);
constraint 2*dummy_upper_xor_4_2[7] = (upper_rot_4_1[7] + upper_modadd_4_0[7] + upper_xor_4_2[7]);
constraint 2*dummy_upper_xor_4_2[8] = (upper_rot_4_1[8] + upper_modadd_4_0[8] + upper_xor_4_2[8]);
constraint 2*dummy_upper_xor_4_2[9] = (upper_rot_4_1[9] + upper_modadd_4_0[9] + upper_xor_4_2[9]);
constraint 2*dummy_upper_xor_4_2[10] = (upper_rot_4_1[10] + upper_modadd_4_0[10] + upper_xor_4_2[10]);
constraint 2*dummy_upper_xor_4_2[11] = (upper_rot_4_1[11] + upper_modadd_4_0[11] + upper_xor_4_2[11]);
constraint 2*dummy_upper_xor_4_2[12] = (upper_rot_4_1[12] + upper_modadd_4_0[12] + upper_xor_4_2[12]);
constraint 2*dummy_upper_xor_4_2[13] = (upper_rot_4_1[13] + upper_modadd_4_0[13] + upper_xor_4_2[13]);
constraint 2*dummy_upper_xor_4_2[14] = (upper_rot_4_1[14] + upper_modadd_4_0[14] + upper_xor_4_2[14]);
constraint 2*dummy_upper_xor_4_2[15] = (upper_rot_4_1[15] + upper_modadd_4_0[15] + upper_xor_4_2[15]);
constraint upper_rot_4_3[0] = upper_modadd_4_0[0];
constraint upper_rot_4_3[1] = upper_modadd_4_0[1];
constraint upper_rot_4_3[2] = upper_modadd_4_0[2];
constraint upper_rot_4_3[3] = upper_modadd_4_0[3];
constraint upper_rot_4_3[4] = upper_modadd_4_0[4];
constraint upper_rot_4_3[5] = upper_modadd_4_0[5];
constraint upper_rot_4_3[6] = upper_modadd_4_0[6];
constraint upper_rot_4_3[7] = upper_modadd_4_0[7];
constraint upper_rot_4_3[8] = upper_modadd_4_0[8];
constraint upper_rot_4_3[9] = upper_modadd_4_0[9];
constraint upper_rot_4_3[10] = upper_modadd_4_0[10];
constraint upper_rot_4_3[11] = upper_modadd_4_0[11];
constraint upper_rot_4_3[12] = upper_modadd_4_0[12];
constraint upper_rot_4_3[13] = upper_modadd_4_0[13];
constraint upper_rot_4_3[14] = upper_modadd_4_0[14];
constraint upper_rot_4_3[15] = upper_modadd_4_0[15];
constraint pre_upper_modadd_4_4_0[0] = upper_rot_3_6[0];
constraint pre_upper_modadd_4_4_0[1] = upper_rot_3_6[1];
constraint pre_upper_modadd_4_4_0[2] = upper_rot_3_6[2];
constraint pre_upper_modadd_4_4_0[3] = upper_rot_3_6[3];
constraint pre_upper_modadd_4_4_0[4] = upper_rot_3_6[4];
constraint pre_upper_modadd_4_4_0[5] = upper_rot_3_6[5];
constraint pre_upper_modadd_4_4_0[6] = upper_rot_3_6[6];
constraint pre_upper_modadd_4_4_0[7] = upper_rot_3_6[7];
constraint pre_upper_modadd_4_4_0[8] = upper_rot_3_6[8];
constraint pre_upper_modadd_4_4_0[9] = upper_rot_3_6[9];
constraint pre_upper_modadd_4_4_0[10] = upper_rot_3_6[10];
constraint pre_upper_modadd_4_4_0[11] = upper_rot_3_6[11];
constraint pre_upper_modadd_4_4_0[12] = upper_rot_3_6[12];
constraint pre_upper_modadd_4_4_0[13] = upper_rot_3_6[13];
constraint pre_upper_modadd_4_4_0[14] = upper_rot_3_6[14];
constraint pre_upper_modadd_4_4_0[15] = upper_rot_3_6[15];
constraint pre_upper_modadd_4_4_1[0] = upper_xor_3_2[0];
constraint pre_upper_modadd_4_4_1[1] = upper_xor_3_2[1];
constraint pre_upper_modadd_4_4_1[2] = upper_xor_3_2[2];
constraint pre_upper_modadd_4_4_1[3] = upper_xor_3_2[3];
constraint pre_upper_modadd_4_4_1[4] = upper_xor_3_2[4];
constraint pre_upper_modadd_4_4_1[5] = upper_xor_3_2[5];
constraint pre_upper_modadd_4_4_1[6] = upper_xor_3_2[6];
constraint pre_upper_modadd_4_4_1[7] = upper_xor_3_2[7];
constraint pre_upper_modadd_4_4_1[8] = upper_xor_3_2[8];
constraint pre_upper_modadd_4_4_1[9] = upper_xor_3_2[9];
constraint pre_upper_modadd_4_4_1[10] = upper_xor_3_2[10];
constraint pre_upper_modadd_4_4_1[11] = upper_xor_3_2[11];
constraint pre_upper_modadd_4_4_1[12] = upper_xor_3_2[12];
constraint pre_upper_modadd_4_4_1[13] = upper_xor_3_2[13];
constraint pre_upper_modadd_4_4_1[14] = upper_xor_3_2[14];
constraint pre_upper_modadd_4_4_1[15] = upper_xor_3_2[15];
constraint forall(j in 0..15)(if eq_upper_modadd_4_4[j] = 1 then (sum([pre_upper_modadd_4_4_1[j], pre_upper_modadd_4_4_0[j], upper_modadd_4_4[j]]) mod 2) = Shi_pre_upper_modadd_4_4_0[j] else true endif) /\ upper_p[9] = (16-sum(eq_upper_modadd_4_4))*100;
constraint upper_rot_4_5[0] = upper_xor_3_2[8];
constraint upper_rot_4_5[1] = upper_xor_3_2[9];
constraint upper_rot_4_5[2] = upper_xor_3_2[10];
constraint upper_rot_4_5[3] = upper_xor_3_2[11];
constraint upper_rot_4_5[4] = upper_xor_3_2[12];
constraint upper_rot_4_5[5] = upper_xor_3_2[13];
constraint upper_rot_4_5[6] = upper_xor_3_2[14];
constraint upper_rot_4_5[7] = upper_xor_3_2[15];
constraint upper_rot_4_5[8] = upper_xor_3_2[0];
constraint upper_rot_4_5[9] = upper_xor_3_2[1];
constraint upper_rot_4_5[10] = upper_xor_3_2[2];
constraint upper_rot_4_5[11] = upper_xor_3_2[3];
constraint upper_rot_4_5[12] = upper_xor_3_2[4];
constraint upper_rot_4_5[13] = upper_xor_3_2[5];
constraint upper_rot_4_5[14] = upper_xor_3_2[6];
constraint upper_rot_4_5[15] = upper_xor_3_2[7];
constraint 2*dummy_upper_xor_4_6[0] = (upper_rot_4_5[0] + upper_modadd_4_4[0] + upper_xor_4_6[0]);
constraint 2*dummy_upper_xor_4_6[1] = (upper_rot_4_5[1] + upper_modadd_4_4[1] + upper_xor_4_6[1]);
constraint 2*dummy_upper_xor_4_6[2] = (upper_rot_4_5[2] + upper_modadd_4_4[2] + upper_xor_4_6[2]);
constraint 2*dummy_upper_xor_4_6[3] = (upper_rot_4_5[3] + upper_modadd_4_4[3] + upper_xor_4_6[3]);
constraint 2*dummy_upper_xor_4_6[4] = (upper_rot_4_5[4] + upper_modadd_4_4[4] + upper_xor_4_6[4]);
constraint 2*dummy_upper_xor_4_6[5] = (upper_rot_4_5[5] + upper_modadd_4_4[5] + upper_xor_4_6[5]);
constraint 2*dummy_upper_xor_4_6[6] = (upper_rot_4_5[6] + upper_modadd_4_4[6] + upper_xor_4_6[6]);
constraint 2*dummy_upper_xor_4_6[7] = (upper_rot_4_5[7] + upper_modadd_4_4[7] + upper_xor_4_6[7]);
constraint 2*dummy_upper_xor_4_6[8] = (upper_rot_4_5[8] + upper_modadd_4_4[8] + upper_xor_4_6[8]);
constraint 2*dummy_upper_xor_4_6[9] = (upper_rot_4_5[9] + upper_modadd_4_4[9] + upper_xor_4_6[9]);
constraint 2*dummy_upper_xor_4_6[10] = (upper_rot_4_5[10] + upper_modadd_4_4[10] + upper_xor_4_6[10]);
constraint 2*dummy_upper_xor_4_6[11] = (upper_rot_4_5[11] + upper_modadd_4_4[11] + upper_xor_4_6[11]);
constraint 2*dummy_upper_xor_4_6[12] = (upper_rot_4_5[12] + upper_modadd_4_4[12] + upper_xor_4_6[12]);
constraint 2*dummy_upper_xor_4_6[13] = (upper_rot_4_5[13] + upper_modadd_4_4[13] + upper_xor_4_6[13]);
constraint 2*dummy_upper_xor_4_6[14] = (upper_rot_4_5[14] + upper_modadd_4_4[14] + upper_xor_4_6[14]);
constraint 2*dummy_upper_xor_4_6[15] = (upper_rot_4_5[15] + upper_modadd_4_4[15] + upper_xor_4_6[15]);
constraint upper_intermediate_output_4_7[0] = upper_rot_4_3[0];
constraint upper_intermediate_output_4_7[1] = upper_rot_4_3[1];
constraint upper_intermediate_output_4_7[2] = upper_rot_4_3[2];
constraint upper_intermediate_output_4_7[3] = upper_rot_4_3[3];
constraint upper_intermediate_output_4_7[4] = upper_rot_4_3[4];
constraint upper_intermediate_output_4_7[5] = upper_rot_4_3[5];
constraint upper_intermediate_output_4_7[6] = upper_rot_4_3[6];
constraint upper_intermediate_output_4_7[7] = upper_rot_4_3[7];
constraint upper_intermediate_output_4_7[8] = upper_rot_4_3[8];
constraint upper_intermediate_output_4_7[9] = upper_rot_4_3[9];
constraint upper_intermediate_output_4_7[10] = upper_rot_4_3[10];
constraint upper_intermediate_output_4_7[11] = upper_rot_4_3[11];
constraint upper_intermediate_output_4_7[12] = upper_rot_4_3[12];
constraint upper_intermediate_output_4_7[13] = upper_rot_4_3[13];
constraint upper_intermediate_output_4_7[14] = upper_rot_4_3[14];
constraint upper_intermediate_output_4_7[15] = upper_rot_4_3[15];
constraint upper_intermediate_output_4_7[16] = upper_xor_4_2[0];
constraint upper_intermediate_output_4_7[17] = upper_xor_4_2[1];
constraint upper_intermediate_output_4_7[18] = upper_xor_4_2[2];
constraint upper_intermediate_output_4_7[19] = upper_xor_4_2[3];
constraint upper_intermediate_output_4_7[20] = upper_xor_4_2[4];
constraint upper_intermediate_output_4_7[21] = upper_xor_4_2[5];
constraint upper_intermediate_output_4_7[22] = upper_xor_4_2[6];
constraint upper_intermediate_output_4_7[23] = upper_xor_4_2[7];
constraint upper_intermediate_output_4_7[24] = upper_xor_4_2[8];
constraint upper_intermediate_output_4_7[25] = upper_xor_4_2[9];
constraint upper_intermediate_output_4_7[26] = upper_xor_4_2[10];
constraint upper_intermediate_output_4_7[27] = upper_xor_4_2[11];
constraint upper_intermediate_output_4_7[28] = upper_xor_4_2[12];
constraint upper_intermediate_output_4_7[29] = upper_xor_4_2[13];
constraint upper_intermediate_output_4_7[30] = upper_xor_4_2[14];
constraint upper_intermediate_output_4_7[31] = upper_xor_4_2[15];
constraint upper_intermediate_output_4_7[32] = upper_modadd_4_4[0];
constraint upper_intermediate_output_4_7[33] = upper_modadd_4_4[1];
constraint upper_intermediate_output_4_7[34] = upper_modadd_4_4[2];
constraint upper_intermediate_output_4_7[35] = upper_modadd_4_4[3];
constraint upper_intermediate_output_4_7[36] = upper_modadd_4_4[4];
constraint upper_intermediate_output_4_7[37] = upper_modadd_4_4[5];
constraint upper_intermediate_output_4_7[38] = upper_modadd_4_4[6];
constraint upper_intermediate_output_4_7[39] = upper_modadd_4_4[7];
constraint upper_intermediate_output_4_7[40] = upper_modadd_4_4[8];
constraint upper_intermediate_output_4_7[41] = upper_modadd_4_4[9];
constraint upper_intermediate_output_4_7[42] = upper_modadd_4_4[10];
constraint upper_intermediate_output_4_7[43] = upper_modadd_4_4[11];
constraint upper_intermediate_output_4_7[44] = upper_modadd_4_4[12];
constraint upper_intermediate_output_4_7[45] = upper_modadd_4_4[13];
constraint upper_intermediate_output_4_7[46] = upper_modadd_4_4[14];
constraint upper_intermediate_output_4_7[47] = upper_modadd_4_4[15];
constraint upper_intermediate_output_4_7[48] = upper_xor_4_6[0];
constraint upper_intermediate_output_4_7[49] = upper_xor_4_6[1];
constraint upper_intermediate_output_4_7[50] = upper_xor_4_6[2];
constraint upper_intermediate_output_4_7[51] = upper_xor_4_6[3];
constraint upper_intermediate_output_4_7[52] = upper_xor_4_6[4];
constraint upper_intermediate_output_4_7[53] = upper_xor_4_6[5];
constraint upper_intermediate_output_4_7[54] = upper_xor_4_6[6];
constraint upper_intermediate_output_4_7[55] = upper_xor_4_6[7];
constraint upper_intermediate_output_4_7[56] = upper_xor_4_6[8];
constraint upper_intermediate_output_4_7[57] = upper_xor_4_6[9];
constraint upper_intermediate_output_4_7[58] = upper_xor_4_6[10];
constraint upper_intermediate_output_4_7[59] = upper_xor_4_6[11];
constraint upper_intermediate_output_4_7[60] = upper_xor_4_6[12];
constraint upper_intermediate_output_4_7[61] = upper_xor_4_6[13];
constraint upper_intermediate_output_4_7[62] = upper_xor_4_6[14];
constraint upper_intermediate_output_4_7[63] = upper_xor_4_6[15];
constraint lower_rot_4_3[0] = lower_modadd_5_0[0];
constraint lower_rot_4_3[1] = lower_modadd_5_0[1];
constraint lower_rot_4_3[2] = lower_modadd_5_0[2];
constraint lower_rot_4_3[3] = lower_modadd_5_0[3];
constraint lower_rot_4_3[4] = lower_modadd_5_0[4];
constraint lower_rot_4_3[5] = lower_modadd_5_0[5];
constraint lower_rot_4_3[6] = lower_modadd_5_0[6];
constraint lower_rot_4_3[7] = lower_modadd_5_0[7];
constraint lower_rot_4_3[8] = lower_modadd_5_0[8];
constraint lower_rot_4_3[9] = lower_modadd_5_0[9];
constraint lower_rot_4_3[10] = lower_modadd_5_0[10];
constraint lower_rot_4_3[11] = lower_modadd_5_0[11];
constraint lower_rot_4_3[12] = lower_modadd_5_0[12];
constraint lower_rot_4_3[13] = lower_modadd_5_0[13];
constraint lower_rot_4_3[14] = lower_modadd_5_0[14];
constraint lower_rot_4_3[15] = lower_modadd_5_0[15];
constraint 2*dummy_lower_xor_4_2[0] = (lower_rot_4_3[0] + lower_rot_5_4[0] + lower_xor_4_2[0]);
constraint 2*dummy_lower_xor_4_2[1] = (lower_rot_4_3[1] + lower_rot_5_4[1] + lower_xor_4_2[1]);
constraint 2*dummy_lower_xor_4_2[2] = (lower_rot_4_3[2] + lower_rot_5_4[2] + lower_xor_4_2[2]);
constraint 2*dummy_lower_xor_4_2[3] = (lower_rot_4_3[3] + lower_rot_5_4[3] + lower_xor_4_2[3]);
constraint 2*dummy_lower_xor_4_2[4] = (lower_rot_4_3[4] + lower_rot_5_4[4] + lower_xor_4_2[4]);
constraint 2*dummy_lower_xor_4_2[5] = (lower_rot_4_3[5] + lower_rot_5_4[5] + lower_xor_4_2[5]);
constraint 2*dummy_lower_xor_4_2[6] = (lower_rot_4_3[6] + lower_rot_5_4[6] + lower_xor_4_2[6]);
constraint 2*dummy_lower_xor_4_2[7] = (lower_rot_4_3[7] + lower_rot_5_4[7] + lower_xor_4_2[7]);
constraint 2*dummy_lower_xor_4_2[8] = (lower_rot_4_3[8] + lower_rot_5_4[8] + lower_xor_4_2[8]);
constraint 2*dummy_lower_xor_4_2[9] = (lower_rot_4_3[9] + lower_rot_5_4[9] + lower_xor_4_2[9]);
constraint 2*dummy_lower_xor_4_2[10] = (lower_rot_4_3[10] + lower_rot_5_4[10] + lower_xor_4_2[10]);
constraint 2*dummy_lower_xor_4_2[11] = (lower_rot_4_3[11] + lower_rot_5_4[11] + lower_xor_4_2[11]);
constraint 2*dummy_lower_xor_4_2[12] = (lower_rot_4_3[12] + lower_rot_5_4[12] + lower_xor_4_2[12]);
constraint 2*dummy_lower_xor_4_2[13] = (lower_rot_4_3[13] + lower_rot_5_4[13] + lower_xor_4_2[13]);
constraint 2*dummy_lower_xor_4_2[14] = (lower_rot_4_3[14] + lower_rot_5_4[14] + lower_xor_4_2[14]);
constraint 2*dummy_lower_xor_4_2[15] = (lower_rot_4_3[15] + lower_rot_5_4[15] + lower_xor_4_2[15]);
constraint 2*dummy_lower_xor_4_6[0] = (lower_modadd_5_3[0] + lower_rot_5_1[0] + lower_xor_4_6[0]);
constraint 2*dummy_lower_xor_4_6[1] = (lower_modadd_5_3[1] + lower_rot_5_1[1] + lower_xor_4_6[1]);
constraint 2*dummy_lower_xor_4_6[2] = (lower_modadd_5_3[2] + lower_rot_5_1[2] + lower_xor_4_6[2]);
constraint 2*dummy_lower_xor_4_6[3] = (lower_modadd_5_3[3] + lower_rot_5_1[3] + lower_xor_4_6[3]);
constraint 2*dummy_lower_xor_4_6[4] = (lower_modadd_5_3[4] + lower_rot_5_1[4] + lower_xor_4_6[4]);
constraint 2*dummy_lower_xor_4_6[5] = (lower_modadd_5_3[5] + lower_rot_5_1[5] + lower_xor_4_6[5]);
constraint 2*dummy_lower_xor_4_6[6] = (lower_modadd_5_3[6] + lower_rot_5_1[6] + lower_xor_4_6[6]);
constraint 2*dummy_lower_xor_4_6[7] = (lower_modadd_5_3[7] + lower_rot_5_1[7] + lower_xor_4_6[7]);
constraint 2*dummy_lower_xor_4_6[8] = (lower_modadd_5_3[8] + lower_rot_5_1[8] + lower_xor_4_6[8]);
constraint 2*dummy_lower_xor_4_6[9] = (lower_modadd_5_3[9] + lower_rot_5_1[9] + lower_xor_4_6[9]);
constraint 2*dummy_lower_xor_4_6[10] = (lower_modadd_5_3[10] + lower_rot_5_1[10] + lower_xor_4_6[10]);
constraint 2*dummy_lower_xor_4_6[11] = (lower_modadd_5_3[11] + lower_rot_5_1[11] + lower_xor_4_6[11]);
constraint 2*dummy_lower_xor_4_6[12] = (lower_modadd_5_3[12] + lower_rot_5_1[12] + lower_xor_4_6[12]);
constraint 2*dummy_lower_xor_4_6[13] = (lower_modadd_5_3[13] + lower_rot_5_1[13] + lower_xor_4_6[13]);
constraint 2*dummy_lower_xor_4_6[14] = (lower_modadd_5_3[14] + lower_rot_5_1[14] + lower_xor_4_6[14]);
constraint 2*dummy_lower_xor_4_6[15] = (lower_modadd_5_3[15] + lower_rot_5_1[15] + lower_xor_4_6[15]);
constraint lower_intermediate_output_4_7[0] = lower_modadd_5_0[0];
constraint lower_intermediate_output_4_7[1] = lower_modadd_5_0[1];
constraint lower_intermediate_output_4_7[2] = lower_modadd_5_0[2];
constraint lower_intermediate_output_4_7[3] = lower_modadd_5_0[3];
constraint lower_intermediate_output_4_7[4] = lower_modadd_5_0[4];
constraint lower_intermediate_output_4_7[5] = lower_modadd_5_0[5];
constraint lower_intermediate_output_4_7[6] = lower_modadd_5_0[6];
constraint lower_intermediate_output_4_7[7] = lower_modadd_5_0[7];
constraint lower_intermediate_output_4_7[8] = lower_modadd_5_0[8];
constraint lower_intermediate_output_4_7[9] = lower_modadd_5_0[9];
constraint lower_intermediate_output_4_7[10] = lower_modadd_5_0[10];
constraint lower_intermediate_output_4_7[11] = lower_modadd_5_0[11];
constraint lower_intermediate_output_4_7[12] = lower_modadd_5_0[12];
constraint lower_intermediate_output_4_7[13] = lower_modadd_5_0[13];
constraint lower_intermediate_output_4_7[14] = lower_modadd_5_0[14];
constraint lower_intermediate_output_4_7[15] = lower_modadd_5_0[15];
constraint lower_intermediate_output_4_7[16] = lower_rot_5_4[0];
constraint lower_intermediate_output_4_7[17] = lower_rot_5_4[1];
constraint lower_intermediate_output_4_7[18] = lower_rot_5_4[2];
constraint lower_intermediate_output_4_7[19] = lower_rot_5_4[3];
constraint lower_intermediate_output_4_7[20] = lower_rot_5_4[4];
constraint lower_intermediate_output_4_7[21] = lower_rot_5_4[5];
constraint lower_intermediate_output_4_7[22] = lower_rot_5_4[6];
constraint lower_intermediate_output_4_7[23] = lower_rot_5_4[7];
constraint lower_intermediate_output_4_7[24] = lower_rot_5_4[8];
constraint lower_intermediate_output_4_7[25] = lower_rot_5_4[9];
constraint lower_intermediate_output_4_7[26] = lower_rot_5_4[10];
constraint lower_intermediate_output_4_7[27] = lower_rot_5_4[11];
constraint lower_intermediate_output_4_7[28] = lower_rot_5_4[12];
constraint lower_intermediate_output_4_7[29] = lower_rot_5_4[13];
constraint lower_intermediate_output_4_7[30] = lower_rot_5_4[14];
constraint lower_intermediate_output_4_7[31] = lower_rot_5_4[15];
constraint lower_intermediate_output_4_7[32] = lower_modadd_5_3[0];
constraint lower_intermediate_output_4_7[33] = lower_modadd_5_3[1];
constraint lower_intermediate_output_4_7[34] = lower_modadd_5_3[2];
constraint lower_intermediate_output_4_7[35] = lower_modadd_5_3[3];
constraint lower_intermediate_output_4_7[36] = lower_modadd_5_3[4];
constraint lower_intermediate_output_4_7[37] = lower_modadd_5_3[5];
constraint lower_intermediate_output_4_7[38] = lower_modadd_5_3[6];
constraint lower_intermediate_output_4_7[39] = lower_modadd_5_3[7];
constraint lower_intermediate_output_4_7[40] = lower_modadd_5_3[8];
constraint lower_intermediate_output_4_7[41] = lower_modadd_5_3[9];
constraint lower_intermediate_output_4_7[42] = lower_modadd_5_3[10];
constraint lower_intermediate_output_4_7[43] = lower_modadd_5_3[11];
constraint lower_intermediate_output_4_7[44] = lower_modadd_5_3[12];
constraint lower_intermediate_output_4_7[45] = lower_modadd_5_3[13];
constraint lower_intermediate_output_4_7[46] = lower_modadd_5_3[14];
constraint lower_intermediate_output_4_7[47] = lower_modadd_5_3[15];
constraint lower_intermediate_output_4_7[48] = lower_rot_5_1[0];
constraint lower_intermediate_output_4_7[49] = lower_rot_5_1[1];
constraint lower_intermediate_output_4_7[50] = lower_rot_5_1[2];
constraint lower_intermediate_output_4_7[51] = lower_rot_5_1[3];
constraint lower_intermediate_output_4_7[52] = lower_rot_5_1[4];
constraint lower_intermediate_output_4_7[53] = lower_rot_5_1[5];
constraint lower_intermediate_output_4_7[54] = lower_rot_5_1[6];
constraint lower_intermediate_output_4_7[55] = lower_rot_5_1[7];
constraint lower_intermediate_output_4_7[56] = lower_rot_5_1[8];
constraint lower_intermediate_output_4_7[57] = lower_rot_5_1[9];
constraint lower_intermediate_output_4_7[58] = lower_rot_5_1[10];
constraint lower_intermediate_output_4_7[59] = lower_rot_5_1[11];
constraint lower_intermediate_output_4_7[60] = lower_rot_5_1[12];
constraint lower_intermediate_output_4_7[61] = lower_rot_5_1[13];
constraint lower_intermediate_output_4_7[62] = lower_rot_5_1[14];
constraint lower_intermediate_output_4_7[63] = lower_rot_5_1[15];
constraint lower_rot_4_1[0] = lower_xor_4_2[11];
constraint lower_rot_4_1[1] = lower_xor_4_2[12];
constraint lower_rot_4_1[2] = lower_xor_4_2[13];
constraint lower_rot_4_1[3] = lower_xor_4_2[14];
constraint lower_rot_4_1[4] = lower_xor_4_2[15];
constraint lower_rot_4_1[5] = lower_xor_4_2[0];
constraint lower_rot_4_1[6] = lower_xor_4_2[1];
constraint lower_rot_4_1[7] = lower_xor_4_2[2];
constraint lower_rot_4_1[8] = lower_xor_4_2[3];
constraint lower_rot_4_1[9] = lower_xor_4_2[4];
constraint lower_rot_4_1[10] = lower_xor_4_2[5];
constraint lower_rot_4_1[11] = lower_xor_4_2[6];
constraint lower_rot_4_1[12] = lower_xor_4_2[7];
constraint lower_rot_4_1[13] = lower_xor_4_2[8];
constraint lower_rot_4_1[14] = lower_xor_4_2[9];
constraint lower_rot_4_1[15] = lower_xor_4_2[10];
constraint lower_rot_4_5[0] = lower_xor_4_6[8];
constraint lower_rot_4_5[1] = lower_xor_4_6[9];
constraint lower_rot_4_5[2] = lower_xor_4_6[10];
constraint lower_rot_4_5[3] = lower_xor_4_6[11];
constraint lower_rot_4_5[4] = lower_xor_4_6[12];
constraint lower_rot_4_5[5] = lower_xor_4_6[13];
constraint lower_rot_4_5[6] = lower_xor_4_6[14];
constraint lower_rot_4_5[7] = lower_xor_4_6[15];
constraint lower_rot_4_5[8] = lower_xor_4_6[0];
constraint lower_rot_4_5[9] = lower_xor_4_6[1];
constraint lower_rot_4_5[10] = lower_xor_4_6[2];
constraint lower_rot_4_5[11] = lower_xor_4_6[3];
constraint lower_rot_4_5[12] = lower_xor_4_6[4];
constraint lower_rot_4_5[13] = lower_xor_4_6[5];
constraint lower_rot_4_5[14] = lower_xor_4_6[6];
constraint lower_rot_4_5[15] = lower_xor_4_6[7];
constraint pre_lower_modadd_4_0_0[0] = lower_rot_4_3[0];
constraint pre_lower_modadd_4_0_0[1] = lower_rot_4_3[1];
constraint pre_lower_modadd_4_0_0[2] = lower_rot_4_3[2];
constraint pre_lower_modadd_4_0_0[3] = lower_rot_4_3[3];
constraint pre_lower_modadd_4_0_0[4] = lower_rot_4_3[4];
constraint pre_lower_modadd_4_0_0[5] = lower_rot_4_3[5];
constraint pre_lower_modadd_4_0_0[6] = lower_rot_4_3[6];
constraint pre_lower_modadd_4_0_0[7] = lower_rot_4_3[7];
constraint pre_lower_modadd_4_0_0[8] = lower_rot_4_3[8];
constraint pre_lower_modadd_4_0_0[9] = lower_rot_4_3[9];
constraint pre_lower_modadd_4_0_0[10] = lower_rot_4_3[10];
constraint pre_lower_modadd_4_0_0[11] = lower_rot_4_3[11];
constraint pre_lower_modadd_4_0_0[12] = lower_rot_4_3[12];
constraint pre_lower_modadd_4_0_0[13] = lower_rot_4_3[13];
constraint pre_lower_modadd_4_0_0[14] = lower_rot_4_3[14];
constraint pre_lower_modadd_4_0_0[15] = lower_rot_4_3[15];
constraint pre_lower_modadd_4_0_1[0] = lower_rot_4_1[0];
constraint pre_lower_modadd_4_0_1[1] = lower_rot_4_1[1];
constraint pre_lower_modadd_4_0_1[2] = lower_rot_4_1[2];
constraint pre_lower_modadd_4_0_1[3] = lower_rot_4_1[3];
constraint pre_lower_modadd_4_0_1[4] = lower_rot_4_1[4];
constraint pre_lower_modadd_4_0_1[5] = lower_rot_4_1[5];
constraint pre_lower_modadd_4_0_1[6] = lower_rot_4_1[6];
constraint pre_lower_modadd_4_0_1[7] = lower_rot_4_1[7];
constraint pre_lower_modadd_4_0_1[8] = lower_rot_4_1[8];
constraint pre_lower_modadd_4_0_1[9] = lower_rot_4_1[9];
constraint pre_lower_modadd_4_0_1[10] = lower_rot_4_1[10];
constraint pre_lower_modadd_4_0_1[11] = lower_rot_4_1[11];
constraint pre_lower_modadd_4_0_1[12] = lower_rot_4_1[12];
constraint pre_lower_modadd_4_0_1[13] = lower_rot_4_1[13];
constraint pre_lower_modadd_4_0_1[14] = lower_rot_4_1[14];
constraint pre_lower_modadd_4_0_1[15] = lower_rot_4_1[15];
constraint forall(j in 0..15)(if eq_lower_modadd_4_0[j] = 1 then (sum([pre_lower_modadd_4_0_1[j], pre_lower_modadd_4_0_0[j], lower_modadd_4_0[j]]) mod 2) = Shi_pre_lower_modadd_4_0_0[j] else true endif) /\ lower_p[2] = (16-sum(eq_lower_modadd_4_0))*100;
constraint pre_lower_modadd_4_4_0[0] = lower_modadd_5_3[0];
constraint pre_lower_modadd_4_4_0[1] = lower_modadd_5_3[1];
constraint pre_lower_modadd_4_4_0[2] = lower_modadd_5_3[2];
constraint pre_lower_modadd_4_4_0[3] = lower_modadd_5_3[3];
constraint pre_lower_modadd_4_4_0[4] = lower_modadd_5_3[4];
constraint pre_lower_modadd_4_4_0[5] = lower_modadd_5_3[5];
constraint pre_lower_modadd_4_4_0[6] = lower_modadd_5_3[6];
constraint pre_lower_modadd_4_4_0[7] = lower_modadd_5_3[7];
constraint pre_lower_modadd_4_4_0[8] = lower_modadd_5_3[8];
constraint pre_lower_modadd_4_4_0[9] = lower_modadd_5_3[9];
constraint pre_lower_modadd_4_4_0[10] = lower_modadd_5_3[10];
constraint pre_lower_modadd_4_4_0[11] = lower_modadd_5_3[11];
constraint pre_lower_modadd_4_4_0[12] = lower_modadd_5_3[12];
constraint pre_lower_modadd_4_4_0[13] = lower_modadd_5_3[13];
constraint pre_lower_modadd_4_4_0[14] = lower_modadd_5_3[14];
constraint pre_lower_modadd_4_4_0[15] = lower_modadd_5_3[15];
constraint pre_lower_modadd_4_4_1[0] = lower_rot_4_5[0];
constraint pre_lower_modadd_4_4_1[1] = lower_rot_4_5[1];
constraint pre_lower_modadd_4_4_1[2] = lower_rot_4_5[2];
constraint pre_lower_modadd_4_4_1[3] = lower_rot_4_5[3];
constraint pre_lower_modadd_4_4_1[4] = lower_rot_4_5[4];
constraint pre_lower_modadd_4_4_1[5] = lower_rot_4_5[5];
constraint pre_lower_modadd_4_4_1[6] = lower_rot_4_5[6];
constraint pre_lower_modadd_4_4_1[7] = lower_rot_4_5[7];
constraint pre_lower_modadd_4_4_1[8] = lower_rot_4_5[8];
constraint pre_lower_modadd_4_4_1[9] = lower_rot_4_5[9];
constraint pre_lower_modadd_4_4_1[10] = lower_rot_4_5[10];
constraint pre_lower_modadd_4_4_1[11] = lower_rot_4_5[11];
constraint pre_lower_modadd_4_4_1[12] = lower_rot_4_5[12];
constraint pre_lower_modadd_4_4_1[13] = lower_rot_4_5[13];
constraint pre_lower_modadd_4_4_1[14] = lower_rot_4_5[14];
constraint pre_lower_modadd_4_4_1[15] = lower_rot_4_5[15];
constraint forall(j in 0..15)(if eq_lower_modadd_4_4[j] = 1 then (sum([pre_lower_modadd_4_4_1[j], pre_lower_modadd_4_4_0[j], lower_modadd_4_4[j]]) mod 2) = Shi_pre_lower_modadd_4_4_0[j] else true endif) /\ lower_p[3] = (16-sum(eq_lower_modadd_4_4))*100;
constraint pre_upper_modadd_5_0_0[0] = upper_rot_4_3[0];
constraint pre_upper_modadd_5_0_0[1] = upper_rot_4_3[1];
constraint pre_upper_modadd_5_0_0[2] = upper_rot_4_3[2];
constraint pre_upper_modadd_5_0_0[3] = upper_rot_4_3[3];
constraint pre_upper_modadd_5_0_0[4] = upper_rot_4_3[4];
constraint pre_upper_modadd_5_0_0[5] = upper_rot_4_3[5];
constraint pre_upper_modadd_5_0_0[6] = upper_rot_4_3[6];
constraint pre_upper_modadd_5_0_0[7] = upper_rot_4_3[7];
constraint pre_upper_modadd_5_0_0[8] = upper_rot_4_3[8];
constraint pre_upper_modadd_5_0_0[9] = upper_rot_4_3[9];
constraint pre_upper_modadd_5_0_0[10] = upper_rot_4_3[10];
constraint pre_upper_modadd_5_0_0[11] = upper_rot_4_3[11];
constraint pre_upper_modadd_5_0_0[12] = upper_rot_4_3[12];
constraint pre_upper_modadd_5_0_0[13] = upper_rot_4_3[13];
constraint pre_upper_modadd_5_0_0[14] = upper_rot_4_3[14];
constraint pre_upper_modadd_5_0_0[15] = upper_rot_4_3[15];
constraint pre_upper_modadd_5_0_1[0] = upper_xor_4_6[0];
constraint pre_upper_modadd_5_0_1[1] = upper_xor_4_6[1];
constraint pre_upper_modadd_5_0_1[2] = upper_xor_4_6[2];
constraint pre_upper_modadd_5_0_1[3] = upper_xor_4_6[3];
constraint pre_upper_modadd_5_0_1[4] = upper_xor_4_6[4];
constraint pre_upper_modadd_5_0_1[5] = upper_xor_4_6[5];
constraint pre_upper_modadd_5_0_1[6] = upper_xor_4_6[6];
constraint pre_upper_modadd_5_0_1[7] = upper_xor_4_6[7];
constraint pre_upper_modadd_5_0_1[8] = upper_xor_4_6[8];
constraint pre_upper_modadd_5_0_1[9] = upper_xor_4_6[9];
constraint pre_upper_modadd_5_0_1[10] = upper_xor_4_6[10];
constraint pre_upper_modadd_5_0_1[11] = upper_xor_4_6[11];
constraint pre_upper_modadd_5_0_1[12] = upper_xor_4_6[12];
constraint pre_upper_modadd_5_0_1[13] = upper_xor_4_6[13];
constraint pre_upper_modadd_5_0_1[14] = upper_xor_4_6[14];
constraint pre_upper_modadd_5_0_1[15] = upper_xor_4_6[15];
constraint forall(j in 0..15)(if eq_upper_modadd_5_0[j] = 1 then (sum([pre_upper_modadd_5_0_1[j], pre_upper_modadd_5_0_0[j], upper_modadd_5_0[j]]) mod 2) = Shi_pre_upper_modadd_5_0_0[j] else true endif) /\ upper_p[10] = (16-sum(eq_upper_modadd_5_0))*100;
constraint upper_rot_5_1[0] = upper_xor_4_6[13];
constraint upper_rot_5_1[1] = upper_xor_4_6[14];
constraint upper_rot_5_1[2] = upper_xor_4_6[15];
constraint upper_rot_5_1[3] = upper_xor_4_6[0];
constraint upper_rot_5_1[4] = upper_xor_4_6[1];
constraint upper_rot_5_1[5] = upper_xor_4_6[2];
constraint upper_rot_5_1[6] = upper_xor_4_6[3];
constraint upper_rot_5_1[7] = upper_xor_4_6[4];
constraint upper_rot_5_1[8] = upper_xor_4_6[5];
constraint upper_rot_5_1[9] = upper_xor_4_6[6];
constraint upper_rot_5_1[10] = upper_xor_4_6[7];
constraint upper_rot_5_1[11] = upper_xor_4_6[8];
constraint upper_rot_5_1[12] = upper_xor_4_6[9];
constraint upper_rot_5_1[13] = upper_xor_4_6[10];
constraint upper_rot_5_1[14] = upper_xor_4_6[11];
constraint upper_rot_5_1[15] = upper_xor_4_6[12];
constraint 2*dummy_upper_xor_5_2[0] = (upper_rot_5_1[0] + upper_modadd_5_0[0] + upper_xor_5_2[0]);
constraint 2*dummy_upper_xor_5_2[1] = (upper_rot_5_1[1] + upper_modadd_5_0[1] + upper_xor_5_2[1]);
constraint 2*dummy_upper_xor_5_2[2] = (upper_rot_5_1[2] + upper_modadd_5_0[2] + upper_xor_5_2[2]);
constraint 2*dummy_upper_xor_5_2[3] = (upper_rot_5_1[3] + upper_modadd_5_0[3] + upper_xor_5_2[3]);
constraint 2*dummy_upper_xor_5_2[4] = (upper_rot_5_1[4] + upper_modadd_5_0[4] + upper_xor_5_2[4]);
constraint 2*dummy_upper_xor_5_2[5] = (upper_rot_5_1[5] + upper_modadd_5_0[5] + upper_xor_5_2[5]);
constraint 2*dummy_upper_xor_5_2[6] = (upper_rot_5_1[6] + upper_modadd_5_0[6] + upper_xor_5_2[6]);
constraint 2*dummy_upper_xor_5_2[7] = (upper_rot_5_1[7] + upper_modadd_5_0[7] + upper_xor_5_2[7]);
constraint 2*dummy_upper_xor_5_2[8] = (upper_rot_5_1[8] + upper_modadd_5_0[8] + upper_xor_5_2[8]);
constraint 2*dummy_upper_xor_5_2[9] = (upper_rot_5_1[9] + upper_modadd_5_0[9] + upper_xor_5_2[9]);
constraint 2*dummy_upper_xor_5_2[10] = (upper_rot_5_1[10] + upper_modadd_5_0[10] + upper_xor_5_2[10]);
constraint 2*dummy_upper_xor_5_2[11] = (upper_rot_5_1[11] + upper_modadd_5_0[11] + upper_xor_5_2[11]);
constraint 2*dummy_upper_xor_5_2[12] = (upper_rot_5_1[12] + upper_modadd_5_0[12] + upper_xor_5_2[12]);
constraint 2*dummy_upper_xor_5_2[13] = (upper_rot_5_1[13] + upper_modadd_5_0[13] + upper_xor_5_2[13]);
constraint 2*dummy_upper_xor_5_2[14] = (upper_rot_5_1[14] + upper_modadd_5_0[14] + upper_xor_5_2[14]);
constraint 2*dummy_upper_xor_5_2[15] = (upper_rot_5_1[15] + upper_modadd_5_0[15] + upper_xor_5_2[15]);
constraint pre_upper_modadd_5_3_0[0] = upper_modadd_4_4[0];
constraint pre_upper_modadd_5_3_0[1] = upper_modadd_4_4[1];
constraint pre_upper_modadd_5_3_0[2] = upper_modadd_4_4[2];
constraint pre_upper_modadd_5_3_0[3] = upper_modadd_4_4[3];
constraint pre_upper_modadd_5_3_0[4] = upper_modadd_4_4[4];
constraint pre_upper_modadd_5_3_0[5] = upper_modadd_4_4[5];
constraint pre_upper_modadd_5_3_0[6] = upper_modadd_4_4[6];
constraint pre_upper_modadd_5_3_0[7] = upper_modadd_4_4[7];
constraint pre_upper_modadd_5_3_0[8] = upper_modadd_4_4[8];
constraint pre_upper_modadd_5_3_0[9] = upper_modadd_4_4[9];
constraint pre_upper_modadd_5_3_0[10] = upper_modadd_4_4[10];
constraint pre_upper_modadd_5_3_0[11] = upper_modadd_4_4[11];
constraint pre_upper_modadd_5_3_0[12] = upper_modadd_4_4[12];
constraint pre_upper_modadd_5_3_0[13] = upper_modadd_4_4[13];
constraint pre_upper_modadd_5_3_0[14] = upper_modadd_4_4[14];
constraint pre_upper_modadd_5_3_0[15] = upper_modadd_4_4[15];
constraint pre_upper_modadd_5_3_1[0] = upper_xor_4_2[0];
constraint pre_upper_modadd_5_3_1[1] = upper_xor_4_2[1];
constraint pre_upper_modadd_5_3_1[2] = upper_xor_4_2[2];
constraint pre_upper_modadd_5_3_1[3] = upper_xor_4_2[3];
constraint pre_upper_modadd_5_3_1[4] = upper_xor_4_2[4];
constraint pre_upper_modadd_5_3_1[5] = upper_xor_4_2[5];
constraint pre_upper_modadd_5_3_1[6] = upper_xor_4_2[6];
constraint pre_upper_modadd_5_3_1[7] = upper_xor_4_2[7];
constraint pre_upper_modadd_5_3_1[8] = upper_xor_4_2[8];
constraint pre_upper_modadd_5_3_1[9] = upper_xor_4_2[9];
constraint pre_upper_modadd_5_3_1[10] = upper_xor_4_2[10];
constraint pre_upper_modadd_5_3_1[11] = upper_xor_4_2[11];
constraint pre_upper_modadd_5_3_1[12] = upper_xor_4_2[12];
constraint pre_upper_modadd_5_3_1[13] = upper_xor_4_2[13];
constraint pre_upper_modadd_5_3_1[14] = upper_xor_4_2[14];
constraint pre_upper_modadd_5_3_1[15] = upper_xor_4_2[15];
constraint forall(j in 0..15)(if eq_upper_modadd_5_3[j] = 1 then (sum([pre_upper_modadd_5_3_1[j], pre_upper_modadd_5_3_0[j], upper_modadd_5_3[j]]) mod 2) = Shi_pre_upper_modadd_5_3_0[j] else true endif) /\ upper_p[11] = (16-sum(eq_upper_modadd_5_3))*100;
constraint upper_rot_5_4[0] = upper_xor_4_2[7];
constraint upper_rot_5_4[1] = upper_xor_4_2[8];
constraint upper_rot_5_4[2] = upper_xor_4_2[9];
constraint upper_rot_5_4[3] = upper_xor_4_2[10];
constraint upper_rot_5_4[4] = upper_xor_4_2[11];
constraint upper_rot_5_4[5] = upper_xor_4_2[12];
constraint upper_rot_5_4[6] = upper_xor_4_2[13];
constraint upper_rot_5_4[7] = upper_xor_4_2[14];
constraint upper_rot_5_4[8] = upper_xor_4_2[15];
constraint upper_rot_5_4[9] = upper_xor_4_2[0];
constraint upper_rot_5_4[10] = upper_xor_4_2[1];
constraint upper_rot_5_4[11] = upper_xor_4_2[2];
constraint upper_rot_5_4[12] = upper_xor_4_2[3];
constraint upper_rot_5_4[13] = upper_xor_4_2[4];
constraint upper_rot_5_4[14] = upper_xor_4_2[5];
constraint upper_rot_5_4[15] = upper_xor_4_2[6];
constraint 2*dummy_upper_xor_5_5[0] = (upper_rot_5_4[0] + upper_modadd_5_3[0] + upper_xor_5_5[0]);
constraint 2*dummy_upper_xor_5_5[1] = (upper_rot_5_4[1] + upper_modadd_5_3[1] + upper_xor_5_5[1]);
constraint 2*dummy_upper_xor_5_5[2] = (upper_rot_5_4[2] + upper_modadd_5_3[2] + upper_xor_5_5[2]);
constraint 2*dummy_upper_xor_5_5[3] = (upper_rot_5_4[3] + upper_modadd_5_3[3] + upper_xor_5_5[3]);
constraint 2*dummy_upper_xor_5_5[4] = (upper_rot_5_4[4] + upper_modadd_5_3[4] + upper_xor_5_5[4]);
constraint 2*dummy_upper_xor_5_5[5] = (upper_rot_5_4[5] + upper_modadd_5_3[5] + upper_xor_5_5[5]);
constraint 2*dummy_upper_xor_5_5[6] = (upper_rot_5_4[6] + upper_modadd_5_3[6] + upper_xor_5_5[6]);
constraint 2*dummy_upper_xor_5_5[7] = (upper_rot_5_4[7] + upper_modadd_5_3[7] + upper_xor_5_5[7]);
constraint 2*dummy_upper_xor_5_5[8] = (upper_rot_5_4[8] + upper_modadd_5_3[8] + upper_xor_5_5[8]);
constraint 2*dummy_upper_xor_5_5[9] = (upper_rot_5_4[9] + upper_modadd_5_3[9] + upper_xor_5_5[9]);
constraint 2*dummy_upper_xor_5_5[10] = (upper_rot_5_4[10] + upper_modadd_5_3[10] + upper_xor_5_5[10]);
constraint 2*dummy_upper_xor_5_5[11] = (upper_rot_5_4[11] + upper_modadd_5_3[11] + upper_xor_5_5[11]);
constraint 2*dummy_upper_xor_5_5[12] = (upper_rot_5_4[12] + upper_modadd_5_3[12] + upper_xor_5_5[12]);
constraint 2*dummy_upper_xor_5_5[13] = (upper_rot_5_4[13] + upper_modadd_5_3[13] + upper_xor_5_5[13]);
constraint 2*dummy_upper_xor_5_5[14] = (upper_rot_5_4[14] + upper_modadd_5_3[14] + upper_xor_5_5[14]);
constraint 2*dummy_upper_xor_5_5[15] = (upper_rot_5_4[15] + upper_modadd_5_3[15] + upper_xor_5_5[15]);
constraint upper_rot_5_6[0] = upper_modadd_5_3[0];
constraint upper_rot_5_6[1] = upper_modadd_5_3[1];
constraint upper_rot_5_6[2] = upper_modadd_5_3[2];
constraint upper_rot_5_6[3] = upper_modadd_5_3[3];
constraint upper_rot_5_6[4] = upper_modadd_5_3[4];
constraint upper_rot_5_6[5] = upper_modadd_5_3[5];
constraint upper_rot_5_6[6] = upper_modadd_5_3[6];
constraint upper_rot_5_6[7] = upper_modadd_5_3[7];
constraint upper_rot_5_6[8] = upper_modadd_5_3[8];
constraint upper_rot_5_6[9] = upper_modadd_5_3[9];
constraint upper_rot_5_6[10] = upper_modadd_5_3[10];
constraint upper_rot_5_6[11] = upper_modadd_5_3[11];
constraint upper_rot_5_6[12] = upper_modadd_5_3[12];
constraint upper_rot_5_6[13] = upper_modadd_5_3[13];
constraint upper_rot_5_6[14] = upper_modadd_5_3[14];
constraint upper_rot_5_6[15] = upper_modadd_5_3[15];
constraint upper_intermediate_output_5_7[0] = upper_modadd_5_0[0];
constraint upper_intermediate_output_5_7[1] = upper_modadd_5_0[1];
constraint upper_intermediate_output_5_7[2] = upper_modadd_5_0[2];
constraint upper_intermediate_output_5_7[3] = upper_modadd_5_0[3];
constraint upper_intermediate_output_5_7[4] = upper_modadd_5_0[4];
constraint upper_intermediate_output_5_7[5] = upper_modadd_5_0[5];
constraint upper_intermediate_output_5_7[6] = upper_modadd_5_0[6];
constraint upper_intermediate_output_5_7[7] = upper_modadd_5_0[7];
constraint upper_intermediate_output_5_7[8] = upper_modadd_5_0[8];
constraint upper_intermediate_output_5_7[9] = upper_modadd_5_0[9];
constraint upper_intermediate_output_5_7[10] = upper_modadd_5_0[10];
constraint upper_intermediate_output_5_7[11] = upper_modadd_5_0[11];
constraint upper_intermediate_output_5_7[12] = upper_modadd_5_0[12];
constraint upper_intermediate_output_5_7[13] = upper_modadd_5_0[13];
constraint upper_intermediate_output_5_7[14] = upper_modadd_5_0[14];
constraint upper_intermediate_output_5_7[15] = upper_modadd_5_0[15];
constraint upper_intermediate_output_5_7[16] = upper_xor_5_5[0];
constraint upper_intermediate_output_5_7[17] = upper_xor_5_5[1];
constraint upper_intermediate_output_5_7[18] = upper_xor_5_5[2];
constraint upper_intermediate_output_5_7[19] = upper_xor_5_5[3];
constraint upper_intermediate_output_5_7[20] = upper_xor_5_5[4];
constraint upper_intermediate_output_5_7[21] = upper_xor_5_5[5];
constraint upper_intermediate_output_5_7[22] = upper_xor_5_5[6];
constraint upper_intermediate_output_5_7[23] = upper_xor_5_5[7];
constraint upper_intermediate_output_5_7[24] = upper_xor_5_5[8];
constraint upper_intermediate_output_5_7[25] = upper_xor_5_5[9];
constraint upper_intermediate_output_5_7[26] = upper_xor_5_5[10];
constraint upper_intermediate_output_5_7[27] = upper_xor_5_5[11];
constraint upper_intermediate_output_5_7[28] = upper_xor_5_5[12];
constraint upper_intermediate_output_5_7[29] = upper_xor_5_5[13];
constraint upper_intermediate_output_5_7[30] = upper_xor_5_5[14];
constraint upper_intermediate_output_5_7[31] = upper_xor_5_5[15];
constraint upper_intermediate_output_5_7[32] = upper_rot_5_6[0];
constraint upper_intermediate_output_5_7[33] = upper_rot_5_6[1];
constraint upper_intermediate_output_5_7[34] = upper_rot_5_6[2];
constraint upper_intermediate_output_5_7[35] = upper_rot_5_6[3];
constraint upper_intermediate_output_5_7[36] = upper_rot_5_6[4];
constraint upper_intermediate_output_5_7[37] = upper_rot_5_6[5];
constraint upper_intermediate_output_5_7[38] = upper_rot_5_6[6];
constraint upper_intermediate_output_5_7[39] = upper_rot_5_6[7];
constraint upper_intermediate_output_5_7[40] = upper_rot_5_6[8];
constraint upper_intermediate_output_5_7[41] = upper_rot_5_6[9];
constraint upper_intermediate_output_5_7[42] = upper_rot_5_6[10];
constraint upper_intermediate_output_5_7[43] = upper_rot_5_6[11];
constraint upper_intermediate_output_5_7[44] = upper_rot_5_6[12];
constraint upper_intermediate_output_5_7[45] = upper_rot_5_6[13];
constraint upper_intermediate_output_5_7[46] = upper_rot_5_6[14];
constraint upper_intermediate_output_5_7[47] = upper_rot_5_6[15];
constraint upper_intermediate_output_5_7[48] = upper_xor_5_2[0];
constraint upper_intermediate_output_5_7[49] = upper_xor_5_2[1];
constraint upper_intermediate_output_5_7[50] = upper_xor_5_2[2];
constraint upper_intermediate_output_5_7[51] = upper_xor_5_2[3];
constraint upper_intermediate_output_5_7[52] = upper_xor_5_2[4];
constraint upper_intermediate_output_5_7[53] = upper_xor_5_2[5];
constraint upper_intermediate_output_5_7[54] = upper_xor_5_2[6];
constraint upper_intermediate_output_5_7[55] = upper_xor_5_2[7];
constraint upper_intermediate_output_5_7[56] = upper_xor_5_2[8];
constraint upper_intermediate_output_5_7[57] = upper_xor_5_2[9];
constraint upper_intermediate_output_5_7[58] = upper_xor_5_2[10];
constraint upper_intermediate_output_5_7[59] = upper_xor_5_2[11];
constraint upper_intermediate_output_5_7[60] = upper_xor_5_2[12];
constraint upper_intermediate_output_5_7[61] = upper_xor_5_2[13];
constraint upper_intermediate_output_5_7[62] = upper_xor_5_2[14];
constraint upper_intermediate_output_5_7[63] = upper_xor_5_2[15];
constraint 2*dummy_lower_xor_5_2[0] = (lower_modadd_6_0[0] + lower_rot_6_5[0] + lower_xor_5_2[0]);
constraint 2*dummy_lower_xor_5_2[1] = (lower_modadd_6_0[1] + lower_rot_6_5[1] + lower_xor_5_2[1]);
constraint 2*dummy_lower_xor_5_2[2] = (lower_modadd_6_0[2] + lower_rot_6_5[2] + lower_xor_5_2[2]);
constraint 2*dummy_lower_xor_5_2[3] = (lower_modadd_6_0[3] + lower_rot_6_5[3] + lower_xor_5_2[3]);
constraint 2*dummy_lower_xor_5_2[4] = (lower_modadd_6_0[4] + lower_rot_6_5[4] + lower_xor_5_2[4]);
constraint 2*dummy_lower_xor_5_2[5] = (lower_modadd_6_0[5] + lower_rot_6_5[5] + lower_xor_5_2[5]);
constraint 2*dummy_lower_xor_5_2[6] = (lower_modadd_6_0[6] + lower_rot_6_5[6] + lower_xor_5_2[6]);
constraint 2*dummy_lower_xor_5_2[7] = (lower_modadd_6_0[7] + lower_rot_6_5[7] + lower_xor_5_2[7]);
constraint 2*dummy_lower_xor_5_2[8] = (lower_modadd_6_0[8] + lower_rot_6_5[8] + lower_xor_5_2[8]);
constraint 2*dummy_lower_xor_5_2[9] = (lower_modadd_6_0[9] + lower_rot_6_5[9] + lower_xor_5_2[9]);
constraint 2*dummy_lower_xor_5_2[10] = (lower_modadd_6_0[10] + lower_rot_6_5[10] + lower_xor_5_2[10]);
constraint 2*dummy_lower_xor_5_2[11] = (lower_modadd_6_0[11] + lower_rot_6_5[11] + lower_xor_5_2[11]);
constraint 2*dummy_lower_xor_5_2[12] = (lower_modadd_6_0[12] + lower_rot_6_5[12] + lower_xor_5_2[12]);
constraint 2*dummy_lower_xor_5_2[13] = (lower_modadd_6_0[13] + lower_rot_6_5[13] + lower_xor_5_2[13]);
constraint 2*dummy_lower_xor_5_2[14] = (lower_modadd_6_0[14] + lower_rot_6_5[14] + lower_xor_5_2[14]);
constraint 2*dummy_lower_xor_5_2[15] = (lower_modadd_6_0[15] + lower_rot_6_5[15] + lower_xor_5_2[15]);
constraint lower_rot_5_6[0] = lower_modadd_6_4[0];
constraint lower_rot_5_6[1] = lower_modadd_6_4[1];
constraint lower_rot_5_6[2] = lower_modadd_6_4[2];
constraint lower_rot_5_6[3] = lower_modadd_6_4[3];
constraint lower_rot_5_6[4] = lower_modadd_6_4[4];
constraint lower_rot_5_6[5] = lower_modadd_6_4[5];
constraint lower_rot_5_6[6] = lower_modadd_6_4[6];
constraint lower_rot_5_6[7] = lower_modadd_6_4[7];
constraint lower_rot_5_6[8] = lower_modadd_6_4[8];
constraint lower_rot_5_6[9] = lower_modadd_6_4[9];
constraint lower_rot_5_6[10] = lower_modadd_6_4[10];
constraint lower_rot_5_6[11] = lower_modadd_6_4[11];
constraint lower_rot_5_6[12] = lower_modadd_6_4[12];
constraint lower_rot_5_6[13] = lower_modadd_6_4[13];
constraint lower_rot_5_6[14] = lower_modadd_6_4[14];
constraint lower_rot_5_6[15] = lower_modadd_6_4[15];
constraint lower_intermediate_output_5_7[0] = lower_modadd_6_0[0];
constraint lower_intermediate_output_5_7[1] = lower_modadd_6_0[1];
constraint lower_intermediate_output_5_7[2] = lower_modadd_6_0[2];
constraint lower_intermediate_output_5_7[3] = lower_modadd_6_0[3];
constraint lower_intermediate_output_5_7[4] = lower_modadd_6_0[4];
constraint lower_intermediate_output_5_7[5] = lower_modadd_6_0[5];
constraint lower_intermediate_output_5_7[6] = lower_modadd_6_0[6];
constraint lower_intermediate_output_5_7[7] = lower_modadd_6_0[7];
constraint lower_intermediate_output_5_7[8] = lower_modadd_6_0[8];
constraint lower_intermediate_output_5_7[9] = lower_modadd_6_0[9];
constraint lower_intermediate_output_5_7[10] = lower_modadd_6_0[10];
constraint lower_intermediate_output_5_7[11] = lower_modadd_6_0[11];
constraint lower_intermediate_output_5_7[12] = lower_modadd_6_0[12];
constraint lower_intermediate_output_5_7[13] = lower_modadd_6_0[13];
constraint lower_intermediate_output_5_7[14] = lower_modadd_6_0[14];
constraint lower_intermediate_output_5_7[15] = lower_modadd_6_0[15];
constraint lower_intermediate_output_5_7[16] = lower_rot_6_1[0];
constraint lower_intermediate_output_5_7[17] = lower_rot_6_1[1];
constraint lower_intermediate_output_5_7[18] = lower_rot_6_1[2];
constraint lower_intermediate_output_5_7[19] = lower_rot_6_1[3];
constraint lower_intermediate_output_5_7[20] = lower_rot_6_1[4];
constraint lower_intermediate_output_5_7[21] = lower_rot_6_1[5];
constraint lower_intermediate_output_5_7[22] = lower_rot_6_1[6];
constraint lower_intermediate_output_5_7[23] = lower_rot_6_1[7];
constraint lower_intermediate_output_5_7[24] = lower_rot_6_1[8];
constraint lower_intermediate_output_5_7[25] = lower_rot_6_1[9];
constraint lower_intermediate_output_5_7[26] = lower_rot_6_1[10];
constraint lower_intermediate_output_5_7[27] = lower_rot_6_1[11];
constraint lower_intermediate_output_5_7[28] = lower_rot_6_1[12];
constraint lower_intermediate_output_5_7[29] = lower_rot_6_1[13];
constraint lower_intermediate_output_5_7[30] = lower_rot_6_1[14];
constraint lower_intermediate_output_5_7[31] = lower_rot_6_1[15];
constraint lower_intermediate_output_5_7[32] = lower_modadd_6_4[0];
constraint lower_intermediate_output_5_7[33] = lower_modadd_6_4[1];
constraint lower_intermediate_output_5_7[34] = lower_modadd_6_4[2];
constraint lower_intermediate_output_5_7[35] = lower_modadd_6_4[3];
constraint lower_intermediate_output_5_7[36] = lower_modadd_6_4[4];
constraint lower_intermediate_output_5_7[37] = lower_modadd_6_4[5];
constraint lower_intermediate_output_5_7[38] = lower_modadd_6_4[6];
constraint lower_intermediate_output_5_7[39] = lower_modadd_6_4[7];
constraint lower_intermediate_output_5_7[40] = lower_modadd_6_4[8];
constraint lower_intermediate_output_5_7[41] = lower_modadd_6_4[9];
constraint lower_intermediate_output_5_7[42] = lower_modadd_6_4[10];
constraint lower_intermediate_output_5_7[43] = lower_modadd_6_4[11];
constraint lower_intermediate_output_5_7[44] = lower_modadd_6_4[12];
constraint lower_intermediate_output_5_7[45] = lower_modadd_6_4[13];
constraint lower_intermediate_output_5_7[46] = lower_modadd_6_4[14];
constraint lower_intermediate_output_5_7[47] = lower_modadd_6_4[15];
constraint lower_intermediate_output_5_7[48] = lower_rot_6_5[0];
constraint lower_intermediate_output_5_7[49] = lower_rot_6_5[1];
constraint lower_intermediate_output_5_7[50] = lower_rot_6_5[2];
constraint lower_intermediate_output_5_7[51] = lower_rot_6_5[3];
constraint lower_intermediate_output_5_7[52] = lower_rot_6_5[4];
constraint lower_intermediate_output_5_7[53] = lower_rot_6_5[5];
constraint lower_intermediate_output_5_7[54] = lower_rot_6_5[6];
constraint lower_intermediate_output_5_7[55] = lower_rot_6_5[7];
constraint lower_intermediate_output_5_7[56] = lower_rot_6_5[8];
constraint lower_intermediate_output_5_7[57] = lower_rot_6_5[9];
constraint lower_intermediate_output_5_7[58] = lower_rot_6_5[10];
constraint lower_intermediate_output_5_7[59] = lower_rot_6_5[11];
constraint lower_intermediate_output_5_7[60] = lower_rot_6_5[12];
constraint lower_intermediate_output_5_7[61] = lower_rot_6_5[13];
constraint lower_intermediate_output_5_7[62] = lower_rot_6_5[14];
constraint lower_intermediate_output_5_7[63] = lower_rot_6_5[15];
constraint lower_rot_5_1[0] = lower_xor_5_2[3];
constraint lower_rot_5_1[1] = lower_xor_5_2[4];
constraint lower_rot_5_1[2] = lower_xor_5_2[5];
constraint lower_rot_5_1[3] = lower_xor_5_2[6];
constraint lower_rot_5_1[4] = lower_xor_5_2[7];
constraint lower_rot_5_1[5] = lower_xor_5_2[8];
constraint lower_rot_5_1[6] = lower_xor_5_2[9];
constraint lower_rot_5_1[7] = lower_xor_5_2[10];
constraint lower_rot_5_1[8] = lower_xor_5_2[11];
constraint lower_rot_5_1[9] = lower_xor_5_2[12];
constraint lower_rot_5_1[10] = lower_xor_5_2[13];
constraint lower_rot_5_1[11] = lower_xor_5_2[14];
constraint lower_rot_5_1[12] = lower_xor_5_2[15];
constraint lower_rot_5_1[13] = lower_xor_5_2[0];
constraint lower_rot_5_1[14] = lower_xor_5_2[1];
constraint lower_rot_5_1[15] = lower_xor_5_2[2];
constraint 2*dummy_lower_xor_5_5[0] = (lower_rot_5_6[0] + lower_rot_6_1[0] + lower_xor_5_5[0]);
constraint 2*dummy_lower_xor_5_5[1] = (lower_rot_5_6[1] + lower_rot_6_1[1] + lower_xor_5_5[1]);
constraint 2*dummy_lower_xor_5_5[2] = (lower_rot_5_6[2] + lower_rot_6_1[2] + lower_xor_5_5[2]);
constraint 2*dummy_lower_xor_5_5[3] = (lower_rot_5_6[3] + lower_rot_6_1[3] + lower_xor_5_5[3]);
constraint 2*dummy_lower_xor_5_5[4] = (lower_rot_5_6[4] + lower_rot_6_1[4] + lower_xor_5_5[4]);
constraint 2*dummy_lower_xor_5_5[5] = (lower_rot_5_6[5] + lower_rot_6_1[5] + lower_xor_5_5[5]);
constraint 2*dummy_lower_xor_5_5[6] = (lower_rot_5_6[6] + lower_rot_6_1[6] + lower_xor_5_5[6]);
constraint 2*dummy_lower_xor_5_5[7] = (lower_rot_5_6[7] + lower_rot_6_1[7] + lower_xor_5_5[7]);
constraint 2*dummy_lower_xor_5_5[8] = (lower_rot_5_6[8] + lower_rot_6_1[8] + lower_xor_5_5[8]);
constraint 2*dummy_lower_xor_5_5[9] = (lower_rot_5_6[9] + lower_rot_6_1[9] + lower_xor_5_5[9]);
constraint 2*dummy_lower_xor_5_5[10] = (lower_rot_5_6[10] + lower_rot_6_1[10] + lower_xor_5_5[10]);
constraint 2*dummy_lower_xor_5_5[11] = (lower_rot_5_6[11] + lower_rot_6_1[11] + lower_xor_5_5[11]);
constraint 2*dummy_lower_xor_5_5[12] = (lower_rot_5_6[12] + lower_rot_6_1[12] + lower_xor_5_5[12]);
constraint 2*dummy_lower_xor_5_5[13] = (lower_rot_5_6[13] + lower_rot_6_1[13] + lower_xor_5_5[13]);
constraint 2*dummy_lower_xor_5_5[14] = (lower_rot_5_6[14] + lower_rot_6_1[14] + lower_xor_5_5[14]);
constraint 2*dummy_lower_xor_5_5[15] = (lower_rot_5_6[15] + lower_rot_6_1[15] + lower_xor_5_5[15]);
constraint pre_lower_modadd_5_0_0[0] = lower_modadd_6_0[0];
constraint pre_lower_modadd_5_0_0[1] = lower_modadd_6_0[1];
constraint pre_lower_modadd_5_0_0[2] = lower_modadd_6_0[2];
constraint pre_lower_modadd_5_0_0[3] = lower_modadd_6_0[3];
constraint pre_lower_modadd_5_0_0[4] = lower_modadd_6_0[4];
constraint pre_lower_modadd_5_0_0[5] = lower_modadd_6_0[5];
constraint pre_lower_modadd_5_0_0[6] = lower_modadd_6_0[6];
constraint pre_lower_modadd_5_0_0[7] = lower_modadd_6_0[7];
constraint pre_lower_modadd_5_0_0[8] = lower_modadd_6_0[8];
constraint pre_lower_modadd_5_0_0[9] = lower_modadd_6_0[9];
constraint pre_lower_modadd_5_0_0[10] = lower_modadd_6_0[10];
constraint pre_lower_modadd_5_0_0[11] = lower_modadd_6_0[11];
constraint pre_lower_modadd_5_0_0[12] = lower_modadd_6_0[12];
constraint pre_lower_modadd_5_0_0[13] = lower_modadd_6_0[13];
constraint pre_lower_modadd_5_0_0[14] = lower_modadd_6_0[14];
constraint pre_lower_modadd_5_0_0[15] = lower_modadd_6_0[15];
constraint pre_lower_modadd_5_0_1[0] = lower_rot_5_1[0];
constraint pre_lower_modadd_5_0_1[1] = lower_rot_5_1[1];
constraint pre_lower_modadd_5_0_1[2] = lower_rot_5_1[2];
constraint pre_lower_modadd_5_0_1[3] = lower_rot_5_1[3];
constraint pre_lower_modadd_5_0_1[4] = lower_rot_5_1[4];
constraint pre_lower_modadd_5_0_1[5] = lower_rot_5_1[5];
constraint pre_lower_modadd_5_0_1[6] = lower_rot_5_1[6];
constraint pre_lower_modadd_5_0_1[7] = lower_rot_5_1[7];
constraint pre_lower_modadd_5_0_1[8] = lower_rot_5_1[8];
constraint pre_lower_modadd_5_0_1[9] = lower_rot_5_1[9];
constraint pre_lower_modadd_5_0_1[10] = lower_rot_5_1[10];
constraint pre_lower_modadd_5_0_1[11] = lower_rot_5_1[11];
constraint pre_lower_modadd_5_0_1[12] = lower_rot_5_1[12];
constraint pre_lower_modadd_5_0_1[13] = lower_rot_5_1[13];
constraint pre_lower_modadd_5_0_1[14] = lower_rot_5_1[14];
constraint pre_lower_modadd_5_0_1[15] = lower_rot_5_1[15];
constraint forall(j in 0..15)(if eq_lower_modadd_5_0[j] = 1 then (sum([pre_lower_modadd_5_0_1[j], pre_lower_modadd_5_0_0[j], lower_modadd_5_0[j]]) mod 2) = Shi_pre_lower_modadd_5_0_0[j] else true endif) /\ lower_p[4] = (16-sum(eq_lower_modadd_5_0))*100;
constraint lower_rot_5_4[0] = lower_xor_5_5[9];
constraint lower_rot_5_4[1] = lower_xor_5_5[10];
constraint lower_rot_5_4[2] = lower_xor_5_5[11];
constraint lower_rot_5_4[3] = lower_xor_5_5[12];
constraint lower_rot_5_4[4] = lower_xor_5_5[13];
constraint lower_rot_5_4[5] = lower_xor_5_5[14];
constraint lower_rot_5_4[6] = lower_xor_5_5[15];
constraint lower_rot_5_4[7] = lower_xor_5_5[0];
constraint lower_rot_5_4[8] = lower_xor_5_5[1];
constraint lower_rot_5_4[9] = lower_xor_5_5[2];
constraint lower_rot_5_4[10] = lower_xor_5_5[3];
constraint lower_rot_5_4[11] = lower_xor_5_5[4];
constraint lower_rot_5_4[12] = lower_xor_5_5[5];
constraint lower_rot_5_4[13] = lower_xor_5_5[6];
constraint lower_rot_5_4[14] = lower_xor_5_5[7];
constraint lower_rot_5_4[15] = lower_xor_5_5[8];
constraint pre_lower_modadd_5_3_0[0] = lower_rot_5_6[0];
constraint pre_lower_modadd_5_3_0[1] = lower_rot_5_6[1];
constraint pre_lower_modadd_5_3_0[2] = lower_rot_5_6[2];
constraint pre_lower_modadd_5_3_0[3] = lower_rot_5_6[3];
constraint pre_lower_modadd_5_3_0[4] = lower_rot_5_6[4];
constraint pre_lower_modadd_5_3_0[5] = lower_rot_5_6[5];
constraint pre_lower_modadd_5_3_0[6] = lower_rot_5_6[6];
constraint pre_lower_modadd_5_3_0[7] = lower_rot_5_6[7];
constraint pre_lower_modadd_5_3_0[8] = lower_rot_5_6[8];
constraint pre_lower_modadd_5_3_0[9] = lower_rot_5_6[9];
constraint pre_lower_modadd_5_3_0[10] = lower_rot_5_6[10];
constraint pre_lower_modadd_5_3_0[11] = lower_rot_5_6[11];
constraint pre_lower_modadd_5_3_0[12] = lower_rot_5_6[12];
constraint pre_lower_modadd_5_3_0[13] = lower_rot_5_6[13];
constraint pre_lower_modadd_5_3_0[14] = lower_rot_5_6[14];
constraint pre_lower_modadd_5_3_0[15] = lower_rot_5_6[15];
constraint pre_lower_modadd_5_3_1[0] = lower_rot_5_4[0];
constraint pre_lower_modadd_5_3_1[1] = lower_rot_5_4[1];
constraint pre_lower_modadd_5_3_1[2] = lower_rot_5_4[2];
constraint pre_lower_modadd_5_3_1[3] = lower_rot_5_4[3];
constraint pre_lower_modadd_5_3_1[4] = lower_rot_5_4[4];
constraint pre_lower_modadd_5_3_1[5] = lower_rot_5_4[5];
constraint pre_lower_modadd_5_3_1[6] = lower_rot_5_4[6];
constraint pre_lower_modadd_5_3_1[7] = lower_rot_5_4[7];
constraint pre_lower_modadd_5_3_1[8] = lower_rot_5_4[8];
constraint pre_lower_modadd_5_3_1[9] = lower_rot_5_4[9];
constraint pre_lower_modadd_5_3_1[10] = lower_rot_5_4[10];
constraint pre_lower_modadd_5_3_1[11] = lower_rot_5_4[11];
constraint pre_lower_modadd_5_3_1[12] = lower_rot_5_4[12];
constraint pre_lower_modadd_5_3_1[13] = lower_rot_5_4[13];
constraint pre_lower_modadd_5_3_1[14] = lower_rot_5_4[14];
constraint pre_lower_modadd_5_3_1[15] = lower_rot_5_4[15];
constraint forall(j in 0..15)(if eq_lower_modadd_5_3[j] = 1 then (sum([pre_lower_modadd_5_3_1[j], pre_lower_modadd_5_3_0[j], lower_modadd_5_3[j]]) mod 2) = Shi_pre_lower_modadd_5_3_0[j] else true endif) /\ lower_p[5] = (16-sum(eq_lower_modadd_5_3))*100;
constraint lower_rot_6_3[0] = lower_modadd_7_0[0];
constraint lower_rot_6_3[1] = lower_modadd_7_0[1];
constraint lower_rot_6_3[2] = lower_modadd_7_0[2];
constraint lower_rot_6_3[3] = lower_modadd_7_0[3];
constraint lower_rot_6_3[4] = lower_modadd_7_0[4];
constraint lower_rot_6_3[5] = lower_modadd_7_0[5];
constraint lower_rot_6_3[6] = lower_modadd_7_0[6];
constraint lower_rot_6_3[7] = lower_modadd_7_0[7];
constraint lower_rot_6_3[8] = lower_modadd_7_0[8];
constraint lower_rot_6_3[9] = lower_modadd_7_0[9];
constraint lower_rot_6_3[10] = lower_modadd_7_0[10];
constraint lower_rot_6_3[11] = lower_modadd_7_0[11];
constraint lower_rot_6_3[12] = lower_modadd_7_0[12];
constraint lower_rot_6_3[13] = lower_modadd_7_0[13];
constraint lower_rot_6_3[14] = lower_modadd_7_0[14];
constraint lower_rot_6_3[15] = lower_modadd_7_0[15];
constraint 2*dummy_lower_xor_6_2[0] = (lower_rot_6_3[0] + lower_rot_7_4[0] + lower_xor_6_2[0]);
constraint 2*dummy_lower_xor_6_2[1] = (lower_rot_6_3[1] + lower_rot_7_4[1] + lower_xor_6_2[1]);
constraint 2*dummy_lower_xor_6_2[2] = (lower_rot_6_3[2] + lower_rot_7_4[2] + lower_xor_6_2[2]);
constraint 2*dummy_lower_xor_6_2[3] = (lower_rot_6_3[3] + lower_rot_7_4[3] + lower_xor_6_2[3]);
constraint 2*dummy_lower_xor_6_2[4] = (lower_rot_6_3[4] + lower_rot_7_4[4] + lower_xor_6_2[4]);
constraint 2*dummy_lower_xor_6_2[5] = (lower_rot_6_3[5] + lower_rot_7_4[5] + lower_xor_6_2[5]);
constraint 2*dummy_lower_xor_6_2[6] = (lower_rot_6_3[6] + lower_rot_7_4[6] + lower_xor_6_2[6]);
constraint 2*dummy_lower_xor_6_2[7] = (lower_rot_6_3[7] + lower_rot_7_4[7] + lower_xor_6_2[7]);
constraint 2*dummy_lower_xor_6_2[8] = (lower_rot_6_3[8] + lower_rot_7_4[8] + lower_xor_6_2[8]);
constraint 2*dummy_lower_xor_6_2[9] = (lower_rot_6_3[9] + lower_rot_7_4[9] + lower_xor_6_2[9]);
constraint 2*dummy_lower_xor_6_2[10] = (lower_rot_6_3[10] + lower_rot_7_4[10] + lower_xor_6_2[10]);
constraint 2*dummy_lower_xor_6_2[11] = (lower_rot_6_3[11] + lower_rot_7_4[11] + lower_xor_6_2[11]);
constraint 2*dummy_lower_xor_6_2[12] = (lower_rot_6_3[12] + lower_rot_7_4[12] + lower_xor_6_2[12]);
constraint 2*dummy_lower_xor_6_2[13] = (lower_rot_6_3[13] + lower_rot_7_4[13] + lower_xor_6_2[13]);
constraint 2*dummy_lower_xor_6_2[14] = (lower_rot_6_3[14] + lower_rot_7_4[14] + lower_xor_6_2[14]);
constraint 2*dummy_lower_xor_6_2[15] = (lower_rot_6_3[15] + lower_rot_7_4[15] + lower_xor_6_2[15]);
constraint 2*dummy_lower_xor_6_6[0] = (lower_modadd_7_3[0] + lower_rot_7_1[0] + lower_xor_6_6[0]);
constraint 2*dummy_lower_xor_6_6[1] = (lower_modadd_7_3[1] + lower_rot_7_1[1] + lower_xor_6_6[1]);
constraint 2*dummy_lower_xor_6_6[2] = (lower_modadd_7_3[2] + lower_rot_7_1[2] + lower_xor_6_6[2]);
constraint 2*dummy_lower_xor_6_6[3] = (lower_modadd_7_3[3] + lower_rot_7_1[3] + lower_xor_6_6[3]);
constraint 2*dummy_lower_xor_6_6[4] = (lower_modadd_7_3[4] + lower_rot_7_1[4] + lower_xor_6_6[4]);
constraint 2*dummy_lower_xor_6_6[5] = (lower_modadd_7_3[5] + lower_rot_7_1[5] + lower_xor_6_6[5]);
constraint 2*dummy_lower_xor_6_6[6] = (lower_modadd_7_3[6] + lower_rot_7_1[6] + lower_xor_6_6[6]);
constraint 2*dummy_lower_xor_6_6[7] = (lower_modadd_7_3[7] + lower_rot_7_1[7] + lower_xor_6_6[7]);
constraint 2*dummy_lower_xor_6_6[8] = (lower_modadd_7_3[8] + lower_rot_7_1[8] + lower_xor_6_6[8]);
constraint 2*dummy_lower_xor_6_6[9] = (lower_modadd_7_3[9] + lower_rot_7_1[9] + lower_xor_6_6[9]);
constraint 2*dummy_lower_xor_6_6[10] = (lower_modadd_7_3[10] + lower_rot_7_1[10] + lower_xor_6_6[10]);
constraint 2*dummy_lower_xor_6_6[11] = (lower_modadd_7_3[11] + lower_rot_7_1[11] + lower_xor_6_6[11]);
constraint 2*dummy_lower_xor_6_6[12] = (lower_modadd_7_3[12] + lower_rot_7_1[12] + lower_xor_6_6[12]);
constraint 2*dummy_lower_xor_6_6[13] = (lower_modadd_7_3[13] + lower_rot_7_1[13] + lower_xor_6_6[13]);
constraint 2*dummy_lower_xor_6_6[14] = (lower_modadd_7_3[14] + lower_rot_7_1[14] + lower_xor_6_6[14]);
constraint 2*dummy_lower_xor_6_6[15] = (lower_modadd_7_3[15] + lower_rot_7_1[15] + lower_xor_6_6[15]);
constraint lower_intermediate_output_6_7[0] = lower_modadd_7_0[0];
constraint lower_intermediate_output_6_7[1] = lower_modadd_7_0[1];
constraint lower_intermediate_output_6_7[2] = lower_modadd_7_0[2];
constraint lower_intermediate_output_6_7[3] = lower_modadd_7_0[3];
constraint lower_intermediate_output_6_7[4] = lower_modadd_7_0[4];
constraint lower_intermediate_output_6_7[5] = lower_modadd_7_0[5];
constraint lower_intermediate_output_6_7[6] = lower_modadd_7_0[6];
constraint lower_intermediate_output_6_7[7] = lower_modadd_7_0[7];
constraint lower_intermediate_output_6_7[8] = lower_modadd_7_0[8];
constraint lower_intermediate_output_6_7[9] = lower_modadd_7_0[9];
constraint lower_intermediate_output_6_7[10] = lower_modadd_7_0[10];
constraint lower_intermediate_output_6_7[11] = lower_modadd_7_0[11];
constraint lower_intermediate_output_6_7[12] = lower_modadd_7_0[12];
constraint lower_intermediate_output_6_7[13] = lower_modadd_7_0[13];
constraint lower_intermediate_output_6_7[14] = lower_modadd_7_0[14];
constraint lower_intermediate_output_6_7[15] = lower_modadd_7_0[15];
constraint lower_intermediate_output_6_7[16] = lower_rot_7_4[0];
constraint lower_intermediate_output_6_7[17] = lower_rot_7_4[1];
constraint lower_intermediate_output_6_7[18] = lower_rot_7_4[2];
constraint lower_intermediate_output_6_7[19] = lower_rot_7_4[3];
constraint lower_intermediate_output_6_7[20] = lower_rot_7_4[4];
constraint lower_intermediate_output_6_7[21] = lower_rot_7_4[5];
constraint lower_intermediate_output_6_7[22] = lower_rot_7_4[6];
constraint lower_intermediate_output_6_7[23] = lower_rot_7_4[7];
constraint lower_intermediate_output_6_7[24] = lower_rot_7_4[8];
constraint lower_intermediate_output_6_7[25] = lower_rot_7_4[9];
constraint lower_intermediate_output_6_7[26] = lower_rot_7_4[10];
constraint lower_intermediate_output_6_7[27] = lower_rot_7_4[11];
constraint lower_intermediate_output_6_7[28] = lower_rot_7_4[12];
constraint lower_intermediate_output_6_7[29] = lower_rot_7_4[13];
constraint lower_intermediate_output_6_7[30] = lower_rot_7_4[14];
constraint lower_intermediate_output_6_7[31] = lower_rot_7_4[15];
constraint lower_intermediate_output_6_7[32] = lower_modadd_7_3[0];
constraint lower_intermediate_output_6_7[33] = lower_modadd_7_3[1];
constraint lower_intermediate_output_6_7[34] = lower_modadd_7_3[2];
constraint lower_intermediate_output_6_7[35] = lower_modadd_7_3[3];
constraint lower_intermediate_output_6_7[36] = lower_modadd_7_3[4];
constraint lower_intermediate_output_6_7[37] = lower_modadd_7_3[5];
constraint lower_intermediate_output_6_7[38] = lower_modadd_7_3[6];
constraint lower_intermediate_output_6_7[39] = lower_modadd_7_3[7];
constraint lower_intermediate_output_6_7[40] = lower_modadd_7_3[8];
constraint lower_intermediate_output_6_7[41] = lower_modadd_7_3[9];
constraint lower_intermediate_output_6_7[42] = lower_modadd_7_3[10];
constraint lower_intermediate_output_6_7[43] = lower_modadd_7_3[11];
constraint lower_intermediate_output_6_7[44] = lower_modadd_7_3[12];
constraint lower_intermediate_output_6_7[45] = lower_modadd_7_3[13];
constraint lower_intermediate_output_6_7[46] = lower_modadd_7_3[14];
constraint lower_intermediate_output_6_7[47] = lower_modadd_7_3[15];
constraint lower_intermediate_output_6_7[48] = lower_rot_7_1[0];
constraint lower_intermediate_output_6_7[49] = lower_rot_7_1[1];
constraint lower_intermediate_output_6_7[50] = lower_rot_7_1[2];
constraint lower_intermediate_output_6_7[51] = lower_rot_7_1[3];
constraint lower_intermediate_output_6_7[52] = lower_rot_7_1[4];
constraint lower_intermediate_output_6_7[53] = lower_rot_7_1[5];
constraint lower_intermediate_output_6_7[54] = lower_rot_7_1[6];
constraint lower_intermediate_output_6_7[55] = lower_rot_7_1[7];
constraint lower_intermediate_output_6_7[56] = lower_rot_7_1[8];
constraint lower_intermediate_output_6_7[57] = lower_rot_7_1[9];
constraint lower_intermediate_output_6_7[58] = lower_rot_7_1[10];
constraint lower_intermediate_output_6_7[59] = lower_rot_7_1[11];
constraint lower_intermediate_output_6_7[60] = lower_rot_7_1[12];
constraint lower_intermediate_output_6_7[61] = lower_rot_7_1[13];
constraint lower_intermediate_output_6_7[62] = lower_rot_7_1[14];
constraint lower_intermediate_output_6_7[63] = lower_rot_7_1[15];
constraint lower_rot_6_1[0] = lower_xor_6_2[11];
constraint lower_rot_6_1[1] = lower_xor_6_2[12];
constraint lower_rot_6_1[2] = lower_xor_6_2[13];
constraint lower_rot_6_1[3] = lower_xor_6_2[14];
constraint lower_rot_6_1[4] = lower_xor_6_2[15];
constraint lower_rot_6_1[5] = lower_xor_6_2[0];
constraint lower_rot_6_1[6] = lower_xor_6_2[1];
constraint lower_rot_6_1[7] = lower_xor_6_2[2];
constraint lower_rot_6_1[8] = lower_xor_6_2[3];
constraint lower_rot_6_1[9] = lower_xor_6_2[4];
constraint lower_rot_6_1[10] = lower_xor_6_2[5];
constraint lower_rot_6_1[11] = lower_xor_6_2[6];
constraint lower_rot_6_1[12] = lower_xor_6_2[7];
constraint lower_rot_6_1[13] = lower_xor_6_2[8];
constraint lower_rot_6_1[14] = lower_xor_6_2[9];
constraint lower_rot_6_1[15] = lower_xor_6_2[10];
constraint lower_rot_6_5[0] = lower_xor_6_6[8];
constraint lower_rot_6_5[1] = lower_xor_6_6[9];
constraint lower_rot_6_5[2] = lower_xor_6_6[10];
constraint lower_rot_6_5[3] = lower_xor_6_6[11];
constraint lower_rot_6_5[4] = lower_xor_6_6[12];
constraint lower_rot_6_5[5] = lower_xor_6_6[13];
constraint lower_rot_6_5[6] = lower_xor_6_6[14];
constraint lower_rot_6_5[7] = lower_xor_6_6[15];
constraint lower_rot_6_5[8] = lower_xor_6_6[0];
constraint lower_rot_6_5[9] = lower_xor_6_6[1];
constraint lower_rot_6_5[10] = lower_xor_6_6[2];
constraint lower_rot_6_5[11] = lower_xor_6_6[3];
constraint lower_rot_6_5[12] = lower_xor_6_6[4];
constraint lower_rot_6_5[13] = lower_xor_6_6[5];
constraint lower_rot_6_5[14] = lower_xor_6_6[6];
constraint lower_rot_6_5[15] = lower_xor_6_6[7];
constraint pre_lower_modadd_6_0_0[0] = lower_rot_6_3[0];
constraint pre_lower_modadd_6_0_0[1] = lower_rot_6_3[1];
constraint pre_lower_modadd_6_0_0[2] = lower_rot_6_3[2];
constraint pre_lower_modadd_6_0_0[3] = lower_rot_6_3[3];
constraint pre_lower_modadd_6_0_0[4] = lower_rot_6_3[4];
constraint pre_lower_modadd_6_0_0[5] = lower_rot_6_3[5];
constraint pre_lower_modadd_6_0_0[6] = lower_rot_6_3[6];
constraint pre_lower_modadd_6_0_0[7] = lower_rot_6_3[7];
constraint pre_lower_modadd_6_0_0[8] = lower_rot_6_3[8];
constraint pre_lower_modadd_6_0_0[9] = lower_rot_6_3[9];
constraint pre_lower_modadd_6_0_0[10] = lower_rot_6_3[10];
constraint pre_lower_modadd_6_0_0[11] = lower_rot_6_3[11];
constraint pre_lower_modadd_6_0_0[12] = lower_rot_6_3[12];
constraint pre_lower_modadd_6_0_0[13] = lower_rot_6_3[13];
constraint pre_lower_modadd_6_0_0[14] = lower_rot_6_3[14];
constraint pre_lower_modadd_6_0_0[15] = lower_rot_6_3[15];
constraint pre_lower_modadd_6_0_1[0] = lower_rot_6_1[0];
constraint pre_lower_modadd_6_0_1[1] = lower_rot_6_1[1];
constraint pre_lower_modadd_6_0_1[2] = lower_rot_6_1[2];
constraint pre_lower_modadd_6_0_1[3] = lower_rot_6_1[3];
constraint pre_lower_modadd_6_0_1[4] = lower_rot_6_1[4];
constraint pre_lower_modadd_6_0_1[5] = lower_rot_6_1[5];
constraint pre_lower_modadd_6_0_1[6] = lower_rot_6_1[6];
constraint pre_lower_modadd_6_0_1[7] = lower_rot_6_1[7];
constraint pre_lower_modadd_6_0_1[8] = lower_rot_6_1[8];
constraint pre_lower_modadd_6_0_1[9] = lower_rot_6_1[9];
constraint pre_lower_modadd_6_0_1[10] = lower_rot_6_1[10];
constraint pre_lower_modadd_6_0_1[11] = lower_rot_6_1[11];
constraint pre_lower_modadd_6_0_1[12] = lower_rot_6_1[12];
constraint pre_lower_modadd_6_0_1[13] = lower_rot_6_1[13];
constraint pre_lower_modadd_6_0_1[14] = lower_rot_6_1[14];
constraint pre_lower_modadd_6_0_1[15] = lower_rot_6_1[15];
constraint forall(j in 0..15)(if eq_lower_modadd_6_0[j] = 1 then (sum([pre_lower_modadd_6_0_1[j], pre_lower_modadd_6_0_0[j], lower_modadd_6_0[j]]) mod 2) = Shi_pre_lower_modadd_6_0_0[j] else true endif) /\ lower_p[6] = (16-sum(eq_lower_modadd_6_0))*100;
constraint pre_lower_modadd_6_4_0[0] = lower_modadd_7_3[0];
constraint pre_lower_modadd_6_4_0[1] = lower_modadd_7_3[1];
constraint pre_lower_modadd_6_4_0[2] = lower_modadd_7_3[2];
constraint pre_lower_modadd_6_4_0[3] = lower_modadd_7_3[3];
constraint pre_lower_modadd_6_4_0[4] = lower_modadd_7_3[4];
constraint pre_lower_modadd_6_4_0[5] = lower_modadd_7_3[5];
constraint pre_lower_modadd_6_4_0[6] = lower_modadd_7_3[6];
constraint pre_lower_modadd_6_4_0[7] = lower_modadd_7_3[7];
constraint pre_lower_modadd_6_4_0[8] = lower_modadd_7_3[8];
constraint pre_lower_modadd_6_4_0[9] = lower_modadd_7_3[9];
constraint pre_lower_modadd_6_4_0[10] = lower_modadd_7_3[10];
constraint pre_lower_modadd_6_4_0[11] = lower_modadd_7_3[11];
constraint pre_lower_modadd_6_4_0[12] = lower_modadd_7_3[12];
constraint pre_lower_modadd_6_4_0[13] = lower_modadd_7_3[13];
constraint pre_lower_modadd_6_4_0[14] = lower_modadd_7_3[14];
constraint pre_lower_modadd_6_4_0[15] = lower_modadd_7_3[15];
constraint pre_lower_modadd_6_4_1[0] = lower_rot_6_5[0];
constraint pre_lower_modadd_6_4_1[1] = lower_rot_6_5[1];
constraint pre_lower_modadd_6_4_1[2] = lower_rot_6_5[2];
constraint pre_lower_modadd_6_4_1[3] = lower_rot_6_5[3];
constraint pre_lower_modadd_6_4_1[4] = lower_rot_6_5[4];
constraint pre_lower_modadd_6_4_1[5] = lower_rot_6_5[5];
constraint pre_lower_modadd_6_4_1[6] = lower_rot_6_5[6];
constraint pre_lower_modadd_6_4_1[7] = lower_rot_6_5[7];
constraint pre_lower_modadd_6_4_1[8] = lower_rot_6_5[8];
constraint pre_lower_modadd_6_4_1[9] = lower_rot_6_5[9];
constraint pre_lower_modadd_6_4_1[10] = lower_rot_6_5[10];
constraint pre_lower_modadd_6_4_1[11] = lower_rot_6_5[11];
constraint pre_lower_modadd_6_4_1[12] = lower_rot_6_5[12];
constraint pre_lower_modadd_6_4_1[13] = lower_rot_6_5[13];
constraint pre_lower_modadd_6_4_1[14] = lower_rot_6_5[14];
constraint pre_lower_modadd_6_4_1[15] = lower_rot_6_5[15];
constraint forall(j in 0..15)(if eq_lower_modadd_6_4[j] = 1 then (sum([pre_lower_modadd_6_4_1[j], pre_lower_modadd_6_4_0[j], lower_modadd_6_4[j]]) mod 2) = Shi_pre_lower_modadd_6_4_0[j] else true endif) /\ lower_p[7] = (16-sum(eq_lower_modadd_6_4))*100;
constraint 2*dummy_lower_xor_7_2[0] = (lower_cipher_output_7_7[0] + lower_cipher_output_7_7[48] + lower_xor_7_2[0]);
constraint 2*dummy_lower_xor_7_2[1] = (lower_cipher_output_7_7[1] + lower_cipher_output_7_7[49] + lower_xor_7_2[1]);
constraint 2*dummy_lower_xor_7_2[2] = (lower_cipher_output_7_7[2] + lower_cipher_output_7_7[50] + lower_xor_7_2[2]);
constraint 2*dummy_lower_xor_7_2[3] = (lower_cipher_output_7_7[3] + lower_cipher_output_7_7[51] + lower_xor_7_2[3]);
constraint 2*dummy_lower_xor_7_2[4] = (lower_cipher_output_7_7[4] + lower_cipher_output_7_7[52] + lower_xor_7_2[4]);
constraint 2*dummy_lower_xor_7_2[5] = (lower_cipher_output_7_7[5] + lower_cipher_output_7_7[53] + lower_xor_7_2[5]);
constraint 2*dummy_lower_xor_7_2[6] = (lower_cipher_output_7_7[6] + lower_cipher_output_7_7[54] + lower_xor_7_2[6]);
constraint 2*dummy_lower_xor_7_2[7] = (lower_cipher_output_7_7[7] + lower_cipher_output_7_7[55] + lower_xor_7_2[7]);
constraint 2*dummy_lower_xor_7_2[8] = (lower_cipher_output_7_7[8] + lower_cipher_output_7_7[56] + lower_xor_7_2[8]);
constraint 2*dummy_lower_xor_7_2[9] = (lower_cipher_output_7_7[9] + lower_cipher_output_7_7[57] + lower_xor_7_2[9]);
constraint 2*dummy_lower_xor_7_2[10] = (lower_cipher_output_7_7[10] + lower_cipher_output_7_7[58] + lower_xor_7_2[10]);
constraint 2*dummy_lower_xor_7_2[11] = (lower_cipher_output_7_7[11] + lower_cipher_output_7_7[59] + lower_xor_7_2[11]);
constraint 2*dummy_lower_xor_7_2[12] = (lower_cipher_output_7_7[12] + lower_cipher_output_7_7[60] + lower_xor_7_2[12]);
constraint 2*dummy_lower_xor_7_2[13] = (lower_cipher_output_7_7[13] + lower_cipher_output_7_7[61] + lower_xor_7_2[13]);
constraint 2*dummy_lower_xor_7_2[14] = (lower_cipher_output_7_7[14] + lower_cipher_output_7_7[62] + lower_xor_7_2[14]);
constraint 2*dummy_lower_xor_7_2[15] = (lower_cipher_output_7_7[15] + lower_cipher_output_7_7[63] + lower_xor_7_2[15]);
constraint lower_rot_7_6[0] = lower_cipher_output_7_7[32];
constraint lower_rot_7_6[1] = lower_cipher_output_7_7[33];
constraint lower_rot_7_6[2] = lower_cipher_output_7_7[34];
constraint lower_rot_7_6[3] = lower_cipher_output_7_7[35];
constraint lower_rot_7_6[4] = lower_cipher_output_7_7[36];
constraint lower_rot_7_6[5] = lower_cipher_output_7_7[37];
constraint lower_rot_7_6[6] = lower_cipher_output_7_7[38];
constraint lower_rot_7_6[7] = lower_cipher_output_7_7[39];
constraint lower_rot_7_6[8] = lower_cipher_output_7_7[40];
constraint lower_rot_7_6[9] = lower_cipher_output_7_7[41];
constraint lower_rot_7_6[10] = lower_cipher_output_7_7[42];
constraint lower_rot_7_6[11] = lower_cipher_output_7_7[43];
constraint lower_rot_7_6[12] = lower_cipher_output_7_7[44];
constraint lower_rot_7_6[13] = lower_cipher_output_7_7[45];
constraint lower_rot_7_6[14] = lower_cipher_output_7_7[46];
constraint lower_rot_7_6[15] = lower_cipher_output_7_7[47];
constraint lower_rot_7_1[0] = lower_xor_7_2[3];
constraint lower_rot_7_1[1] = lower_xor_7_2[4];
constraint lower_rot_7_1[2] = lower_xor_7_2[5];
constraint lower_rot_7_1[3] = lower_xor_7_2[6];
constraint lower_rot_7_1[4] = lower_xor_7_2[7];
constraint lower_rot_7_1[5] = lower_xor_7_2[8];
constraint lower_rot_7_1[6] = lower_xor_7_2[9];
constraint lower_rot_7_1[7] = lower_xor_7_2[10];
constraint lower_rot_7_1[8] = lower_xor_7_2[11];
constraint lower_rot_7_1[9] = lower_xor_7_2[12];
constraint lower_rot_7_1[10] = lower_xor_7_2[13];
constraint lower_rot_7_1[11] = lower_xor_7_2[14];
constraint lower_rot_7_1[12] = lower_xor_7_2[15];
constraint lower_rot_7_1[13] = lower_xor_7_2[0];
constraint lower_rot_7_1[14] = lower_xor_7_2[1];
constraint lower_rot_7_1[15] = lower_xor_7_2[2];
constraint 2*dummy_lower_xor_7_5[0] = (lower_rot_7_6[0] + lower_cipher_output_7_7[16] + lower_xor_7_5[0]);
constraint 2*dummy_lower_xor_7_5[1] = (lower_rot_7_6[1] + lower_cipher_output_7_7[17] + lower_xor_7_5[1]);
constraint 2*dummy_lower_xor_7_5[2] = (lower_rot_7_6[2] + lower_cipher_output_7_7[18] + lower_xor_7_5[2]);
constraint 2*dummy_lower_xor_7_5[3] = (lower_rot_7_6[3] + lower_cipher_output_7_7[19] + lower_xor_7_5[3]);
constraint 2*dummy_lower_xor_7_5[4] = (lower_rot_7_6[4] + lower_cipher_output_7_7[20] + lower_xor_7_5[4]);
constraint 2*dummy_lower_xor_7_5[5] = (lower_rot_7_6[5] + lower_cipher_output_7_7[21] + lower_xor_7_5[5]);
constraint 2*dummy_lower_xor_7_5[6] = (lower_rot_7_6[6] + lower_cipher_output_7_7[22] + lower_xor_7_5[6]);
constraint 2*dummy_lower_xor_7_5[7] = (lower_rot_7_6[7] + lower_cipher_output_7_7[23] + lower_xor_7_5[7]);
constraint 2*dummy_lower_xor_7_5[8] = (lower_rot_7_6[8] + lower_cipher_output_7_7[24] + lower_xor_7_5[8]);
constraint 2*dummy_lower_xor_7_5[9] = (lower_rot_7_6[9] + lower_cipher_output_7_7[25] + lower_xor_7_5[9]);
constraint 2*dummy_lower_xor_7_5[10] = (lower_rot_7_6[10] + lower_cipher_output_7_7[26] + lower_xor_7_5[10]);
constraint 2*dummy_lower_xor_7_5[11] = (lower_rot_7_6[11] + lower_cipher_output_7_7[27] + lower_xor_7_5[11]);
constraint 2*dummy_lower_xor_7_5[12] = (lower_rot_7_6[12] + lower_cipher_output_7_7[28] + lower_xor_7_5[12]);
constraint 2*dummy_lower_xor_7_5[13] = (lower_rot_7_6[13] + lower_cipher_output_7_7[29] + lower_xor_7_5[13]);
constraint 2*dummy_lower_xor_7_5[14] = (lower_rot_7_6[14] + lower_cipher_output_7_7[30] + lower_xor_7_5[14]);
constraint 2*dummy_lower_xor_7_5[15] = (lower_rot_7_6[15] + lower_cipher_output_7_7[31] + lower_xor_7_5[15]);
constraint pre_lower_modadd_7_0_0[0] = lower_cipher_output_7_7[0];
constraint pre_lower_modadd_7_0_0[1] = lower_cipher_output_7_7[1];
constraint pre_lower_modadd_7_0_0[2] = lower_cipher_output_7_7[2];
constraint pre_lower_modadd_7_0_0[3] = lower_cipher_output_7_7[3];
constraint pre_lower_modadd_7_0_0[4] = lower_cipher_output_7_7[4];
constraint pre_lower_modadd_7_0_0[5] = lower_cipher_output_7_7[5];
constraint pre_lower_modadd_7_0_0[6] = lower_cipher_output_7_7[6];
constraint pre_lower_modadd_7_0_0[7] = lower_cipher_output_7_7[7];
constraint pre_lower_modadd_7_0_0[8] = lower_cipher_output_7_7[8];
constraint pre_lower_modadd_7_0_0[9] = lower_cipher_output_7_7[9];
constraint pre_lower_modadd_7_0_0[10] = lower_cipher_output_7_7[10];
constraint pre_lower_modadd_7_0_0[11] = lower_cipher_output_7_7[11];
constraint pre_lower_modadd_7_0_0[12] = lower_cipher_output_7_7[12];
constraint pre_lower_modadd_7_0_0[13] = lower_cipher_output_7_7[13];
constraint pre_lower_modadd_7_0_0[14] = lower_cipher_output_7_7[14];
constraint pre_lower_modadd_7_0_0[15] = lower_cipher_output_7_7[15];
constraint pre_lower_modadd_7_0_1[0] = lower_rot_7_1[0];
constraint pre_lower_modadd_7_0_1[1] = lower_rot_7_1[1];
constraint pre_lower_modadd_7_0_1[2] = lower_rot_7_1[2];
constraint pre_lower_modadd_7_0_1[3] = lower_rot_7_1[3];
constraint pre_lower_modadd_7_0_1[4] = lower_rot_7_1[4];
constraint pre_lower_modadd_7_0_1[5] = lower_rot_7_1[5];
constraint pre_lower_modadd_7_0_1[6] = lower_rot_7_1[6];
constraint pre_lower_modadd_7_0_1[7] = lower_rot_7_1[7];
constraint pre_lower_modadd_7_0_1[8] = lower_rot_7_1[8];
constraint pre_lower_modadd_7_0_1[9] = lower_rot_7_1[9];
constraint pre_lower_modadd_7_0_1[10] = lower_rot_7_1[10];
constraint pre_lower_modadd_7_0_1[11] = lower_rot_7_1[11];
constraint pre_lower_modadd_7_0_1[12] = lower_rot_7_1[12];
constraint pre_lower_modadd_7_0_1[13] = lower_rot_7_1[13];
constraint pre_lower_modadd_7_0_1[14] = lower_rot_7_1[14];
constraint pre_lower_modadd_7_0_1[15] = lower_rot_7_1[15];
constraint forall(j in 0..15)(if eq_lower_modadd_7_0[j] = 1 then (sum([pre_lower_modadd_7_0_1[j], pre_lower_modadd_7_0_0[j], lower_modadd_7_0[j]]) mod 2) = Shi_pre_lower_modadd_7_0_0[j] else true endif) /\ lower_p[8] = (16-sum(eq_lower_modadd_7_0))*100;
constraint lower_rot_7_4[0] = lower_xor_7_5[9];
constraint lower_rot_7_4[1] = lower_xor_7_5[10];
constraint lower_rot_7_4[2] = lower_xor_7_5[11];
constraint lower_rot_7_4[3] = lower_xor_7_5[12];
constraint lower_rot_7_4[4] = lower_xor_7_5[13];
constraint lower_rot_7_4[5] = lower_xor_7_5[14];
constraint lower_rot_7_4[6] = lower_xor_7_5[15];
constraint lower_rot_7_4[7] = lower_xor_7_5[0];
constraint lower_rot_7_4[8] = lower_xor_7_5[1];
constraint lower_rot_7_4[9] = lower_xor_7_5[2];
constraint lower_rot_7_4[10] = lower_xor_7_5[3];
constraint lower_rot_7_4[11] = lower_xor_7_5[4];
constraint lower_rot_7_4[12] = lower_xor_7_5[5];
constraint lower_rot_7_4[13] = lower_xor_7_5[6];
constraint lower_rot_7_4[14] = lower_xor_7_5[7];
constraint lower_rot_7_4[15] = lower_xor_7_5[8];
constraint pre_lower_modadd_7_3_0[0] = lower_rot_7_6[0];
constraint pre_lower_modadd_7_3_0[1] = lower_rot_7_6[1];
constraint pre_lower_modadd_7_3_0[2] = lower_rot_7_6[2];
constraint pre_lower_modadd_7_3_0[3] = lower_rot_7_6[3];
constraint pre_lower_modadd_7_3_0[4] = lower_rot_7_6[4];
constraint pre_lower_modadd_7_3_0[5] = lower_rot_7_6[5];
constraint pre_lower_modadd_7_3_0[6] = lower_rot_7_6[6];
constraint pre_lower_modadd_7_3_0[7] = lower_rot_7_6[7];
constraint pre_lower_modadd_7_3_0[8] = lower_rot_7_6[8];
constraint pre_lower_modadd_7_3_0[9] = lower_rot_7_6[9];
constraint pre_lower_modadd_7_3_0[10] = lower_rot_7_6[10];
constraint pre_lower_modadd_7_3_0[11] = lower_rot_7_6[11];
constraint pre_lower_modadd_7_3_0[12] = lower_rot_7_6[12];
constraint pre_lower_modadd_7_3_0[13] = lower_rot_7_6[13];
constraint pre_lower_modadd_7_3_0[14] = lower_rot_7_6[14];
constraint pre_lower_modadd_7_3_0[15] = lower_rot_7_6[15];
constraint pre_lower_modadd_7_3_1[0] = lower_rot_7_4[0];
constraint pre_lower_modadd_7_3_1[1] = lower_rot_7_4[1];
constraint pre_lower_modadd_7_3_1[2] = lower_rot_7_4[2];
constraint pre_lower_modadd_7_3_1[3] = lower_rot_7_4[3];
constraint pre_lower_modadd_7_3_1[4] = lower_rot_7_4[4];
constraint pre_lower_modadd_7_3_1[5] = lower_rot_7_4[5];
constraint pre_lower_modadd_7_3_1[6] = lower_rot_7_4[6];
constraint pre_lower_modadd_7_3_1[7] = lower_rot_7_4[7];
constraint pre_lower_modadd_7_3_1[8] = lower_rot_7_4[8];
constraint pre_lower_modadd_7_3_1[9] = lower_rot_7_4[9];
constraint pre_lower_modadd_7_3_1[10] = lower_rot_7_4[10];
constraint pre_lower_modadd_7_3_1[11] = lower_rot_7_4[11];
constraint pre_lower_modadd_7_3_1[12] = lower_rot_7_4[12];
constraint pre_lower_modadd_7_3_1[13] = lower_rot_7_4[13];
constraint pre_lower_modadd_7_3_1[14] = lower_rot_7_4[14];
constraint pre_lower_modadd_7_3_1[15] = lower_rot_7_4[15];
constraint forall(j in 0..15)(if eq_lower_modadd_7_3[j] = 1 then (sum([pre_lower_modadd_7_3_1[j], pre_lower_modadd_7_3_0[j], lower_modadd_7_3[j]]) mod 2) = Shi_pre_lower_modadd_7_3_0[j] else true endif) /\ lower_p[9] = (16-sum(eq_lower_modadd_7_3))*100;
constraint onlyLargeSwitch_UBCT_enum(array1d(0..16-1, [pre_upper_modadd_3_0_0[15],pre_upper_modadd_3_0_0[14],pre_upper_modadd_3_0_0[13],pre_upper_modadd_3_0_0[12],pre_upper_modadd_3_0_0[11],pre_upper_modadd_3_0_0[10],pre_upper_modadd_3_0_0[9],pre_upper_modadd_3_0_0[8],pre_upper_modadd_3_0_0[7],pre_upper_modadd_3_0_0[6],pre_upper_modadd_3_0_0[5],pre_upper_modadd_3_0_0[4],pre_upper_modadd_3_0_0[3],pre_upper_modadd_3_0_0[2],pre_upper_modadd_3_0_0[1],pre_upper_modadd_3_0_0[0]]), array1d(0..16-1, [pre_upper_modadd_3_0_1[15],pre_upper_modadd_3_0_1[14],pre_upper_modadd_3_0_1[13],pre_upper_modadd_3_0_1[12],pre_upper_modadd_3_0_1[11],pre_upper_modadd_3_0_1[10],pre_upper_modadd_3_0_1[9],pre_upper_modadd_3_0_1[8],pre_upper_modadd_3_0_1[7],pre_upper_modadd_3_0_1[6],pre_upper_modadd_3_0_1[5],pre_upper_modadd_3_0_1[4],pre_upper_modadd_3_0_1[3],pre_upper_modadd_3_0_1[2],pre_upper_modadd_3_0_1[1],pre_upper_modadd_3_0_1[0]]), array1d(0..16-1, [pre_lower_modadd_3_0_0[15],pre_lower_modadd_3_0_0[14],pre_lower_modadd_3_0_0[13],pre_lower_modadd_3_0_0[12],pre_lower_modadd_3_0_0[11],pre_lower_modadd_3_0_0[10],pre_lower_modadd_3_0_0[9],pre_lower_modadd_3_0_0[8],pre_lower_modadd_3_0_0[7],pre_lower_modadd_3_0_0[6],pre_lower_modadd_3_0_0[5],pre_lower_modadd_3_0_0[4],pre_lower_modadd_3_0_0[3],pre_lower_modadd_3_0_0[2],pre_lower_modadd_3_0_0[1],pre_lower_modadd_3_0_0[0]]), array1d(0..16-1, [pre_lower_modadd_3_0_1[15],pre_lower_modadd_3_0_1[14],pre_lower_modadd_3_0_1[13],pre_lower_modadd_3_0_1[12],pre_lower_modadd_3_0_1[11],pre_lower_modadd_3_0_1[10],pre_lower_modadd_3_0_1[9],pre_lower_modadd_3_0_1[8],pre_lower_modadd_3_0_1[7],pre_lower_modadd_3_0_1[6],pre_lower_modadd_3_0_1[5],pre_lower_modadd_3_0_1[4],pre_lower_modadd_3_0_1[3],pre_lower_modadd_3_0_1[2],pre_lower_modadd_3_0_1[1],pre_lower_modadd_3_0_1[0]]), array1d(0..16-1, [upper_modadd_3_0[15],upper_modadd_3_0[14],upper_modadd_3_0[13],upper_modadd_3_0[12],upper_modadd_3_0[11],upper_modadd_3_0[10],upper_modadd_3_0[9],upper_modadd_3_0[8],upper_modadd_3_0[7],upper_modadd_3_0[6],upper_modadd_3_0[5],upper_modadd_3_0[4],upper_modadd_3_0[3],upper_modadd_3_0[2],upper_modadd_3_0[1],upper_modadd_3_0[0]]), 8, 16) = true;

constraint ubct_compute(array1d(0..16-1, [pre_upper_modadd_3_0_0[0],pre_upper_modadd_3_0_0[1],pre_upper_modadd_3_0_0[2],pre_upper_modadd_3_0_0[3],pre_upper_modadd_3_0_0[4],pre_upper_modadd_3_0_0[5],pre_upper_modadd_3_0_0[6],pre_upper_modadd_3_0_0[7],pre_upper_modadd_3_0_0[8],pre_upper_modadd_3_0_0[9],pre_upper_modadd_3_0_0[10],pre_upper_modadd_3_0_0[11],pre_upper_modadd_3_0_0[12],pre_upper_modadd_3_0_0[13],pre_upper_modadd_3_0_0[14],pre_upper_modadd_3_0_0[15]]), array1d(0..16-1, [pre_upper_modadd_3_0_1[0],pre_upper_modadd_3_0_1[1],pre_upper_modadd_3_0_1[2],pre_upper_modadd_3_0_1[3],pre_upper_modadd_3_0_1[4],pre_upper_modadd_3_0_1[5],pre_upper_modadd_3_0_1[6],pre_upper_modadd_3_0_1[7],pre_upper_modadd_3_0_1[8],pre_upper_modadd_3_0_1[9],pre_upper_modadd_3_0_1[10],pre_upper_modadd_3_0_1[11],pre_upper_modadd_3_0_1[12],pre_upper_modadd_3_0_1[13],pre_upper_modadd_3_0_1[14],pre_upper_modadd_3_0_1[15]]), array1d(0..16-1, [pre_lower_modadd_3_0_0[0],pre_lower_modadd_3_0_0[1],pre_lower_modadd_3_0_0[2],pre_lower_modadd_3_0_0[3],pre_lower_modadd_3_0_0[4],pre_lower_modadd_3_0_0[5],pre_lower_modadd_3_0_0[6],pre_lower_modadd_3_0_0[7],pre_lower_modadd_3_0_0[8],pre_lower_modadd_3_0_0[9],pre_lower_modadd_3_0_0[10],pre_lower_modadd_3_0_0[11],pre_lower_modadd_3_0_0[12],pre_lower_modadd_3_0_0[13],pre_lower_modadd_3_0_0[14],pre_lower_modadd_3_0_0[15]]), array1d(0..16-1, [pre_lower_modadd_3_0_1[0],pre_lower_modadd_3_0_1[1],pre_lower_modadd_3_0_1[2],pre_lower_modadd_3_0_1[3],pre_lower_modadd_3_0_1[4],pre_lower_modadd_3_0_1[5],pre_lower_modadd_3_0_1[6],pre_lower_modadd_3_0_1[7],pre_lower_modadd_3_0_1[8],pre_lower_modadd_3_0_1[9],pre_lower_modadd_3_0_1[10],pre_lower_modadd_3_0_1[11],pre_lower_modadd_3_0_1[12],pre_lower_modadd_3_0_1[13],pre_lower_modadd_3_0_1[14],pre_lower_modadd_3_0_1[15]]), array1d(0..16-1, [upper_modadd_3_0[0],upper_modadd_3_0[1],upper_modadd_3_0[2],upper_modadd_3_0[3],upper_modadd_3_0[4],upper_modadd_3_0[5],upper_modadd_3_0[6],upper_modadd_3_0[7],upper_modadd_3_0[8],upper_modadd_3_0[9],upper_modadd_3_0[10],upper_modadd_3_0[11],upper_modadd_3_0[12],upper_modadd_3_0[13],upper_modadd_3_0[14],upper_modadd_3_0[15]]), 16, middle_p[0]);

constraint onlyLargeSwitch_UBCT_enum(array1d(0..16-1, [pre_upper_modadd_3_3_0[15],pre_upper_modadd_3_3_0[14],pre_upper_modadd_3_3_0[13],pre_upper_modadd_3_3_0[12],pre_upper_modadd_3_3_0[11],pre_upper_modadd_3_3_0[10],pre_upper_modadd_3_3_0[9],pre_upper_modadd_3_3_0[8],pre_upper_modadd_3_3_0[7],pre_upper_modadd_3_3_0[6],pre_upper_modadd_3_3_0[5],pre_upper_modadd_3_3_0[4],pre_upper_modadd_3_3_0[3],pre_upper_modadd_3_3_0[2],pre_upper_modadd_3_3_0[1],pre_upper_modadd_3_3_0[0]]), array1d(0..16-1, [pre_upper_modadd_3_3_1[15],pre_upper_modadd_3_3_1[14],pre_upper_modadd_3_3_1[13],pre_upper_modadd_3_3_1[12],pre_upper_modadd_3_3_1[11],pre_upper_modadd_3_3_1[10],pre_upper_modadd_3_3_1[9],pre_upper_modadd_3_3_1[8],pre_upper_modadd_3_3_1[7],pre_upper_modadd_3_3_1[6],pre_upper_modadd_3_3_1[5],pre_upper_modadd_3_3_1[4],pre_upper_modadd_3_3_1[3],pre_upper_modadd_3_3_1[2],pre_upper_modadd_3_3_1[1],pre_upper_modadd_3_3_1[0]]), array1d(0..16-1, [pre_lower_modadd_3_3_0[15],pre_lower_modadd_3_3_0[14],pre_lower_modadd_3_3_0[13],pre_lower_modadd_3_3_0[12],pre_lower_modadd_3_3_0[11],pre_lower_modadd_3_3_0[10],pre_lower_modadd_3_3_0[9],pre_lower_modadd_3_3_0[8],pre_lower_modadd_3_3_0[7],pre_lower_modadd_3_3_0[6],pre_lower_modadd_3_3_0[5],pre_lower_modadd_3_3_0[4],pre_lower_modadd_3_3_0[3],pre_lower_modadd_3_3_0[2],pre_lower_modadd_3_3_0[1],pre_lower_modadd_3_3_0[0]]), array1d(0..16-1, [pre_lower_modadd_3_3_1[15],pre_lower_modadd_3_3_1[14],pre_lower_modadd_3_3_1[13],pre_lower_modadd_3_3_1[12],pre_lower_modadd_3_3_1[11],pre_lower_modadd_3_3_1[10],pre_lower_modadd_3_3_1[9],pre_lower_modadd_3_3_1[8],pre_lower_modadd_3_3_1[7],pre_lower_modadd_3_3_1[6],pre_lower_modadd_3_3_1[5],pre_lower_modadd_3_3_1[4],pre_lower_modadd_3_3_1[3],pre_lower_modadd_3_3_1[2],pre_lower_modadd_3_3_1[1],pre_lower_modadd_3_3_1[0]]), array1d(0..16-1, [upper_modadd_3_3[15],upper_modadd_3_3[14],upper_modadd_3_3[13],upper_modadd_3_3[12],upper_modadd_3_3[11],upper_modadd_3_3[10],upper_modadd_3_3[9],upper_modadd_3_3[8],upper_modadd_3_3[7],upper_modadd_3_3[6],upper_modadd_3_3[5],upper_modadd_3_3[4],upper_modadd_3_3[3],upper_modadd_3_3[2],upper_modadd_3_3[1],upper_modadd_3_3[0]]), 8, 16) = true;

constraint ubct_compute(array1d(0..16-1, [pre_upper_modadd_3_3_0[0],pre_upper_modadd_3_3_0[1],pre_upper_modadd_3_3_0[2],pre_upper_modadd_3_3_0[3],pre_upper_modadd_3_3_0[4],pre_upper_modadd_3_3_0[5],pre_upper_modadd_3_3_0[6],pre_upper_modadd_3_3_0[7],pre_upper_modadd_3_3_0[8],pre_upper_modadd_3_3_0[9],pre_upper_modadd_3_3_0[10],pre_upper_modadd_3_3_0[11],pre_upper_modadd_3_3_0[12],pre_upper_modadd_3_3_0[13],pre_upper_modadd_3_3_0[14],pre_upper_modadd_3_3_0[15]]), array1d(0..16-1, [pre_upper_modadd_3_3_1[0],pre_upper_modadd_3_3_1[1],pre_upper_modadd_3_3_1[2],pre_upper_modadd_3_3_1[3],pre_upper_modadd_3_3_1[4],pre_upper_modadd_3_3_1[5],pre_upper_modadd_3_3_1[6],pre_upper_modadd_3_3_1[7],pre_upper_modadd_3_3_1[8],pre_upper_modadd_3_3_1[9],pre_upper_modadd_3_3_1[10],pre_upper_modadd_3_3_1[11],pre_upper_modadd_3_3_1[12],pre_upper_modadd_3_3_1[13],pre_upper_modadd_3_3_1[14],pre_upper_modadd_3_3_1[15]]), array1d(0..16-1, [pre_lower_modadd_3_3_0[0],pre_lower_modadd_3_3_0[1],pre_lower_modadd_3_3_0[2],pre_lower_modadd_3_3_0[3],pre_lower_modadd_3_3_0[4],pre_lower_modadd_3_3_0[5],pre_lower_modadd_3_3_0[6],pre_lower_modadd_3_3_0[7],pre_lower_modadd_3_3_0[8],pre_lower_modadd_3_3_0[9],pre_lower_modadd_3_3_0[10],pre_lower_modadd_3_3_0[11],pre_lower_modadd_3_3_0[12],pre_lower_modadd_3_3_0[13],pre_lower_modadd_3_3_0[14],pre_lower_modadd_3_3_0[15]]), array1d(0..16-1, [pre_lower_modadd_3_3_1[0],pre_lower_modadd_3_3_1[1],pre_lower_modadd_3_3_1[2],pre_lower_modadd_3_3_1[3],pre_lower_modadd_3_3_1[4],pre_lower_modadd_3_3_1[5],pre_lower_modadd_3_3_1[6],pre_lower_modadd_3_3_1[7],pre_lower_modadd_3_3_1[8],pre_lower_modadd_3_3_1[9],pre_lower_modadd_3_3_1[10],pre_lower_modadd_3_3_1[11],pre_lower_modadd_3_3_1[12],pre_lower_modadd_3_3_1[13],pre_lower_modadd_3_3_1[14],pre_lower_modadd_3_3_1[15]]), array1d(0..16-1, [upper_modadd_3_3[0],upper_modadd_3_3[1],upper_modadd_3_3[2],upper_modadd_3_3[3],upper_modadd_3_3[4],upper_modadd_3_3[5],upper_modadd_3_3[6],upper_modadd_3_3[7],upper_modadd_3_3[8],upper_modadd_3_3[9],upper_modadd_3_3[10],upper_modadd_3_3[11],upper_modadd_3_3[12],upper_modadd_3_3[13],upper_modadd_3_3[14],upper_modadd_3_3[15]]), 16, middle_p[1]);

constraint onlyLargeSwitch_LBCT_enum(array1d(0..16-1, [pre_upper_modadd_5_0_0[15],pre_upper_modadd_5_0_0[14],pre_upper_modadd_5_0_0[13],pre_upper_modadd_5_0_0[12],pre_upper_modadd_5_0_0[11],pre_upper_modadd_5_0_0[10],pre_upper_modadd_5_0_0[9],pre_upper_modadd_5_0_0[8],pre_upper_modadd_5_0_0[7],pre_upper_modadd_5_0_0[6],pre_upper_modadd_5_0_0[5],pre_upper_modadd_5_0_0[4],pre_upper_modadd_5_0_0[3],pre_upper_modadd_5_0_0[2],pre_upper_modadd_5_0_0[1],pre_upper_modadd_5_0_0[0]]), array1d(0..16-1, [pre_upper_modadd_5_0_1[15],pre_upper_modadd_5_0_1[14],pre_upper_modadd_5_0_1[13],pre_upper_modadd_5_0_1[12],pre_upper_modadd_5_0_1[11],pre_upper_modadd_5_0_1[10],pre_upper_modadd_5_0_1[9],pre_upper_modadd_5_0_1[8],pre_upper_modadd_5_0_1[7],pre_upper_modadd_5_0_1[6],pre_upper_modadd_5_0_1[5],pre_upper_modadd_5_0_1[4],pre_upper_modadd_5_0_1[3],pre_upper_modadd_5_0_1[2],pre_upper_modadd_5_0_1[1],pre_upper_modadd_5_0_1[0]]), array1d(0..16-1, [pre_lower_modadd_5_0_0[15],pre_lower_modadd_5_0_0[14],pre_lower_modadd_5_0_0[13],pre_lower_modadd_5_0_0[12],pre_lower_modadd_5_0_0[11],pre_lower_modadd_5_0_0[10],pre_lower_modadd_5_0_0[9],pre_lower_modadd_5_0_0[8],pre_lower_modadd_5_0_0[7],pre_lower_modadd_5_0_0[6],pre_lower_modadd_5_0_0[5],pre_lower_modadd_5_0_0[4],pre_lower_modadd_5_0_0[3],pre_lower_modadd_5_0_0[2],pre_lower_modadd_5_0_0[1],pre_lower_modadd_5_0_0[0]]), array1d(0..16-1, [pre_lower_modadd_5_0_1[15],pre_lower_modadd_5_0_1[14],pre_lower_modadd_5_0_1[13],pre_lower_modadd_5_0_1[12],pre_lower_modadd_5_0_1[11],pre_lower_modadd_5_0_1[10],pre_lower_modadd_5_0_1[9],pre_lower_modadd_5_0_1[8],pre_lower_modadd_5_0_1[7],pre_lower_modadd_5_0_1[6],pre_lower_modadd_5_0_1[5],pre_lower_modadd_5_0_1[4],pre_lower_modadd_5_0_1[3],pre_lower_modadd_5_0_1[2],pre_lower_modadd_5_0_1[1],pre_lower_modadd_5_0_1[0]]), array1d(0..16-1, [lower_modadd_5_0[15],lower_modadd_5_0[14],lower_modadd_5_0[13],lower_modadd_5_0[12],lower_modadd_5_0[11],lower_modadd_5_0[10],lower_modadd_5_0[9],lower_modadd_5_0[8],lower_modadd_5_0[7],lower_modadd_5_0[6],lower_modadd_5_0[5],lower_modadd_5_0[4],lower_modadd_5_0[3],lower_modadd_5_0[2],lower_modadd_5_0[1],lower_modadd_5_0[0]]), 8, 16) = true;

constraint lbct_compute(array1d(0..16-1, [pre_upper_modadd_5_0_0[0],pre_upper_modadd_5_0_0[1],pre_upper_modadd_5_0_0[2],pre_upper_modadd_5_0_0[3],pre_upper_modadd_5_0_0[4],pre_upper_modadd_5_0_0[5],pre_upper_modadd_5_0_0[6],pre_upper_modadd_5_0_0[7],pre_upper_modadd_5_0_0[8],pre_upper_modadd_5_0_0[9],pre_upper_modadd_5_0_0[10],pre_upper_modadd_5_0_0[11],pre_upper_modadd_5_0_0[12],pre_upper_modadd_5_0_0[13],pre_upper_modadd_5_0_0[14],pre_upper_modadd_5_0_0[15]]), array1d(0..16-1, [pre_upper_modadd_5_0_1[0],pre_upper_modadd_5_0_1[1],pre_upper_modadd_5_0_1[2],pre_upper_modadd_5_0_1[3],pre_upper_modadd_5_0_1[4],pre_upper_modadd_5_0_1[5],pre_upper_modadd_5_0_1[6],pre_upper_modadd_5_0_1[7],pre_upper_modadd_5_0_1[8],pre_upper_modadd_5_0_1[9],pre_upper_modadd_5_0_1[10],pre_upper_modadd_5_0_1[11],pre_upper_modadd_5_0_1[12],pre_upper_modadd_5_0_1[13],pre_upper_modadd_5_0_1[14],pre_upper_modadd_5_0_1[15]]), array1d(0..16-1, [pre_lower_modadd_5_0_0[0],pre_lower_modadd_5_0_0[1],pre_lower_modadd_5_0_0[2],pre_lower_modadd_5_0_0[3],pre_lower_modadd_5_0_0[4],pre_lower_modadd_5_0_0[5],pre_lower_modadd_5_0_0[6],pre_lower_modadd_5_0_0[7],pre_lower_modadd_5_0_0[8],pre_lower_modadd_5_0_0[9],pre_lower_modadd_5_0_0[10],pre_lower_modadd_5_0_0[11],pre_lower_modadd_5_0_0[12],pre_lower_modadd_5_0_0[13],pre_lower_modadd_5_0_0[14],pre_lower_modadd_5_0_0[15]]), array1d(0..16-1, [pre_lower_modadd_5_0_1[0],pre_lower_modadd_5_0_1[1],pre_lower_modadd_5_0_1[2],pre_lower_modadd_5_0_1[3],pre_lower_modadd_5_0_1[4],pre_lower_modadd_5_0_1[5],pre_lower_modadd_5_0_1[6],pre_lower_modadd_5_0_1[7],pre_lower_modadd_5_0_1[8],pre_lower_modadd_5_0_1[9],pre_lower_modadd_5_0_1[10],pre_lower_modadd_5_0_1[11],pre_lower_modadd_5_0_1[12],pre_lower_modadd_5_0_1[13],pre_lower_modadd_5_0_1[14],pre_lower_modadd_5_0_1[15]]), array1d(0..16-1, [lower_modadd_5_0[0],lower_modadd_5_0[1],lower_modadd_5_0[2],lower_modadd_5_0[3],lower_modadd_5_0[4],lower_modadd_5_0[5],lower_modadd_5_0[6],lower_modadd_5_0[7],lower_modadd_5_0[8],lower_modadd_5_0[9],lower_modadd_5_0[10],lower_modadd_5_0[11],lower_modadd_5_0[12],lower_modadd_5_0[13],lower_modadd_5_0[14],lower_modadd_5_0[15]]), 16, middle_p[2]);

constraint onlyLargeSwitch_LBCT_enum(array1d(0..16-1, [pre_upper_modadd_5_3_0[15],pre_upper_modadd_5_3_0[14],pre_upper_modadd_5_3_0[13],pre_upper_modadd_5_3_0[12],pre_upper_modadd_5_3_0[11],pre_upper_modadd_5_3_0[10],pre_upper_modadd_5_3_0[9],pre_upper_modadd_5_3_0[8],pre_upper_modadd_5_3_0[7],pre_upper_modadd_5_3_0[6],pre_upper_modadd_5_3_0[5],pre_upper_modadd_5_3_0[4],pre_upper_modadd_5_3_0[3],pre_upper_modadd_5_3_0[2],pre_upper_modadd_5_3_0[1],pre_upper_modadd_5_3_0[0]]), array1d(0..16-1, [pre_upper_modadd_5_3_1[15],pre_upper_modadd_5_3_1[14],pre_upper_modadd_5_3_1[13],pre_upper_modadd_5_3_1[12],pre_upper_modadd_5_3_1[11],pre_upper_modadd_5_3_1[10],pre_upper_modadd_5_3_1[9],pre_upper_modadd_5_3_1[8],pre_upper_modadd_5_3_1[7],pre_upper_modadd_5_3_1[6],pre_upper_modadd_5_3_1[5],pre_upper_modadd_5_3_1[4],pre_upper_modadd_5_3_1[3],pre_upper_modadd_5_3_1[2],pre_upper_modadd_5_3_1[1],pre_upper_modadd_5_3_1[0]]), array1d(0..16-1, [pre_lower_modadd_5_3_0[15],pre_lower_modadd_5_3_0[14],pre_lower_modadd_5_3_0[13],pre_lower_modadd_5_3_0[12],pre_lower_modadd_5_3_0[11],pre_lower_modadd_5_3_0[10],pre_lower_modadd_5_3_0[9],pre_lower_modadd_5_3_0[8],pre_lower_modadd_5_3_0[7],pre_lower_modadd_5_3_0[6],pre_lower_modadd_5_3_0[5],pre_lower_modadd_5_3_0[4],pre_lower_modadd_5_3_0[3],pre_lower_modadd_5_3_0[2],pre_lower_modadd_5_3_0[1],pre_lower_modadd_5_3_0[0]]), array1d(0..16-1, [pre_lower_modadd_5_3_1[15],pre_lower_modadd_5_3_1[14],pre_lower_modadd_5_3_1[13],pre_lower_modadd_5_3_1[12],pre_lower_modadd_5_3_1[11],pre_lower_modadd_5_3_1[10],pre_lower_modadd_5_3_1[9],pre_lower_modadd_5_3_1[8],pre_lower_modadd_5_3_1[7],pre_lower_modadd_5_3_1[6],pre_lower_modadd_5_3_1[5],pre_lower_modadd_5_3_1[4],pre_lower_modadd_5_3_1[3],pre_lower_modadd_5_3_1[2],pre_lower_modadd_5_3_1[1],pre_lower_modadd_5_3_1[0]]), array1d(0..16-1, [lower_modadd_5_3[15],lower_modadd_5_3[14],lower_modadd_5_3[13],lower_modadd_5_3[12],lower_modadd_5_3[11],lower_modadd_5_3[10],lower_modadd_5_3[9],lower_modadd_5_3[8],lower_modadd_5_3[7],lower_modadd_5_3[6],lower_modadd_5_3[5],lower_modadd_5_3[4],lower_modadd_5_3[3],lower_modadd_5_3[2],lower_modadd_5_3[1],lower_modadd_5_3[0]]), 8, 16) = true;

constraint lbct_compute(array1d(0..16-1, [pre_upper_modadd_5_3_0[0],pre_upper_modadd_5_3_0[1],pre_upper_modadd_5_3_0[2],pre_upper_modadd_5_3_0[3],pre_upper_modadd_5_3_0[4],pre_upper_modadd_5_3_0[5],pre_upper_modadd_5_3_0[6],pre_upper_modadd_5_3_0[7],pre_upper_modadd_5_3_0[8],pre_upper_modadd_5_3_0[9],pre_upper_modadd_5_3_0[10],pre_upper_modadd_5_3_0[11],pre_upper_modadd_5_3_0[12],pre_upper_modadd_5_3_0[13],pre_upper_modadd_5_3_0[14],pre_upper_modadd_5_3_0[15]]), array1d(0..16-1, [pre_upper_modadd_5_3_1[0],pre_upper_modadd_5_3_1[1],pre_upper_modadd_5_3_1[2],pre_upper_modadd_5_3_1[3],pre_upper_modadd_5_3_1[4],pre_upper_modadd_5_3_1[5],pre_upper_modadd_5_3_1[6],pre_upper_modadd_5_3_1[7],pre_upper_modadd_5_3_1[8],pre_upper_modadd_5_3_1[9],pre_upper_modadd_5_3_1[10],pre_upper_modadd_5_3_1[11],pre_upper_modadd_5_3_1[12],pre_upper_modadd_5_3_1[13],pre_upper_modadd_5_3_1[14],pre_upper_modadd_5_3_1[15]]), array1d(0..16-1, [pre_lower_modadd_5_3_0[0],pre_lower_modadd_5_3_0[1],pre_lower_modadd_5_3_0[2],pre_lower_modadd_5_3_0[3],pre_lower_modadd_5_3_0[4],pre_lower_modadd_5_3_0[5],pre_lower_modadd_5_3_0[6],pre_lower_modadd_5_3_0[7],pre_lower_modadd_5_3_0[8],pre_lower_modadd_5_3_0[9],pre_lower_modadd_5_3_0[10],pre_lower_modadd_5_3_0[11],pre_lower_modadd_5_3_0[12],pre_lower_modadd_5_3_0[13],pre_lower_modadd_5_3_0[14],pre_lower_modadd_5_3_0[15]]), array1d(0..16-1, [pre_lower_modadd_5_3_1[0],pre_lower_modadd_5_3_1[1],pre_lower_modadd_5_3_1[2],pre_lower_modadd_5_3_1[3],pre_lower_modadd_5_3_1[4],pre_lower_modadd_5_3_1[5],pre_lower_modadd_5_3_1[6],pre_lower_modadd_5_3_1[7],pre_lower_modadd_5_3_1[8],pre_lower_modadd_5_3_1[9],pre_lower_modadd_5_3_1[10],pre_lower_modadd_5_3_1[11],pre_lower_modadd_5_3_1[12],pre_lower_modadd_5_3_1[13],pre_lower_modadd_5_3_1[14],pre_lower_modadd_5_3_1[15]]), array1d(0..16-1, [lower_modadd_5_3[0],lower_modadd_5_3[1],lower_modadd_5_3[2],lower_modadd_5_3[3],lower_modadd_5_3[4],lower_modadd_5_3[5],lower_modadd_5_3[6],lower_modadd_5_3[7],lower_modadd_5_3[8],lower_modadd_5_3[9],lower_modadd_5_3[10],lower_modadd_5_3[11],lower_modadd_5_3[12],lower_modadd_5_3[13],lower_modadd_5_3[14],lower_modadd_5_3[15]]), 16, middle_p[3]);

constraint onlyLargeSwitch_EBCT_enum(array1d(0..16-1, [pre_upper_modadd_4_0_0[15],pre_upper_modadd_4_0_0[14],pre_upper_modadd_4_0_0[13],pre_upper_modadd_4_0_0[12],pre_upper_modadd_4_0_0[11],pre_upper_modadd_4_0_0[10],pre_upper_modadd_4_0_0[9],pre_upper_modadd_4_0_0[8],pre_upper_modadd_4_0_0[7],pre_upper_modadd_4_0_0[6],pre_upper_modadd_4_0_0[5],pre_upper_modadd_4_0_0[4],pre_upper_modadd_4_0_0[3],pre_upper_modadd_4_0_0[2],pre_upper_modadd_4_0_0[1],pre_upper_modadd_4_0_0[0]]), array1d(0..16-1, [pre_upper_modadd_4_0_1[15],pre_upper_modadd_4_0_1[14],pre_upper_modadd_4_0_1[13],pre_upper_modadd_4_0_1[12],pre_upper_modadd_4_0_1[11],pre_upper_modadd_4_0_1[10],pre_upper_modadd_4_0_1[9],pre_upper_modadd_4_0_1[8],pre_upper_modadd_4_0_1[7],pre_upper_modadd_4_0_1[6],pre_upper_modadd_4_0_1[5],pre_upper_modadd_4_0_1[4],pre_upper_modadd_4_0_1[3],pre_upper_modadd_4_0_1[2],pre_upper_modadd_4_0_1[1],pre_upper_modadd_4_0_1[0]]), array1d(0..16-1, [pre_lower_modadd_4_0_0[15],pre_lower_modadd_4_0_0[14],pre_lower_modadd_4_0_0[13],pre_lower_modadd_4_0_0[12],pre_lower_modadd_4_0_0[11],pre_lower_modadd_4_0_0[10],pre_lower_modadd_4_0_0[9],pre_lower_modadd_4_0_0[8],pre_lower_modadd_4_0_0[7],pre_lower_modadd_4_0_0[6],pre_lower_modadd_4_0_0[5],pre_lower_modadd_4_0_0[4],pre_lower_modadd_4_0_0[3],pre_lower_modadd_4_0_0[2],pre_lower_modadd_4_0_0[1],pre_lower_modadd_4_0_0[0]]), array1d(0..16-1, [pre_lower_modadd_4_0_1[15],pre_lower_modadd_4_0_1[14],pre_lower_modadd_4_0_1[13],pre_lower_modadd_4_0_1[12],pre_lower_modadd_4_0_1[11],pre_lower_modadd_4_0_1[10],pre_lower_modadd_4_0_1[9],pre_lower_modadd_4_0_1[8],pre_lower_modadd_4_0_1[7],pre_lower_modadd_4_0_1[6],pre_lower_modadd_4_0_1[5],pre_lower_modadd_4_0_1[4],pre_lower_modadd_4_0_1[3],pre_lower_modadd_4_0_1[2],pre_lower_modadd_4_0_1[1],pre_lower_modadd_4_0_1[0]]), array1d(0..16-1, [upper_modadd_4_0[15],upper_modadd_4_0[14],upper_modadd_4_0[13],upper_modadd_4_0[12],upper_modadd_4_0[11],upper_modadd_4_0[10],upper_modadd_4_0[9],upper_modadd_4_0[8],upper_modadd_4_0[7],upper_modadd_4_0[6],upper_modadd_4_0[5],upper_modadd_4_0[4],upper_modadd_4_0[3],upper_modadd_4_0[2],upper_modadd_4_0[1],upper_modadd_4_0[0]]), array1d(0..16-1, [lower_modadd_4_0[15],lower_modadd_4_0[14],lower_modadd_4_0[13],lower_modadd_4_0[12],lower_modadd_4_0[11],lower_modadd_4_0[10],lower_modadd_4_0[9],lower_modadd_4_0[8],lower_modadd_4_0[7],lower_modadd_4_0[6],lower_modadd_4_0[5],lower_modadd_4_0[4],lower_modadd_4_0[3],lower_modadd_4_0[2],lower_modadd_4_0[1],lower_modadd_4_0[0]]), 8, 16) = true;

constraint ebct_compute(array1d(0..16-1, [pre_upper_modadd_4_0_0[0],pre_upper_modadd_4_0_0[1],pre_upper_modadd_4_0_0[2],pre_upper_modadd_4_0_0[3],pre_upper_modadd_4_0_0[4],pre_upper_modadd_4_0_0[5],pre_upper_modadd_4_0_0[6],pre_upper_modadd_4_0_0[7],pre_upper_modadd_4_0_0[8],pre_upper_modadd_4_0_0[9],pre_upper_modadd_4_0_0[10],pre_upper_modadd_4_0_0[11],pre_upper_modadd_4_0_0[12],pre_upper_modadd_4_0_0[13],pre_upper_modadd_4_0_0[14],pre_upper_modadd_4_0_0[15]]), array1d(0..16-1, [pre_upper_modadd_4_0_1[0],pre_upper_modadd_4_0_1[1],pre_upper_modadd_4_0_1[2],pre_upper_modadd_4_0_1[3],pre_upper_modadd_4_0_1[4],pre_upper_modadd_4_0_1[5],pre_upper_modadd_4_0_1[6],pre_upper_modadd_4_0_1[7],pre_upper_modadd_4_0_1[8],pre_upper_modadd_4_0_1[9],pre_upper_modadd_4_0_1[10],pre_upper_modadd_4_0_1[11],pre_upper_modadd_4_0_1[12],pre_upper_modadd_4_0_1[13],pre_upper_modadd_4_0_1[14],pre_upper_modadd_4_0_1[15]]), array1d(0..16-1, [pre_lower_modadd_4_0_0[0],pre_lower_modadd_4_0_0[1],pre_lower_modadd_4_0_0[2],pre_lower_modadd_4_0_0[3],pre_lower_modadd_4_0_0[4],pre_lower_modadd_4_0_0[5],pre_lower_modadd_4_0_0[6],pre_lower_modadd_4_0_0[7],pre_lower_modadd_4_0_0[8],pre_lower_modadd_4_0_0[9],pre_lower_modadd_4_0_0[10],pre_lower_modadd_4_0_0[11],pre_lower_modadd_4_0_0[12],pre_lower_modadd_4_0_0[13],pre_lower_modadd_4_0_0[14],pre_lower_modadd_4_0_0[15]]), array1d(0..16-1, [pre_lower_modadd_4_0_1[0],pre_lower_modadd_4_0_1[1],pre_lower_modadd_4_0_1[2],pre_lower_modadd_4_0_1[3],pre_lower_modadd_4_0_1[4],pre_lower_modadd_4_0_1[5],pre_lower_modadd_4_0_1[6],pre_lower_modadd_4_0_1[7],pre_lower_modadd_4_0_1[8],pre_lower_modadd_4_0_1[9],pre_lower_modadd_4_0_1[10],pre_lower_modadd_4_0_1[11],pre_lower_modadd_4_0_1[12],pre_lower_modadd_4_0_1[13],pre_lower_modadd_4_0_1[14],pre_lower_modadd_4_0_1[15]]), array1d(0..16-1, [upper_modadd_4_0[0],upper_modadd_4_0[1],upper_modadd_4_0[2],upper_modadd_4_0[3],upper_modadd_4_0[4],upper_modadd_4_0[5],upper_modadd_4_0[6],upper_modadd_4_0[7],upper_modadd_4_0[8],upper_modadd_4_0[9],upper_modadd_4_0[10],upper_modadd_4_0[11],upper_modadd_4_0[12],upper_modadd_4_0[13],upper_modadd_4_0[14],upper_modadd_4_0[15]]), array1d(0..16-1, [lower_modadd_4_0[0],lower_modadd_4_0[1],lower_modadd_4_0[2],lower_modadd_4_0[3],lower_modadd_4_0[4],lower_modadd_4_0[5],lower_modadd_4_0[6],lower_modadd_4_0[7],lower_modadd_4_0[8],lower_modadd_4_0[9],lower_modadd_4_0[10],lower_modadd_4_0[11],lower_modadd_4_0[12],lower_modadd_4_0[13],lower_modadd_4_0[14],lower_modadd_4_0[15]]), 16, middle_p[4]);

constraint onlyLargeSwitch_EBCT_enum(array1d(0..16-1, [pre_upper_modadd_4_4_0[15],pre_upper_modadd_4_4_0[14],pre_upper_modadd_4_4_0[13],pre_upper_modadd_4_4_0[12],pre_upper_modadd_4_4_0[11],pre_upper_modadd_4_4_0[10],pre_upper_modadd_4_4_0[9],pre_upper_modadd_4_4_0[8],pre_upper_modadd_4_4_0[7],pre_upper_modadd_4_4_0[6],pre_upper_modadd_4_4_0[5],pre_upper_modadd_4_4_0[4],pre_upper_modadd_4_4_0[3],pre_upper_modadd_4_4_0[2],pre_upper_modadd_4_4_0[1],pre_upper_modadd_4_4_0[0]]), array1d(0..16-1, [pre_upper_modadd_4_4_1[15],pre_upper_modadd_4_4_1[14],pre_upper_modadd_4_4_1[13],pre_upper_modadd_4_4_1[12],pre_upper_modadd_4_4_1[11],pre_upper_modadd_4_4_1[10],pre_upper_modadd_4_4_1[9],pre_upper_modadd_4_4_1[8],pre_upper_modadd_4_4_1[7],pre_upper_modadd_4_4_1[6],pre_upper_modadd_4_4_1[5],pre_upper_modadd_4_4_1[4],pre_upper_modadd_4_4_1[3],pre_upper_modadd_4_4_1[2],pre_upper_modadd_4_4_1[1],pre_upper_modadd_4_4_1[0]]), array1d(0..16-1, [pre_lower_modadd_4_4_0[15],pre_lower_modadd_4_4_0[14],pre_lower_modadd_4_4_0[13],pre_lower_modadd_4_4_0[12],pre_lower_modadd_4_4_0[11],pre_lower_modadd_4_4_0[10],pre_lower_modadd_4_4_0[9],pre_lower_modadd_4_4_0[8],pre_lower_modadd_4_4_0[7],pre_lower_modadd_4_4_0[6],pre_lower_modadd_4_4_0[5],pre_lower_modadd_4_4_0[4],pre_lower_modadd_4_4_0[3],pre_lower_modadd_4_4_0[2],pre_lower_modadd_4_4_0[1],pre_lower_modadd_4_4_0[0]]), array1d(0..16-1, [pre_lower_modadd_4_4_1[15],pre_lower_modadd_4_4_1[14],pre_lower_modadd_4_4_1[13],pre_lower_modadd_4_4_1[12],pre_lower_modadd_4_4_1[11],pre_lower_modadd_4_4_1[10],pre_lower_modadd_4_4_1[9],pre_lower_modadd_4_4_1[8],pre_lower_modadd_4_4_1[7],pre_lower_modadd_4_4_1[6],pre_lower_modadd_4_4_1[5],pre_lower_modadd_4_4_1[4],pre_lower_modadd_4_4_1[3],pre_lower_modadd_4_4_1[2],pre_lower_modadd_4_4_1[1],pre_lower_modadd_4_4_1[0]]), array1d(0..16-1, [upper_modadd_4_4[15],upper_modadd_4_4[14],upper_modadd_4_4[13],upper_modadd_4_4[12],upper_modadd_4_4[11],upper_modadd_4_4[10],upper_modadd_4_4[9],upper_modadd_4_4[8],upper_modadd_4_4[7],upper_modadd_4_4[6],upper_modadd_4_4[5],upper_modadd_4_4[4],upper_modadd_4_4[3],upper_modadd_4_4[2],upper_modadd_4_4[1],upper_modadd_4_4[0]]), array1d(0..16-1, [lower_modadd_4_4[15],lower_modadd_4_4[14],lower_modadd_4_4[13],lower_modadd_4_4[12],lower_modadd_4_4[11],lower_modadd_4_4[10],lower_modadd_4_4[9],lower_modadd_4_4[8],lower_modadd_4_4[7],lower_modadd_4_4[6],lower_modadd_4_4[5],lower_modadd_4_4[4],lower_modadd_4_4[3],lower_modadd_4_4[2],lower_modadd_4_4[1],lower_modadd_4_4[0]]), 8, 16) = true;

constraint ebct_compute(array1d(0..16-1, [pre_upper_modadd_4_4_0[0],pre_upper_modadd_4_4_0[1],pre_upper_modadd_4_4_0[2],pre_upper_modadd_4_4_0[3],pre_upper_modadd_4_4_0[4],pre_upper_modadd_4_4_0[5],pre_upper_modadd_4_4_0[6],pre_upper_modadd_4_4_0[7],pre_upper_modadd_4_4_0[8],pre_upper_modadd_4_4_0[9],pre_upper_modadd_4_4_0[10],pre_upper_modadd_4_4_0[11],pre_upper_modadd_4_4_0[12],pre_upper_modadd_4_4_0[13],pre_upper_modadd_4_4_0[14],pre_upper_modadd_4_4_0[15]]), array1d(0..16-1, [pre_upper_modadd_4_4_1[0],pre_upper_modadd_4_4_1[1],pre_upper_modadd_4_4_1[2],pre_upper_modadd_4_4_1[3],pre_upper_modadd_4_4_1[4],pre_upper_modadd_4_4_1[5],pre_upper_modadd_4_4_1[6],pre_upper_modadd_4_4_1[7],pre_upper_modadd_4_4_1[8],pre_upper_modadd_4_4_1[9],pre_upper_modadd_4_4_1[10],pre_upper_modadd_4_4_1[11],pre_upper_modadd_4_4_1[12],pre_upper_modadd_4_4_1[13],pre_upper_modadd_4_4_1[14],pre_upper_modadd_4_4_1[15]]), array1d(0..16-1, [pre_lower_modadd_4_4_0[0],pre_lower_modadd_4_4_0[1],pre_lower_modadd_4_4_0[2],pre_lower_modadd_4_4_0[3],pre_lower_modadd_4_4_0[4],pre_lower_modadd_4_4_0[5],pre_lower_modadd_4_4_0[6],pre_lower_modadd_4_4_0[7],pre_lower_modadd_4_4_0[8],pre_lower_modadd_4_4_0[9],pre_lower_modadd_4_4_0[10],pre_lower_modadd_4_4_0[11],pre_lower_modadd_4_4_0[12],pre_lower_modadd_4_4_0[13],pre_lower_modadd_4_4_0[14],pre_lower_modadd_4_4_0[15]]), array1d(0..16-1, [pre_lower_modadd_4_4_1[0],pre_lower_modadd_4_4_1[1],pre_lower_modadd_4_4_1[2],pre_lower_modadd_4_4_1[3],pre_lower_modadd_4_4_1[4],pre_lower_modadd_4_4_1[5],pre_lower_modadd_4_4_1[6],pre_lower_modadd_4_4_1[7],pre_lower_modadd_4_4_1[8],pre_lower_modadd_4_4_1[9],pre_lower_modadd_4_4_1[10],pre_lower_modadd_4_4_1[11],pre_lower_modadd_4_4_1[12],pre_lower_modadd_4_4_1[13],pre_lower_modadd_4_4_1[14],pre_lower_modadd_4_4_1[15]]), array1d(0..16-1, [upper_modadd_4_4[0],upper_modadd_4_4[1],upper_modadd_4_4[2],upper_modadd_4_4[3],upper_modadd_4_4[4],upper_modadd_4_4[5],upper_modadd_4_4[6],upper_modadd_4_4[7],upper_modadd_4_4[8],upper_modadd_4_4[9],upper_modadd_4_4[10],upper_modadd_4_4[11],upper_modadd_4_4[12],upper_modadd_4_4[13],upper_modadd_4_4[14],upper_modadd_4_4[15]]), array1d(0..16-1, [lower_modadd_4_4[0],lower_modadd_4_4[1],lower_modadd_4_4[2],lower_modadd_4_4[3],lower_modadd_4_4[4],lower_modadd_4_4[5],lower_modadd_4_4[6],lower_modadd_4_4[7],lower_modadd_4_4[8],lower_modadd_4_4[9],lower_modadd_4_4[10],lower_modadd_4_4[11],lower_modadd_4_4[12],lower_modadd_4_4[13],lower_modadd_4_4[14],lower_modadd_4_4[15]]), 16, middle_p[5]);

array[0..63] of var 0..1: upper_plaintext;
array[0..63] of var 0..1: lower_cipher_output_7_7;
array[0..15] of var 0..1: upper_modadd_0_0;
array[0..15] of var 0..1: upper_rot_0_1;
array[0..15] of var 0..1: upper_xor_0_2;
array[0..15] of var 0..1: upper_rot_0_3;
array[0..15] of var 0..1: upper_modadd_0_4;
array[0..15] of var 0..1: upper_rot_0_5;
array[0..15] of var 0..1: upper_xor_0_6;
array[0..63] of var 0..1: upper_intermediate_output_0_7;
array[0..15] of var 0..1: upper_modadd_1_0;
array[0..15] of var 0..1: upper_rot_1_1;
array[0..15] of var 0..1: upper_xor_1_2;
array[0..15] of var 0..1: upper_modadd_1_3;
array[0..15] of var 0..1: upper_rot_1_4;
array[0..15] of var 0..1: upper_xor_1_5;
array[0..15] of var 0..1: upper_rot_1_6;
array[0..63] of var 0..1: upper_intermediate_output_1_7;
array[0..15] of var 0..1: upper_modadd_2_0;
array[0..15] of var 0..1: upper_rot_2_1;
array[0..15] of var 0..1: upper_xor_2_2;
array[0..15] of var 0..1: upper_rot_2_3;
array[0..15] of var 0..1: upper_modadd_2_4;
array[0..15] of var 0..1: upper_rot_2_5;
array[0..15] of var 0..1: upper_xor_2_6;
array[0..63] of var 0..1: upper_intermediate_output_2_7;
array[0..15] of var 0..1: upper_modadd_3_0;
array[0..15] of var 0..1: upper_rot_3_1;
array[0..15] of var 0..1: upper_xor_3_2;
array[0..15] of var 0..1: upper_modadd_3_3;
array[0..15] of var 0..1: upper_rot_3_4;
array[0..15] of var 0..1: upper_xor_3_5;
array[0..15] of var 0..1: upper_rot_3_6;
array[0..63] of var 0..1: upper_intermediate_output_3_7;
array[0..15] of var 0..1: lower_xor_3_2;
array[0..15] of var 0..1: lower_rot_3_6;
array[0..63] of var 0..1: lower_intermediate_output_3_7;
array[0..15] of var 0..1: lower_rot_3_1;
array[0..15] of var 0..1: lower_xor_3_5;
array[0..15] of var 0..1: lower_modadd_3_0;
array[0..15] of var 0..1: lower_rot_3_4;
array[0..15] of var 0..1: lower_modadd_3_3;
array[0..15] of var 0..1: upper_modadd_4_0;
array[0..15] of var 0..1: upper_rot_4_1;
array[0..15] of var 0..1: upper_xor_4_2;
array[0..15] of var 0..1: upper_rot_4_3;
array[0..15] of var 0..1: upper_modadd_4_4;
array[0..15] of var 0..1: upper_rot_4_5;
array[0..15] of var 0..1: upper_xor_4_6;
array[0..63] of var 0..1: upper_intermediate_output_4_7;
array[0..15] of var 0..1: lower_rot_4_3;
array[0..15] of var 0..1: lower_xor_4_2;
array[0..15] of var 0..1: lower_xor_4_6;
array[0..63] of var 0..1: lower_intermediate_output_4_7;
array[0..15] of var 0..1: lower_rot_4_1;
array[0..15] of var 0..1: lower_rot_4_5;
array[0..15] of var 0..1: lower_modadd_4_0;
array[0..15] of var 0..1: lower_modadd_4_4;
array[0..15] of var 0..1: upper_modadd_5_0;
array[0..15] of var 0..1: upper_rot_5_1;
array[0..15] of var 0..1: upper_xor_5_2;
array[0..15] of var 0..1: upper_modadd_5_3;
array[0..15] of var 0..1: upper_rot_5_4;
array[0..15] of var 0..1: upper_xor_5_5;
array[0..15] of var 0..1: upper_rot_5_6;
array[0..63] of var 0..1: upper_intermediate_output_5_7;
array[0..15] of var 0..1: lower_xor_5_2;
array[0..15] of var 0..1: lower_rot_5_6;
array[0..63] of var 0..1: lower_intermediate_output_5_7;
array[0..15] of var 0..1: lower_rot_5_1;
array[0..15] of var 0..1: lower_xor_5_5;
array[0..15] of var 0..1: lower_modadd_5_0;
array[0..15] of var 0..1: lower_rot_5_4;
array[0..15] of var 0..1: lower_modadd_5_3;
array[0..15] of var 0..1: lower_rot_6_3;
array[0..15] of var 0..1: lower_xor_6_2;
array[0..15] of var 0..1: lower_xor_6_6;
array[0..63] of var 0..1: lower_intermediate_output_6_7;
array[0..15] of var 0..1: lower_rot_6_1;
array[0..15] of var 0..1: lower_rot_6_5;
array[0..15] of var 0..1: lower_modadd_6_0;
array[0..15] of var 0..1: lower_modadd_6_4;
array[0..15] of var 0..1: lower_xor_7_2;
array[0..15] of var 0..1: lower_rot_7_6;
array[0..15] of var 0..1: lower_rot_7_1;
array[0..15] of var 0..1: lower_xor_7_5;
array[0..15] of var 0..1: lower_modadd_7_0;
array[0..15] of var 0..1: lower_rot_7_4;
array[0..15] of var 0..1: lower_modadd_7_3;
array[0..16-1] of var int: p;
array[0..12-1] of var {0, 900, 200, 1100, 400, 1300, 600, 1500, 800, 100, 1000, 300, 1200, 500, 1400, 700}: upper_p;
constraint p[0] = upper_p[0];
constraint p[1] = upper_p[1];
constraint p[2] = upper_p[2];
constraint p[3] = upper_p[3];
constraint p[4] = upper_p[4];
constraint p[5] = upper_p[5];
var int: upper_weight = upper_p[0] + upper_p[1] + upper_p[2] + upper_p[3] + upper_p[4] + upper_p[5];
array[0..10-1] of var {0, 900, 200, 1100, 400, 1300, 600, 1500, 800, 100, 1000, 300, 1200, 500, 1400, 700}: lower_p;
constraint p[6] = lower_p[6];
constraint p[7] = lower_p[7];
constraint p[8] = lower_p[8];
constraint p[9] = lower_p[9];
var int: lower_weight = lower_p[6] + lower_p[7] + lower_p[8] + lower_p[9];
array[0..6-1] of var 0..3200: middle_p;
var int: middle_weight = sum(middle_p);
constraint p[10] = middle_p[0];
constraint p[11] = middle_p[1];
constraint p[12] = middle_p[2];
constraint p[13] = middle_p[3];
constraint p[14] = middle_p[4];
constraint p[15] = middle_p[5];
var int: weight = (2 * upper_weight) + (2 * lower_weight) + middle_weight;
solve:: int_search(p, smallest, indomain_min, complete) minimize weight;
output["upper_plaintext = "++ show(upper_plaintext) ++ "\n" ++"lower_cipher_output_7_7 = "++ show(lower_cipher_output_7_7) ++ "\n" ++"upper_modadd_0_0 = "++ show(upper_modadd_0_0)++ "\n" ++ "upper probability = "++ show(upper_p[0]/100) ++ "\n" ++"upper_rot_0_1 = "++ show(upper_rot_0_1)++ "\n" ++"upper_xor_0_2 = "++ show(upper_xor_0_2)++ "\n" ++"upper_rot_0_3 = "++ show(upper_rot_0_3)++ "\n" ++"upper_modadd_0_4 = "++ show(upper_modadd_0_4)++ "\n" ++ "upper probability = "++ show(upper_p[1]/100) ++ "\n" ++"upper_rot_0_5 = "++ show(upper_rot_0_5)++ "\n" ++"upper_xor_0_6 = "++ show(upper_xor_0_6)++ "\n" ++"upper_intermediate_output_0_7 = "++ show(upper_intermediate_output_0_7)++ "\n" ++"upper_modadd_1_0 = "++ show(upper_modadd_1_0)++ "\n" ++ "upper probability = "++ show(upper_p[2]/100) ++ "\n" ++"upper_rot_1_1 = "++ show(upper_rot_1_1)++ "\n" ++"upper_xor_1_2 = "++ show(upper_xor_1_2)++ "\n" ++"upper_modadd_1_3 = "++ show(upper_modadd_1_3)++ "\n" ++ "upper probability = "++ show(upper_p[3]/100) ++ "\n" ++"upper_rot_1_4 = "++ show(upper_rot_1_4)++ "\n" ++"upper_xor_1_5 = "++ show(upper_xor_1_5)++ "\n" ++"upper_rot_1_6 = "++ show(upper_rot_1_6)++ "\n" ++"upper_intermediate_output_1_7 = "++ show(upper_intermediate_output_1_7)++ "\n" ++"upper_modadd_2_0 = "++ show(upper_modadd_2_0)++ "\n" ++ "upper probability = "++ show(upper_p[4]/100) ++ "\n" ++"upper_rot_2_1 = "++ show(upper_rot_2_1)++ "\n" ++"upper_xor_2_2 = "++ show(upper_xor_2_2)++ "\n" ++"upper_rot_2_3 = "++ show(upper_rot_2_3)++ "\n" ++"upper_modadd_2_4 = "++ show(upper_modadd_2_4)++ "\n" ++ "upper probability = "++ show(upper_p[5]/100) ++ "\n" ++"upper_rot_2_5 = "++ show(upper_rot_2_5)++ "\n" ++"upper_xor_2_6 = "++ show(upper_xor_2_6)++ "\n" ++"upper_intermediate_output_2_7 = "++ show(upper_intermediate_output_2_7)++ "\n" ++"upper_modadd_3_0 = "++ show(upper_modadd_3_0)++ "\n" ++ "middle probability = "++ show(middle_p[0]/100) ++ "\n" ++"upper_rot_3_1 = "++ show(upper_rot_3_1)++ "\n" ++"upper_xor_3_2 = "++ show(upper_xor_3_2)++ "\n" ++"upper_modadd_3_3 = "++ show(upper_modadd_3_3)++ "\n" ++ "middle probability = "++ show(middle_p[1]/100) ++ "\n" ++"upper_rot_3_4 = "++ show(upper_rot_3_4)++ "\n" ++"upper_xor_3_5 = "++ show(upper_xor_3_5)++ "\n" ++"upper_rot_3_6 = "++ show(upper_rot_3_6)++ "\n" ++"upper_intermediate_output_3_7 = "++ show(upper_intermediate_output_3_7)++ "\n" ++"lower_xor_3_2 = "++ show(lower_xor_3_2)++ "\n" ++"lower_rot_3_6 = "++ show(lower_rot_3_6)++ "\n" ++"lower_intermediate_output_3_7 = "++ show(lower_intermediate_output_3_7)++ "\n" ++"lower_rot_3_1 = "++ show(lower_rot_3_1)++ "\n" ++"lower_xor_3_5 = "++ show(lower_xor_3_5)++ "\n" ++"lower_modadd_3_0 = "++ show(lower_modadd_3_0)++ "\n" ++ "lower_rot_3_4 = "++ show(lower_rot_3_4)++ "\n" ++"lower_modadd_3_3 = "++ show(lower_modadd_3_3)++ "\n" ++ "upper_modadd_4_0 = "++ show(upper_modadd_4_0)++ "\n" ++ "middle probability = "++ show(middle_p[4]/100) ++ "\n" ++"upper_rot_4_1 = "++ show(upper_rot_4_1)++ "\n" ++"upper_xor_4_2 = "++ show(upper_xor_4_2)++ "\n" ++"upper_rot_4_3 = "++ show(upper_rot_4_3)++ "\n" ++"upper_modadd_4_4 = "++ show(upper_modadd_4_4)++ "\n" ++ "middle probability = "++ show(middle_p[5]/100) ++ "\n" ++"upper_rot_4_5 = "++ show(upper_rot_4_5)++ "\n" ++"upper_xor_4_6 = "++ show(upper_xor_4_6)++ "\n" ++"upper_intermediate_output_4_7 = "++ show(upper_intermediate_output_4_7)++ "\n" ++"lower_rot_4_3 = "++ show(lower_rot_4_3)++ "\n" ++"lower_xor_4_2 = "++ show(lower_xor_4_2)++ "\n" ++"lower_xor_4_6 = "++ show(lower_xor_4_6)++ "\n" ++"lower_intermediate_output_4_7 = "++ show(lower_intermediate_output_4_7)++ "\n" ++"lower_rot_4_1 = "++ show(lower_rot_4_1)++ "\n" ++"lower_rot_4_5 = "++ show(lower_rot_4_5)++ "\n" ++"lower_modadd_4_0 = "++ show(lower_modadd_4_0)++ "\n" ++ "lower_modadd_4_4 = "++ show(lower_modadd_4_4)++ "\n" ++ "upper_modadd_5_0 = "++ show(upper_modadd_5_0)++ "\n" ++ "middle probability = "++ show(middle_p[2]/100) ++ "\n" ++"upper_rot_5_1 = "++ show(upper_rot_5_1)++ "\n" ++"upper_xor_5_2 = "++ show(upper_xor_5_2)++ "\n" ++"upper_modadd_5_3 = "++ show(upper_modadd_5_3)++ "\n" ++ "middle probability = "++ show(middle_p[3]/100) ++ "\n" ++"upper_rot_5_4 = "++ show(upper_rot_5_4)++ "\n" ++"upper_xor_5_5 = "++ show(upper_xor_5_5)++ "\n" ++"upper_rot_5_6 = "++ show(upper_rot_5_6)++ "\n" ++"upper_intermediate_output_5_7 = "++ show(upper_intermediate_output_5_7)++ "\n" ++"lower_xor_5_2 = "++ show(lower_xor_5_2)++ "\n" ++"lower_rot_5_6 = "++ show(lower_rot_5_6)++ "\n" ++"lower_intermediate_output_5_7 = "++ show(lower_intermediate_output_5_7)++ "\n" ++"lower_rot_5_1 = "++ show(lower_rot_5_1)++ "\n" ++"lower_xor_5_5 = "++ show(lower_xor_5_5)++ "\n" ++"lower_modadd_5_0 = "++ show(lower_modadd_5_0)++ "\n" ++ "lower_rot_5_4 = "++ show(lower_rot_5_4)++ "\n" ++"lower_modadd_5_3 = "++ show(lower_modadd_5_3)++ "\n" ++ "lower_rot_6_3 = "++ show(lower_rot_6_3)++ "\n" ++"lower_xor_6_2 = "++ show(lower_xor_6_2)++ "\n" ++"lower_xor_6_6 = "++ show(lower_xor_6_6)++ "\n" ++"lower_intermediate_output_6_7 = "++ show(lower_intermediate_output_6_7)++ "\n" ++"lower_rot_6_1 = "++ show(lower_rot_6_1)++ "\n" ++"lower_rot_6_5 = "++ show(lower_rot_6_5)++ "\n" ++"lower_modadd_6_0 = "++ show(lower_modadd_6_0)++ "\n" ++ "lower probability = "++ show(lower_p[6]/100) ++ "\n" ++"lower_modadd_6_4 = "++ show(lower_modadd_6_4)++ "\n" ++ "lower probability = "++ show(lower_p[7]/100) ++ "\n" ++"lower_xor_7_2 = "++ show(lower_xor_7_2)++ "\n" ++"lower_rot_7_6 = "++ show(lower_rot_7_6)++ "\n" ++"lower_rot_7_1 = "++ show(lower_rot_7_1)++ "\n" ++"lower_xor_7_5 = "++ show(lower_xor_7_5)++ "\n" ++"lower_modadd_7_0 = "++ show(lower_modadd_7_0)++ "\n" ++ "lower probability = "++ show(lower_p[8]/100) ++ "\n" ++"lower_rot_7_4 = "++ show(lower_rot_7_4)++ "\n" ++"lower_modadd_7_3 = "++ show(lower_modadd_7_3)++ "\n" ++ "lower probability = "++ show(lower_p[9]/100) ++ "\n" ++"Upper weight = " ++ show(upper_weight/100) ++ "\n" ++"Lower weight = " ++ show(lower_weight/100) ++ "\n" ++"Middle weight = " ++ show(middle_weight/100) ++ "\n" ++"Trail weight = " ++ show(weight/100)  ];

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
    array[0..15] of var 0..1: dL,
    array[0..15] of var 0..1: dR,
    array[0..15] of var 0..1: nL,
    array[0..15] of var 0..1: nR,
    array[0..15] of var 0..1: dLL,
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
    array[0..15] of var 0..1: dL,
    array[0..15] of var 0..1: dR,
    array[0..15] of var 0..1: nL,
    array[0..15] of var 0..1: nR,
    array[0..15] of var 0..1: nLL,
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
    

    include "table.mzn";
    int:num_workers_ebct = 8;
    int: num_rows_ebct = 64;
    int: num_cols_last_table_ebct = 14;
    int: num_cols_ebct = 16;
    array[0..num_cols_ebct-1] of var 0..1: b_ebct;
    array[0..num_workers_ebct-1,0..num_rows_ebct-1,0..num_cols_ebct-1] of 0..1: ebct_table =
         array3d(0..num_workers_ebct-1,0..num_rows_ebct-1,0..num_cols_ebct-1,
      [
     0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
   0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
   1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
   0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
   1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
   1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
   1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
   1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
   0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
   0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1,
   1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1,
   0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1,
   1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1,
   0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0,
   0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
   1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0,
   0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
   1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
   0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
   1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
   0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
   1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
   0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0,
   1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
   0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
   1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
   0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
   1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0,
   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0,
   0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1,
   1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0,
   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1,
   1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0,
   0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
   1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
   1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1,
   0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1,
   0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
   1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
   1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
   0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
   0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
   0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
   0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
   1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
   0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0,
   1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0,
   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0,
   1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1,
   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0,
   1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1,
   0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0,
   1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1,
   1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1,
   0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1,
   1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1,
   0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
   0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
   1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
   0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0,
   1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
   0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
   1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
   0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
   1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
   0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1,
   1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1,
   1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
   0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
   0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0,
   1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
   0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0,
   1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
   0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0,
   1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0,
   1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      ]);
    
    array[0..num_rows_ebct-1,0..num_cols_last_table_ebct-1] of 0..1: last_table_ebct =
         array2d(0..num_rows_ebct-1,0..num_cols_last_table_ebct-1,
      [
         0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
  0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
  1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0,
  0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
  1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,
  0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,
  1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
  0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
  1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,
  0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,
  1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
  0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0,
  1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
  0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
  1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0,
  0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0,
  1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0,
  0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0,
  1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0,
  0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0,
  1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1,
  1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0,
  0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0,
  1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1,
  0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1,
  1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0,
  0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0,
  1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0,
  0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0,
  1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0,
  0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1,
  1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0,
  0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0,
  1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1,
  0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0,
  1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0,
  0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0,
  1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0,
  0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0,
  1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0,
  0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0,
  1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0,
  0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1,
  1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0,
  0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0,
  1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1,
  0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0,
  1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1,
  0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1,
  1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0,
  0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0,
  1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0,
  0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0,
  1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0,
  0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0,
  1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0,
  0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0,
  1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0,
  0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0,
  1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1,
  0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1,
  1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0
      ]);
    
    
    predicate onlyLargeSwitch_EBCT_enum(
      array[int] of var 0..1: dL,
      array[int] of var 0..1:dR,
      array[int] of var 0..1: nL,
      array[int] of var 0..1:nR,
      array[int] of var 0..1: dLL,
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
            array[0..13] of var bool: isValid;
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
                    array[0..15] of var 0..1: column = array1d(0..15, [dL[i], dR[i], nL[i], nR[i], dLL[i], nLL[i], matrix[i, 0*8+cn], matrix[i, 1*8+cn], matrix[i, 2*8+cn], matrix[i, 3*8+cn], matrix[i, 4*8+cn], matrix[i, 5*8+cn], matrix[i, 6*8+cn], matrix[i, 7*8+cn], halfSize0[i, cn], halfSize1[i, cn]])
                } in
                BVAssign_ebct(column, cn)
            ) /\
            (dp[i + 1, 0] \/ dp[i + 1, 1] \/ dp[i + 1, 2] \/ dp[i + 1, 3] \/ dp[i + 1, 4] \/ dp[i + 1, 5] \/ dp[i + 1, 6] \/ dp[i + 1, 7]) /\
            forall(j in 0..7) (
                (ifEnforced[i] == not(isHalf[i])) /\
                (not(ifEnforced[i]) \/ not(dp[i,j]) \/ matrix[i, j*8+j]) /\
                (not(ifEnforced[i]) \/ not(dp[i,j]) \/ dp[i+1,j]) /\
                sum([not(ifEnforced[i]), not(dp[i,j]), matrix[i, j * 8 + j]]) >= 1 /\
                sum([not(ifEnforced[i]), not(dp[i,j]), dp[i + 1,j]]) >= 1
            ) /\
            forall(j in 0..7) (
                (enforcedLiterals[i,j] -> (not(matrix[i,j * 8 + j]) /\ dp[i,j])) /\
                (not(enforcedLiterals[i,j]) -> (matrix[i,j * 8 + j] \/ not(dp[i,j])))
            ) /\
            (ifEnforced[i] \/ enforcedLiterals[i,0] \/ enforcedLiterals[i,1] \/ enforcedLiterals[i,2] \/ enforcedLiterals[i,3] \/ enforcedLiterals[i,4] \/ enforcedLiterals[i,5] \/ enforcedLiterals[i,6] \/ enforcedLiterals[i,7]) /\
            forall(r in 0..7) (
                forall(cc in 0..7) (
                    (literals[i, r * 8 + cc] -> (matrix[i, r * 8 + cc] /\ dp[i, cc])) /\
                    (not(literals[i, r * 8 + cc]) -> (not(matrix[i,r * 8 + cc]) \/ not(dp[i,cc]))) /\
                    (matrix[i,r * 8 + cc] >=  literals[i,r * 8 + cc]) /\
                    (dp[i,cc] >=           literals[i,r * 8 + cc])  /\
                    sum([ literals[i, r * 8 + cc], true ]) >= sum([ matrix[i, r * 8 + cc], dp[i,cc] ])
                ) /\
                (dp[i + 1,r] -> (literals[i,r * 8 + 0] \/ literals[i,r * 8 + 1] \/ literals[i,r * 8 + 2] \/ literals[i,r * 8 + 3] \/ literals[i,r * 8 + 4] \/ literals[i,r * 8 + 5] \/ literals[i,r * 8 + 6] \/ literals[i,r * 8 + 7])) /\
                (not(dp[i + 1,r]) -> (not(literals[i,r * 8 + 0]) /\ not(literals[i,r * 8 + 1]) /\ not(literals[i,r * 8 + 2]) /\ not(literals[i,r * 8 + 3]) /\ not(literals[i,r * 8 + 4]) /\ not(literals[i,r * 8 + 5]) /\ not(literals[i,r * 8 + 6]) /\ not(literals[i,r * 8 + 7]))) /\
                forall(li in 0..7) (
                    dp[i + 1,r] >= literals[i, r * 8 + li] 
                ) /\
                (sum([ literals[i,r * 8 + 0], literals[i,r * 8 + 1], literals[i,r * 8 + 2], literals[i,r * 8 + 3], literals[i,r * 8 + 4], literals[i,r * 8 + 5], literals[i,r * 8 + 6], literals[i,r * 8 + 7] ]) >= dp[i + 1,r])
            )
        ) /\
        ( isValid[0] == dL[branchSize - 1] /\
            isValid[1] == dR[branchSize -1] /\
            isValid[2] == nL[branchSize - 1] /\
            isValid[3] == nR[branchSize -1] /\
            isValid[4] == dLL[branchSize - 1] /\
            isValid[5] == nLL[branchSize -1] 
        ) /\
            (BVAssign_last_table_ebct(isValid))
        /\
        forall(i in 0..7) (
            (lastLiterals[i] -> (dp[branchSize-1,i] /\ isValid[6 + i])) /\
            (not(lastLiterals[i]) -> (not(dp[branchSize-1,i]) \/ not(isValid[6 + i])))
        ) /\
        (lastLiterals[0] \/ lastLiterals[1] \/ lastLiterals[2] \/ lastLiterals[3] \/ lastLiterals[4] \/ lastLiterals[5] \/ lastLiterals[6] \/ lastLiterals[7])
        ;         

        predicate BVAssign_ebct(array[0..num_cols_ebct-1] of var 0..1: column, int: index) =
        let {
            array[int] of set of int: indices = [index..index, 0..num_rows_ebct-1, 0..num_cols_ebct-1];
            array[int,int] of int: extractedFromTable = slice_2d(ebct_table, indices, 0..num_rows_ebct-1, 0..num_cols_ebct-1);
        } in
        table(column, extractedFromTable);

        predicate BVAssign_last_table_ebct(array[0..num_cols_last_table_ebct-1] of var bool: isValid) =  table(isValid, last_table_ebct);  
    
 
    array[0..63, 0..7, 0..7] of 0..4: tables_ebct = array3d(0..63, 0..7, 0..7, 
[
  4, 0, 0, 0, 0, 2, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 2, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 2, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 2, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  2, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  2, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 2, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 1, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 2, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 1, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
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
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 1, 
 
  2, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  2, 0, 0, 0, 0, 2, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 2, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 2, 0, 0, 2, 0, 
  0, 0, 0, 2, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  2, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  2, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  2, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 2, 0, 0, 
  2, 0, 0, 0, 0, 2, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 2, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 2, 0, 0, 4, 0, 
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
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 1, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  2, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  2, 0, 0, 0, 0, 2, 0, 0, 
  0, 0, 0, 0, 0, 2, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 2, 0, 0, 0, 0, 
  0, 0, 0, 2, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0,
 
  0, 0, 2, 0, 0, 0, 0, 2, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 2, 

  0, 2, 0, 0, 2, 0, 0, 0, 
  0, 2, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 1, 
 
  2, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  2, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
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
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  2, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  2, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
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
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  2, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 4, 0, 0, 0, 0, 2, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 2, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 2, 0, 0, 0, 0, 0, 0, 
  0, 2, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
  0, 1, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 1, 
  0, 0, 0, 0, 0, 0, 0, 1, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 2, 
  0, 0, 0, 0, 0, 0, 0, 2, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 2, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 2, 0, 0, 2, 0, 0, 0, 
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
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  2, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 2, 0, 
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
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 1, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 1, 0, 0, 2, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 2, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 

  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 2, 0, 0, 0, 0, 2, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 2, 
 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 2, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 2, 0, 0, 4, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0]);
 
array[0..7,0..2] of 0..1: valid_state_ebct = array2d(0..7,0..2,
[
0,0,0,%lsb is the first one, msb the last one
1,0,0,
1,1,0,
0,1,0,
1,0,0,
0,0,0,
0,1,0,
1,1,0
]);

predicate ebct_compute(
    array[0..15] of var 0..1: dL,
    array[0..15] of var 0..1: dR,
    array[0..15] of var 0..1: nL,
    array[0..15] of var 0..1: nR,
    array[0..15] of var 0..1: dLL,
    array[0..15] of var 0..1: nLL,
    int: branchSize,
    var 0..3200: ebct_minus_log_2
) =
let {
    array[1..branchSize-1,0..7] of var 0.0..1.0: dp_ebct;
    array[1..branchSize-1] of var 0..63: tmp0;
    var 0.0..1.0: ebct_value;
} in
(
    (
        tmp0[1] == nLL[branchSize-1]*32 + dLL[branchSize-1]*16 + nR[branchSize-1]*8 + nL[branchSize-1]*4 + dR[branchSize-1]*2 + dL[branchSize-1]
    ) /\
    forall(j in 0..7)(
        dp_ebct[1,j] == int2float(tables_ebct[tmp0[1],j,0]) / 4.0
    ) /\
    forall(i in 2..branchSize-1)(
        tmp0[i] == nLL[branchSize-i]*32 + dLL[branchSize-i]*16 + nR[branchSize-i]*8 + nL[branchSize-i]*4 + dR[branchSize-i]*2 + dL[branchSize-i]
    ) /\
    forall(i in 2..branchSize-1, j in 0..7)(
            dp_ebct[i,j] == sum(k in 0..7)(
                 dp_ebct[i-1,k] * int2float(tables_ebct[tmp0[i],j,k]) 
            ) / 4.0
    ) /\
    (
        ebct_value == sum(state in 0..7)(
                                        if ((valid_state_ebct[state,0] + valid_state_ebct[state,2] + nLL[1] + nR[1] + nL[1]) mod 2 == 0) /\
                                           ((valid_state_ebct[state,0] + valid_state_ebct[state,1] + dLL[1] + dR[1] + dL[1]) mod 2 == 0)
                                            then dp_ebct[branchSize-1,state]
                                        else
                                            0
                                        endif
        )
    ) /\
    (
        approx_prob_log(ebct_value,ebct_minus_log_2)
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
constraint sum(lower_cipher_output_7_7)>0;
