
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
array[0..15] of var 0..1: pre_upper_modadd_0_7_0;
array[0..15] of var 0..1: pre_upper_modadd_0_7_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_0_7_1 = LShift(pre_upper_modadd_0_7_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_0_7_0 = LShift(pre_upper_modadd_0_7_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_0_7 = LShift(upper_modadd_0_7,1);
array[0..15] of var 0..1: eq_upper_modadd_0_7 = Eq(Shi_pre_upper_modadd_0_7_1, Shi_pre_upper_modadd_0_7_0, Shi_upper_modadd_0_7);
array[0..16-1] of var 0..1: dummy_upper_xor_0_9;
array[0..15] of var 0..1: pre_upper_modadd_0_10_0;
array[0..15] of var 0..1: pre_upper_modadd_0_10_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_0_10_1 = LShift(pre_upper_modadd_0_10_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_0_10_0 = LShift(pre_upper_modadd_0_10_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_0_10 = LShift(upper_modadd_0_10,1);
array[0..15] of var 0..1: eq_upper_modadd_0_10 = Eq(Shi_pre_upper_modadd_0_10_1, Shi_pre_upper_modadd_0_10_0, Shi_upper_modadd_0_10);
array[0..16-1] of var 0..1: dummy_upper_xor_0_12;
array[0..15] of var 0..1: pre_upper_modadd_1_0_0;
array[0..15] of var 0..1: pre_upper_modadd_1_0_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_0_1 = LShift(pre_upper_modadd_1_0_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_0_0 = LShift(pre_upper_modadd_1_0_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_1_0 = LShift(upper_modadd_1_0,1);
array[0..15] of var 0..1: eq_upper_modadd_1_0 = Eq(Shi_pre_upper_modadd_1_0_1, Shi_pre_upper_modadd_1_0_0, Shi_upper_modadd_1_0);
array[0..16-1] of var 0..1: dummy_upper_xor_1_2;
array[0..15] of var 0..1: pre_upper_modadd_1_4_0;
array[0..15] of var 0..1: pre_upper_modadd_1_4_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_4_1 = LShift(pre_upper_modadd_1_4_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_4_0 = LShift(pre_upper_modadd_1_4_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_1_4 = LShift(upper_modadd_1_4,1);
array[0..15] of var 0..1: eq_upper_modadd_1_4 = Eq(Shi_pre_upper_modadd_1_4_1, Shi_pre_upper_modadd_1_4_0, Shi_upper_modadd_1_4);
array[0..16-1] of var 0..1: dummy_upper_xor_1_6;
array[0..15] of var 0..1: pre_upper_modadd_1_7_0;
array[0..15] of var 0..1: pre_upper_modadd_1_7_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_7_1 = LShift(pre_upper_modadd_1_7_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_7_0 = LShift(pre_upper_modadd_1_7_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_1_7 = LShift(upper_modadd_1_7,1);
array[0..15] of var 0..1: eq_upper_modadd_1_7 = Eq(Shi_pre_upper_modadd_1_7_1, Shi_pre_upper_modadd_1_7_0, Shi_upper_modadd_1_7);
array[0..16-1] of var 0..1: dummy_upper_xor_1_9;
array[0..15] of var 0..1: pre_upper_modadd_1_10_0;
array[0..15] of var 0..1: pre_upper_modadd_1_10_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_10_1 = LShift(pre_upper_modadd_1_10_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_1_10_0 = LShift(pre_upper_modadd_1_10_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_1_10 = LShift(upper_modadd_1_10,1);
array[0..15] of var 0..1: eq_upper_modadd_1_10 = Eq(Shi_pre_upper_modadd_1_10_1, Shi_pre_upper_modadd_1_10_0, Shi_upper_modadd_1_10);
array[0..16-1] of var 0..1: dummy_upper_xor_1_12;
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
array[0..15] of var 0..1: pre_upper_modadd_2_7_0;
array[0..15] of var 0..1: pre_upper_modadd_2_7_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_2_7_1 = LShift(pre_upper_modadd_2_7_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_2_7_0 = LShift(pre_upper_modadd_2_7_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_2_7 = LShift(upper_modadd_2_7,1);
array[0..15] of var 0..1: eq_upper_modadd_2_7 = Eq(Shi_pre_upper_modadd_2_7_1, Shi_pre_upper_modadd_2_7_0, Shi_upper_modadd_2_7);
array[0..16-1] of var 0..1: dummy_upper_xor_2_9;
array[0..15] of var 0..1: pre_upper_modadd_2_10_0;
array[0..15] of var 0..1: pre_upper_modadd_2_10_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_2_10_1 = LShift(pre_upper_modadd_2_10_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_2_10_0 = LShift(pre_upper_modadd_2_10_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_2_10 = LShift(upper_modadd_2_10,1);
array[0..15] of var 0..1: eq_upper_modadd_2_10 = Eq(Shi_pre_upper_modadd_2_10_1, Shi_pre_upper_modadd_2_10_0, Shi_upper_modadd_2_10);
array[0..16-1] of var 0..1: dummy_upper_xor_2_12;
array[0..15] of var 0..1: pre_upper_modadd_3_0_0;
array[0..15] of var 0..1: pre_upper_modadd_3_0_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_0_1 = LShift(pre_upper_modadd_3_0_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_0_0 = LShift(pre_upper_modadd_3_0_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_3_0 = LShift(upper_modadd_3_0,1);
array[0..15] of var 0..1: eq_upper_modadd_3_0 = Eq(Shi_pre_upper_modadd_3_0_1, Shi_pre_upper_modadd_3_0_0, Shi_upper_modadd_3_0);
array[0..16-1] of var 0..1: dummy_upper_xor_3_2;
array[0..15] of var 0..1: pre_upper_modadd_3_4_0;
array[0..15] of var 0..1: pre_upper_modadd_3_4_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_4_1 = LShift(pre_upper_modadd_3_4_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_4_0 = LShift(pre_upper_modadd_3_4_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_3_4 = LShift(upper_modadd_3_4,1);
array[0..15] of var 0..1: eq_upper_modadd_3_4 = Eq(Shi_pre_upper_modadd_3_4_1, Shi_pre_upper_modadd_3_4_0, Shi_upper_modadd_3_4);
array[0..16-1] of var 0..1: dummy_upper_xor_3_6;
array[0..15] of var 0..1: pre_upper_modadd_3_7_0;
array[0..15] of var 0..1: pre_upper_modadd_3_7_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_7_1 = LShift(pre_upper_modadd_3_7_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_7_0 = LShift(pre_upper_modadd_3_7_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_3_7 = LShift(upper_modadd_3_7,1);
array[0..15] of var 0..1: eq_upper_modadd_3_7 = Eq(Shi_pre_upper_modadd_3_7_1, Shi_pre_upper_modadd_3_7_0, Shi_upper_modadd_3_7);
array[0..16-1] of var 0..1: dummy_upper_xor_3_9;
array[0..15] of var 0..1: pre_upper_modadd_3_10_0;
array[0..15] of var 0..1: pre_upper_modadd_3_10_1;
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_10_1 = LShift(pre_upper_modadd_3_10_1,1);
array[0..15] of var 0..1: Shi_pre_upper_modadd_3_10_0 = LShift(pre_upper_modadd_3_10_0,1);
array[0..15] of var 0..1: Shi_upper_modadd_3_10 = LShift(upper_modadd_3_10,1);
array[0..15] of var 0..1: eq_upper_modadd_3_10 = Eq(Shi_pre_upper_modadd_3_10_1, Shi_pre_upper_modadd_3_10_0, Shi_upper_modadd_3_10);
array[0..16-1] of var 0..1: dummy_upper_xor_3_12;
array[0..16-1] of var 0..1: dummy_lower_xor_3_9;
array[0..16-1] of var 0..1: dummy_lower_xor_3_12;
array[0..15] of var 0..1: pre_lower_modadd_3_7_0;
array[0..15] of var 0..1: pre_lower_modadd_3_7_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_7_1 = LShift(pre_lower_modadd_3_7_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_7_0 = LShift(pre_lower_modadd_3_7_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_3_7 = LShift(lower_modadd_3_7,1);
array[0..15] of var 0..1: eq_lower_modadd_3_7 = Eq(Shi_pre_lower_modadd_3_7_1, Shi_pre_lower_modadd_3_7_0, Shi_lower_modadd_3_7);
array[0..15] of var 0..1: pre_lower_modadd_3_10_0;
array[0..15] of var 0..1: pre_lower_modadd_3_10_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_10_1 = LShift(pre_lower_modadd_3_10_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_10_0 = LShift(pre_lower_modadd_3_10_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_3_10 = LShift(lower_modadd_3_10,1);
array[0..15] of var 0..1: eq_lower_modadd_3_10 = Eq(Shi_pre_lower_modadd_3_10_1, Shi_pre_lower_modadd_3_10_0, Shi_lower_modadd_3_10);
array[0..16-1] of var 0..1: dummy_lower_xor_3_2;
array[0..16-1] of var 0..1: dummy_lower_xor_3_6;
array[0..15] of var 0..1: pre_lower_modadd_3_0_0;
array[0..15] of var 0..1: pre_lower_modadd_3_0_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_0_1 = LShift(pre_lower_modadd_3_0_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_0_0 = LShift(pre_lower_modadd_3_0_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_3_0 = LShift(lower_modadd_3_0,1);
array[0..15] of var 0..1: eq_lower_modadd_3_0 = Eq(Shi_pre_lower_modadd_3_0_1, Shi_pre_lower_modadd_3_0_0, Shi_lower_modadd_3_0);
array[0..15] of var 0..1: pre_lower_modadd_3_4_0;
array[0..15] of var 0..1: pre_lower_modadd_3_4_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_4_1 = LShift(pre_lower_modadd_3_4_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_3_4_0 = LShift(pre_lower_modadd_3_4_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_3_4 = LShift(lower_modadd_3_4,1);
array[0..15] of var 0..1: eq_lower_modadd_3_4 = Eq(Shi_pre_lower_modadd_3_4_1, Shi_pre_lower_modadd_3_4_0, Shi_lower_modadd_3_4);
array[0..16-1] of var 0..1: dummy_lower_xor_4_9;
array[0..16-1] of var 0..1: dummy_lower_xor_4_12;
array[0..15] of var 0..1: pre_lower_modadd_4_7_0;
array[0..15] of var 0..1: pre_lower_modadd_4_7_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_4_7_1 = LShift(pre_lower_modadd_4_7_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_4_7_0 = LShift(pre_lower_modadd_4_7_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_4_7 = LShift(lower_modadd_4_7,1);
array[0..15] of var 0..1: eq_lower_modadd_4_7 = Eq(Shi_pre_lower_modadd_4_7_1, Shi_pre_lower_modadd_4_7_0, Shi_lower_modadd_4_7);
array[0..15] of var 0..1: pre_lower_modadd_4_10_0;
array[0..15] of var 0..1: pre_lower_modadd_4_10_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_4_10_1 = LShift(pre_lower_modadd_4_10_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_4_10_0 = LShift(pre_lower_modadd_4_10_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_4_10 = LShift(lower_modadd_4_10,1);
array[0..15] of var 0..1: eq_lower_modadd_4_10 = Eq(Shi_pre_lower_modadd_4_10_1, Shi_pre_lower_modadd_4_10_0, Shi_lower_modadd_4_10);
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
array[0..16-1] of var 0..1: dummy_lower_xor_5_9;
array[0..16-1] of var 0..1: dummy_lower_xor_5_12;
array[0..15] of var 0..1: pre_lower_modadd_5_7_0;
array[0..15] of var 0..1: pre_lower_modadd_5_7_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_7_1 = LShift(pre_lower_modadd_5_7_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_7_0 = LShift(pre_lower_modadd_5_7_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_5_7 = LShift(lower_modadd_5_7,1);
array[0..15] of var 0..1: eq_lower_modadd_5_7 = Eq(Shi_pre_lower_modadd_5_7_1, Shi_pre_lower_modadd_5_7_0, Shi_lower_modadd_5_7);
array[0..15] of var 0..1: pre_lower_modadd_5_10_0;
array[0..15] of var 0..1: pre_lower_modadd_5_10_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_10_1 = LShift(pre_lower_modadd_5_10_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_10_0 = LShift(pre_lower_modadd_5_10_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_5_10 = LShift(lower_modadd_5_10,1);
array[0..15] of var 0..1: eq_lower_modadd_5_10 = Eq(Shi_pre_lower_modadd_5_10_1, Shi_pre_lower_modadd_5_10_0, Shi_lower_modadd_5_10);
array[0..16-1] of var 0..1: dummy_lower_xor_5_2;
array[0..16-1] of var 0..1: dummy_lower_xor_5_6;
array[0..15] of var 0..1: pre_lower_modadd_5_0_0;
array[0..15] of var 0..1: pre_lower_modadd_5_0_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_0_1 = LShift(pre_lower_modadd_5_0_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_0_0 = LShift(pre_lower_modadd_5_0_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_5_0 = LShift(lower_modadd_5_0,1);
array[0..15] of var 0..1: eq_lower_modadd_5_0 = Eq(Shi_pre_lower_modadd_5_0_1, Shi_pre_lower_modadd_5_0_0, Shi_lower_modadd_5_0);
array[0..15] of var 0..1: pre_lower_modadd_5_4_0;
array[0..15] of var 0..1: pre_lower_modadd_5_4_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_4_1 = LShift(pre_lower_modadd_5_4_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_5_4_0 = LShift(pre_lower_modadd_5_4_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_5_4 = LShift(lower_modadd_5_4,1);
array[0..15] of var 0..1: eq_lower_modadd_5_4 = Eq(Shi_pre_lower_modadd_5_4_1, Shi_pre_lower_modadd_5_4_0, Shi_lower_modadd_5_4);
array[0..16-1] of var 0..1: dummy_lower_xor_6_9;
array[0..16-1] of var 0..1: dummy_lower_xor_6_12;
array[0..15] of var 0..1: pre_lower_modadd_6_7_0;
array[0..15] of var 0..1: pre_lower_modadd_6_7_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_6_7_1 = LShift(pre_lower_modadd_6_7_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_6_7_0 = LShift(pre_lower_modadd_6_7_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_6_7 = LShift(lower_modadd_6_7,1);
array[0..15] of var 0..1: eq_lower_modadd_6_7 = Eq(Shi_pre_lower_modadd_6_7_1, Shi_pre_lower_modadd_6_7_0, Shi_lower_modadd_6_7);
array[0..15] of var 0..1: pre_lower_modadd_6_10_0;
array[0..15] of var 0..1: pre_lower_modadd_6_10_1;
array[0..15] of var 0..1: Shi_pre_lower_modadd_6_10_1 = LShift(pre_lower_modadd_6_10_1,1);
array[0..15] of var 0..1: Shi_pre_lower_modadd_6_10_0 = LShift(pre_lower_modadd_6_10_0,1);
array[0..15] of var 0..1: Shi_lower_modadd_6_10 = LShift(lower_modadd_6_10,1);
array[0..15] of var 0..1: eq_lower_modadd_6_10 = Eq(Shi_pre_lower_modadd_6_10_1, Shi_pre_lower_modadd_6_10_0, Shi_lower_modadd_6_10);
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
constraint pre_upper_modadd_0_7_0[0] = upper_rot_0_3[0];
constraint pre_upper_modadd_0_7_0[1] = upper_rot_0_3[1];
constraint pre_upper_modadd_0_7_0[2] = upper_rot_0_3[2];
constraint pre_upper_modadd_0_7_0[3] = upper_rot_0_3[3];
constraint pre_upper_modadd_0_7_0[4] = upper_rot_0_3[4];
constraint pre_upper_modadd_0_7_0[5] = upper_rot_0_3[5];
constraint pre_upper_modadd_0_7_0[6] = upper_rot_0_3[6];
constraint pre_upper_modadd_0_7_0[7] = upper_rot_0_3[7];
constraint pre_upper_modadd_0_7_0[8] = upper_rot_0_3[8];
constraint pre_upper_modadd_0_7_0[9] = upper_rot_0_3[9];
constraint pre_upper_modadd_0_7_0[10] = upper_rot_0_3[10];
constraint pre_upper_modadd_0_7_0[11] = upper_rot_0_3[11];
constraint pre_upper_modadd_0_7_0[12] = upper_rot_0_3[12];
constraint pre_upper_modadd_0_7_0[13] = upper_rot_0_3[13];
constraint pre_upper_modadd_0_7_0[14] = upper_rot_0_3[14];
constraint pre_upper_modadd_0_7_0[15] = upper_rot_0_3[15];
constraint pre_upper_modadd_0_7_1[0] = upper_xor_0_6[0];
constraint pre_upper_modadd_0_7_1[1] = upper_xor_0_6[1];
constraint pre_upper_modadd_0_7_1[2] = upper_xor_0_6[2];
constraint pre_upper_modadd_0_7_1[3] = upper_xor_0_6[3];
constraint pre_upper_modadd_0_7_1[4] = upper_xor_0_6[4];
constraint pre_upper_modadd_0_7_1[5] = upper_xor_0_6[5];
constraint pre_upper_modadd_0_7_1[6] = upper_xor_0_6[6];
constraint pre_upper_modadd_0_7_1[7] = upper_xor_0_6[7];
constraint pre_upper_modadd_0_7_1[8] = upper_xor_0_6[8];
constraint pre_upper_modadd_0_7_1[9] = upper_xor_0_6[9];
constraint pre_upper_modadd_0_7_1[10] = upper_xor_0_6[10];
constraint pre_upper_modadd_0_7_1[11] = upper_xor_0_6[11];
constraint pre_upper_modadd_0_7_1[12] = upper_xor_0_6[12];
constraint pre_upper_modadd_0_7_1[13] = upper_xor_0_6[13];
constraint pre_upper_modadd_0_7_1[14] = upper_xor_0_6[14];
constraint pre_upper_modadd_0_7_1[15] = upper_xor_0_6[15];
constraint forall(j in 0..15)(if eq_upper_modadd_0_7[j] = 1 then (sum([pre_upper_modadd_0_7_1[j], pre_upper_modadd_0_7_0[j], upper_modadd_0_7[j]]) mod 2) = Shi_pre_upper_modadd_0_7_0[j] else true endif) /\ upper_p[2] = (16-sum(eq_upper_modadd_0_7))*100;
constraint upper_rot_0_8[0] = upper_xor_0_6[13];
constraint upper_rot_0_8[1] = upper_xor_0_6[14];
constraint upper_rot_0_8[2] = upper_xor_0_6[15];
constraint upper_rot_0_8[3] = upper_xor_0_6[0];
constraint upper_rot_0_8[4] = upper_xor_0_6[1];
constraint upper_rot_0_8[5] = upper_xor_0_6[2];
constraint upper_rot_0_8[6] = upper_xor_0_6[3];
constraint upper_rot_0_8[7] = upper_xor_0_6[4];
constraint upper_rot_0_8[8] = upper_xor_0_6[5];
constraint upper_rot_0_8[9] = upper_xor_0_6[6];
constraint upper_rot_0_8[10] = upper_xor_0_6[7];
constraint upper_rot_0_8[11] = upper_xor_0_6[8];
constraint upper_rot_0_8[12] = upper_xor_0_6[9];
constraint upper_rot_0_8[13] = upper_xor_0_6[10];
constraint upper_rot_0_8[14] = upper_xor_0_6[11];
constraint upper_rot_0_8[15] = upper_xor_0_6[12];
constraint 2*dummy_upper_xor_0_9[0] = (upper_rot_0_8[0] + upper_modadd_0_7[0] + upper_xor_0_9[0]);
constraint 2*dummy_upper_xor_0_9[1] = (upper_rot_0_8[1] + upper_modadd_0_7[1] + upper_xor_0_9[1]);
constraint 2*dummy_upper_xor_0_9[2] = (upper_rot_0_8[2] + upper_modadd_0_7[2] + upper_xor_0_9[2]);
constraint 2*dummy_upper_xor_0_9[3] = (upper_rot_0_8[3] + upper_modadd_0_7[3] + upper_xor_0_9[3]);
constraint 2*dummy_upper_xor_0_9[4] = (upper_rot_0_8[4] + upper_modadd_0_7[4] + upper_xor_0_9[4]);
constraint 2*dummy_upper_xor_0_9[5] = (upper_rot_0_8[5] + upper_modadd_0_7[5] + upper_xor_0_9[5]);
constraint 2*dummy_upper_xor_0_9[6] = (upper_rot_0_8[6] + upper_modadd_0_7[6] + upper_xor_0_9[6]);
constraint 2*dummy_upper_xor_0_9[7] = (upper_rot_0_8[7] + upper_modadd_0_7[7] + upper_xor_0_9[7]);
constraint 2*dummy_upper_xor_0_9[8] = (upper_rot_0_8[8] + upper_modadd_0_7[8] + upper_xor_0_9[8]);
constraint 2*dummy_upper_xor_0_9[9] = (upper_rot_0_8[9] + upper_modadd_0_7[9] + upper_xor_0_9[9]);
constraint 2*dummy_upper_xor_0_9[10] = (upper_rot_0_8[10] + upper_modadd_0_7[10] + upper_xor_0_9[10]);
constraint 2*dummy_upper_xor_0_9[11] = (upper_rot_0_8[11] + upper_modadd_0_7[11] + upper_xor_0_9[11]);
constraint 2*dummy_upper_xor_0_9[12] = (upper_rot_0_8[12] + upper_modadd_0_7[12] + upper_xor_0_9[12]);
constraint 2*dummy_upper_xor_0_9[13] = (upper_rot_0_8[13] + upper_modadd_0_7[13] + upper_xor_0_9[13]);
constraint 2*dummy_upper_xor_0_9[14] = (upper_rot_0_8[14] + upper_modadd_0_7[14] + upper_xor_0_9[14]);
constraint 2*dummy_upper_xor_0_9[15] = (upper_rot_0_8[15] + upper_modadd_0_7[15] + upper_xor_0_9[15]);
constraint pre_upper_modadd_0_10_0[0] = upper_modadd_0_4[0];
constraint pre_upper_modadd_0_10_0[1] = upper_modadd_0_4[1];
constraint pre_upper_modadd_0_10_0[2] = upper_modadd_0_4[2];
constraint pre_upper_modadd_0_10_0[3] = upper_modadd_0_4[3];
constraint pre_upper_modadd_0_10_0[4] = upper_modadd_0_4[4];
constraint pre_upper_modadd_0_10_0[5] = upper_modadd_0_4[5];
constraint pre_upper_modadd_0_10_0[6] = upper_modadd_0_4[6];
constraint pre_upper_modadd_0_10_0[7] = upper_modadd_0_4[7];
constraint pre_upper_modadd_0_10_0[8] = upper_modadd_0_4[8];
constraint pre_upper_modadd_0_10_0[9] = upper_modadd_0_4[9];
constraint pre_upper_modadd_0_10_0[10] = upper_modadd_0_4[10];
constraint pre_upper_modadd_0_10_0[11] = upper_modadd_0_4[11];
constraint pre_upper_modadd_0_10_0[12] = upper_modadd_0_4[12];
constraint pre_upper_modadd_0_10_0[13] = upper_modadd_0_4[13];
constraint pre_upper_modadd_0_10_0[14] = upper_modadd_0_4[14];
constraint pre_upper_modadd_0_10_0[15] = upper_modadd_0_4[15];
constraint pre_upper_modadd_0_10_1[0] = upper_xor_0_2[0];
constraint pre_upper_modadd_0_10_1[1] = upper_xor_0_2[1];
constraint pre_upper_modadd_0_10_1[2] = upper_xor_0_2[2];
constraint pre_upper_modadd_0_10_1[3] = upper_xor_0_2[3];
constraint pre_upper_modadd_0_10_1[4] = upper_xor_0_2[4];
constraint pre_upper_modadd_0_10_1[5] = upper_xor_0_2[5];
constraint pre_upper_modadd_0_10_1[6] = upper_xor_0_2[6];
constraint pre_upper_modadd_0_10_1[7] = upper_xor_0_2[7];
constraint pre_upper_modadd_0_10_1[8] = upper_xor_0_2[8];
constraint pre_upper_modadd_0_10_1[9] = upper_xor_0_2[9];
constraint pre_upper_modadd_0_10_1[10] = upper_xor_0_2[10];
constraint pre_upper_modadd_0_10_1[11] = upper_xor_0_2[11];
constraint pre_upper_modadd_0_10_1[12] = upper_xor_0_2[12];
constraint pre_upper_modadd_0_10_1[13] = upper_xor_0_2[13];
constraint pre_upper_modadd_0_10_1[14] = upper_xor_0_2[14];
constraint pre_upper_modadd_0_10_1[15] = upper_xor_0_2[15];
constraint forall(j in 0..15)(if eq_upper_modadd_0_10[j] = 1 then (sum([pre_upper_modadd_0_10_1[j], pre_upper_modadd_0_10_0[j], upper_modadd_0_10[j]]) mod 2) = Shi_pre_upper_modadd_0_10_0[j] else true endif) /\ upper_p[3] = (16-sum(eq_upper_modadd_0_10))*100;
constraint upper_rot_0_11[0] = upper_xor_0_2[7];
constraint upper_rot_0_11[1] = upper_xor_0_2[8];
constraint upper_rot_0_11[2] = upper_xor_0_2[9];
constraint upper_rot_0_11[3] = upper_xor_0_2[10];
constraint upper_rot_0_11[4] = upper_xor_0_2[11];
constraint upper_rot_0_11[5] = upper_xor_0_2[12];
constraint upper_rot_0_11[6] = upper_xor_0_2[13];
constraint upper_rot_0_11[7] = upper_xor_0_2[14];
constraint upper_rot_0_11[8] = upper_xor_0_2[15];
constraint upper_rot_0_11[9] = upper_xor_0_2[0];
constraint upper_rot_0_11[10] = upper_xor_0_2[1];
constraint upper_rot_0_11[11] = upper_xor_0_2[2];
constraint upper_rot_0_11[12] = upper_xor_0_2[3];
constraint upper_rot_0_11[13] = upper_xor_0_2[4];
constraint upper_rot_0_11[14] = upper_xor_0_2[5];
constraint upper_rot_0_11[15] = upper_xor_0_2[6];
constraint 2*dummy_upper_xor_0_12[0] = (upper_rot_0_11[0] + upper_modadd_0_10[0] + upper_xor_0_12[0]);
constraint 2*dummy_upper_xor_0_12[1] = (upper_rot_0_11[1] + upper_modadd_0_10[1] + upper_xor_0_12[1]);
constraint 2*dummy_upper_xor_0_12[2] = (upper_rot_0_11[2] + upper_modadd_0_10[2] + upper_xor_0_12[2]);
constraint 2*dummy_upper_xor_0_12[3] = (upper_rot_0_11[3] + upper_modadd_0_10[3] + upper_xor_0_12[3]);
constraint 2*dummy_upper_xor_0_12[4] = (upper_rot_0_11[4] + upper_modadd_0_10[4] + upper_xor_0_12[4]);
constraint 2*dummy_upper_xor_0_12[5] = (upper_rot_0_11[5] + upper_modadd_0_10[5] + upper_xor_0_12[5]);
constraint 2*dummy_upper_xor_0_12[6] = (upper_rot_0_11[6] + upper_modadd_0_10[6] + upper_xor_0_12[6]);
constraint 2*dummy_upper_xor_0_12[7] = (upper_rot_0_11[7] + upper_modadd_0_10[7] + upper_xor_0_12[7]);
constraint 2*dummy_upper_xor_0_12[8] = (upper_rot_0_11[8] + upper_modadd_0_10[8] + upper_xor_0_12[8]);
constraint 2*dummy_upper_xor_0_12[9] = (upper_rot_0_11[9] + upper_modadd_0_10[9] + upper_xor_0_12[9]);
constraint 2*dummy_upper_xor_0_12[10] = (upper_rot_0_11[10] + upper_modadd_0_10[10] + upper_xor_0_12[10]);
constraint 2*dummy_upper_xor_0_12[11] = (upper_rot_0_11[11] + upper_modadd_0_10[11] + upper_xor_0_12[11]);
constraint 2*dummy_upper_xor_0_12[12] = (upper_rot_0_11[12] + upper_modadd_0_10[12] + upper_xor_0_12[12]);
constraint 2*dummy_upper_xor_0_12[13] = (upper_rot_0_11[13] + upper_modadd_0_10[13] + upper_xor_0_12[13]);
constraint 2*dummy_upper_xor_0_12[14] = (upper_rot_0_11[14] + upper_modadd_0_10[14] + upper_xor_0_12[14]);
constraint 2*dummy_upper_xor_0_12[15] = (upper_rot_0_11[15] + upper_modadd_0_10[15] + upper_xor_0_12[15]);
constraint upper_rot_0_13[0] = upper_modadd_0_10[0];
constraint upper_rot_0_13[1] = upper_modadd_0_10[1];
constraint upper_rot_0_13[2] = upper_modadd_0_10[2];
constraint upper_rot_0_13[3] = upper_modadd_0_10[3];
constraint upper_rot_0_13[4] = upper_modadd_0_10[4];
constraint upper_rot_0_13[5] = upper_modadd_0_10[5];
constraint upper_rot_0_13[6] = upper_modadd_0_10[6];
constraint upper_rot_0_13[7] = upper_modadd_0_10[7];
constraint upper_rot_0_13[8] = upper_modadd_0_10[8];
constraint upper_rot_0_13[9] = upper_modadd_0_10[9];
constraint upper_rot_0_13[10] = upper_modadd_0_10[10];
constraint upper_rot_0_13[11] = upper_modadd_0_10[11];
constraint upper_rot_0_13[12] = upper_modadd_0_10[12];
constraint upper_rot_0_13[13] = upper_modadd_0_10[13];
constraint upper_rot_0_13[14] = upper_modadd_0_10[14];
constraint upper_rot_0_13[15] = upper_modadd_0_10[15];
constraint upper_intermediate_output_0_14[0] = upper_modadd_0_7[0];
constraint upper_intermediate_output_0_14[1] = upper_modadd_0_7[1];
constraint upper_intermediate_output_0_14[2] = upper_modadd_0_7[2];
constraint upper_intermediate_output_0_14[3] = upper_modadd_0_7[3];
constraint upper_intermediate_output_0_14[4] = upper_modadd_0_7[4];
constraint upper_intermediate_output_0_14[5] = upper_modadd_0_7[5];
constraint upper_intermediate_output_0_14[6] = upper_modadd_0_7[6];
constraint upper_intermediate_output_0_14[7] = upper_modadd_0_7[7];
constraint upper_intermediate_output_0_14[8] = upper_modadd_0_7[8];
constraint upper_intermediate_output_0_14[9] = upper_modadd_0_7[9];
constraint upper_intermediate_output_0_14[10] = upper_modadd_0_7[10];
constraint upper_intermediate_output_0_14[11] = upper_modadd_0_7[11];
constraint upper_intermediate_output_0_14[12] = upper_modadd_0_7[12];
constraint upper_intermediate_output_0_14[13] = upper_modadd_0_7[13];
constraint upper_intermediate_output_0_14[14] = upper_modadd_0_7[14];
constraint upper_intermediate_output_0_14[15] = upper_modadd_0_7[15];
constraint upper_intermediate_output_0_14[16] = upper_xor_0_12[0];
constraint upper_intermediate_output_0_14[17] = upper_xor_0_12[1];
constraint upper_intermediate_output_0_14[18] = upper_xor_0_12[2];
constraint upper_intermediate_output_0_14[19] = upper_xor_0_12[3];
constraint upper_intermediate_output_0_14[20] = upper_xor_0_12[4];
constraint upper_intermediate_output_0_14[21] = upper_xor_0_12[5];
constraint upper_intermediate_output_0_14[22] = upper_xor_0_12[6];
constraint upper_intermediate_output_0_14[23] = upper_xor_0_12[7];
constraint upper_intermediate_output_0_14[24] = upper_xor_0_12[8];
constraint upper_intermediate_output_0_14[25] = upper_xor_0_12[9];
constraint upper_intermediate_output_0_14[26] = upper_xor_0_12[10];
constraint upper_intermediate_output_0_14[27] = upper_xor_0_12[11];
constraint upper_intermediate_output_0_14[28] = upper_xor_0_12[12];
constraint upper_intermediate_output_0_14[29] = upper_xor_0_12[13];
constraint upper_intermediate_output_0_14[30] = upper_xor_0_12[14];
constraint upper_intermediate_output_0_14[31] = upper_xor_0_12[15];
constraint upper_intermediate_output_0_14[32] = upper_rot_0_13[0];
constraint upper_intermediate_output_0_14[33] = upper_rot_0_13[1];
constraint upper_intermediate_output_0_14[34] = upper_rot_0_13[2];
constraint upper_intermediate_output_0_14[35] = upper_rot_0_13[3];
constraint upper_intermediate_output_0_14[36] = upper_rot_0_13[4];
constraint upper_intermediate_output_0_14[37] = upper_rot_0_13[5];
constraint upper_intermediate_output_0_14[38] = upper_rot_0_13[6];
constraint upper_intermediate_output_0_14[39] = upper_rot_0_13[7];
constraint upper_intermediate_output_0_14[40] = upper_rot_0_13[8];
constraint upper_intermediate_output_0_14[41] = upper_rot_0_13[9];
constraint upper_intermediate_output_0_14[42] = upper_rot_0_13[10];
constraint upper_intermediate_output_0_14[43] = upper_rot_0_13[11];
constraint upper_intermediate_output_0_14[44] = upper_rot_0_13[12];
constraint upper_intermediate_output_0_14[45] = upper_rot_0_13[13];
constraint upper_intermediate_output_0_14[46] = upper_rot_0_13[14];
constraint upper_intermediate_output_0_14[47] = upper_rot_0_13[15];
constraint upper_intermediate_output_0_14[48] = upper_xor_0_9[0];
constraint upper_intermediate_output_0_14[49] = upper_xor_0_9[1];
constraint upper_intermediate_output_0_14[50] = upper_xor_0_9[2];
constraint upper_intermediate_output_0_14[51] = upper_xor_0_9[3];
constraint upper_intermediate_output_0_14[52] = upper_xor_0_9[4];
constraint upper_intermediate_output_0_14[53] = upper_xor_0_9[5];
constraint upper_intermediate_output_0_14[54] = upper_xor_0_9[6];
constraint upper_intermediate_output_0_14[55] = upper_xor_0_9[7];
constraint upper_intermediate_output_0_14[56] = upper_xor_0_9[8];
constraint upper_intermediate_output_0_14[57] = upper_xor_0_9[9];
constraint upper_intermediate_output_0_14[58] = upper_xor_0_9[10];
constraint upper_intermediate_output_0_14[59] = upper_xor_0_9[11];
constraint upper_intermediate_output_0_14[60] = upper_xor_0_9[12];
constraint upper_intermediate_output_0_14[61] = upper_xor_0_9[13];
constraint upper_intermediate_output_0_14[62] = upper_xor_0_9[14];
constraint upper_intermediate_output_0_14[63] = upper_xor_0_9[15];
constraint pre_upper_modadd_1_0_0[0] = upper_modadd_0_7[0];
constraint pre_upper_modadd_1_0_0[1] = upper_modadd_0_7[1];
constraint pre_upper_modadd_1_0_0[2] = upper_modadd_0_7[2];
constraint pre_upper_modadd_1_0_0[3] = upper_modadd_0_7[3];
constraint pre_upper_modadd_1_0_0[4] = upper_modadd_0_7[4];
constraint pre_upper_modadd_1_0_0[5] = upper_modadd_0_7[5];
constraint pre_upper_modadd_1_0_0[6] = upper_modadd_0_7[6];
constraint pre_upper_modadd_1_0_0[7] = upper_modadd_0_7[7];
constraint pre_upper_modadd_1_0_0[8] = upper_modadd_0_7[8];
constraint pre_upper_modadd_1_0_0[9] = upper_modadd_0_7[9];
constraint pre_upper_modadd_1_0_0[10] = upper_modadd_0_7[10];
constraint pre_upper_modadd_1_0_0[11] = upper_modadd_0_7[11];
constraint pre_upper_modadd_1_0_0[12] = upper_modadd_0_7[12];
constraint pre_upper_modadd_1_0_0[13] = upper_modadd_0_7[13];
constraint pre_upper_modadd_1_0_0[14] = upper_modadd_0_7[14];
constraint pre_upper_modadd_1_0_0[15] = upper_modadd_0_7[15];
constraint pre_upper_modadd_1_0_1[0] = upper_xor_0_12[0];
constraint pre_upper_modadd_1_0_1[1] = upper_xor_0_12[1];
constraint pre_upper_modadd_1_0_1[2] = upper_xor_0_12[2];
constraint pre_upper_modadd_1_0_1[3] = upper_xor_0_12[3];
constraint pre_upper_modadd_1_0_1[4] = upper_xor_0_12[4];
constraint pre_upper_modadd_1_0_1[5] = upper_xor_0_12[5];
constraint pre_upper_modadd_1_0_1[6] = upper_xor_0_12[6];
constraint pre_upper_modadd_1_0_1[7] = upper_xor_0_12[7];
constraint pre_upper_modadd_1_0_1[8] = upper_xor_0_12[8];
constraint pre_upper_modadd_1_0_1[9] = upper_xor_0_12[9];
constraint pre_upper_modadd_1_0_1[10] = upper_xor_0_12[10];
constraint pre_upper_modadd_1_0_1[11] = upper_xor_0_12[11];
constraint pre_upper_modadd_1_0_1[12] = upper_xor_0_12[12];
constraint pre_upper_modadd_1_0_1[13] = upper_xor_0_12[13];
constraint pre_upper_modadd_1_0_1[14] = upper_xor_0_12[14];
constraint pre_upper_modadd_1_0_1[15] = upper_xor_0_12[15];
constraint forall(j in 0..15)(if eq_upper_modadd_1_0[j] = 1 then (sum([pre_upper_modadd_1_0_1[j], pre_upper_modadd_1_0_0[j], upper_modadd_1_0[j]]) mod 2) = Shi_pre_upper_modadd_1_0_0[j] else true endif) /\ upper_p[4] = (16-sum(eq_upper_modadd_1_0))*100;
constraint upper_rot_1_1[0] = upper_xor_0_12[5];
constraint upper_rot_1_1[1] = upper_xor_0_12[6];
constraint upper_rot_1_1[2] = upper_xor_0_12[7];
constraint upper_rot_1_1[3] = upper_xor_0_12[8];
constraint upper_rot_1_1[4] = upper_xor_0_12[9];
constraint upper_rot_1_1[5] = upper_xor_0_12[10];
constraint upper_rot_1_1[6] = upper_xor_0_12[11];
constraint upper_rot_1_1[7] = upper_xor_0_12[12];
constraint upper_rot_1_1[8] = upper_xor_0_12[13];
constraint upper_rot_1_1[9] = upper_xor_0_12[14];
constraint upper_rot_1_1[10] = upper_xor_0_12[15];
constraint upper_rot_1_1[11] = upper_xor_0_12[0];
constraint upper_rot_1_1[12] = upper_xor_0_12[1];
constraint upper_rot_1_1[13] = upper_xor_0_12[2];
constraint upper_rot_1_1[14] = upper_xor_0_12[3];
constraint upper_rot_1_1[15] = upper_xor_0_12[4];
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
constraint upper_rot_1_3[0] = upper_modadd_1_0[0];
constraint upper_rot_1_3[1] = upper_modadd_1_0[1];
constraint upper_rot_1_3[2] = upper_modadd_1_0[2];
constraint upper_rot_1_3[3] = upper_modadd_1_0[3];
constraint upper_rot_1_3[4] = upper_modadd_1_0[4];
constraint upper_rot_1_3[5] = upper_modadd_1_0[5];
constraint upper_rot_1_3[6] = upper_modadd_1_0[6];
constraint upper_rot_1_3[7] = upper_modadd_1_0[7];
constraint upper_rot_1_3[8] = upper_modadd_1_0[8];
constraint upper_rot_1_3[9] = upper_modadd_1_0[9];
constraint upper_rot_1_3[10] = upper_modadd_1_0[10];
constraint upper_rot_1_3[11] = upper_modadd_1_0[11];
constraint upper_rot_1_3[12] = upper_modadd_1_0[12];
constraint upper_rot_1_3[13] = upper_modadd_1_0[13];
constraint upper_rot_1_3[14] = upper_modadd_1_0[14];
constraint upper_rot_1_3[15] = upper_modadd_1_0[15];
constraint pre_upper_modadd_1_4_0[0] = upper_rot_0_13[0];
constraint pre_upper_modadd_1_4_0[1] = upper_rot_0_13[1];
constraint pre_upper_modadd_1_4_0[2] = upper_rot_0_13[2];
constraint pre_upper_modadd_1_4_0[3] = upper_rot_0_13[3];
constraint pre_upper_modadd_1_4_0[4] = upper_rot_0_13[4];
constraint pre_upper_modadd_1_4_0[5] = upper_rot_0_13[5];
constraint pre_upper_modadd_1_4_0[6] = upper_rot_0_13[6];
constraint pre_upper_modadd_1_4_0[7] = upper_rot_0_13[7];
constraint pre_upper_modadd_1_4_0[8] = upper_rot_0_13[8];
constraint pre_upper_modadd_1_4_0[9] = upper_rot_0_13[9];
constraint pre_upper_modadd_1_4_0[10] = upper_rot_0_13[10];
constraint pre_upper_modadd_1_4_0[11] = upper_rot_0_13[11];
constraint pre_upper_modadd_1_4_0[12] = upper_rot_0_13[12];
constraint pre_upper_modadd_1_4_0[13] = upper_rot_0_13[13];
constraint pre_upper_modadd_1_4_0[14] = upper_rot_0_13[14];
constraint pre_upper_modadd_1_4_0[15] = upper_rot_0_13[15];
constraint pre_upper_modadd_1_4_1[0] = upper_xor_0_9[0];
constraint pre_upper_modadd_1_4_1[1] = upper_xor_0_9[1];
constraint pre_upper_modadd_1_4_1[2] = upper_xor_0_9[2];
constraint pre_upper_modadd_1_4_1[3] = upper_xor_0_9[3];
constraint pre_upper_modadd_1_4_1[4] = upper_xor_0_9[4];
constraint pre_upper_modadd_1_4_1[5] = upper_xor_0_9[5];
constraint pre_upper_modadd_1_4_1[6] = upper_xor_0_9[6];
constraint pre_upper_modadd_1_4_1[7] = upper_xor_0_9[7];
constraint pre_upper_modadd_1_4_1[8] = upper_xor_0_9[8];
constraint pre_upper_modadd_1_4_1[9] = upper_xor_0_9[9];
constraint pre_upper_modadd_1_4_1[10] = upper_xor_0_9[10];
constraint pre_upper_modadd_1_4_1[11] = upper_xor_0_9[11];
constraint pre_upper_modadd_1_4_1[12] = upper_xor_0_9[12];
constraint pre_upper_modadd_1_4_1[13] = upper_xor_0_9[13];
constraint pre_upper_modadd_1_4_1[14] = upper_xor_0_9[14];
constraint pre_upper_modadd_1_4_1[15] = upper_xor_0_9[15];
constraint forall(j in 0..15)(if eq_upper_modadd_1_4[j] = 1 then (sum([pre_upper_modadd_1_4_1[j], pre_upper_modadd_1_4_0[j], upper_modadd_1_4[j]]) mod 2) = Shi_pre_upper_modadd_1_4_0[j] else true endif) /\ upper_p[5] = (16-sum(eq_upper_modadd_1_4))*100;
constraint upper_rot_1_5[0] = upper_xor_0_9[8];
constraint upper_rot_1_5[1] = upper_xor_0_9[9];
constraint upper_rot_1_5[2] = upper_xor_0_9[10];
constraint upper_rot_1_5[3] = upper_xor_0_9[11];
constraint upper_rot_1_5[4] = upper_xor_0_9[12];
constraint upper_rot_1_5[5] = upper_xor_0_9[13];
constraint upper_rot_1_5[6] = upper_xor_0_9[14];
constraint upper_rot_1_5[7] = upper_xor_0_9[15];
constraint upper_rot_1_5[8] = upper_xor_0_9[0];
constraint upper_rot_1_5[9] = upper_xor_0_9[1];
constraint upper_rot_1_5[10] = upper_xor_0_9[2];
constraint upper_rot_1_5[11] = upper_xor_0_9[3];
constraint upper_rot_1_5[12] = upper_xor_0_9[4];
constraint upper_rot_1_5[13] = upper_xor_0_9[5];
constraint upper_rot_1_5[14] = upper_xor_0_9[6];
constraint upper_rot_1_5[15] = upper_xor_0_9[7];
constraint 2*dummy_upper_xor_1_6[0] = (upper_rot_1_5[0] + upper_modadd_1_4[0] + upper_xor_1_6[0]);
constraint 2*dummy_upper_xor_1_6[1] = (upper_rot_1_5[1] + upper_modadd_1_4[1] + upper_xor_1_6[1]);
constraint 2*dummy_upper_xor_1_6[2] = (upper_rot_1_5[2] + upper_modadd_1_4[2] + upper_xor_1_6[2]);
constraint 2*dummy_upper_xor_1_6[3] = (upper_rot_1_5[3] + upper_modadd_1_4[3] + upper_xor_1_6[3]);
constraint 2*dummy_upper_xor_1_6[4] = (upper_rot_1_5[4] + upper_modadd_1_4[4] + upper_xor_1_6[4]);
constraint 2*dummy_upper_xor_1_6[5] = (upper_rot_1_5[5] + upper_modadd_1_4[5] + upper_xor_1_6[5]);
constraint 2*dummy_upper_xor_1_6[6] = (upper_rot_1_5[6] + upper_modadd_1_4[6] + upper_xor_1_6[6]);
constraint 2*dummy_upper_xor_1_6[7] = (upper_rot_1_5[7] + upper_modadd_1_4[7] + upper_xor_1_6[7]);
constraint 2*dummy_upper_xor_1_6[8] = (upper_rot_1_5[8] + upper_modadd_1_4[8] + upper_xor_1_6[8]);
constraint 2*dummy_upper_xor_1_6[9] = (upper_rot_1_5[9] + upper_modadd_1_4[9] + upper_xor_1_6[9]);
constraint 2*dummy_upper_xor_1_6[10] = (upper_rot_1_5[10] + upper_modadd_1_4[10] + upper_xor_1_6[10]);
constraint 2*dummy_upper_xor_1_6[11] = (upper_rot_1_5[11] + upper_modadd_1_4[11] + upper_xor_1_6[11]);
constraint 2*dummy_upper_xor_1_6[12] = (upper_rot_1_5[12] + upper_modadd_1_4[12] + upper_xor_1_6[12]);
constraint 2*dummy_upper_xor_1_6[13] = (upper_rot_1_5[13] + upper_modadd_1_4[13] + upper_xor_1_6[13]);
constraint 2*dummy_upper_xor_1_6[14] = (upper_rot_1_5[14] + upper_modadd_1_4[14] + upper_xor_1_6[14]);
constraint 2*dummy_upper_xor_1_6[15] = (upper_rot_1_5[15] + upper_modadd_1_4[15] + upper_xor_1_6[15]);
constraint pre_upper_modadd_1_7_0[0] = upper_rot_1_3[0];
constraint pre_upper_modadd_1_7_0[1] = upper_rot_1_3[1];
constraint pre_upper_modadd_1_7_0[2] = upper_rot_1_3[2];
constraint pre_upper_modadd_1_7_0[3] = upper_rot_1_3[3];
constraint pre_upper_modadd_1_7_0[4] = upper_rot_1_3[4];
constraint pre_upper_modadd_1_7_0[5] = upper_rot_1_3[5];
constraint pre_upper_modadd_1_7_0[6] = upper_rot_1_3[6];
constraint pre_upper_modadd_1_7_0[7] = upper_rot_1_3[7];
constraint pre_upper_modadd_1_7_0[8] = upper_rot_1_3[8];
constraint pre_upper_modadd_1_7_0[9] = upper_rot_1_3[9];
constraint pre_upper_modadd_1_7_0[10] = upper_rot_1_3[10];
constraint pre_upper_modadd_1_7_0[11] = upper_rot_1_3[11];
constraint pre_upper_modadd_1_7_0[12] = upper_rot_1_3[12];
constraint pre_upper_modadd_1_7_0[13] = upper_rot_1_3[13];
constraint pre_upper_modadd_1_7_0[14] = upper_rot_1_3[14];
constraint pre_upper_modadd_1_7_0[15] = upper_rot_1_3[15];
constraint pre_upper_modadd_1_7_1[0] = upper_xor_1_6[0];
constraint pre_upper_modadd_1_7_1[1] = upper_xor_1_6[1];
constraint pre_upper_modadd_1_7_1[2] = upper_xor_1_6[2];
constraint pre_upper_modadd_1_7_1[3] = upper_xor_1_6[3];
constraint pre_upper_modadd_1_7_1[4] = upper_xor_1_6[4];
constraint pre_upper_modadd_1_7_1[5] = upper_xor_1_6[5];
constraint pre_upper_modadd_1_7_1[6] = upper_xor_1_6[6];
constraint pre_upper_modadd_1_7_1[7] = upper_xor_1_6[7];
constraint pre_upper_modadd_1_7_1[8] = upper_xor_1_6[8];
constraint pre_upper_modadd_1_7_1[9] = upper_xor_1_6[9];
constraint pre_upper_modadd_1_7_1[10] = upper_xor_1_6[10];
constraint pre_upper_modadd_1_7_1[11] = upper_xor_1_6[11];
constraint pre_upper_modadd_1_7_1[12] = upper_xor_1_6[12];
constraint pre_upper_modadd_1_7_1[13] = upper_xor_1_6[13];
constraint pre_upper_modadd_1_7_1[14] = upper_xor_1_6[14];
constraint pre_upper_modadd_1_7_1[15] = upper_xor_1_6[15];
constraint forall(j in 0..15)(if eq_upper_modadd_1_7[j] = 1 then (sum([pre_upper_modadd_1_7_1[j], pre_upper_modadd_1_7_0[j], upper_modadd_1_7[j]]) mod 2) = Shi_pre_upper_modadd_1_7_0[j] else true endif) /\ upper_p[6] = (16-sum(eq_upper_modadd_1_7))*100;
constraint upper_rot_1_8[0] = upper_xor_1_6[13];
constraint upper_rot_1_8[1] = upper_xor_1_6[14];
constraint upper_rot_1_8[2] = upper_xor_1_6[15];
constraint upper_rot_1_8[3] = upper_xor_1_6[0];
constraint upper_rot_1_8[4] = upper_xor_1_6[1];
constraint upper_rot_1_8[5] = upper_xor_1_6[2];
constraint upper_rot_1_8[6] = upper_xor_1_6[3];
constraint upper_rot_1_8[7] = upper_xor_1_6[4];
constraint upper_rot_1_8[8] = upper_xor_1_6[5];
constraint upper_rot_1_8[9] = upper_xor_1_6[6];
constraint upper_rot_1_8[10] = upper_xor_1_6[7];
constraint upper_rot_1_8[11] = upper_xor_1_6[8];
constraint upper_rot_1_8[12] = upper_xor_1_6[9];
constraint upper_rot_1_8[13] = upper_xor_1_6[10];
constraint upper_rot_1_8[14] = upper_xor_1_6[11];
constraint upper_rot_1_8[15] = upper_xor_1_6[12];
constraint 2*dummy_upper_xor_1_9[0] = (upper_rot_1_8[0] + upper_modadd_1_7[0] + upper_xor_1_9[0]);
constraint 2*dummy_upper_xor_1_9[1] = (upper_rot_1_8[1] + upper_modadd_1_7[1] + upper_xor_1_9[1]);
constraint 2*dummy_upper_xor_1_9[2] = (upper_rot_1_8[2] + upper_modadd_1_7[2] + upper_xor_1_9[2]);
constraint 2*dummy_upper_xor_1_9[3] = (upper_rot_1_8[3] + upper_modadd_1_7[3] + upper_xor_1_9[3]);
constraint 2*dummy_upper_xor_1_9[4] = (upper_rot_1_8[4] + upper_modadd_1_7[4] + upper_xor_1_9[4]);
constraint 2*dummy_upper_xor_1_9[5] = (upper_rot_1_8[5] + upper_modadd_1_7[5] + upper_xor_1_9[5]);
constraint 2*dummy_upper_xor_1_9[6] = (upper_rot_1_8[6] + upper_modadd_1_7[6] + upper_xor_1_9[6]);
constraint 2*dummy_upper_xor_1_9[7] = (upper_rot_1_8[7] + upper_modadd_1_7[7] + upper_xor_1_9[7]);
constraint 2*dummy_upper_xor_1_9[8] = (upper_rot_1_8[8] + upper_modadd_1_7[8] + upper_xor_1_9[8]);
constraint 2*dummy_upper_xor_1_9[9] = (upper_rot_1_8[9] + upper_modadd_1_7[9] + upper_xor_1_9[9]);
constraint 2*dummy_upper_xor_1_9[10] = (upper_rot_1_8[10] + upper_modadd_1_7[10] + upper_xor_1_9[10]);
constraint 2*dummy_upper_xor_1_9[11] = (upper_rot_1_8[11] + upper_modadd_1_7[11] + upper_xor_1_9[11]);
constraint 2*dummy_upper_xor_1_9[12] = (upper_rot_1_8[12] + upper_modadd_1_7[12] + upper_xor_1_9[12]);
constraint 2*dummy_upper_xor_1_9[13] = (upper_rot_1_8[13] + upper_modadd_1_7[13] + upper_xor_1_9[13]);
constraint 2*dummy_upper_xor_1_9[14] = (upper_rot_1_8[14] + upper_modadd_1_7[14] + upper_xor_1_9[14]);
constraint 2*dummy_upper_xor_1_9[15] = (upper_rot_1_8[15] + upper_modadd_1_7[15] + upper_xor_1_9[15]);
constraint pre_upper_modadd_1_10_0[0] = upper_modadd_1_4[0];
constraint pre_upper_modadd_1_10_0[1] = upper_modadd_1_4[1];
constraint pre_upper_modadd_1_10_0[2] = upper_modadd_1_4[2];
constraint pre_upper_modadd_1_10_0[3] = upper_modadd_1_4[3];
constraint pre_upper_modadd_1_10_0[4] = upper_modadd_1_4[4];
constraint pre_upper_modadd_1_10_0[5] = upper_modadd_1_4[5];
constraint pre_upper_modadd_1_10_0[6] = upper_modadd_1_4[6];
constraint pre_upper_modadd_1_10_0[7] = upper_modadd_1_4[7];
constraint pre_upper_modadd_1_10_0[8] = upper_modadd_1_4[8];
constraint pre_upper_modadd_1_10_0[9] = upper_modadd_1_4[9];
constraint pre_upper_modadd_1_10_0[10] = upper_modadd_1_4[10];
constraint pre_upper_modadd_1_10_0[11] = upper_modadd_1_4[11];
constraint pre_upper_modadd_1_10_0[12] = upper_modadd_1_4[12];
constraint pre_upper_modadd_1_10_0[13] = upper_modadd_1_4[13];
constraint pre_upper_modadd_1_10_0[14] = upper_modadd_1_4[14];
constraint pre_upper_modadd_1_10_0[15] = upper_modadd_1_4[15];
constraint pre_upper_modadd_1_10_1[0] = upper_xor_1_2[0];
constraint pre_upper_modadd_1_10_1[1] = upper_xor_1_2[1];
constraint pre_upper_modadd_1_10_1[2] = upper_xor_1_2[2];
constraint pre_upper_modadd_1_10_1[3] = upper_xor_1_2[3];
constraint pre_upper_modadd_1_10_1[4] = upper_xor_1_2[4];
constraint pre_upper_modadd_1_10_1[5] = upper_xor_1_2[5];
constraint pre_upper_modadd_1_10_1[6] = upper_xor_1_2[6];
constraint pre_upper_modadd_1_10_1[7] = upper_xor_1_2[7];
constraint pre_upper_modadd_1_10_1[8] = upper_xor_1_2[8];
constraint pre_upper_modadd_1_10_1[9] = upper_xor_1_2[9];
constraint pre_upper_modadd_1_10_1[10] = upper_xor_1_2[10];
constraint pre_upper_modadd_1_10_1[11] = upper_xor_1_2[11];
constraint pre_upper_modadd_1_10_1[12] = upper_xor_1_2[12];
constraint pre_upper_modadd_1_10_1[13] = upper_xor_1_2[13];
constraint pre_upper_modadd_1_10_1[14] = upper_xor_1_2[14];
constraint pre_upper_modadd_1_10_1[15] = upper_xor_1_2[15];
constraint forall(j in 0..15)(if eq_upper_modadd_1_10[j] = 1 then (sum([pre_upper_modadd_1_10_1[j], pre_upper_modadd_1_10_0[j], upper_modadd_1_10[j]]) mod 2) = Shi_pre_upper_modadd_1_10_0[j] else true endif) /\ upper_p[7] = (16-sum(eq_upper_modadd_1_10))*100;
constraint upper_rot_1_11[0] = upper_xor_1_2[7];
constraint upper_rot_1_11[1] = upper_xor_1_2[8];
constraint upper_rot_1_11[2] = upper_xor_1_2[9];
constraint upper_rot_1_11[3] = upper_xor_1_2[10];
constraint upper_rot_1_11[4] = upper_xor_1_2[11];
constraint upper_rot_1_11[5] = upper_xor_1_2[12];
constraint upper_rot_1_11[6] = upper_xor_1_2[13];
constraint upper_rot_1_11[7] = upper_xor_1_2[14];
constraint upper_rot_1_11[8] = upper_xor_1_2[15];
constraint upper_rot_1_11[9] = upper_xor_1_2[0];
constraint upper_rot_1_11[10] = upper_xor_1_2[1];
constraint upper_rot_1_11[11] = upper_xor_1_2[2];
constraint upper_rot_1_11[12] = upper_xor_1_2[3];
constraint upper_rot_1_11[13] = upper_xor_1_2[4];
constraint upper_rot_1_11[14] = upper_xor_1_2[5];
constraint upper_rot_1_11[15] = upper_xor_1_2[6];
constraint 2*dummy_upper_xor_1_12[0] = (upper_rot_1_11[0] + upper_modadd_1_10[0] + upper_xor_1_12[0]);
constraint 2*dummy_upper_xor_1_12[1] = (upper_rot_1_11[1] + upper_modadd_1_10[1] + upper_xor_1_12[1]);
constraint 2*dummy_upper_xor_1_12[2] = (upper_rot_1_11[2] + upper_modadd_1_10[2] + upper_xor_1_12[2]);
constraint 2*dummy_upper_xor_1_12[3] = (upper_rot_1_11[3] + upper_modadd_1_10[3] + upper_xor_1_12[3]);
constraint 2*dummy_upper_xor_1_12[4] = (upper_rot_1_11[4] + upper_modadd_1_10[4] + upper_xor_1_12[4]);
constraint 2*dummy_upper_xor_1_12[5] = (upper_rot_1_11[5] + upper_modadd_1_10[5] + upper_xor_1_12[5]);
constraint 2*dummy_upper_xor_1_12[6] = (upper_rot_1_11[6] + upper_modadd_1_10[6] + upper_xor_1_12[6]);
constraint 2*dummy_upper_xor_1_12[7] = (upper_rot_1_11[7] + upper_modadd_1_10[7] + upper_xor_1_12[7]);
constraint 2*dummy_upper_xor_1_12[8] = (upper_rot_1_11[8] + upper_modadd_1_10[8] + upper_xor_1_12[8]);
constraint 2*dummy_upper_xor_1_12[9] = (upper_rot_1_11[9] + upper_modadd_1_10[9] + upper_xor_1_12[9]);
constraint 2*dummy_upper_xor_1_12[10] = (upper_rot_1_11[10] + upper_modadd_1_10[10] + upper_xor_1_12[10]);
constraint 2*dummy_upper_xor_1_12[11] = (upper_rot_1_11[11] + upper_modadd_1_10[11] + upper_xor_1_12[11]);
constraint 2*dummy_upper_xor_1_12[12] = (upper_rot_1_11[12] + upper_modadd_1_10[12] + upper_xor_1_12[12]);
constraint 2*dummy_upper_xor_1_12[13] = (upper_rot_1_11[13] + upper_modadd_1_10[13] + upper_xor_1_12[13]);
constraint 2*dummy_upper_xor_1_12[14] = (upper_rot_1_11[14] + upper_modadd_1_10[14] + upper_xor_1_12[14]);
constraint 2*dummy_upper_xor_1_12[15] = (upper_rot_1_11[15] + upper_modadd_1_10[15] + upper_xor_1_12[15]);
constraint upper_rot_1_13[0] = upper_modadd_1_10[0];
constraint upper_rot_1_13[1] = upper_modadd_1_10[1];
constraint upper_rot_1_13[2] = upper_modadd_1_10[2];
constraint upper_rot_1_13[3] = upper_modadd_1_10[3];
constraint upper_rot_1_13[4] = upper_modadd_1_10[4];
constraint upper_rot_1_13[5] = upper_modadd_1_10[5];
constraint upper_rot_1_13[6] = upper_modadd_1_10[6];
constraint upper_rot_1_13[7] = upper_modadd_1_10[7];
constraint upper_rot_1_13[8] = upper_modadd_1_10[8];
constraint upper_rot_1_13[9] = upper_modadd_1_10[9];
constraint upper_rot_1_13[10] = upper_modadd_1_10[10];
constraint upper_rot_1_13[11] = upper_modadd_1_10[11];
constraint upper_rot_1_13[12] = upper_modadd_1_10[12];
constraint upper_rot_1_13[13] = upper_modadd_1_10[13];
constraint upper_rot_1_13[14] = upper_modadd_1_10[14];
constraint upper_rot_1_13[15] = upper_modadd_1_10[15];
constraint upper_intermediate_output_1_14[0] = upper_modadd_1_7[0];
constraint upper_intermediate_output_1_14[1] = upper_modadd_1_7[1];
constraint upper_intermediate_output_1_14[2] = upper_modadd_1_7[2];
constraint upper_intermediate_output_1_14[3] = upper_modadd_1_7[3];
constraint upper_intermediate_output_1_14[4] = upper_modadd_1_7[4];
constraint upper_intermediate_output_1_14[5] = upper_modadd_1_7[5];
constraint upper_intermediate_output_1_14[6] = upper_modadd_1_7[6];
constraint upper_intermediate_output_1_14[7] = upper_modadd_1_7[7];
constraint upper_intermediate_output_1_14[8] = upper_modadd_1_7[8];
constraint upper_intermediate_output_1_14[9] = upper_modadd_1_7[9];
constraint upper_intermediate_output_1_14[10] = upper_modadd_1_7[10];
constraint upper_intermediate_output_1_14[11] = upper_modadd_1_7[11];
constraint upper_intermediate_output_1_14[12] = upper_modadd_1_7[12];
constraint upper_intermediate_output_1_14[13] = upper_modadd_1_7[13];
constraint upper_intermediate_output_1_14[14] = upper_modadd_1_7[14];
constraint upper_intermediate_output_1_14[15] = upper_modadd_1_7[15];
constraint upper_intermediate_output_1_14[16] = upper_xor_1_12[0];
constraint upper_intermediate_output_1_14[17] = upper_xor_1_12[1];
constraint upper_intermediate_output_1_14[18] = upper_xor_1_12[2];
constraint upper_intermediate_output_1_14[19] = upper_xor_1_12[3];
constraint upper_intermediate_output_1_14[20] = upper_xor_1_12[4];
constraint upper_intermediate_output_1_14[21] = upper_xor_1_12[5];
constraint upper_intermediate_output_1_14[22] = upper_xor_1_12[6];
constraint upper_intermediate_output_1_14[23] = upper_xor_1_12[7];
constraint upper_intermediate_output_1_14[24] = upper_xor_1_12[8];
constraint upper_intermediate_output_1_14[25] = upper_xor_1_12[9];
constraint upper_intermediate_output_1_14[26] = upper_xor_1_12[10];
constraint upper_intermediate_output_1_14[27] = upper_xor_1_12[11];
constraint upper_intermediate_output_1_14[28] = upper_xor_1_12[12];
constraint upper_intermediate_output_1_14[29] = upper_xor_1_12[13];
constraint upper_intermediate_output_1_14[30] = upper_xor_1_12[14];
constraint upper_intermediate_output_1_14[31] = upper_xor_1_12[15];
constraint upper_intermediate_output_1_14[32] = upper_rot_1_13[0];
constraint upper_intermediate_output_1_14[33] = upper_rot_1_13[1];
constraint upper_intermediate_output_1_14[34] = upper_rot_1_13[2];
constraint upper_intermediate_output_1_14[35] = upper_rot_1_13[3];
constraint upper_intermediate_output_1_14[36] = upper_rot_1_13[4];
constraint upper_intermediate_output_1_14[37] = upper_rot_1_13[5];
constraint upper_intermediate_output_1_14[38] = upper_rot_1_13[6];
constraint upper_intermediate_output_1_14[39] = upper_rot_1_13[7];
constraint upper_intermediate_output_1_14[40] = upper_rot_1_13[8];
constraint upper_intermediate_output_1_14[41] = upper_rot_1_13[9];
constraint upper_intermediate_output_1_14[42] = upper_rot_1_13[10];
constraint upper_intermediate_output_1_14[43] = upper_rot_1_13[11];
constraint upper_intermediate_output_1_14[44] = upper_rot_1_13[12];
constraint upper_intermediate_output_1_14[45] = upper_rot_1_13[13];
constraint upper_intermediate_output_1_14[46] = upper_rot_1_13[14];
constraint upper_intermediate_output_1_14[47] = upper_rot_1_13[15];
constraint upper_intermediate_output_1_14[48] = upper_xor_1_9[0];
constraint upper_intermediate_output_1_14[49] = upper_xor_1_9[1];
constraint upper_intermediate_output_1_14[50] = upper_xor_1_9[2];
constraint upper_intermediate_output_1_14[51] = upper_xor_1_9[3];
constraint upper_intermediate_output_1_14[52] = upper_xor_1_9[4];
constraint upper_intermediate_output_1_14[53] = upper_xor_1_9[5];
constraint upper_intermediate_output_1_14[54] = upper_xor_1_9[6];
constraint upper_intermediate_output_1_14[55] = upper_xor_1_9[7];
constraint upper_intermediate_output_1_14[56] = upper_xor_1_9[8];
constraint upper_intermediate_output_1_14[57] = upper_xor_1_9[9];
constraint upper_intermediate_output_1_14[58] = upper_xor_1_9[10];
constraint upper_intermediate_output_1_14[59] = upper_xor_1_9[11];
constraint upper_intermediate_output_1_14[60] = upper_xor_1_9[12];
constraint upper_intermediate_output_1_14[61] = upper_xor_1_9[13];
constraint upper_intermediate_output_1_14[62] = upper_xor_1_9[14];
constraint upper_intermediate_output_1_14[63] = upper_xor_1_9[15];
constraint pre_upper_modadd_2_0_0[0] = upper_modadd_1_7[0];
constraint pre_upper_modadd_2_0_0[1] = upper_modadd_1_7[1];
constraint pre_upper_modadd_2_0_0[2] = upper_modadd_1_7[2];
constraint pre_upper_modadd_2_0_0[3] = upper_modadd_1_7[3];
constraint pre_upper_modadd_2_0_0[4] = upper_modadd_1_7[4];
constraint pre_upper_modadd_2_0_0[5] = upper_modadd_1_7[5];
constraint pre_upper_modadd_2_0_0[6] = upper_modadd_1_7[6];
constraint pre_upper_modadd_2_0_0[7] = upper_modadd_1_7[7];
constraint pre_upper_modadd_2_0_0[8] = upper_modadd_1_7[8];
constraint pre_upper_modadd_2_0_0[9] = upper_modadd_1_7[9];
constraint pre_upper_modadd_2_0_0[10] = upper_modadd_1_7[10];
constraint pre_upper_modadd_2_0_0[11] = upper_modadd_1_7[11];
constraint pre_upper_modadd_2_0_0[12] = upper_modadd_1_7[12];
constraint pre_upper_modadd_2_0_0[13] = upper_modadd_1_7[13];
constraint pre_upper_modadd_2_0_0[14] = upper_modadd_1_7[14];
constraint pre_upper_modadd_2_0_0[15] = upper_modadd_1_7[15];
constraint pre_upper_modadd_2_0_1[0] = upper_xor_1_12[0];
constraint pre_upper_modadd_2_0_1[1] = upper_xor_1_12[1];
constraint pre_upper_modadd_2_0_1[2] = upper_xor_1_12[2];
constraint pre_upper_modadd_2_0_1[3] = upper_xor_1_12[3];
constraint pre_upper_modadd_2_0_1[4] = upper_xor_1_12[4];
constraint pre_upper_modadd_2_0_1[5] = upper_xor_1_12[5];
constraint pre_upper_modadd_2_0_1[6] = upper_xor_1_12[6];
constraint pre_upper_modadd_2_0_1[7] = upper_xor_1_12[7];
constraint pre_upper_modadd_2_0_1[8] = upper_xor_1_12[8];
constraint pre_upper_modadd_2_0_1[9] = upper_xor_1_12[9];
constraint pre_upper_modadd_2_0_1[10] = upper_xor_1_12[10];
constraint pre_upper_modadd_2_0_1[11] = upper_xor_1_12[11];
constraint pre_upper_modadd_2_0_1[12] = upper_xor_1_12[12];
constraint pre_upper_modadd_2_0_1[13] = upper_xor_1_12[13];
constraint pre_upper_modadd_2_0_1[14] = upper_xor_1_12[14];
constraint pre_upper_modadd_2_0_1[15] = upper_xor_1_12[15];
constraint forall(j in 0..15)(if eq_upper_modadd_2_0[j] = 1 then (sum([pre_upper_modadd_2_0_1[j], pre_upper_modadd_2_0_0[j], upper_modadd_2_0[j]]) mod 2) = Shi_pre_upper_modadd_2_0_0[j] else true endif) /\ upper_p[8] = (16-sum(eq_upper_modadd_2_0))*100;
constraint upper_rot_2_1[0] = upper_xor_1_12[5];
constraint upper_rot_2_1[1] = upper_xor_1_12[6];
constraint upper_rot_2_1[2] = upper_xor_1_12[7];
constraint upper_rot_2_1[3] = upper_xor_1_12[8];
constraint upper_rot_2_1[4] = upper_xor_1_12[9];
constraint upper_rot_2_1[5] = upper_xor_1_12[10];
constraint upper_rot_2_1[6] = upper_xor_1_12[11];
constraint upper_rot_2_1[7] = upper_xor_1_12[12];
constraint upper_rot_2_1[8] = upper_xor_1_12[13];
constraint upper_rot_2_1[9] = upper_xor_1_12[14];
constraint upper_rot_2_1[10] = upper_xor_1_12[15];
constraint upper_rot_2_1[11] = upper_xor_1_12[0];
constraint upper_rot_2_1[12] = upper_xor_1_12[1];
constraint upper_rot_2_1[13] = upper_xor_1_12[2];
constraint upper_rot_2_1[14] = upper_xor_1_12[3];
constraint upper_rot_2_1[15] = upper_xor_1_12[4];
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
constraint pre_upper_modadd_2_4_0[0] = upper_rot_1_13[0];
constraint pre_upper_modadd_2_4_0[1] = upper_rot_1_13[1];
constraint pre_upper_modadd_2_4_0[2] = upper_rot_1_13[2];
constraint pre_upper_modadd_2_4_0[3] = upper_rot_1_13[3];
constraint pre_upper_modadd_2_4_0[4] = upper_rot_1_13[4];
constraint pre_upper_modadd_2_4_0[5] = upper_rot_1_13[5];
constraint pre_upper_modadd_2_4_0[6] = upper_rot_1_13[6];
constraint pre_upper_modadd_2_4_0[7] = upper_rot_1_13[7];
constraint pre_upper_modadd_2_4_0[8] = upper_rot_1_13[8];
constraint pre_upper_modadd_2_4_0[9] = upper_rot_1_13[9];
constraint pre_upper_modadd_2_4_0[10] = upper_rot_1_13[10];
constraint pre_upper_modadd_2_4_0[11] = upper_rot_1_13[11];
constraint pre_upper_modadd_2_4_0[12] = upper_rot_1_13[12];
constraint pre_upper_modadd_2_4_0[13] = upper_rot_1_13[13];
constraint pre_upper_modadd_2_4_0[14] = upper_rot_1_13[14];
constraint pre_upper_modadd_2_4_0[15] = upper_rot_1_13[15];
constraint pre_upper_modadd_2_4_1[0] = upper_xor_1_9[0];
constraint pre_upper_modadd_2_4_1[1] = upper_xor_1_9[1];
constraint pre_upper_modadd_2_4_1[2] = upper_xor_1_9[2];
constraint pre_upper_modadd_2_4_1[3] = upper_xor_1_9[3];
constraint pre_upper_modadd_2_4_1[4] = upper_xor_1_9[4];
constraint pre_upper_modadd_2_4_1[5] = upper_xor_1_9[5];
constraint pre_upper_modadd_2_4_1[6] = upper_xor_1_9[6];
constraint pre_upper_modadd_2_4_1[7] = upper_xor_1_9[7];
constraint pre_upper_modadd_2_4_1[8] = upper_xor_1_9[8];
constraint pre_upper_modadd_2_4_1[9] = upper_xor_1_9[9];
constraint pre_upper_modadd_2_4_1[10] = upper_xor_1_9[10];
constraint pre_upper_modadd_2_4_1[11] = upper_xor_1_9[11];
constraint pre_upper_modadd_2_4_1[12] = upper_xor_1_9[12];
constraint pre_upper_modadd_2_4_1[13] = upper_xor_1_9[13];
constraint pre_upper_modadd_2_4_1[14] = upper_xor_1_9[14];
constraint pre_upper_modadd_2_4_1[15] = upper_xor_1_9[15];
constraint forall(j in 0..15)(if eq_upper_modadd_2_4[j] = 1 then (sum([pre_upper_modadd_2_4_1[j], pre_upper_modadd_2_4_0[j], upper_modadd_2_4[j]]) mod 2) = Shi_pre_upper_modadd_2_4_0[j] else true endif) /\ upper_p[9] = (16-sum(eq_upper_modadd_2_4))*100;
constraint upper_rot_2_5[0] = upper_xor_1_9[8];
constraint upper_rot_2_5[1] = upper_xor_1_9[9];
constraint upper_rot_2_5[2] = upper_xor_1_9[10];
constraint upper_rot_2_5[3] = upper_xor_1_9[11];
constraint upper_rot_2_5[4] = upper_xor_1_9[12];
constraint upper_rot_2_5[5] = upper_xor_1_9[13];
constraint upper_rot_2_5[6] = upper_xor_1_9[14];
constraint upper_rot_2_5[7] = upper_xor_1_9[15];
constraint upper_rot_2_5[8] = upper_xor_1_9[0];
constraint upper_rot_2_5[9] = upper_xor_1_9[1];
constraint upper_rot_2_5[10] = upper_xor_1_9[2];
constraint upper_rot_2_5[11] = upper_xor_1_9[3];
constraint upper_rot_2_5[12] = upper_xor_1_9[4];
constraint upper_rot_2_5[13] = upper_xor_1_9[5];
constraint upper_rot_2_5[14] = upper_xor_1_9[6];
constraint upper_rot_2_5[15] = upper_xor_1_9[7];
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
constraint pre_upper_modadd_2_7_0[0] = upper_rot_2_3[0];
constraint pre_upper_modadd_2_7_0[1] = upper_rot_2_3[1];
constraint pre_upper_modadd_2_7_0[2] = upper_rot_2_3[2];
constraint pre_upper_modadd_2_7_0[3] = upper_rot_2_3[3];
constraint pre_upper_modadd_2_7_0[4] = upper_rot_2_3[4];
constraint pre_upper_modadd_2_7_0[5] = upper_rot_2_3[5];
constraint pre_upper_modadd_2_7_0[6] = upper_rot_2_3[6];
constraint pre_upper_modadd_2_7_0[7] = upper_rot_2_3[7];
constraint pre_upper_modadd_2_7_0[8] = upper_rot_2_3[8];
constraint pre_upper_modadd_2_7_0[9] = upper_rot_2_3[9];
constraint pre_upper_modadd_2_7_0[10] = upper_rot_2_3[10];
constraint pre_upper_modadd_2_7_0[11] = upper_rot_2_3[11];
constraint pre_upper_modadd_2_7_0[12] = upper_rot_2_3[12];
constraint pre_upper_modadd_2_7_0[13] = upper_rot_2_3[13];
constraint pre_upper_modadd_2_7_0[14] = upper_rot_2_3[14];
constraint pre_upper_modadd_2_7_0[15] = upper_rot_2_3[15];
constraint pre_upper_modadd_2_7_1[0] = upper_xor_2_6[0];
constraint pre_upper_modadd_2_7_1[1] = upper_xor_2_6[1];
constraint pre_upper_modadd_2_7_1[2] = upper_xor_2_6[2];
constraint pre_upper_modadd_2_7_1[3] = upper_xor_2_6[3];
constraint pre_upper_modadd_2_7_1[4] = upper_xor_2_6[4];
constraint pre_upper_modadd_2_7_1[5] = upper_xor_2_6[5];
constraint pre_upper_modadd_2_7_1[6] = upper_xor_2_6[6];
constraint pre_upper_modadd_2_7_1[7] = upper_xor_2_6[7];
constraint pre_upper_modadd_2_7_1[8] = upper_xor_2_6[8];
constraint pre_upper_modadd_2_7_1[9] = upper_xor_2_6[9];
constraint pre_upper_modadd_2_7_1[10] = upper_xor_2_6[10];
constraint pre_upper_modadd_2_7_1[11] = upper_xor_2_6[11];
constraint pre_upper_modadd_2_7_1[12] = upper_xor_2_6[12];
constraint pre_upper_modadd_2_7_1[13] = upper_xor_2_6[13];
constraint pre_upper_modadd_2_7_1[14] = upper_xor_2_6[14];
constraint pre_upper_modadd_2_7_1[15] = upper_xor_2_6[15];
constraint forall(j in 0..15)(if eq_upper_modadd_2_7[j] = 1 then (sum([pre_upper_modadd_2_7_1[j], pre_upper_modadd_2_7_0[j], upper_modadd_2_7[j]]) mod 2) = Shi_pre_upper_modadd_2_7_0[j] else true endif) /\ upper_p[10] = (16-sum(eq_upper_modadd_2_7))*100;
constraint upper_rot_2_8[0] = upper_xor_2_6[13];
constraint upper_rot_2_8[1] = upper_xor_2_6[14];
constraint upper_rot_2_8[2] = upper_xor_2_6[15];
constraint upper_rot_2_8[3] = upper_xor_2_6[0];
constraint upper_rot_2_8[4] = upper_xor_2_6[1];
constraint upper_rot_2_8[5] = upper_xor_2_6[2];
constraint upper_rot_2_8[6] = upper_xor_2_6[3];
constraint upper_rot_2_8[7] = upper_xor_2_6[4];
constraint upper_rot_2_8[8] = upper_xor_2_6[5];
constraint upper_rot_2_8[9] = upper_xor_2_6[6];
constraint upper_rot_2_8[10] = upper_xor_2_6[7];
constraint upper_rot_2_8[11] = upper_xor_2_6[8];
constraint upper_rot_2_8[12] = upper_xor_2_6[9];
constraint upper_rot_2_8[13] = upper_xor_2_6[10];
constraint upper_rot_2_8[14] = upper_xor_2_6[11];
constraint upper_rot_2_8[15] = upper_xor_2_6[12];
constraint 2*dummy_upper_xor_2_9[0] = (upper_rot_2_8[0] + upper_modadd_2_7[0] + upper_xor_2_9[0]);
constraint 2*dummy_upper_xor_2_9[1] = (upper_rot_2_8[1] + upper_modadd_2_7[1] + upper_xor_2_9[1]);
constraint 2*dummy_upper_xor_2_9[2] = (upper_rot_2_8[2] + upper_modadd_2_7[2] + upper_xor_2_9[2]);
constraint 2*dummy_upper_xor_2_9[3] = (upper_rot_2_8[3] + upper_modadd_2_7[3] + upper_xor_2_9[3]);
constraint 2*dummy_upper_xor_2_9[4] = (upper_rot_2_8[4] + upper_modadd_2_7[4] + upper_xor_2_9[4]);
constraint 2*dummy_upper_xor_2_9[5] = (upper_rot_2_8[5] + upper_modadd_2_7[5] + upper_xor_2_9[5]);
constraint 2*dummy_upper_xor_2_9[6] = (upper_rot_2_8[6] + upper_modadd_2_7[6] + upper_xor_2_9[6]);
constraint 2*dummy_upper_xor_2_9[7] = (upper_rot_2_8[7] + upper_modadd_2_7[7] + upper_xor_2_9[7]);
constraint 2*dummy_upper_xor_2_9[8] = (upper_rot_2_8[8] + upper_modadd_2_7[8] + upper_xor_2_9[8]);
constraint 2*dummy_upper_xor_2_9[9] = (upper_rot_2_8[9] + upper_modadd_2_7[9] + upper_xor_2_9[9]);
constraint 2*dummy_upper_xor_2_9[10] = (upper_rot_2_8[10] + upper_modadd_2_7[10] + upper_xor_2_9[10]);
constraint 2*dummy_upper_xor_2_9[11] = (upper_rot_2_8[11] + upper_modadd_2_7[11] + upper_xor_2_9[11]);
constraint 2*dummy_upper_xor_2_9[12] = (upper_rot_2_8[12] + upper_modadd_2_7[12] + upper_xor_2_9[12]);
constraint 2*dummy_upper_xor_2_9[13] = (upper_rot_2_8[13] + upper_modadd_2_7[13] + upper_xor_2_9[13]);
constraint 2*dummy_upper_xor_2_9[14] = (upper_rot_2_8[14] + upper_modadd_2_7[14] + upper_xor_2_9[14]);
constraint 2*dummy_upper_xor_2_9[15] = (upper_rot_2_8[15] + upper_modadd_2_7[15] + upper_xor_2_9[15]);
constraint pre_upper_modadd_2_10_0[0] = upper_modadd_2_4[0];
constraint pre_upper_modadd_2_10_0[1] = upper_modadd_2_4[1];
constraint pre_upper_modadd_2_10_0[2] = upper_modadd_2_4[2];
constraint pre_upper_modadd_2_10_0[3] = upper_modadd_2_4[3];
constraint pre_upper_modadd_2_10_0[4] = upper_modadd_2_4[4];
constraint pre_upper_modadd_2_10_0[5] = upper_modadd_2_4[5];
constraint pre_upper_modadd_2_10_0[6] = upper_modadd_2_4[6];
constraint pre_upper_modadd_2_10_0[7] = upper_modadd_2_4[7];
constraint pre_upper_modadd_2_10_0[8] = upper_modadd_2_4[8];
constraint pre_upper_modadd_2_10_0[9] = upper_modadd_2_4[9];
constraint pre_upper_modadd_2_10_0[10] = upper_modadd_2_4[10];
constraint pre_upper_modadd_2_10_0[11] = upper_modadd_2_4[11];
constraint pre_upper_modadd_2_10_0[12] = upper_modadd_2_4[12];
constraint pre_upper_modadd_2_10_0[13] = upper_modadd_2_4[13];
constraint pre_upper_modadd_2_10_0[14] = upper_modadd_2_4[14];
constraint pre_upper_modadd_2_10_0[15] = upper_modadd_2_4[15];
constraint pre_upper_modadd_2_10_1[0] = upper_xor_2_2[0];
constraint pre_upper_modadd_2_10_1[1] = upper_xor_2_2[1];
constraint pre_upper_modadd_2_10_1[2] = upper_xor_2_2[2];
constraint pre_upper_modadd_2_10_1[3] = upper_xor_2_2[3];
constraint pre_upper_modadd_2_10_1[4] = upper_xor_2_2[4];
constraint pre_upper_modadd_2_10_1[5] = upper_xor_2_2[5];
constraint pre_upper_modadd_2_10_1[6] = upper_xor_2_2[6];
constraint pre_upper_modadd_2_10_1[7] = upper_xor_2_2[7];
constraint pre_upper_modadd_2_10_1[8] = upper_xor_2_2[8];
constraint pre_upper_modadd_2_10_1[9] = upper_xor_2_2[9];
constraint pre_upper_modadd_2_10_1[10] = upper_xor_2_2[10];
constraint pre_upper_modadd_2_10_1[11] = upper_xor_2_2[11];
constraint pre_upper_modadd_2_10_1[12] = upper_xor_2_2[12];
constraint pre_upper_modadd_2_10_1[13] = upper_xor_2_2[13];
constraint pre_upper_modadd_2_10_1[14] = upper_xor_2_2[14];
constraint pre_upper_modadd_2_10_1[15] = upper_xor_2_2[15];
constraint forall(j in 0..15)(if eq_upper_modadd_2_10[j] = 1 then (sum([pre_upper_modadd_2_10_1[j], pre_upper_modadd_2_10_0[j], upper_modadd_2_10[j]]) mod 2) = Shi_pre_upper_modadd_2_10_0[j] else true endif) /\ upper_p[11] = (16-sum(eq_upper_modadd_2_10))*100;
constraint upper_rot_2_11[0] = upper_xor_2_2[7];
constraint upper_rot_2_11[1] = upper_xor_2_2[8];
constraint upper_rot_2_11[2] = upper_xor_2_2[9];
constraint upper_rot_2_11[3] = upper_xor_2_2[10];
constraint upper_rot_2_11[4] = upper_xor_2_2[11];
constraint upper_rot_2_11[5] = upper_xor_2_2[12];
constraint upper_rot_2_11[6] = upper_xor_2_2[13];
constraint upper_rot_2_11[7] = upper_xor_2_2[14];
constraint upper_rot_2_11[8] = upper_xor_2_2[15];
constraint upper_rot_2_11[9] = upper_xor_2_2[0];
constraint upper_rot_2_11[10] = upper_xor_2_2[1];
constraint upper_rot_2_11[11] = upper_xor_2_2[2];
constraint upper_rot_2_11[12] = upper_xor_2_2[3];
constraint upper_rot_2_11[13] = upper_xor_2_2[4];
constraint upper_rot_2_11[14] = upper_xor_2_2[5];
constraint upper_rot_2_11[15] = upper_xor_2_2[6];
constraint 2*dummy_upper_xor_2_12[0] = (upper_rot_2_11[0] + upper_modadd_2_10[0] + upper_xor_2_12[0]);
constraint 2*dummy_upper_xor_2_12[1] = (upper_rot_2_11[1] + upper_modadd_2_10[1] + upper_xor_2_12[1]);
constraint 2*dummy_upper_xor_2_12[2] = (upper_rot_2_11[2] + upper_modadd_2_10[2] + upper_xor_2_12[2]);
constraint 2*dummy_upper_xor_2_12[3] = (upper_rot_2_11[3] + upper_modadd_2_10[3] + upper_xor_2_12[3]);
constraint 2*dummy_upper_xor_2_12[4] = (upper_rot_2_11[4] + upper_modadd_2_10[4] + upper_xor_2_12[4]);
constraint 2*dummy_upper_xor_2_12[5] = (upper_rot_2_11[5] + upper_modadd_2_10[5] + upper_xor_2_12[5]);
constraint 2*dummy_upper_xor_2_12[6] = (upper_rot_2_11[6] + upper_modadd_2_10[6] + upper_xor_2_12[6]);
constraint 2*dummy_upper_xor_2_12[7] = (upper_rot_2_11[7] + upper_modadd_2_10[7] + upper_xor_2_12[7]);
constraint 2*dummy_upper_xor_2_12[8] = (upper_rot_2_11[8] + upper_modadd_2_10[8] + upper_xor_2_12[8]);
constraint 2*dummy_upper_xor_2_12[9] = (upper_rot_2_11[9] + upper_modadd_2_10[9] + upper_xor_2_12[9]);
constraint 2*dummy_upper_xor_2_12[10] = (upper_rot_2_11[10] + upper_modadd_2_10[10] + upper_xor_2_12[10]);
constraint 2*dummy_upper_xor_2_12[11] = (upper_rot_2_11[11] + upper_modadd_2_10[11] + upper_xor_2_12[11]);
constraint 2*dummy_upper_xor_2_12[12] = (upper_rot_2_11[12] + upper_modadd_2_10[12] + upper_xor_2_12[12]);
constraint 2*dummy_upper_xor_2_12[13] = (upper_rot_2_11[13] + upper_modadd_2_10[13] + upper_xor_2_12[13]);
constraint 2*dummy_upper_xor_2_12[14] = (upper_rot_2_11[14] + upper_modadd_2_10[14] + upper_xor_2_12[14]);
constraint 2*dummy_upper_xor_2_12[15] = (upper_rot_2_11[15] + upper_modadd_2_10[15] + upper_xor_2_12[15]);
constraint upper_rot_2_13[0] = upper_modadd_2_10[0];
constraint upper_rot_2_13[1] = upper_modadd_2_10[1];
constraint upper_rot_2_13[2] = upper_modadd_2_10[2];
constraint upper_rot_2_13[3] = upper_modadd_2_10[3];
constraint upper_rot_2_13[4] = upper_modadd_2_10[4];
constraint upper_rot_2_13[5] = upper_modadd_2_10[5];
constraint upper_rot_2_13[6] = upper_modadd_2_10[6];
constraint upper_rot_2_13[7] = upper_modadd_2_10[7];
constraint upper_rot_2_13[8] = upper_modadd_2_10[8];
constraint upper_rot_2_13[9] = upper_modadd_2_10[9];
constraint upper_rot_2_13[10] = upper_modadd_2_10[10];
constraint upper_rot_2_13[11] = upper_modadd_2_10[11];
constraint upper_rot_2_13[12] = upper_modadd_2_10[12];
constraint upper_rot_2_13[13] = upper_modadd_2_10[13];
constraint upper_rot_2_13[14] = upper_modadd_2_10[14];
constraint upper_rot_2_13[15] = upper_modadd_2_10[15];
constraint upper_intermediate_output_2_14[0] = upper_modadd_2_7[0];
constraint upper_intermediate_output_2_14[1] = upper_modadd_2_7[1];
constraint upper_intermediate_output_2_14[2] = upper_modadd_2_7[2];
constraint upper_intermediate_output_2_14[3] = upper_modadd_2_7[3];
constraint upper_intermediate_output_2_14[4] = upper_modadd_2_7[4];
constraint upper_intermediate_output_2_14[5] = upper_modadd_2_7[5];
constraint upper_intermediate_output_2_14[6] = upper_modadd_2_7[6];
constraint upper_intermediate_output_2_14[7] = upper_modadd_2_7[7];
constraint upper_intermediate_output_2_14[8] = upper_modadd_2_7[8];
constraint upper_intermediate_output_2_14[9] = upper_modadd_2_7[9];
constraint upper_intermediate_output_2_14[10] = upper_modadd_2_7[10];
constraint upper_intermediate_output_2_14[11] = upper_modadd_2_7[11];
constraint upper_intermediate_output_2_14[12] = upper_modadd_2_7[12];
constraint upper_intermediate_output_2_14[13] = upper_modadd_2_7[13];
constraint upper_intermediate_output_2_14[14] = upper_modadd_2_7[14];
constraint upper_intermediate_output_2_14[15] = upper_modadd_2_7[15];
constraint upper_intermediate_output_2_14[16] = upper_xor_2_12[0];
constraint upper_intermediate_output_2_14[17] = upper_xor_2_12[1];
constraint upper_intermediate_output_2_14[18] = upper_xor_2_12[2];
constraint upper_intermediate_output_2_14[19] = upper_xor_2_12[3];
constraint upper_intermediate_output_2_14[20] = upper_xor_2_12[4];
constraint upper_intermediate_output_2_14[21] = upper_xor_2_12[5];
constraint upper_intermediate_output_2_14[22] = upper_xor_2_12[6];
constraint upper_intermediate_output_2_14[23] = upper_xor_2_12[7];
constraint upper_intermediate_output_2_14[24] = upper_xor_2_12[8];
constraint upper_intermediate_output_2_14[25] = upper_xor_2_12[9];
constraint upper_intermediate_output_2_14[26] = upper_xor_2_12[10];
constraint upper_intermediate_output_2_14[27] = upper_xor_2_12[11];
constraint upper_intermediate_output_2_14[28] = upper_xor_2_12[12];
constraint upper_intermediate_output_2_14[29] = upper_xor_2_12[13];
constraint upper_intermediate_output_2_14[30] = upper_xor_2_12[14];
constraint upper_intermediate_output_2_14[31] = upper_xor_2_12[15];
constraint upper_intermediate_output_2_14[32] = upper_rot_2_13[0];
constraint upper_intermediate_output_2_14[33] = upper_rot_2_13[1];
constraint upper_intermediate_output_2_14[34] = upper_rot_2_13[2];
constraint upper_intermediate_output_2_14[35] = upper_rot_2_13[3];
constraint upper_intermediate_output_2_14[36] = upper_rot_2_13[4];
constraint upper_intermediate_output_2_14[37] = upper_rot_2_13[5];
constraint upper_intermediate_output_2_14[38] = upper_rot_2_13[6];
constraint upper_intermediate_output_2_14[39] = upper_rot_2_13[7];
constraint upper_intermediate_output_2_14[40] = upper_rot_2_13[8];
constraint upper_intermediate_output_2_14[41] = upper_rot_2_13[9];
constraint upper_intermediate_output_2_14[42] = upper_rot_2_13[10];
constraint upper_intermediate_output_2_14[43] = upper_rot_2_13[11];
constraint upper_intermediate_output_2_14[44] = upper_rot_2_13[12];
constraint upper_intermediate_output_2_14[45] = upper_rot_2_13[13];
constraint upper_intermediate_output_2_14[46] = upper_rot_2_13[14];
constraint upper_intermediate_output_2_14[47] = upper_rot_2_13[15];
constraint upper_intermediate_output_2_14[48] = upper_xor_2_9[0];
constraint upper_intermediate_output_2_14[49] = upper_xor_2_9[1];
constraint upper_intermediate_output_2_14[50] = upper_xor_2_9[2];
constraint upper_intermediate_output_2_14[51] = upper_xor_2_9[3];
constraint upper_intermediate_output_2_14[52] = upper_xor_2_9[4];
constraint upper_intermediate_output_2_14[53] = upper_xor_2_9[5];
constraint upper_intermediate_output_2_14[54] = upper_xor_2_9[6];
constraint upper_intermediate_output_2_14[55] = upper_xor_2_9[7];
constraint upper_intermediate_output_2_14[56] = upper_xor_2_9[8];
constraint upper_intermediate_output_2_14[57] = upper_xor_2_9[9];
constraint upper_intermediate_output_2_14[58] = upper_xor_2_9[10];
constraint upper_intermediate_output_2_14[59] = upper_xor_2_9[11];
constraint upper_intermediate_output_2_14[60] = upper_xor_2_9[12];
constraint upper_intermediate_output_2_14[61] = upper_xor_2_9[13];
constraint upper_intermediate_output_2_14[62] = upper_xor_2_9[14];
constraint upper_intermediate_output_2_14[63] = upper_xor_2_9[15];
constraint pre_upper_modadd_3_0_0[0] = upper_modadd_2_7[0];
constraint pre_upper_modadd_3_0_0[1] = upper_modadd_2_7[1];
constraint pre_upper_modadd_3_0_0[2] = upper_modadd_2_7[2];
constraint pre_upper_modadd_3_0_0[3] = upper_modadd_2_7[3];
constraint pre_upper_modadd_3_0_0[4] = upper_modadd_2_7[4];
constraint pre_upper_modadd_3_0_0[5] = upper_modadd_2_7[5];
constraint pre_upper_modadd_3_0_0[6] = upper_modadd_2_7[6];
constraint pre_upper_modadd_3_0_0[7] = upper_modadd_2_7[7];
constraint pre_upper_modadd_3_0_0[8] = upper_modadd_2_7[8];
constraint pre_upper_modadd_3_0_0[9] = upper_modadd_2_7[9];
constraint pre_upper_modadd_3_0_0[10] = upper_modadd_2_7[10];
constraint pre_upper_modadd_3_0_0[11] = upper_modadd_2_7[11];
constraint pre_upper_modadd_3_0_0[12] = upper_modadd_2_7[12];
constraint pre_upper_modadd_3_0_0[13] = upper_modadd_2_7[13];
constraint pre_upper_modadd_3_0_0[14] = upper_modadd_2_7[14];
constraint pre_upper_modadd_3_0_0[15] = upper_modadd_2_7[15];
constraint pre_upper_modadd_3_0_1[0] = upper_xor_2_12[0];
constraint pre_upper_modadd_3_0_1[1] = upper_xor_2_12[1];
constraint pre_upper_modadd_3_0_1[2] = upper_xor_2_12[2];
constraint pre_upper_modadd_3_0_1[3] = upper_xor_2_12[3];
constraint pre_upper_modadd_3_0_1[4] = upper_xor_2_12[4];
constraint pre_upper_modadd_3_0_1[5] = upper_xor_2_12[5];
constraint pre_upper_modadd_3_0_1[6] = upper_xor_2_12[6];
constraint pre_upper_modadd_3_0_1[7] = upper_xor_2_12[7];
constraint pre_upper_modadd_3_0_1[8] = upper_xor_2_12[8];
constraint pre_upper_modadd_3_0_1[9] = upper_xor_2_12[9];
constraint pre_upper_modadd_3_0_1[10] = upper_xor_2_12[10];
constraint pre_upper_modadd_3_0_1[11] = upper_xor_2_12[11];
constraint pre_upper_modadd_3_0_1[12] = upper_xor_2_12[12];
constraint pre_upper_modadd_3_0_1[13] = upper_xor_2_12[13];
constraint pre_upper_modadd_3_0_1[14] = upper_xor_2_12[14];
constraint pre_upper_modadd_3_0_1[15] = upper_xor_2_12[15];
constraint forall(j in 0..15)(if eq_upper_modadd_3_0[j] = 1 then (sum([pre_upper_modadd_3_0_1[j], pre_upper_modadd_3_0_0[j], upper_modadd_3_0[j]]) mod 2) = Shi_pre_upper_modadd_3_0_0[j] else true endif) /\ upper_p[12] = (16-sum(eq_upper_modadd_3_0))*100;
constraint upper_rot_3_1[0] = upper_xor_2_12[5];
constraint upper_rot_3_1[1] = upper_xor_2_12[6];
constraint upper_rot_3_1[2] = upper_xor_2_12[7];
constraint upper_rot_3_1[3] = upper_xor_2_12[8];
constraint upper_rot_3_1[4] = upper_xor_2_12[9];
constraint upper_rot_3_1[5] = upper_xor_2_12[10];
constraint upper_rot_3_1[6] = upper_xor_2_12[11];
constraint upper_rot_3_1[7] = upper_xor_2_12[12];
constraint upper_rot_3_1[8] = upper_xor_2_12[13];
constraint upper_rot_3_1[9] = upper_xor_2_12[14];
constraint upper_rot_3_1[10] = upper_xor_2_12[15];
constraint upper_rot_3_1[11] = upper_xor_2_12[0];
constraint upper_rot_3_1[12] = upper_xor_2_12[1];
constraint upper_rot_3_1[13] = upper_xor_2_12[2];
constraint upper_rot_3_1[14] = upper_xor_2_12[3];
constraint upper_rot_3_1[15] = upper_xor_2_12[4];
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
constraint upper_rot_3_3[0] = upper_modadd_3_0[0];
constraint upper_rot_3_3[1] = upper_modadd_3_0[1];
constraint upper_rot_3_3[2] = upper_modadd_3_0[2];
constraint upper_rot_3_3[3] = upper_modadd_3_0[3];
constraint upper_rot_3_3[4] = upper_modadd_3_0[4];
constraint upper_rot_3_3[5] = upper_modadd_3_0[5];
constraint upper_rot_3_3[6] = upper_modadd_3_0[6];
constraint upper_rot_3_3[7] = upper_modadd_3_0[7];
constraint upper_rot_3_3[8] = upper_modadd_3_0[8];
constraint upper_rot_3_3[9] = upper_modadd_3_0[9];
constraint upper_rot_3_3[10] = upper_modadd_3_0[10];
constraint upper_rot_3_3[11] = upper_modadd_3_0[11];
constraint upper_rot_3_3[12] = upper_modadd_3_0[12];
constraint upper_rot_3_3[13] = upper_modadd_3_0[13];
constraint upper_rot_3_3[14] = upper_modadd_3_0[14];
constraint upper_rot_3_3[15] = upper_modadd_3_0[15];
constraint pre_upper_modadd_3_4_0[0] = upper_rot_2_13[0];
constraint pre_upper_modadd_3_4_0[1] = upper_rot_2_13[1];
constraint pre_upper_modadd_3_4_0[2] = upper_rot_2_13[2];
constraint pre_upper_modadd_3_4_0[3] = upper_rot_2_13[3];
constraint pre_upper_modadd_3_4_0[4] = upper_rot_2_13[4];
constraint pre_upper_modadd_3_4_0[5] = upper_rot_2_13[5];
constraint pre_upper_modadd_3_4_0[6] = upper_rot_2_13[6];
constraint pre_upper_modadd_3_4_0[7] = upper_rot_2_13[7];
constraint pre_upper_modadd_3_4_0[8] = upper_rot_2_13[8];
constraint pre_upper_modadd_3_4_0[9] = upper_rot_2_13[9];
constraint pre_upper_modadd_3_4_0[10] = upper_rot_2_13[10];
constraint pre_upper_modadd_3_4_0[11] = upper_rot_2_13[11];
constraint pre_upper_modadd_3_4_0[12] = upper_rot_2_13[12];
constraint pre_upper_modadd_3_4_0[13] = upper_rot_2_13[13];
constraint pre_upper_modadd_3_4_0[14] = upper_rot_2_13[14];
constraint pre_upper_modadd_3_4_0[15] = upper_rot_2_13[15];
constraint pre_upper_modadd_3_4_1[0] = upper_xor_2_9[0];
constraint pre_upper_modadd_3_4_1[1] = upper_xor_2_9[1];
constraint pre_upper_modadd_3_4_1[2] = upper_xor_2_9[2];
constraint pre_upper_modadd_3_4_1[3] = upper_xor_2_9[3];
constraint pre_upper_modadd_3_4_1[4] = upper_xor_2_9[4];
constraint pre_upper_modadd_3_4_1[5] = upper_xor_2_9[5];
constraint pre_upper_modadd_3_4_1[6] = upper_xor_2_9[6];
constraint pre_upper_modadd_3_4_1[7] = upper_xor_2_9[7];
constraint pre_upper_modadd_3_4_1[8] = upper_xor_2_9[8];
constraint pre_upper_modadd_3_4_1[9] = upper_xor_2_9[9];
constraint pre_upper_modadd_3_4_1[10] = upper_xor_2_9[10];
constraint pre_upper_modadd_3_4_1[11] = upper_xor_2_9[11];
constraint pre_upper_modadd_3_4_1[12] = upper_xor_2_9[12];
constraint pre_upper_modadd_3_4_1[13] = upper_xor_2_9[13];
constraint pre_upper_modadd_3_4_1[14] = upper_xor_2_9[14];
constraint pre_upper_modadd_3_4_1[15] = upper_xor_2_9[15];
constraint forall(j in 0..15)(if eq_upper_modadd_3_4[j] = 1 then (sum([pre_upper_modadd_3_4_1[j], pre_upper_modadd_3_4_0[j], upper_modadd_3_4[j]]) mod 2) = Shi_pre_upper_modadd_3_4_0[j] else true endif) /\ upper_p[13] = (16-sum(eq_upper_modadd_3_4))*100;
constraint upper_rot_3_5[0] = upper_xor_2_9[8];
constraint upper_rot_3_5[1] = upper_xor_2_9[9];
constraint upper_rot_3_5[2] = upper_xor_2_9[10];
constraint upper_rot_3_5[3] = upper_xor_2_9[11];
constraint upper_rot_3_5[4] = upper_xor_2_9[12];
constraint upper_rot_3_5[5] = upper_xor_2_9[13];
constraint upper_rot_3_5[6] = upper_xor_2_9[14];
constraint upper_rot_3_5[7] = upper_xor_2_9[15];
constraint upper_rot_3_5[8] = upper_xor_2_9[0];
constraint upper_rot_3_5[9] = upper_xor_2_9[1];
constraint upper_rot_3_5[10] = upper_xor_2_9[2];
constraint upper_rot_3_5[11] = upper_xor_2_9[3];
constraint upper_rot_3_5[12] = upper_xor_2_9[4];
constraint upper_rot_3_5[13] = upper_xor_2_9[5];
constraint upper_rot_3_5[14] = upper_xor_2_9[6];
constraint upper_rot_3_5[15] = upper_xor_2_9[7];
constraint 2*dummy_upper_xor_3_6[0] = (upper_rot_3_5[0] + upper_modadd_3_4[0] + upper_xor_3_6[0]);
constraint 2*dummy_upper_xor_3_6[1] = (upper_rot_3_5[1] + upper_modadd_3_4[1] + upper_xor_3_6[1]);
constraint 2*dummy_upper_xor_3_6[2] = (upper_rot_3_5[2] + upper_modadd_3_4[2] + upper_xor_3_6[2]);
constraint 2*dummy_upper_xor_3_6[3] = (upper_rot_3_5[3] + upper_modadd_3_4[3] + upper_xor_3_6[3]);
constraint 2*dummy_upper_xor_3_6[4] = (upper_rot_3_5[4] + upper_modadd_3_4[4] + upper_xor_3_6[4]);
constraint 2*dummy_upper_xor_3_6[5] = (upper_rot_3_5[5] + upper_modadd_3_4[5] + upper_xor_3_6[5]);
constraint 2*dummy_upper_xor_3_6[6] = (upper_rot_3_5[6] + upper_modadd_3_4[6] + upper_xor_3_6[6]);
constraint 2*dummy_upper_xor_3_6[7] = (upper_rot_3_5[7] + upper_modadd_3_4[7] + upper_xor_3_6[7]);
constraint 2*dummy_upper_xor_3_6[8] = (upper_rot_3_5[8] + upper_modadd_3_4[8] + upper_xor_3_6[8]);
constraint 2*dummy_upper_xor_3_6[9] = (upper_rot_3_5[9] + upper_modadd_3_4[9] + upper_xor_3_6[9]);
constraint 2*dummy_upper_xor_3_6[10] = (upper_rot_3_5[10] + upper_modadd_3_4[10] + upper_xor_3_6[10]);
constraint 2*dummy_upper_xor_3_6[11] = (upper_rot_3_5[11] + upper_modadd_3_4[11] + upper_xor_3_6[11]);
constraint 2*dummy_upper_xor_3_6[12] = (upper_rot_3_5[12] + upper_modadd_3_4[12] + upper_xor_3_6[12]);
constraint 2*dummy_upper_xor_3_6[13] = (upper_rot_3_5[13] + upper_modadd_3_4[13] + upper_xor_3_6[13]);
constraint 2*dummy_upper_xor_3_6[14] = (upper_rot_3_5[14] + upper_modadd_3_4[14] + upper_xor_3_6[14]);
constraint 2*dummy_upper_xor_3_6[15] = (upper_rot_3_5[15] + upper_modadd_3_4[15] + upper_xor_3_6[15]);
constraint pre_upper_modadd_3_7_0[0] = upper_rot_3_3[0];
constraint pre_upper_modadd_3_7_0[1] = upper_rot_3_3[1];
constraint pre_upper_modadd_3_7_0[2] = upper_rot_3_3[2];
constraint pre_upper_modadd_3_7_0[3] = upper_rot_3_3[3];
constraint pre_upper_modadd_3_7_0[4] = upper_rot_3_3[4];
constraint pre_upper_modadd_3_7_0[5] = upper_rot_3_3[5];
constraint pre_upper_modadd_3_7_0[6] = upper_rot_3_3[6];
constraint pre_upper_modadd_3_7_0[7] = upper_rot_3_3[7];
constraint pre_upper_modadd_3_7_0[8] = upper_rot_3_3[8];
constraint pre_upper_modadd_3_7_0[9] = upper_rot_3_3[9];
constraint pre_upper_modadd_3_7_0[10] = upper_rot_3_3[10];
constraint pre_upper_modadd_3_7_0[11] = upper_rot_3_3[11];
constraint pre_upper_modadd_3_7_0[12] = upper_rot_3_3[12];
constraint pre_upper_modadd_3_7_0[13] = upper_rot_3_3[13];
constraint pre_upper_modadd_3_7_0[14] = upper_rot_3_3[14];
constraint pre_upper_modadd_3_7_0[15] = upper_rot_3_3[15];
constraint pre_upper_modadd_3_7_1[0] = upper_xor_3_6[0];
constraint pre_upper_modadd_3_7_1[1] = upper_xor_3_6[1];
constraint pre_upper_modadd_3_7_1[2] = upper_xor_3_6[2];
constraint pre_upper_modadd_3_7_1[3] = upper_xor_3_6[3];
constraint pre_upper_modadd_3_7_1[4] = upper_xor_3_6[4];
constraint pre_upper_modadd_3_7_1[5] = upper_xor_3_6[5];
constraint pre_upper_modadd_3_7_1[6] = upper_xor_3_6[6];
constraint pre_upper_modadd_3_7_1[7] = upper_xor_3_6[7];
constraint pre_upper_modadd_3_7_1[8] = upper_xor_3_6[8];
constraint pre_upper_modadd_3_7_1[9] = upper_xor_3_6[9];
constraint pre_upper_modadd_3_7_1[10] = upper_xor_3_6[10];
constraint pre_upper_modadd_3_7_1[11] = upper_xor_3_6[11];
constraint pre_upper_modadd_3_7_1[12] = upper_xor_3_6[12];
constraint pre_upper_modadd_3_7_1[13] = upper_xor_3_6[13];
constraint pre_upper_modadd_3_7_1[14] = upper_xor_3_6[14];
constraint pre_upper_modadd_3_7_1[15] = upper_xor_3_6[15];
constraint forall(j in 0..15)(if eq_upper_modadd_3_7[j] = 1 then (sum([pre_upper_modadd_3_7_1[j], pre_upper_modadd_3_7_0[j], upper_modadd_3_7[j]]) mod 2) = Shi_pre_upper_modadd_3_7_0[j] else true endif) /\ upper_p[14] = (16-sum(eq_upper_modadd_3_7))*100;
constraint upper_rot_3_8[0] = upper_xor_3_6[13];
constraint upper_rot_3_8[1] = upper_xor_3_6[14];
constraint upper_rot_3_8[2] = upper_xor_3_6[15];
constraint upper_rot_3_8[3] = upper_xor_3_6[0];
constraint upper_rot_3_8[4] = upper_xor_3_6[1];
constraint upper_rot_3_8[5] = upper_xor_3_6[2];
constraint upper_rot_3_8[6] = upper_xor_3_6[3];
constraint upper_rot_3_8[7] = upper_xor_3_6[4];
constraint upper_rot_3_8[8] = upper_xor_3_6[5];
constraint upper_rot_3_8[9] = upper_xor_3_6[6];
constraint upper_rot_3_8[10] = upper_xor_3_6[7];
constraint upper_rot_3_8[11] = upper_xor_3_6[8];
constraint upper_rot_3_8[12] = upper_xor_3_6[9];
constraint upper_rot_3_8[13] = upper_xor_3_6[10];
constraint upper_rot_3_8[14] = upper_xor_3_6[11];
constraint upper_rot_3_8[15] = upper_xor_3_6[12];
constraint 2*dummy_upper_xor_3_9[0] = (upper_rot_3_8[0] + upper_modadd_3_7[0] + upper_xor_3_9[0]);
constraint 2*dummy_upper_xor_3_9[1] = (upper_rot_3_8[1] + upper_modadd_3_7[1] + upper_xor_3_9[1]);
constraint 2*dummy_upper_xor_3_9[2] = (upper_rot_3_8[2] + upper_modadd_3_7[2] + upper_xor_3_9[2]);
constraint 2*dummy_upper_xor_3_9[3] = (upper_rot_3_8[3] + upper_modadd_3_7[3] + upper_xor_3_9[3]);
constraint 2*dummy_upper_xor_3_9[4] = (upper_rot_3_8[4] + upper_modadd_3_7[4] + upper_xor_3_9[4]);
constraint 2*dummy_upper_xor_3_9[5] = (upper_rot_3_8[5] + upper_modadd_3_7[5] + upper_xor_3_9[5]);
constraint 2*dummy_upper_xor_3_9[6] = (upper_rot_3_8[6] + upper_modadd_3_7[6] + upper_xor_3_9[6]);
constraint 2*dummy_upper_xor_3_9[7] = (upper_rot_3_8[7] + upper_modadd_3_7[7] + upper_xor_3_9[7]);
constraint 2*dummy_upper_xor_3_9[8] = (upper_rot_3_8[8] + upper_modadd_3_7[8] + upper_xor_3_9[8]);
constraint 2*dummy_upper_xor_3_9[9] = (upper_rot_3_8[9] + upper_modadd_3_7[9] + upper_xor_3_9[9]);
constraint 2*dummy_upper_xor_3_9[10] = (upper_rot_3_8[10] + upper_modadd_3_7[10] + upper_xor_3_9[10]);
constraint 2*dummy_upper_xor_3_9[11] = (upper_rot_3_8[11] + upper_modadd_3_7[11] + upper_xor_3_9[11]);
constraint 2*dummy_upper_xor_3_9[12] = (upper_rot_3_8[12] + upper_modadd_3_7[12] + upper_xor_3_9[12]);
constraint 2*dummy_upper_xor_3_9[13] = (upper_rot_3_8[13] + upper_modadd_3_7[13] + upper_xor_3_9[13]);
constraint 2*dummy_upper_xor_3_9[14] = (upper_rot_3_8[14] + upper_modadd_3_7[14] + upper_xor_3_9[14]);
constraint 2*dummy_upper_xor_3_9[15] = (upper_rot_3_8[15] + upper_modadd_3_7[15] + upper_xor_3_9[15]);
constraint pre_upper_modadd_3_10_0[0] = upper_modadd_3_4[0];
constraint pre_upper_modadd_3_10_0[1] = upper_modadd_3_4[1];
constraint pre_upper_modadd_3_10_0[2] = upper_modadd_3_4[2];
constraint pre_upper_modadd_3_10_0[3] = upper_modadd_3_4[3];
constraint pre_upper_modadd_3_10_0[4] = upper_modadd_3_4[4];
constraint pre_upper_modadd_3_10_0[5] = upper_modadd_3_4[5];
constraint pre_upper_modadd_3_10_0[6] = upper_modadd_3_4[6];
constraint pre_upper_modadd_3_10_0[7] = upper_modadd_3_4[7];
constraint pre_upper_modadd_3_10_0[8] = upper_modadd_3_4[8];
constraint pre_upper_modadd_3_10_0[9] = upper_modadd_3_4[9];
constraint pre_upper_modadd_3_10_0[10] = upper_modadd_3_4[10];
constraint pre_upper_modadd_3_10_0[11] = upper_modadd_3_4[11];
constraint pre_upper_modadd_3_10_0[12] = upper_modadd_3_4[12];
constraint pre_upper_modadd_3_10_0[13] = upper_modadd_3_4[13];
constraint pre_upper_modadd_3_10_0[14] = upper_modadd_3_4[14];
constraint pre_upper_modadd_3_10_0[15] = upper_modadd_3_4[15];
constraint pre_upper_modadd_3_10_1[0] = upper_xor_3_2[0];
constraint pre_upper_modadd_3_10_1[1] = upper_xor_3_2[1];
constraint pre_upper_modadd_3_10_1[2] = upper_xor_3_2[2];
constraint pre_upper_modadd_3_10_1[3] = upper_xor_3_2[3];
constraint pre_upper_modadd_3_10_1[4] = upper_xor_3_2[4];
constraint pre_upper_modadd_3_10_1[5] = upper_xor_3_2[5];
constraint pre_upper_modadd_3_10_1[6] = upper_xor_3_2[6];
constraint pre_upper_modadd_3_10_1[7] = upper_xor_3_2[7];
constraint pre_upper_modadd_3_10_1[8] = upper_xor_3_2[8];
constraint pre_upper_modadd_3_10_1[9] = upper_xor_3_2[9];
constraint pre_upper_modadd_3_10_1[10] = upper_xor_3_2[10];
constraint pre_upper_modadd_3_10_1[11] = upper_xor_3_2[11];
constraint pre_upper_modadd_3_10_1[12] = upper_xor_3_2[12];
constraint pre_upper_modadd_3_10_1[13] = upper_xor_3_2[13];
constraint pre_upper_modadd_3_10_1[14] = upper_xor_3_2[14];
constraint pre_upper_modadd_3_10_1[15] = upper_xor_3_2[15];
constraint forall(j in 0..15)(if eq_upper_modadd_3_10[j] = 1 then (sum([pre_upper_modadd_3_10_1[j], pre_upper_modadd_3_10_0[j], upper_modadd_3_10[j]]) mod 2) = Shi_pre_upper_modadd_3_10_0[j] else true endif) /\ upper_p[15] = (16-sum(eq_upper_modadd_3_10))*100;
constraint upper_rot_3_11[0] = upper_xor_3_2[7];
constraint upper_rot_3_11[1] = upper_xor_3_2[8];
constraint upper_rot_3_11[2] = upper_xor_3_2[9];
constraint upper_rot_3_11[3] = upper_xor_3_2[10];
constraint upper_rot_3_11[4] = upper_xor_3_2[11];
constraint upper_rot_3_11[5] = upper_xor_3_2[12];
constraint upper_rot_3_11[6] = upper_xor_3_2[13];
constraint upper_rot_3_11[7] = upper_xor_3_2[14];
constraint upper_rot_3_11[8] = upper_xor_3_2[15];
constraint upper_rot_3_11[9] = upper_xor_3_2[0];
constraint upper_rot_3_11[10] = upper_xor_3_2[1];
constraint upper_rot_3_11[11] = upper_xor_3_2[2];
constraint upper_rot_3_11[12] = upper_xor_3_2[3];
constraint upper_rot_3_11[13] = upper_xor_3_2[4];
constraint upper_rot_3_11[14] = upper_xor_3_2[5];
constraint upper_rot_3_11[15] = upper_xor_3_2[6];
constraint 2*dummy_upper_xor_3_12[0] = (upper_rot_3_11[0] + upper_modadd_3_10[0] + upper_xor_3_12[0]);
constraint 2*dummy_upper_xor_3_12[1] = (upper_rot_3_11[1] + upper_modadd_3_10[1] + upper_xor_3_12[1]);
constraint 2*dummy_upper_xor_3_12[2] = (upper_rot_3_11[2] + upper_modadd_3_10[2] + upper_xor_3_12[2]);
constraint 2*dummy_upper_xor_3_12[3] = (upper_rot_3_11[3] + upper_modadd_3_10[3] + upper_xor_3_12[3]);
constraint 2*dummy_upper_xor_3_12[4] = (upper_rot_3_11[4] + upper_modadd_3_10[4] + upper_xor_3_12[4]);
constraint 2*dummy_upper_xor_3_12[5] = (upper_rot_3_11[5] + upper_modadd_3_10[5] + upper_xor_3_12[5]);
constraint 2*dummy_upper_xor_3_12[6] = (upper_rot_3_11[6] + upper_modadd_3_10[6] + upper_xor_3_12[6]);
constraint 2*dummy_upper_xor_3_12[7] = (upper_rot_3_11[7] + upper_modadd_3_10[7] + upper_xor_3_12[7]);
constraint 2*dummy_upper_xor_3_12[8] = (upper_rot_3_11[8] + upper_modadd_3_10[8] + upper_xor_3_12[8]);
constraint 2*dummy_upper_xor_3_12[9] = (upper_rot_3_11[9] + upper_modadd_3_10[9] + upper_xor_3_12[9]);
constraint 2*dummy_upper_xor_3_12[10] = (upper_rot_3_11[10] + upper_modadd_3_10[10] + upper_xor_3_12[10]);
constraint 2*dummy_upper_xor_3_12[11] = (upper_rot_3_11[11] + upper_modadd_3_10[11] + upper_xor_3_12[11]);
constraint 2*dummy_upper_xor_3_12[12] = (upper_rot_3_11[12] + upper_modadd_3_10[12] + upper_xor_3_12[12]);
constraint 2*dummy_upper_xor_3_12[13] = (upper_rot_3_11[13] + upper_modadd_3_10[13] + upper_xor_3_12[13]);
constraint 2*dummy_upper_xor_3_12[14] = (upper_rot_3_11[14] + upper_modadd_3_10[14] + upper_xor_3_12[14]);
constraint 2*dummy_upper_xor_3_12[15] = (upper_rot_3_11[15] + upper_modadd_3_10[15] + upper_xor_3_12[15]);
constraint upper_rot_3_13[0] = upper_modadd_3_10[0];
constraint upper_rot_3_13[1] = upper_modadd_3_10[1];
constraint upper_rot_3_13[2] = upper_modadd_3_10[2];
constraint upper_rot_3_13[3] = upper_modadd_3_10[3];
constraint upper_rot_3_13[4] = upper_modadd_3_10[4];
constraint upper_rot_3_13[5] = upper_modadd_3_10[5];
constraint upper_rot_3_13[6] = upper_modadd_3_10[6];
constraint upper_rot_3_13[7] = upper_modadd_3_10[7];
constraint upper_rot_3_13[8] = upper_modadd_3_10[8];
constraint upper_rot_3_13[9] = upper_modadd_3_10[9];
constraint upper_rot_3_13[10] = upper_modadd_3_10[10];
constraint upper_rot_3_13[11] = upper_modadd_3_10[11];
constraint upper_rot_3_13[12] = upper_modadd_3_10[12];
constraint upper_rot_3_13[13] = upper_modadd_3_10[13];
constraint upper_rot_3_13[14] = upper_modadd_3_10[14];
constraint upper_rot_3_13[15] = upper_modadd_3_10[15];
constraint upper_intermediate_output_3_14[0] = upper_modadd_3_7[0];
constraint upper_intermediate_output_3_14[1] = upper_modadd_3_7[1];
constraint upper_intermediate_output_3_14[2] = upper_modadd_3_7[2];
constraint upper_intermediate_output_3_14[3] = upper_modadd_3_7[3];
constraint upper_intermediate_output_3_14[4] = upper_modadd_3_7[4];
constraint upper_intermediate_output_3_14[5] = upper_modadd_3_7[5];
constraint upper_intermediate_output_3_14[6] = upper_modadd_3_7[6];
constraint upper_intermediate_output_3_14[7] = upper_modadd_3_7[7];
constraint upper_intermediate_output_3_14[8] = upper_modadd_3_7[8];
constraint upper_intermediate_output_3_14[9] = upper_modadd_3_7[9];
constraint upper_intermediate_output_3_14[10] = upper_modadd_3_7[10];
constraint upper_intermediate_output_3_14[11] = upper_modadd_3_7[11];
constraint upper_intermediate_output_3_14[12] = upper_modadd_3_7[12];
constraint upper_intermediate_output_3_14[13] = upper_modadd_3_7[13];
constraint upper_intermediate_output_3_14[14] = upper_modadd_3_7[14];
constraint upper_intermediate_output_3_14[15] = upper_modadd_3_7[15];
constraint upper_intermediate_output_3_14[16] = upper_xor_3_12[0];
constraint upper_intermediate_output_3_14[17] = upper_xor_3_12[1];
constraint upper_intermediate_output_3_14[18] = upper_xor_3_12[2];
constraint upper_intermediate_output_3_14[19] = upper_xor_3_12[3];
constraint upper_intermediate_output_3_14[20] = upper_xor_3_12[4];
constraint upper_intermediate_output_3_14[21] = upper_xor_3_12[5];
constraint upper_intermediate_output_3_14[22] = upper_xor_3_12[6];
constraint upper_intermediate_output_3_14[23] = upper_xor_3_12[7];
constraint upper_intermediate_output_3_14[24] = upper_xor_3_12[8];
constraint upper_intermediate_output_3_14[25] = upper_xor_3_12[9];
constraint upper_intermediate_output_3_14[26] = upper_xor_3_12[10];
constraint upper_intermediate_output_3_14[27] = upper_xor_3_12[11];
constraint upper_intermediate_output_3_14[28] = upper_xor_3_12[12];
constraint upper_intermediate_output_3_14[29] = upper_xor_3_12[13];
constraint upper_intermediate_output_3_14[30] = upper_xor_3_12[14];
constraint upper_intermediate_output_3_14[31] = upper_xor_3_12[15];
constraint upper_intermediate_output_3_14[32] = upper_rot_3_13[0];
constraint upper_intermediate_output_3_14[33] = upper_rot_3_13[1];
constraint upper_intermediate_output_3_14[34] = upper_rot_3_13[2];
constraint upper_intermediate_output_3_14[35] = upper_rot_3_13[3];
constraint upper_intermediate_output_3_14[36] = upper_rot_3_13[4];
constraint upper_intermediate_output_3_14[37] = upper_rot_3_13[5];
constraint upper_intermediate_output_3_14[38] = upper_rot_3_13[6];
constraint upper_intermediate_output_3_14[39] = upper_rot_3_13[7];
constraint upper_intermediate_output_3_14[40] = upper_rot_3_13[8];
constraint upper_intermediate_output_3_14[41] = upper_rot_3_13[9];
constraint upper_intermediate_output_3_14[42] = upper_rot_3_13[10];
constraint upper_intermediate_output_3_14[43] = upper_rot_3_13[11];
constraint upper_intermediate_output_3_14[44] = upper_rot_3_13[12];
constraint upper_intermediate_output_3_14[45] = upper_rot_3_13[13];
constraint upper_intermediate_output_3_14[46] = upper_rot_3_13[14];
constraint upper_intermediate_output_3_14[47] = upper_rot_3_13[15];
constraint upper_intermediate_output_3_14[48] = upper_xor_3_9[0];
constraint upper_intermediate_output_3_14[49] = upper_xor_3_9[1];
constraint upper_intermediate_output_3_14[50] = upper_xor_3_9[2];
constraint upper_intermediate_output_3_14[51] = upper_xor_3_9[3];
constraint upper_intermediate_output_3_14[52] = upper_xor_3_9[4];
constraint upper_intermediate_output_3_14[53] = upper_xor_3_9[5];
constraint upper_intermediate_output_3_14[54] = upper_xor_3_9[6];
constraint upper_intermediate_output_3_14[55] = upper_xor_3_9[7];
constraint upper_intermediate_output_3_14[56] = upper_xor_3_9[8];
constraint upper_intermediate_output_3_14[57] = upper_xor_3_9[9];
constraint upper_intermediate_output_3_14[58] = upper_xor_3_9[10];
constraint upper_intermediate_output_3_14[59] = upper_xor_3_9[11];
constraint upper_intermediate_output_3_14[60] = upper_xor_3_9[12];
constraint upper_intermediate_output_3_14[61] = upper_xor_3_9[13];
constraint upper_intermediate_output_3_14[62] = upper_xor_3_9[14];
constraint upper_intermediate_output_3_14[63] = upper_xor_3_9[15];
constraint 2*dummy_lower_xor_3_9[0] = (lower_modadd_4_0[0] + lower_rot_4_5[0] + lower_xor_3_9[0]);
constraint 2*dummy_lower_xor_3_9[1] = (lower_modadd_4_0[1] + lower_rot_4_5[1] + lower_xor_3_9[1]);
constraint 2*dummy_lower_xor_3_9[2] = (lower_modadd_4_0[2] + lower_rot_4_5[2] + lower_xor_3_9[2]);
constraint 2*dummy_lower_xor_3_9[3] = (lower_modadd_4_0[3] + lower_rot_4_5[3] + lower_xor_3_9[3]);
constraint 2*dummy_lower_xor_3_9[4] = (lower_modadd_4_0[4] + lower_rot_4_5[4] + lower_xor_3_9[4]);
constraint 2*dummy_lower_xor_3_9[5] = (lower_modadd_4_0[5] + lower_rot_4_5[5] + lower_xor_3_9[5]);
constraint 2*dummy_lower_xor_3_9[6] = (lower_modadd_4_0[6] + lower_rot_4_5[6] + lower_xor_3_9[6]);
constraint 2*dummy_lower_xor_3_9[7] = (lower_modadd_4_0[7] + lower_rot_4_5[7] + lower_xor_3_9[7]);
constraint 2*dummy_lower_xor_3_9[8] = (lower_modadd_4_0[8] + lower_rot_4_5[8] + lower_xor_3_9[8]);
constraint 2*dummy_lower_xor_3_9[9] = (lower_modadd_4_0[9] + lower_rot_4_5[9] + lower_xor_3_9[9]);
constraint 2*dummy_lower_xor_3_9[10] = (lower_modadd_4_0[10] + lower_rot_4_5[10] + lower_xor_3_9[10]);
constraint 2*dummy_lower_xor_3_9[11] = (lower_modadd_4_0[11] + lower_rot_4_5[11] + lower_xor_3_9[11]);
constraint 2*dummy_lower_xor_3_9[12] = (lower_modadd_4_0[12] + lower_rot_4_5[12] + lower_xor_3_9[12]);
constraint 2*dummy_lower_xor_3_9[13] = (lower_modadd_4_0[13] + lower_rot_4_5[13] + lower_xor_3_9[13]);
constraint 2*dummy_lower_xor_3_9[14] = (lower_modadd_4_0[14] + lower_rot_4_5[14] + lower_xor_3_9[14]);
constraint 2*dummy_lower_xor_3_9[15] = (lower_modadd_4_0[15] + lower_rot_4_5[15] + lower_xor_3_9[15]);
constraint lower_rot_3_13[0] = lower_modadd_4_4[0];
constraint lower_rot_3_13[1] = lower_modadd_4_4[1];
constraint lower_rot_3_13[2] = lower_modadd_4_4[2];
constraint lower_rot_3_13[3] = lower_modadd_4_4[3];
constraint lower_rot_3_13[4] = lower_modadd_4_4[4];
constraint lower_rot_3_13[5] = lower_modadd_4_4[5];
constraint lower_rot_3_13[6] = lower_modadd_4_4[6];
constraint lower_rot_3_13[7] = lower_modadd_4_4[7];
constraint lower_rot_3_13[8] = lower_modadd_4_4[8];
constraint lower_rot_3_13[9] = lower_modadd_4_4[9];
constraint lower_rot_3_13[10] = lower_modadd_4_4[10];
constraint lower_rot_3_13[11] = lower_modadd_4_4[11];
constraint lower_rot_3_13[12] = lower_modadd_4_4[12];
constraint lower_rot_3_13[13] = lower_modadd_4_4[13];
constraint lower_rot_3_13[14] = lower_modadd_4_4[14];
constraint lower_rot_3_13[15] = lower_modadd_4_4[15];
constraint lower_intermediate_output_3_14[0] = lower_modadd_4_0[0];
constraint lower_intermediate_output_3_14[1] = lower_modadd_4_0[1];
constraint lower_intermediate_output_3_14[2] = lower_modadd_4_0[2];
constraint lower_intermediate_output_3_14[3] = lower_modadd_4_0[3];
constraint lower_intermediate_output_3_14[4] = lower_modadd_4_0[4];
constraint lower_intermediate_output_3_14[5] = lower_modadd_4_0[5];
constraint lower_intermediate_output_3_14[6] = lower_modadd_4_0[6];
constraint lower_intermediate_output_3_14[7] = lower_modadd_4_0[7];
constraint lower_intermediate_output_3_14[8] = lower_modadd_4_0[8];
constraint lower_intermediate_output_3_14[9] = lower_modadd_4_0[9];
constraint lower_intermediate_output_3_14[10] = lower_modadd_4_0[10];
constraint lower_intermediate_output_3_14[11] = lower_modadd_4_0[11];
constraint lower_intermediate_output_3_14[12] = lower_modadd_4_0[12];
constraint lower_intermediate_output_3_14[13] = lower_modadd_4_0[13];
constraint lower_intermediate_output_3_14[14] = lower_modadd_4_0[14];
constraint lower_intermediate_output_3_14[15] = lower_modadd_4_0[15];
constraint lower_intermediate_output_3_14[16] = lower_rot_4_1[0];
constraint lower_intermediate_output_3_14[17] = lower_rot_4_1[1];
constraint lower_intermediate_output_3_14[18] = lower_rot_4_1[2];
constraint lower_intermediate_output_3_14[19] = lower_rot_4_1[3];
constraint lower_intermediate_output_3_14[20] = lower_rot_4_1[4];
constraint lower_intermediate_output_3_14[21] = lower_rot_4_1[5];
constraint lower_intermediate_output_3_14[22] = lower_rot_4_1[6];
constraint lower_intermediate_output_3_14[23] = lower_rot_4_1[7];
constraint lower_intermediate_output_3_14[24] = lower_rot_4_1[8];
constraint lower_intermediate_output_3_14[25] = lower_rot_4_1[9];
constraint lower_intermediate_output_3_14[26] = lower_rot_4_1[10];
constraint lower_intermediate_output_3_14[27] = lower_rot_4_1[11];
constraint lower_intermediate_output_3_14[28] = lower_rot_4_1[12];
constraint lower_intermediate_output_3_14[29] = lower_rot_4_1[13];
constraint lower_intermediate_output_3_14[30] = lower_rot_4_1[14];
constraint lower_intermediate_output_3_14[31] = lower_rot_4_1[15];
constraint lower_intermediate_output_3_14[32] = lower_modadd_4_4[0];
constraint lower_intermediate_output_3_14[33] = lower_modadd_4_4[1];
constraint lower_intermediate_output_3_14[34] = lower_modadd_4_4[2];
constraint lower_intermediate_output_3_14[35] = lower_modadd_4_4[3];
constraint lower_intermediate_output_3_14[36] = lower_modadd_4_4[4];
constraint lower_intermediate_output_3_14[37] = lower_modadd_4_4[5];
constraint lower_intermediate_output_3_14[38] = lower_modadd_4_4[6];
constraint lower_intermediate_output_3_14[39] = lower_modadd_4_4[7];
constraint lower_intermediate_output_3_14[40] = lower_modadd_4_4[8];
constraint lower_intermediate_output_3_14[41] = lower_modadd_4_4[9];
constraint lower_intermediate_output_3_14[42] = lower_modadd_4_4[10];
constraint lower_intermediate_output_3_14[43] = lower_modadd_4_4[11];
constraint lower_intermediate_output_3_14[44] = lower_modadd_4_4[12];
constraint lower_intermediate_output_3_14[45] = lower_modadd_4_4[13];
constraint lower_intermediate_output_3_14[46] = lower_modadd_4_4[14];
constraint lower_intermediate_output_3_14[47] = lower_modadd_4_4[15];
constraint lower_intermediate_output_3_14[48] = lower_rot_4_5[0];
constraint lower_intermediate_output_3_14[49] = lower_rot_4_5[1];
constraint lower_intermediate_output_3_14[50] = lower_rot_4_5[2];
constraint lower_intermediate_output_3_14[51] = lower_rot_4_5[3];
constraint lower_intermediate_output_3_14[52] = lower_rot_4_5[4];
constraint lower_intermediate_output_3_14[53] = lower_rot_4_5[5];
constraint lower_intermediate_output_3_14[54] = lower_rot_4_5[6];
constraint lower_intermediate_output_3_14[55] = lower_rot_4_5[7];
constraint lower_intermediate_output_3_14[56] = lower_rot_4_5[8];
constraint lower_intermediate_output_3_14[57] = lower_rot_4_5[9];
constraint lower_intermediate_output_3_14[58] = lower_rot_4_5[10];
constraint lower_intermediate_output_3_14[59] = lower_rot_4_5[11];
constraint lower_intermediate_output_3_14[60] = lower_rot_4_5[12];
constraint lower_intermediate_output_3_14[61] = lower_rot_4_5[13];
constraint lower_intermediate_output_3_14[62] = lower_rot_4_5[14];
constraint lower_intermediate_output_3_14[63] = lower_rot_4_5[15];
constraint lower_rot_3_8[0] = lower_xor_3_9[3];
constraint lower_rot_3_8[1] = lower_xor_3_9[4];
constraint lower_rot_3_8[2] = lower_xor_3_9[5];
constraint lower_rot_3_8[3] = lower_xor_3_9[6];
constraint lower_rot_3_8[4] = lower_xor_3_9[7];
constraint lower_rot_3_8[5] = lower_xor_3_9[8];
constraint lower_rot_3_8[6] = lower_xor_3_9[9];
constraint lower_rot_3_8[7] = lower_xor_3_9[10];
constraint lower_rot_3_8[8] = lower_xor_3_9[11];
constraint lower_rot_3_8[9] = lower_xor_3_9[12];
constraint lower_rot_3_8[10] = lower_xor_3_9[13];
constraint lower_rot_3_8[11] = lower_xor_3_9[14];
constraint lower_rot_3_8[12] = lower_xor_3_9[15];
constraint lower_rot_3_8[13] = lower_xor_3_9[0];
constraint lower_rot_3_8[14] = lower_xor_3_9[1];
constraint lower_rot_3_8[15] = lower_xor_3_9[2];
constraint 2*dummy_lower_xor_3_12[0] = (lower_rot_3_13[0] + lower_rot_4_1[0] + lower_xor_3_12[0]);
constraint 2*dummy_lower_xor_3_12[1] = (lower_rot_3_13[1] + lower_rot_4_1[1] + lower_xor_3_12[1]);
constraint 2*dummy_lower_xor_3_12[2] = (lower_rot_3_13[2] + lower_rot_4_1[2] + lower_xor_3_12[2]);
constraint 2*dummy_lower_xor_3_12[3] = (lower_rot_3_13[3] + lower_rot_4_1[3] + lower_xor_3_12[3]);
constraint 2*dummy_lower_xor_3_12[4] = (lower_rot_3_13[4] + lower_rot_4_1[4] + lower_xor_3_12[4]);
constraint 2*dummy_lower_xor_3_12[5] = (lower_rot_3_13[5] + lower_rot_4_1[5] + lower_xor_3_12[5]);
constraint 2*dummy_lower_xor_3_12[6] = (lower_rot_3_13[6] + lower_rot_4_1[6] + lower_xor_3_12[6]);
constraint 2*dummy_lower_xor_3_12[7] = (lower_rot_3_13[7] + lower_rot_4_1[7] + lower_xor_3_12[7]);
constraint 2*dummy_lower_xor_3_12[8] = (lower_rot_3_13[8] + lower_rot_4_1[8] + lower_xor_3_12[8]);
constraint 2*dummy_lower_xor_3_12[9] = (lower_rot_3_13[9] + lower_rot_4_1[9] + lower_xor_3_12[9]);
constraint 2*dummy_lower_xor_3_12[10] = (lower_rot_3_13[10] + lower_rot_4_1[10] + lower_xor_3_12[10]);
constraint 2*dummy_lower_xor_3_12[11] = (lower_rot_3_13[11] + lower_rot_4_1[11] + lower_xor_3_12[11]);
constraint 2*dummy_lower_xor_3_12[12] = (lower_rot_3_13[12] + lower_rot_4_1[12] + lower_xor_3_12[12]);
constraint 2*dummy_lower_xor_3_12[13] = (lower_rot_3_13[13] + lower_rot_4_1[13] + lower_xor_3_12[13]);
constraint 2*dummy_lower_xor_3_12[14] = (lower_rot_3_13[14] + lower_rot_4_1[14] + lower_xor_3_12[14]);
constraint 2*dummy_lower_xor_3_12[15] = (lower_rot_3_13[15] + lower_rot_4_1[15] + lower_xor_3_12[15]);
constraint pre_lower_modadd_3_7_0[0] = lower_modadd_4_0[0];
constraint pre_lower_modadd_3_7_0[1] = lower_modadd_4_0[1];
constraint pre_lower_modadd_3_7_0[2] = lower_modadd_4_0[2];
constraint pre_lower_modadd_3_7_0[3] = lower_modadd_4_0[3];
constraint pre_lower_modadd_3_7_0[4] = lower_modadd_4_0[4];
constraint pre_lower_modadd_3_7_0[5] = lower_modadd_4_0[5];
constraint pre_lower_modadd_3_7_0[6] = lower_modadd_4_0[6];
constraint pre_lower_modadd_3_7_0[7] = lower_modadd_4_0[7];
constraint pre_lower_modadd_3_7_0[8] = lower_modadd_4_0[8];
constraint pre_lower_modadd_3_7_0[9] = lower_modadd_4_0[9];
constraint pre_lower_modadd_3_7_0[10] = lower_modadd_4_0[10];
constraint pre_lower_modadd_3_7_0[11] = lower_modadd_4_0[11];
constraint pre_lower_modadd_3_7_0[12] = lower_modadd_4_0[12];
constraint pre_lower_modadd_3_7_0[13] = lower_modadd_4_0[13];
constraint pre_lower_modadd_3_7_0[14] = lower_modadd_4_0[14];
constraint pre_lower_modadd_3_7_0[15] = lower_modadd_4_0[15];
constraint pre_lower_modadd_3_7_1[0] = lower_rot_3_8[0];
constraint pre_lower_modadd_3_7_1[1] = lower_rot_3_8[1];
constraint pre_lower_modadd_3_7_1[2] = lower_rot_3_8[2];
constraint pre_lower_modadd_3_7_1[3] = lower_rot_3_8[3];
constraint pre_lower_modadd_3_7_1[4] = lower_rot_3_8[4];
constraint pre_lower_modadd_3_7_1[5] = lower_rot_3_8[5];
constraint pre_lower_modadd_3_7_1[6] = lower_rot_3_8[6];
constraint pre_lower_modadd_3_7_1[7] = lower_rot_3_8[7];
constraint pre_lower_modadd_3_7_1[8] = lower_rot_3_8[8];
constraint pre_lower_modadd_3_7_1[9] = lower_rot_3_8[9];
constraint pre_lower_modadd_3_7_1[10] = lower_rot_3_8[10];
constraint pre_lower_modadd_3_7_1[11] = lower_rot_3_8[11];
constraint pre_lower_modadd_3_7_1[12] = lower_rot_3_8[12];
constraint pre_lower_modadd_3_7_1[13] = lower_rot_3_8[13];
constraint pre_lower_modadd_3_7_1[14] = lower_rot_3_8[14];
constraint pre_lower_modadd_3_7_1[15] = lower_rot_3_8[15];
constraint forall(j in 0..15)(if eq_lower_modadd_3_7[j] = 1 then (sum([pre_lower_modadd_3_7_1[j], pre_lower_modadd_3_7_0[j], lower_modadd_3_7[j]]) mod 2) = Shi_pre_lower_modadd_3_7_0[j] else true endif) /\ lower_p[0] = (16-sum(eq_lower_modadd_3_7))*100;
constraint lower_rot_3_11[0] = lower_xor_3_12[9];
constraint lower_rot_3_11[1] = lower_xor_3_12[10];
constraint lower_rot_3_11[2] = lower_xor_3_12[11];
constraint lower_rot_3_11[3] = lower_xor_3_12[12];
constraint lower_rot_3_11[4] = lower_xor_3_12[13];
constraint lower_rot_3_11[5] = lower_xor_3_12[14];
constraint lower_rot_3_11[6] = lower_xor_3_12[15];
constraint lower_rot_3_11[7] = lower_xor_3_12[0];
constraint lower_rot_3_11[8] = lower_xor_3_12[1];
constraint lower_rot_3_11[9] = lower_xor_3_12[2];
constraint lower_rot_3_11[10] = lower_xor_3_12[3];
constraint lower_rot_3_11[11] = lower_xor_3_12[4];
constraint lower_rot_3_11[12] = lower_xor_3_12[5];
constraint lower_rot_3_11[13] = lower_xor_3_12[6];
constraint lower_rot_3_11[14] = lower_xor_3_12[7];
constraint lower_rot_3_11[15] = lower_xor_3_12[8];
constraint lower_rot_3_3[0] = lower_modadd_3_7[0];
constraint lower_rot_3_3[1] = lower_modadd_3_7[1];
constraint lower_rot_3_3[2] = lower_modadd_3_7[2];
constraint lower_rot_3_3[3] = lower_modadd_3_7[3];
constraint lower_rot_3_3[4] = lower_modadd_3_7[4];
constraint lower_rot_3_3[5] = lower_modadd_3_7[5];
constraint lower_rot_3_3[6] = lower_modadd_3_7[6];
constraint lower_rot_3_3[7] = lower_modadd_3_7[7];
constraint lower_rot_3_3[8] = lower_modadd_3_7[8];
constraint lower_rot_3_3[9] = lower_modadd_3_7[9];
constraint lower_rot_3_3[10] = lower_modadd_3_7[10];
constraint lower_rot_3_3[11] = lower_modadd_3_7[11];
constraint lower_rot_3_3[12] = lower_modadd_3_7[12];
constraint lower_rot_3_3[13] = lower_modadd_3_7[13];
constraint lower_rot_3_3[14] = lower_modadd_3_7[14];
constraint lower_rot_3_3[15] = lower_modadd_3_7[15];
constraint pre_lower_modadd_3_10_0[0] = lower_rot_3_13[0];
constraint pre_lower_modadd_3_10_0[1] = lower_rot_3_13[1];
constraint pre_lower_modadd_3_10_0[2] = lower_rot_3_13[2];
constraint pre_lower_modadd_3_10_0[3] = lower_rot_3_13[3];
constraint pre_lower_modadd_3_10_0[4] = lower_rot_3_13[4];
constraint pre_lower_modadd_3_10_0[5] = lower_rot_3_13[5];
constraint pre_lower_modadd_3_10_0[6] = lower_rot_3_13[6];
constraint pre_lower_modadd_3_10_0[7] = lower_rot_3_13[7];
constraint pre_lower_modadd_3_10_0[8] = lower_rot_3_13[8];
constraint pre_lower_modadd_3_10_0[9] = lower_rot_3_13[9];
constraint pre_lower_modadd_3_10_0[10] = lower_rot_3_13[10];
constraint pre_lower_modadd_3_10_0[11] = lower_rot_3_13[11];
constraint pre_lower_modadd_3_10_0[12] = lower_rot_3_13[12];
constraint pre_lower_modadd_3_10_0[13] = lower_rot_3_13[13];
constraint pre_lower_modadd_3_10_0[14] = lower_rot_3_13[14];
constraint pre_lower_modadd_3_10_0[15] = lower_rot_3_13[15];
constraint pre_lower_modadd_3_10_1[0] = lower_rot_3_11[0];
constraint pre_lower_modadd_3_10_1[1] = lower_rot_3_11[1];
constraint pre_lower_modadd_3_10_1[2] = lower_rot_3_11[2];
constraint pre_lower_modadd_3_10_1[3] = lower_rot_3_11[3];
constraint pre_lower_modadd_3_10_1[4] = lower_rot_3_11[4];
constraint pre_lower_modadd_3_10_1[5] = lower_rot_3_11[5];
constraint pre_lower_modadd_3_10_1[6] = lower_rot_3_11[6];
constraint pre_lower_modadd_3_10_1[7] = lower_rot_3_11[7];
constraint pre_lower_modadd_3_10_1[8] = lower_rot_3_11[8];
constraint pre_lower_modadd_3_10_1[9] = lower_rot_3_11[9];
constraint pre_lower_modadd_3_10_1[10] = lower_rot_3_11[10];
constraint pre_lower_modadd_3_10_1[11] = lower_rot_3_11[11];
constraint pre_lower_modadd_3_10_1[12] = lower_rot_3_11[12];
constraint pre_lower_modadd_3_10_1[13] = lower_rot_3_11[13];
constraint pre_lower_modadd_3_10_1[14] = lower_rot_3_11[14];
constraint pre_lower_modadd_3_10_1[15] = lower_rot_3_11[15];
constraint forall(j in 0..15)(if eq_lower_modadd_3_10[j] = 1 then (sum([pre_lower_modadd_3_10_1[j], pre_lower_modadd_3_10_0[j], lower_modadd_3_10[j]]) mod 2) = Shi_pre_lower_modadd_3_10_0[j] else true endif) /\ lower_p[1] = (16-sum(eq_lower_modadd_3_10))*100;
constraint 2*dummy_lower_xor_3_2[0] = (lower_rot_3_3[0] + lower_rot_3_11[0] + lower_xor_3_2[0]);
constraint 2*dummy_lower_xor_3_2[1] = (lower_rot_3_3[1] + lower_rot_3_11[1] + lower_xor_3_2[1]);
constraint 2*dummy_lower_xor_3_2[2] = (lower_rot_3_3[2] + lower_rot_3_11[2] + lower_xor_3_2[2]);
constraint 2*dummy_lower_xor_3_2[3] = (lower_rot_3_3[3] + lower_rot_3_11[3] + lower_xor_3_2[3]);
constraint 2*dummy_lower_xor_3_2[4] = (lower_rot_3_3[4] + lower_rot_3_11[4] + lower_xor_3_2[4]);
constraint 2*dummy_lower_xor_3_2[5] = (lower_rot_3_3[5] + lower_rot_3_11[5] + lower_xor_3_2[5]);
constraint 2*dummy_lower_xor_3_2[6] = (lower_rot_3_3[6] + lower_rot_3_11[6] + lower_xor_3_2[6]);
constraint 2*dummy_lower_xor_3_2[7] = (lower_rot_3_3[7] + lower_rot_3_11[7] + lower_xor_3_2[7]);
constraint 2*dummy_lower_xor_3_2[8] = (lower_rot_3_3[8] + lower_rot_3_11[8] + lower_xor_3_2[8]);
constraint 2*dummy_lower_xor_3_2[9] = (lower_rot_3_3[9] + lower_rot_3_11[9] + lower_xor_3_2[9]);
constraint 2*dummy_lower_xor_3_2[10] = (lower_rot_3_3[10] + lower_rot_3_11[10] + lower_xor_3_2[10]);
constraint 2*dummy_lower_xor_3_2[11] = (lower_rot_3_3[11] + lower_rot_3_11[11] + lower_xor_3_2[11]);
constraint 2*dummy_lower_xor_3_2[12] = (lower_rot_3_3[12] + lower_rot_3_11[12] + lower_xor_3_2[12]);
constraint 2*dummy_lower_xor_3_2[13] = (lower_rot_3_3[13] + lower_rot_3_11[13] + lower_xor_3_2[13]);
constraint 2*dummy_lower_xor_3_2[14] = (lower_rot_3_3[14] + lower_rot_3_11[14] + lower_xor_3_2[14]);
constraint 2*dummy_lower_xor_3_2[15] = (lower_rot_3_3[15] + lower_rot_3_11[15] + lower_xor_3_2[15]);
constraint 2*dummy_lower_xor_3_6[0] = (lower_modadd_3_10[0] + lower_rot_3_8[0] + lower_xor_3_6[0]);
constraint 2*dummy_lower_xor_3_6[1] = (lower_modadd_3_10[1] + lower_rot_3_8[1] + lower_xor_3_6[1]);
constraint 2*dummy_lower_xor_3_6[2] = (lower_modadd_3_10[2] + lower_rot_3_8[2] + lower_xor_3_6[2]);
constraint 2*dummy_lower_xor_3_6[3] = (lower_modadd_3_10[3] + lower_rot_3_8[3] + lower_xor_3_6[3]);
constraint 2*dummy_lower_xor_3_6[4] = (lower_modadd_3_10[4] + lower_rot_3_8[4] + lower_xor_3_6[4]);
constraint 2*dummy_lower_xor_3_6[5] = (lower_modadd_3_10[5] + lower_rot_3_8[5] + lower_xor_3_6[5]);
constraint 2*dummy_lower_xor_3_6[6] = (lower_modadd_3_10[6] + lower_rot_3_8[6] + lower_xor_3_6[6]);
constraint 2*dummy_lower_xor_3_6[7] = (lower_modadd_3_10[7] + lower_rot_3_8[7] + lower_xor_3_6[7]);
constraint 2*dummy_lower_xor_3_6[8] = (lower_modadd_3_10[8] + lower_rot_3_8[8] + lower_xor_3_6[8]);
constraint 2*dummy_lower_xor_3_6[9] = (lower_modadd_3_10[9] + lower_rot_3_8[9] + lower_xor_3_6[9]);
constraint 2*dummy_lower_xor_3_6[10] = (lower_modadd_3_10[10] + lower_rot_3_8[10] + lower_xor_3_6[10]);
constraint 2*dummy_lower_xor_3_6[11] = (lower_modadd_3_10[11] + lower_rot_3_8[11] + lower_xor_3_6[11]);
constraint 2*dummy_lower_xor_3_6[12] = (lower_modadd_3_10[12] + lower_rot_3_8[12] + lower_xor_3_6[12]);
constraint 2*dummy_lower_xor_3_6[13] = (lower_modadd_3_10[13] + lower_rot_3_8[13] + lower_xor_3_6[13]);
constraint 2*dummy_lower_xor_3_6[14] = (lower_modadd_3_10[14] + lower_rot_3_8[14] + lower_xor_3_6[14]);
constraint 2*dummy_lower_xor_3_6[15] = (lower_modadd_3_10[15] + lower_rot_3_8[15] + lower_xor_3_6[15]);
constraint lower_rot_3_1[0] = lower_xor_3_2[11];
constraint lower_rot_3_1[1] = lower_xor_3_2[12];
constraint lower_rot_3_1[2] = lower_xor_3_2[13];
constraint lower_rot_3_1[3] = lower_xor_3_2[14];
constraint lower_rot_3_1[4] = lower_xor_3_2[15];
constraint lower_rot_3_1[5] = lower_xor_3_2[0];
constraint lower_rot_3_1[6] = lower_xor_3_2[1];
constraint lower_rot_3_1[7] = lower_xor_3_2[2];
constraint lower_rot_3_1[8] = lower_xor_3_2[3];
constraint lower_rot_3_1[9] = lower_xor_3_2[4];
constraint lower_rot_3_1[10] = lower_xor_3_2[5];
constraint lower_rot_3_1[11] = lower_xor_3_2[6];
constraint lower_rot_3_1[12] = lower_xor_3_2[7];
constraint lower_rot_3_1[13] = lower_xor_3_2[8];
constraint lower_rot_3_1[14] = lower_xor_3_2[9];
constraint lower_rot_3_1[15] = lower_xor_3_2[10];
constraint lower_rot_3_5[0] = lower_xor_3_6[8];
constraint lower_rot_3_5[1] = lower_xor_3_6[9];
constraint lower_rot_3_5[2] = lower_xor_3_6[10];
constraint lower_rot_3_5[3] = lower_xor_3_6[11];
constraint lower_rot_3_5[4] = lower_xor_3_6[12];
constraint lower_rot_3_5[5] = lower_xor_3_6[13];
constraint lower_rot_3_5[6] = lower_xor_3_6[14];
constraint lower_rot_3_5[7] = lower_xor_3_6[15];
constraint lower_rot_3_5[8] = lower_xor_3_6[0];
constraint lower_rot_3_5[9] = lower_xor_3_6[1];
constraint lower_rot_3_5[10] = lower_xor_3_6[2];
constraint lower_rot_3_5[11] = lower_xor_3_6[3];
constraint lower_rot_3_5[12] = lower_xor_3_6[4];
constraint lower_rot_3_5[13] = lower_xor_3_6[5];
constraint lower_rot_3_5[14] = lower_xor_3_6[6];
constraint lower_rot_3_5[15] = lower_xor_3_6[7];
constraint pre_lower_modadd_3_0_0[0] = lower_rot_3_3[0];
constraint pre_lower_modadd_3_0_0[1] = lower_rot_3_3[1];
constraint pre_lower_modadd_3_0_0[2] = lower_rot_3_3[2];
constraint pre_lower_modadd_3_0_0[3] = lower_rot_3_3[3];
constraint pre_lower_modadd_3_0_0[4] = lower_rot_3_3[4];
constraint pre_lower_modadd_3_0_0[5] = lower_rot_3_3[5];
constraint pre_lower_modadd_3_0_0[6] = lower_rot_3_3[6];
constraint pre_lower_modadd_3_0_0[7] = lower_rot_3_3[7];
constraint pre_lower_modadd_3_0_0[8] = lower_rot_3_3[8];
constraint pre_lower_modadd_3_0_0[9] = lower_rot_3_3[9];
constraint pre_lower_modadd_3_0_0[10] = lower_rot_3_3[10];
constraint pre_lower_modadd_3_0_0[11] = lower_rot_3_3[11];
constraint pre_lower_modadd_3_0_0[12] = lower_rot_3_3[12];
constraint pre_lower_modadd_3_0_0[13] = lower_rot_3_3[13];
constraint pre_lower_modadd_3_0_0[14] = lower_rot_3_3[14];
constraint pre_lower_modadd_3_0_0[15] = lower_rot_3_3[15];
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
constraint forall(j in 0..15)(if eq_lower_modadd_3_0[j] = 1 then (sum([pre_lower_modadd_3_0_1[j], pre_lower_modadd_3_0_0[j], lower_modadd_3_0[j]]) mod 2) = Shi_pre_lower_modadd_3_0_0[j] else true endif) /\ lower_p[2] = (16-sum(eq_lower_modadd_3_0))*100;
constraint pre_lower_modadd_3_4_0[0] = lower_modadd_3_10[0];
constraint pre_lower_modadd_3_4_0[1] = lower_modadd_3_10[1];
constraint pre_lower_modadd_3_4_0[2] = lower_modadd_3_10[2];
constraint pre_lower_modadd_3_4_0[3] = lower_modadd_3_10[3];
constraint pre_lower_modadd_3_4_0[4] = lower_modadd_3_10[4];
constraint pre_lower_modadd_3_4_0[5] = lower_modadd_3_10[5];
constraint pre_lower_modadd_3_4_0[6] = lower_modadd_3_10[6];
constraint pre_lower_modadd_3_4_0[7] = lower_modadd_3_10[7];
constraint pre_lower_modadd_3_4_0[8] = lower_modadd_3_10[8];
constraint pre_lower_modadd_3_4_0[9] = lower_modadd_3_10[9];
constraint pre_lower_modadd_3_4_0[10] = lower_modadd_3_10[10];
constraint pre_lower_modadd_3_4_0[11] = lower_modadd_3_10[11];
constraint pre_lower_modadd_3_4_0[12] = lower_modadd_3_10[12];
constraint pre_lower_modadd_3_4_0[13] = lower_modadd_3_10[13];
constraint pre_lower_modadd_3_4_0[14] = lower_modadd_3_10[14];
constraint pre_lower_modadd_3_4_0[15] = lower_modadd_3_10[15];
constraint pre_lower_modadd_3_4_1[0] = lower_rot_3_5[0];
constraint pre_lower_modadd_3_4_1[1] = lower_rot_3_5[1];
constraint pre_lower_modadd_3_4_1[2] = lower_rot_3_5[2];
constraint pre_lower_modadd_3_4_1[3] = lower_rot_3_5[3];
constraint pre_lower_modadd_3_4_1[4] = lower_rot_3_5[4];
constraint pre_lower_modadd_3_4_1[5] = lower_rot_3_5[5];
constraint pre_lower_modadd_3_4_1[6] = lower_rot_3_5[6];
constraint pre_lower_modadd_3_4_1[7] = lower_rot_3_5[7];
constraint pre_lower_modadd_3_4_1[8] = lower_rot_3_5[8];
constraint pre_lower_modadd_3_4_1[9] = lower_rot_3_5[9];
constraint pre_lower_modadd_3_4_1[10] = lower_rot_3_5[10];
constraint pre_lower_modadd_3_4_1[11] = lower_rot_3_5[11];
constraint pre_lower_modadd_3_4_1[12] = lower_rot_3_5[12];
constraint pre_lower_modadd_3_4_1[13] = lower_rot_3_5[13];
constraint pre_lower_modadd_3_4_1[14] = lower_rot_3_5[14];
constraint pre_lower_modadd_3_4_1[15] = lower_rot_3_5[15];
constraint forall(j in 0..15)(if eq_lower_modadd_3_4[j] = 1 then (sum([pre_lower_modadd_3_4_1[j], pre_lower_modadd_3_4_0[j], lower_modadd_3_4[j]]) mod 2) = Shi_pre_lower_modadd_3_4_0[j] else true endif) /\ lower_p[3] = (16-sum(eq_lower_modadd_3_4))*100;
constraint 2*dummy_lower_xor_4_9[0] = (lower_modadd_5_0[0] + lower_rot_5_5[0] + lower_xor_4_9[0]);
constraint 2*dummy_lower_xor_4_9[1] = (lower_modadd_5_0[1] + lower_rot_5_5[1] + lower_xor_4_9[1]);
constraint 2*dummy_lower_xor_4_9[2] = (lower_modadd_5_0[2] + lower_rot_5_5[2] + lower_xor_4_9[2]);
constraint 2*dummy_lower_xor_4_9[3] = (lower_modadd_5_0[3] + lower_rot_5_5[3] + lower_xor_4_9[3]);
constraint 2*dummy_lower_xor_4_9[4] = (lower_modadd_5_0[4] + lower_rot_5_5[4] + lower_xor_4_9[4]);
constraint 2*dummy_lower_xor_4_9[5] = (lower_modadd_5_0[5] + lower_rot_5_5[5] + lower_xor_4_9[5]);
constraint 2*dummy_lower_xor_4_9[6] = (lower_modadd_5_0[6] + lower_rot_5_5[6] + lower_xor_4_9[6]);
constraint 2*dummy_lower_xor_4_9[7] = (lower_modadd_5_0[7] + lower_rot_5_5[7] + lower_xor_4_9[7]);
constraint 2*dummy_lower_xor_4_9[8] = (lower_modadd_5_0[8] + lower_rot_5_5[8] + lower_xor_4_9[8]);
constraint 2*dummy_lower_xor_4_9[9] = (lower_modadd_5_0[9] + lower_rot_5_5[9] + lower_xor_4_9[9]);
constraint 2*dummy_lower_xor_4_9[10] = (lower_modadd_5_0[10] + lower_rot_5_5[10] + lower_xor_4_9[10]);
constraint 2*dummy_lower_xor_4_9[11] = (lower_modadd_5_0[11] + lower_rot_5_5[11] + lower_xor_4_9[11]);
constraint 2*dummy_lower_xor_4_9[12] = (lower_modadd_5_0[12] + lower_rot_5_5[12] + lower_xor_4_9[12]);
constraint 2*dummy_lower_xor_4_9[13] = (lower_modadd_5_0[13] + lower_rot_5_5[13] + lower_xor_4_9[13]);
constraint 2*dummy_lower_xor_4_9[14] = (lower_modadd_5_0[14] + lower_rot_5_5[14] + lower_xor_4_9[14]);
constraint 2*dummy_lower_xor_4_9[15] = (lower_modadd_5_0[15] + lower_rot_5_5[15] + lower_xor_4_9[15]);
constraint lower_rot_4_13[0] = lower_modadd_5_4[0];
constraint lower_rot_4_13[1] = lower_modadd_5_4[1];
constraint lower_rot_4_13[2] = lower_modadd_5_4[2];
constraint lower_rot_4_13[3] = lower_modadd_5_4[3];
constraint lower_rot_4_13[4] = lower_modadd_5_4[4];
constraint lower_rot_4_13[5] = lower_modadd_5_4[5];
constraint lower_rot_4_13[6] = lower_modadd_5_4[6];
constraint lower_rot_4_13[7] = lower_modadd_5_4[7];
constraint lower_rot_4_13[8] = lower_modadd_5_4[8];
constraint lower_rot_4_13[9] = lower_modadd_5_4[9];
constraint lower_rot_4_13[10] = lower_modadd_5_4[10];
constraint lower_rot_4_13[11] = lower_modadd_5_4[11];
constraint lower_rot_4_13[12] = lower_modadd_5_4[12];
constraint lower_rot_4_13[13] = lower_modadd_5_4[13];
constraint lower_rot_4_13[14] = lower_modadd_5_4[14];
constraint lower_rot_4_13[15] = lower_modadd_5_4[15];
constraint lower_intermediate_output_4_14[0] = lower_modadd_5_0[0];
constraint lower_intermediate_output_4_14[1] = lower_modadd_5_0[1];
constraint lower_intermediate_output_4_14[2] = lower_modadd_5_0[2];
constraint lower_intermediate_output_4_14[3] = lower_modadd_5_0[3];
constraint lower_intermediate_output_4_14[4] = lower_modadd_5_0[4];
constraint lower_intermediate_output_4_14[5] = lower_modadd_5_0[5];
constraint lower_intermediate_output_4_14[6] = lower_modadd_5_0[6];
constraint lower_intermediate_output_4_14[7] = lower_modadd_5_0[7];
constraint lower_intermediate_output_4_14[8] = lower_modadd_5_0[8];
constraint lower_intermediate_output_4_14[9] = lower_modadd_5_0[9];
constraint lower_intermediate_output_4_14[10] = lower_modadd_5_0[10];
constraint lower_intermediate_output_4_14[11] = lower_modadd_5_0[11];
constraint lower_intermediate_output_4_14[12] = lower_modadd_5_0[12];
constraint lower_intermediate_output_4_14[13] = lower_modadd_5_0[13];
constraint lower_intermediate_output_4_14[14] = lower_modadd_5_0[14];
constraint lower_intermediate_output_4_14[15] = lower_modadd_5_0[15];
constraint lower_intermediate_output_4_14[16] = lower_rot_5_1[0];
constraint lower_intermediate_output_4_14[17] = lower_rot_5_1[1];
constraint lower_intermediate_output_4_14[18] = lower_rot_5_1[2];
constraint lower_intermediate_output_4_14[19] = lower_rot_5_1[3];
constraint lower_intermediate_output_4_14[20] = lower_rot_5_1[4];
constraint lower_intermediate_output_4_14[21] = lower_rot_5_1[5];
constraint lower_intermediate_output_4_14[22] = lower_rot_5_1[6];
constraint lower_intermediate_output_4_14[23] = lower_rot_5_1[7];
constraint lower_intermediate_output_4_14[24] = lower_rot_5_1[8];
constraint lower_intermediate_output_4_14[25] = lower_rot_5_1[9];
constraint lower_intermediate_output_4_14[26] = lower_rot_5_1[10];
constraint lower_intermediate_output_4_14[27] = lower_rot_5_1[11];
constraint lower_intermediate_output_4_14[28] = lower_rot_5_1[12];
constraint lower_intermediate_output_4_14[29] = lower_rot_5_1[13];
constraint lower_intermediate_output_4_14[30] = lower_rot_5_1[14];
constraint lower_intermediate_output_4_14[31] = lower_rot_5_1[15];
constraint lower_intermediate_output_4_14[32] = lower_modadd_5_4[0];
constraint lower_intermediate_output_4_14[33] = lower_modadd_5_4[1];
constraint lower_intermediate_output_4_14[34] = lower_modadd_5_4[2];
constraint lower_intermediate_output_4_14[35] = lower_modadd_5_4[3];
constraint lower_intermediate_output_4_14[36] = lower_modadd_5_4[4];
constraint lower_intermediate_output_4_14[37] = lower_modadd_5_4[5];
constraint lower_intermediate_output_4_14[38] = lower_modadd_5_4[6];
constraint lower_intermediate_output_4_14[39] = lower_modadd_5_4[7];
constraint lower_intermediate_output_4_14[40] = lower_modadd_5_4[8];
constraint lower_intermediate_output_4_14[41] = lower_modadd_5_4[9];
constraint lower_intermediate_output_4_14[42] = lower_modadd_5_4[10];
constraint lower_intermediate_output_4_14[43] = lower_modadd_5_4[11];
constraint lower_intermediate_output_4_14[44] = lower_modadd_5_4[12];
constraint lower_intermediate_output_4_14[45] = lower_modadd_5_4[13];
constraint lower_intermediate_output_4_14[46] = lower_modadd_5_4[14];
constraint lower_intermediate_output_4_14[47] = lower_modadd_5_4[15];
constraint lower_intermediate_output_4_14[48] = lower_rot_5_5[0];
constraint lower_intermediate_output_4_14[49] = lower_rot_5_5[1];
constraint lower_intermediate_output_4_14[50] = lower_rot_5_5[2];
constraint lower_intermediate_output_4_14[51] = lower_rot_5_5[3];
constraint lower_intermediate_output_4_14[52] = lower_rot_5_5[4];
constraint lower_intermediate_output_4_14[53] = lower_rot_5_5[5];
constraint lower_intermediate_output_4_14[54] = lower_rot_5_5[6];
constraint lower_intermediate_output_4_14[55] = lower_rot_5_5[7];
constraint lower_intermediate_output_4_14[56] = lower_rot_5_5[8];
constraint lower_intermediate_output_4_14[57] = lower_rot_5_5[9];
constraint lower_intermediate_output_4_14[58] = lower_rot_5_5[10];
constraint lower_intermediate_output_4_14[59] = lower_rot_5_5[11];
constraint lower_intermediate_output_4_14[60] = lower_rot_5_5[12];
constraint lower_intermediate_output_4_14[61] = lower_rot_5_5[13];
constraint lower_intermediate_output_4_14[62] = lower_rot_5_5[14];
constraint lower_intermediate_output_4_14[63] = lower_rot_5_5[15];
constraint lower_rot_4_8[0] = lower_xor_4_9[3];
constraint lower_rot_4_8[1] = lower_xor_4_9[4];
constraint lower_rot_4_8[2] = lower_xor_4_9[5];
constraint lower_rot_4_8[3] = lower_xor_4_9[6];
constraint lower_rot_4_8[4] = lower_xor_4_9[7];
constraint lower_rot_4_8[5] = lower_xor_4_9[8];
constraint lower_rot_4_8[6] = lower_xor_4_9[9];
constraint lower_rot_4_8[7] = lower_xor_4_9[10];
constraint lower_rot_4_8[8] = lower_xor_4_9[11];
constraint lower_rot_4_8[9] = lower_xor_4_9[12];
constraint lower_rot_4_8[10] = lower_xor_4_9[13];
constraint lower_rot_4_8[11] = lower_xor_4_9[14];
constraint lower_rot_4_8[12] = lower_xor_4_9[15];
constraint lower_rot_4_8[13] = lower_xor_4_9[0];
constraint lower_rot_4_8[14] = lower_xor_4_9[1];
constraint lower_rot_4_8[15] = lower_xor_4_9[2];
constraint 2*dummy_lower_xor_4_12[0] = (lower_rot_4_13[0] + lower_rot_5_1[0] + lower_xor_4_12[0]);
constraint 2*dummy_lower_xor_4_12[1] = (lower_rot_4_13[1] + lower_rot_5_1[1] + lower_xor_4_12[1]);
constraint 2*dummy_lower_xor_4_12[2] = (lower_rot_4_13[2] + lower_rot_5_1[2] + lower_xor_4_12[2]);
constraint 2*dummy_lower_xor_4_12[3] = (lower_rot_4_13[3] + lower_rot_5_1[3] + lower_xor_4_12[3]);
constraint 2*dummy_lower_xor_4_12[4] = (lower_rot_4_13[4] + lower_rot_5_1[4] + lower_xor_4_12[4]);
constraint 2*dummy_lower_xor_4_12[5] = (lower_rot_4_13[5] + lower_rot_5_1[5] + lower_xor_4_12[5]);
constraint 2*dummy_lower_xor_4_12[6] = (lower_rot_4_13[6] + lower_rot_5_1[6] + lower_xor_4_12[6]);
constraint 2*dummy_lower_xor_4_12[7] = (lower_rot_4_13[7] + lower_rot_5_1[7] + lower_xor_4_12[7]);
constraint 2*dummy_lower_xor_4_12[8] = (lower_rot_4_13[8] + lower_rot_5_1[8] + lower_xor_4_12[8]);
constraint 2*dummy_lower_xor_4_12[9] = (lower_rot_4_13[9] + lower_rot_5_1[9] + lower_xor_4_12[9]);
constraint 2*dummy_lower_xor_4_12[10] = (lower_rot_4_13[10] + lower_rot_5_1[10] + lower_xor_4_12[10]);
constraint 2*dummy_lower_xor_4_12[11] = (lower_rot_4_13[11] + lower_rot_5_1[11] + lower_xor_4_12[11]);
constraint 2*dummy_lower_xor_4_12[12] = (lower_rot_4_13[12] + lower_rot_5_1[12] + lower_xor_4_12[12]);
constraint 2*dummy_lower_xor_4_12[13] = (lower_rot_4_13[13] + lower_rot_5_1[13] + lower_xor_4_12[13]);
constraint 2*dummy_lower_xor_4_12[14] = (lower_rot_4_13[14] + lower_rot_5_1[14] + lower_xor_4_12[14]);
constraint 2*dummy_lower_xor_4_12[15] = (lower_rot_4_13[15] + lower_rot_5_1[15] + lower_xor_4_12[15]);
constraint pre_lower_modadd_4_7_0[0] = lower_modadd_5_0[0];
constraint pre_lower_modadd_4_7_0[1] = lower_modadd_5_0[1];
constraint pre_lower_modadd_4_7_0[2] = lower_modadd_5_0[2];
constraint pre_lower_modadd_4_7_0[3] = lower_modadd_5_0[3];
constraint pre_lower_modadd_4_7_0[4] = lower_modadd_5_0[4];
constraint pre_lower_modadd_4_7_0[5] = lower_modadd_5_0[5];
constraint pre_lower_modadd_4_7_0[6] = lower_modadd_5_0[6];
constraint pre_lower_modadd_4_7_0[7] = lower_modadd_5_0[7];
constraint pre_lower_modadd_4_7_0[8] = lower_modadd_5_0[8];
constraint pre_lower_modadd_4_7_0[9] = lower_modadd_5_0[9];
constraint pre_lower_modadd_4_7_0[10] = lower_modadd_5_0[10];
constraint pre_lower_modadd_4_7_0[11] = lower_modadd_5_0[11];
constraint pre_lower_modadd_4_7_0[12] = lower_modadd_5_0[12];
constraint pre_lower_modadd_4_7_0[13] = lower_modadd_5_0[13];
constraint pre_lower_modadd_4_7_0[14] = lower_modadd_5_0[14];
constraint pre_lower_modadd_4_7_0[15] = lower_modadd_5_0[15];
constraint pre_lower_modadd_4_7_1[0] = lower_rot_4_8[0];
constraint pre_lower_modadd_4_7_1[1] = lower_rot_4_8[1];
constraint pre_lower_modadd_4_7_1[2] = lower_rot_4_8[2];
constraint pre_lower_modadd_4_7_1[3] = lower_rot_4_8[3];
constraint pre_lower_modadd_4_7_1[4] = lower_rot_4_8[4];
constraint pre_lower_modadd_4_7_1[5] = lower_rot_4_8[5];
constraint pre_lower_modadd_4_7_1[6] = lower_rot_4_8[6];
constraint pre_lower_modadd_4_7_1[7] = lower_rot_4_8[7];
constraint pre_lower_modadd_4_7_1[8] = lower_rot_4_8[8];
constraint pre_lower_modadd_4_7_1[9] = lower_rot_4_8[9];
constraint pre_lower_modadd_4_7_1[10] = lower_rot_4_8[10];
constraint pre_lower_modadd_4_7_1[11] = lower_rot_4_8[11];
constraint pre_lower_modadd_4_7_1[12] = lower_rot_4_8[12];
constraint pre_lower_modadd_4_7_1[13] = lower_rot_4_8[13];
constraint pre_lower_modadd_4_7_1[14] = lower_rot_4_8[14];
constraint pre_lower_modadd_4_7_1[15] = lower_rot_4_8[15];
constraint forall(j in 0..15)(if eq_lower_modadd_4_7[j] = 1 then (sum([pre_lower_modadd_4_7_1[j], pre_lower_modadd_4_7_0[j], lower_modadd_4_7[j]]) mod 2) = Shi_pre_lower_modadd_4_7_0[j] else true endif) /\ lower_p[4] = (16-sum(eq_lower_modadd_4_7))*100;
constraint lower_rot_4_11[0] = lower_xor_4_12[9];
constraint lower_rot_4_11[1] = lower_xor_4_12[10];
constraint lower_rot_4_11[2] = lower_xor_4_12[11];
constraint lower_rot_4_11[3] = lower_xor_4_12[12];
constraint lower_rot_4_11[4] = lower_xor_4_12[13];
constraint lower_rot_4_11[5] = lower_xor_4_12[14];
constraint lower_rot_4_11[6] = lower_xor_4_12[15];
constraint lower_rot_4_11[7] = lower_xor_4_12[0];
constraint lower_rot_4_11[8] = lower_xor_4_12[1];
constraint lower_rot_4_11[9] = lower_xor_4_12[2];
constraint lower_rot_4_11[10] = lower_xor_4_12[3];
constraint lower_rot_4_11[11] = lower_xor_4_12[4];
constraint lower_rot_4_11[12] = lower_xor_4_12[5];
constraint lower_rot_4_11[13] = lower_xor_4_12[6];
constraint lower_rot_4_11[14] = lower_xor_4_12[7];
constraint lower_rot_4_11[15] = lower_xor_4_12[8];
constraint lower_rot_4_3[0] = lower_modadd_4_7[0];
constraint lower_rot_4_3[1] = lower_modadd_4_7[1];
constraint lower_rot_4_3[2] = lower_modadd_4_7[2];
constraint lower_rot_4_3[3] = lower_modadd_4_7[3];
constraint lower_rot_4_3[4] = lower_modadd_4_7[4];
constraint lower_rot_4_3[5] = lower_modadd_4_7[5];
constraint lower_rot_4_3[6] = lower_modadd_4_7[6];
constraint lower_rot_4_3[7] = lower_modadd_4_7[7];
constraint lower_rot_4_3[8] = lower_modadd_4_7[8];
constraint lower_rot_4_3[9] = lower_modadd_4_7[9];
constraint lower_rot_4_3[10] = lower_modadd_4_7[10];
constraint lower_rot_4_3[11] = lower_modadd_4_7[11];
constraint lower_rot_4_3[12] = lower_modadd_4_7[12];
constraint lower_rot_4_3[13] = lower_modadd_4_7[13];
constraint lower_rot_4_3[14] = lower_modadd_4_7[14];
constraint lower_rot_4_3[15] = lower_modadd_4_7[15];
constraint pre_lower_modadd_4_10_0[0] = lower_rot_4_13[0];
constraint pre_lower_modadd_4_10_0[1] = lower_rot_4_13[1];
constraint pre_lower_modadd_4_10_0[2] = lower_rot_4_13[2];
constraint pre_lower_modadd_4_10_0[3] = lower_rot_4_13[3];
constraint pre_lower_modadd_4_10_0[4] = lower_rot_4_13[4];
constraint pre_lower_modadd_4_10_0[5] = lower_rot_4_13[5];
constraint pre_lower_modadd_4_10_0[6] = lower_rot_4_13[6];
constraint pre_lower_modadd_4_10_0[7] = lower_rot_4_13[7];
constraint pre_lower_modadd_4_10_0[8] = lower_rot_4_13[8];
constraint pre_lower_modadd_4_10_0[9] = lower_rot_4_13[9];
constraint pre_lower_modadd_4_10_0[10] = lower_rot_4_13[10];
constraint pre_lower_modadd_4_10_0[11] = lower_rot_4_13[11];
constraint pre_lower_modadd_4_10_0[12] = lower_rot_4_13[12];
constraint pre_lower_modadd_4_10_0[13] = lower_rot_4_13[13];
constraint pre_lower_modadd_4_10_0[14] = lower_rot_4_13[14];
constraint pre_lower_modadd_4_10_0[15] = lower_rot_4_13[15];
constraint pre_lower_modadd_4_10_1[0] = lower_rot_4_11[0];
constraint pre_lower_modadd_4_10_1[1] = lower_rot_4_11[1];
constraint pre_lower_modadd_4_10_1[2] = lower_rot_4_11[2];
constraint pre_lower_modadd_4_10_1[3] = lower_rot_4_11[3];
constraint pre_lower_modadd_4_10_1[4] = lower_rot_4_11[4];
constraint pre_lower_modadd_4_10_1[5] = lower_rot_4_11[5];
constraint pre_lower_modadd_4_10_1[6] = lower_rot_4_11[6];
constraint pre_lower_modadd_4_10_1[7] = lower_rot_4_11[7];
constraint pre_lower_modadd_4_10_1[8] = lower_rot_4_11[8];
constraint pre_lower_modadd_4_10_1[9] = lower_rot_4_11[9];
constraint pre_lower_modadd_4_10_1[10] = lower_rot_4_11[10];
constraint pre_lower_modadd_4_10_1[11] = lower_rot_4_11[11];
constraint pre_lower_modadd_4_10_1[12] = lower_rot_4_11[12];
constraint pre_lower_modadd_4_10_1[13] = lower_rot_4_11[13];
constraint pre_lower_modadd_4_10_1[14] = lower_rot_4_11[14];
constraint pre_lower_modadd_4_10_1[15] = lower_rot_4_11[15];
constraint forall(j in 0..15)(if eq_lower_modadd_4_10[j] = 1 then (sum([pre_lower_modadd_4_10_1[j], pre_lower_modadd_4_10_0[j], lower_modadd_4_10[j]]) mod 2) = Shi_pre_lower_modadd_4_10_0[j] else true endif) /\ lower_p[5] = (16-sum(eq_lower_modadd_4_10))*100;
constraint 2*dummy_lower_xor_4_2[0] = (lower_rot_4_3[0] + lower_rot_4_11[0] + lower_xor_4_2[0]);
constraint 2*dummy_lower_xor_4_2[1] = (lower_rot_4_3[1] + lower_rot_4_11[1] + lower_xor_4_2[1]);
constraint 2*dummy_lower_xor_4_2[2] = (lower_rot_4_3[2] + lower_rot_4_11[2] + lower_xor_4_2[2]);
constraint 2*dummy_lower_xor_4_2[3] = (lower_rot_4_3[3] + lower_rot_4_11[3] + lower_xor_4_2[3]);
constraint 2*dummy_lower_xor_4_2[4] = (lower_rot_4_3[4] + lower_rot_4_11[4] + lower_xor_4_2[4]);
constraint 2*dummy_lower_xor_4_2[5] = (lower_rot_4_3[5] + lower_rot_4_11[5] + lower_xor_4_2[5]);
constraint 2*dummy_lower_xor_4_2[6] = (lower_rot_4_3[6] + lower_rot_4_11[6] + lower_xor_4_2[6]);
constraint 2*dummy_lower_xor_4_2[7] = (lower_rot_4_3[7] + lower_rot_4_11[7] + lower_xor_4_2[7]);
constraint 2*dummy_lower_xor_4_2[8] = (lower_rot_4_3[8] + lower_rot_4_11[8] + lower_xor_4_2[8]);
constraint 2*dummy_lower_xor_4_2[9] = (lower_rot_4_3[9] + lower_rot_4_11[9] + lower_xor_4_2[9]);
constraint 2*dummy_lower_xor_4_2[10] = (lower_rot_4_3[10] + lower_rot_4_11[10] + lower_xor_4_2[10]);
constraint 2*dummy_lower_xor_4_2[11] = (lower_rot_4_3[11] + lower_rot_4_11[11] + lower_xor_4_2[11]);
constraint 2*dummy_lower_xor_4_2[12] = (lower_rot_4_3[12] + lower_rot_4_11[12] + lower_xor_4_2[12]);
constraint 2*dummy_lower_xor_4_2[13] = (lower_rot_4_3[13] + lower_rot_4_11[13] + lower_xor_4_2[13]);
constraint 2*dummy_lower_xor_4_2[14] = (lower_rot_4_3[14] + lower_rot_4_11[14] + lower_xor_4_2[14]);
constraint 2*dummy_lower_xor_4_2[15] = (lower_rot_4_3[15] + lower_rot_4_11[15] + lower_xor_4_2[15]);
constraint 2*dummy_lower_xor_4_6[0] = (lower_modadd_4_10[0] + lower_rot_4_8[0] + lower_xor_4_6[0]);
constraint 2*dummy_lower_xor_4_6[1] = (lower_modadd_4_10[1] + lower_rot_4_8[1] + lower_xor_4_6[1]);
constraint 2*dummy_lower_xor_4_6[2] = (lower_modadd_4_10[2] + lower_rot_4_8[2] + lower_xor_4_6[2]);
constraint 2*dummy_lower_xor_4_6[3] = (lower_modadd_4_10[3] + lower_rot_4_8[3] + lower_xor_4_6[3]);
constraint 2*dummy_lower_xor_4_6[4] = (lower_modadd_4_10[4] + lower_rot_4_8[4] + lower_xor_4_6[4]);
constraint 2*dummy_lower_xor_4_6[5] = (lower_modadd_4_10[5] + lower_rot_4_8[5] + lower_xor_4_6[5]);
constraint 2*dummy_lower_xor_4_6[6] = (lower_modadd_4_10[6] + lower_rot_4_8[6] + lower_xor_4_6[6]);
constraint 2*dummy_lower_xor_4_6[7] = (lower_modadd_4_10[7] + lower_rot_4_8[7] + lower_xor_4_6[7]);
constraint 2*dummy_lower_xor_4_6[8] = (lower_modadd_4_10[8] + lower_rot_4_8[8] + lower_xor_4_6[8]);
constraint 2*dummy_lower_xor_4_6[9] = (lower_modadd_4_10[9] + lower_rot_4_8[9] + lower_xor_4_6[9]);
constraint 2*dummy_lower_xor_4_6[10] = (lower_modadd_4_10[10] + lower_rot_4_8[10] + lower_xor_4_6[10]);
constraint 2*dummy_lower_xor_4_6[11] = (lower_modadd_4_10[11] + lower_rot_4_8[11] + lower_xor_4_6[11]);
constraint 2*dummy_lower_xor_4_6[12] = (lower_modadd_4_10[12] + lower_rot_4_8[12] + lower_xor_4_6[12]);
constraint 2*dummy_lower_xor_4_6[13] = (lower_modadd_4_10[13] + lower_rot_4_8[13] + lower_xor_4_6[13]);
constraint 2*dummy_lower_xor_4_6[14] = (lower_modadd_4_10[14] + lower_rot_4_8[14] + lower_xor_4_6[14]);
constraint 2*dummy_lower_xor_4_6[15] = (lower_modadd_4_10[15] + lower_rot_4_8[15] + lower_xor_4_6[15]);
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
constraint forall(j in 0..15)(if eq_lower_modadd_4_0[j] = 1 then (sum([pre_lower_modadd_4_0_1[j], pre_lower_modadd_4_0_0[j], lower_modadd_4_0[j]]) mod 2) = Shi_pre_lower_modadd_4_0_0[j] else true endif) /\ lower_p[6] = (16-sum(eq_lower_modadd_4_0))*100;
constraint pre_lower_modadd_4_4_0[0] = lower_modadd_4_10[0];
constraint pre_lower_modadd_4_4_0[1] = lower_modadd_4_10[1];
constraint pre_lower_modadd_4_4_0[2] = lower_modadd_4_10[2];
constraint pre_lower_modadd_4_4_0[3] = lower_modadd_4_10[3];
constraint pre_lower_modadd_4_4_0[4] = lower_modadd_4_10[4];
constraint pre_lower_modadd_4_4_0[5] = lower_modadd_4_10[5];
constraint pre_lower_modadd_4_4_0[6] = lower_modadd_4_10[6];
constraint pre_lower_modadd_4_4_0[7] = lower_modadd_4_10[7];
constraint pre_lower_modadd_4_4_0[8] = lower_modadd_4_10[8];
constraint pre_lower_modadd_4_4_0[9] = lower_modadd_4_10[9];
constraint pre_lower_modadd_4_4_0[10] = lower_modadd_4_10[10];
constraint pre_lower_modadd_4_4_0[11] = lower_modadd_4_10[11];
constraint pre_lower_modadd_4_4_0[12] = lower_modadd_4_10[12];
constraint pre_lower_modadd_4_4_0[13] = lower_modadd_4_10[13];
constraint pre_lower_modadd_4_4_0[14] = lower_modadd_4_10[14];
constraint pre_lower_modadd_4_4_0[15] = lower_modadd_4_10[15];
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
constraint forall(j in 0..15)(if eq_lower_modadd_4_4[j] = 1 then (sum([pre_lower_modadd_4_4_1[j], pre_lower_modadd_4_4_0[j], lower_modadd_4_4[j]]) mod 2) = Shi_pre_lower_modadd_4_4_0[j] else true endif) /\ lower_p[7] = (16-sum(eq_lower_modadd_4_4))*100;
constraint 2*dummy_lower_xor_5_9[0] = (lower_modadd_6_0[0] + lower_rot_6_5[0] + lower_xor_5_9[0]);
constraint 2*dummy_lower_xor_5_9[1] = (lower_modadd_6_0[1] + lower_rot_6_5[1] + lower_xor_5_9[1]);
constraint 2*dummy_lower_xor_5_9[2] = (lower_modadd_6_0[2] + lower_rot_6_5[2] + lower_xor_5_9[2]);
constraint 2*dummy_lower_xor_5_9[3] = (lower_modadd_6_0[3] + lower_rot_6_5[3] + lower_xor_5_9[3]);
constraint 2*dummy_lower_xor_5_9[4] = (lower_modadd_6_0[4] + lower_rot_6_5[4] + lower_xor_5_9[4]);
constraint 2*dummy_lower_xor_5_9[5] = (lower_modadd_6_0[5] + lower_rot_6_5[5] + lower_xor_5_9[5]);
constraint 2*dummy_lower_xor_5_9[6] = (lower_modadd_6_0[6] + lower_rot_6_5[6] + lower_xor_5_9[6]);
constraint 2*dummy_lower_xor_5_9[7] = (lower_modadd_6_0[7] + lower_rot_6_5[7] + lower_xor_5_9[7]);
constraint 2*dummy_lower_xor_5_9[8] = (lower_modadd_6_0[8] + lower_rot_6_5[8] + lower_xor_5_9[8]);
constraint 2*dummy_lower_xor_5_9[9] = (lower_modadd_6_0[9] + lower_rot_6_5[9] + lower_xor_5_9[9]);
constraint 2*dummy_lower_xor_5_9[10] = (lower_modadd_6_0[10] + lower_rot_6_5[10] + lower_xor_5_9[10]);
constraint 2*dummy_lower_xor_5_9[11] = (lower_modadd_6_0[11] + lower_rot_6_5[11] + lower_xor_5_9[11]);
constraint 2*dummy_lower_xor_5_9[12] = (lower_modadd_6_0[12] + lower_rot_6_5[12] + lower_xor_5_9[12]);
constraint 2*dummy_lower_xor_5_9[13] = (lower_modadd_6_0[13] + lower_rot_6_5[13] + lower_xor_5_9[13]);
constraint 2*dummy_lower_xor_5_9[14] = (lower_modadd_6_0[14] + lower_rot_6_5[14] + lower_xor_5_9[14]);
constraint 2*dummy_lower_xor_5_9[15] = (lower_modadd_6_0[15] + lower_rot_6_5[15] + lower_xor_5_9[15]);
constraint lower_rot_5_13[0] = lower_modadd_6_4[0];
constraint lower_rot_5_13[1] = lower_modadd_6_4[1];
constraint lower_rot_5_13[2] = lower_modadd_6_4[2];
constraint lower_rot_5_13[3] = lower_modadd_6_4[3];
constraint lower_rot_5_13[4] = lower_modadd_6_4[4];
constraint lower_rot_5_13[5] = lower_modadd_6_4[5];
constraint lower_rot_5_13[6] = lower_modadd_6_4[6];
constraint lower_rot_5_13[7] = lower_modadd_6_4[7];
constraint lower_rot_5_13[8] = lower_modadd_6_4[8];
constraint lower_rot_5_13[9] = lower_modadd_6_4[9];
constraint lower_rot_5_13[10] = lower_modadd_6_4[10];
constraint lower_rot_5_13[11] = lower_modadd_6_4[11];
constraint lower_rot_5_13[12] = lower_modadd_6_4[12];
constraint lower_rot_5_13[13] = lower_modadd_6_4[13];
constraint lower_rot_5_13[14] = lower_modadd_6_4[14];
constraint lower_rot_5_13[15] = lower_modadd_6_4[15];
constraint lower_intermediate_output_5_14[0] = lower_modadd_6_0[0];
constraint lower_intermediate_output_5_14[1] = lower_modadd_6_0[1];
constraint lower_intermediate_output_5_14[2] = lower_modadd_6_0[2];
constraint lower_intermediate_output_5_14[3] = lower_modadd_6_0[3];
constraint lower_intermediate_output_5_14[4] = lower_modadd_6_0[4];
constraint lower_intermediate_output_5_14[5] = lower_modadd_6_0[5];
constraint lower_intermediate_output_5_14[6] = lower_modadd_6_0[6];
constraint lower_intermediate_output_5_14[7] = lower_modadd_6_0[7];
constraint lower_intermediate_output_5_14[8] = lower_modadd_6_0[8];
constraint lower_intermediate_output_5_14[9] = lower_modadd_6_0[9];
constraint lower_intermediate_output_5_14[10] = lower_modadd_6_0[10];
constraint lower_intermediate_output_5_14[11] = lower_modadd_6_0[11];
constraint lower_intermediate_output_5_14[12] = lower_modadd_6_0[12];
constraint lower_intermediate_output_5_14[13] = lower_modadd_6_0[13];
constraint lower_intermediate_output_5_14[14] = lower_modadd_6_0[14];
constraint lower_intermediate_output_5_14[15] = lower_modadd_6_0[15];
constraint lower_intermediate_output_5_14[16] = lower_rot_6_1[0];
constraint lower_intermediate_output_5_14[17] = lower_rot_6_1[1];
constraint lower_intermediate_output_5_14[18] = lower_rot_6_1[2];
constraint lower_intermediate_output_5_14[19] = lower_rot_6_1[3];
constraint lower_intermediate_output_5_14[20] = lower_rot_6_1[4];
constraint lower_intermediate_output_5_14[21] = lower_rot_6_1[5];
constraint lower_intermediate_output_5_14[22] = lower_rot_6_1[6];
constraint lower_intermediate_output_5_14[23] = lower_rot_6_1[7];
constraint lower_intermediate_output_5_14[24] = lower_rot_6_1[8];
constraint lower_intermediate_output_5_14[25] = lower_rot_6_1[9];
constraint lower_intermediate_output_5_14[26] = lower_rot_6_1[10];
constraint lower_intermediate_output_5_14[27] = lower_rot_6_1[11];
constraint lower_intermediate_output_5_14[28] = lower_rot_6_1[12];
constraint lower_intermediate_output_5_14[29] = lower_rot_6_1[13];
constraint lower_intermediate_output_5_14[30] = lower_rot_6_1[14];
constraint lower_intermediate_output_5_14[31] = lower_rot_6_1[15];
constraint lower_intermediate_output_5_14[32] = lower_modadd_6_4[0];
constraint lower_intermediate_output_5_14[33] = lower_modadd_6_4[1];
constraint lower_intermediate_output_5_14[34] = lower_modadd_6_4[2];
constraint lower_intermediate_output_5_14[35] = lower_modadd_6_4[3];
constraint lower_intermediate_output_5_14[36] = lower_modadd_6_4[4];
constraint lower_intermediate_output_5_14[37] = lower_modadd_6_4[5];
constraint lower_intermediate_output_5_14[38] = lower_modadd_6_4[6];
constraint lower_intermediate_output_5_14[39] = lower_modadd_6_4[7];
constraint lower_intermediate_output_5_14[40] = lower_modadd_6_4[8];
constraint lower_intermediate_output_5_14[41] = lower_modadd_6_4[9];
constraint lower_intermediate_output_5_14[42] = lower_modadd_6_4[10];
constraint lower_intermediate_output_5_14[43] = lower_modadd_6_4[11];
constraint lower_intermediate_output_5_14[44] = lower_modadd_6_4[12];
constraint lower_intermediate_output_5_14[45] = lower_modadd_6_4[13];
constraint lower_intermediate_output_5_14[46] = lower_modadd_6_4[14];
constraint lower_intermediate_output_5_14[47] = lower_modadd_6_4[15];
constraint lower_intermediate_output_5_14[48] = lower_rot_6_5[0];
constraint lower_intermediate_output_5_14[49] = lower_rot_6_5[1];
constraint lower_intermediate_output_5_14[50] = lower_rot_6_5[2];
constraint lower_intermediate_output_5_14[51] = lower_rot_6_5[3];
constraint lower_intermediate_output_5_14[52] = lower_rot_6_5[4];
constraint lower_intermediate_output_5_14[53] = lower_rot_6_5[5];
constraint lower_intermediate_output_5_14[54] = lower_rot_6_5[6];
constraint lower_intermediate_output_5_14[55] = lower_rot_6_5[7];
constraint lower_intermediate_output_5_14[56] = lower_rot_6_5[8];
constraint lower_intermediate_output_5_14[57] = lower_rot_6_5[9];
constraint lower_intermediate_output_5_14[58] = lower_rot_6_5[10];
constraint lower_intermediate_output_5_14[59] = lower_rot_6_5[11];
constraint lower_intermediate_output_5_14[60] = lower_rot_6_5[12];
constraint lower_intermediate_output_5_14[61] = lower_rot_6_5[13];
constraint lower_intermediate_output_5_14[62] = lower_rot_6_5[14];
constraint lower_intermediate_output_5_14[63] = lower_rot_6_5[15];
constraint lower_rot_5_8[0] = lower_xor_5_9[3];
constraint lower_rot_5_8[1] = lower_xor_5_9[4];
constraint lower_rot_5_8[2] = lower_xor_5_9[5];
constraint lower_rot_5_8[3] = lower_xor_5_9[6];
constraint lower_rot_5_8[4] = lower_xor_5_9[7];
constraint lower_rot_5_8[5] = lower_xor_5_9[8];
constraint lower_rot_5_8[6] = lower_xor_5_9[9];
constraint lower_rot_5_8[7] = lower_xor_5_9[10];
constraint lower_rot_5_8[8] = lower_xor_5_9[11];
constraint lower_rot_5_8[9] = lower_xor_5_9[12];
constraint lower_rot_5_8[10] = lower_xor_5_9[13];
constraint lower_rot_5_8[11] = lower_xor_5_9[14];
constraint lower_rot_5_8[12] = lower_xor_5_9[15];
constraint lower_rot_5_8[13] = lower_xor_5_9[0];
constraint lower_rot_5_8[14] = lower_xor_5_9[1];
constraint lower_rot_5_8[15] = lower_xor_5_9[2];
constraint 2*dummy_lower_xor_5_12[0] = (lower_rot_5_13[0] + lower_rot_6_1[0] + lower_xor_5_12[0]);
constraint 2*dummy_lower_xor_5_12[1] = (lower_rot_5_13[1] + lower_rot_6_1[1] + lower_xor_5_12[1]);
constraint 2*dummy_lower_xor_5_12[2] = (lower_rot_5_13[2] + lower_rot_6_1[2] + lower_xor_5_12[2]);
constraint 2*dummy_lower_xor_5_12[3] = (lower_rot_5_13[3] + lower_rot_6_1[3] + lower_xor_5_12[3]);
constraint 2*dummy_lower_xor_5_12[4] = (lower_rot_5_13[4] + lower_rot_6_1[4] + lower_xor_5_12[4]);
constraint 2*dummy_lower_xor_5_12[5] = (lower_rot_5_13[5] + lower_rot_6_1[5] + lower_xor_5_12[5]);
constraint 2*dummy_lower_xor_5_12[6] = (lower_rot_5_13[6] + lower_rot_6_1[6] + lower_xor_5_12[6]);
constraint 2*dummy_lower_xor_5_12[7] = (lower_rot_5_13[7] + lower_rot_6_1[7] + lower_xor_5_12[7]);
constraint 2*dummy_lower_xor_5_12[8] = (lower_rot_5_13[8] + lower_rot_6_1[8] + lower_xor_5_12[8]);
constraint 2*dummy_lower_xor_5_12[9] = (lower_rot_5_13[9] + lower_rot_6_1[9] + lower_xor_5_12[9]);
constraint 2*dummy_lower_xor_5_12[10] = (lower_rot_5_13[10] + lower_rot_6_1[10] + lower_xor_5_12[10]);
constraint 2*dummy_lower_xor_5_12[11] = (lower_rot_5_13[11] + lower_rot_6_1[11] + lower_xor_5_12[11]);
constraint 2*dummy_lower_xor_5_12[12] = (lower_rot_5_13[12] + lower_rot_6_1[12] + lower_xor_5_12[12]);
constraint 2*dummy_lower_xor_5_12[13] = (lower_rot_5_13[13] + lower_rot_6_1[13] + lower_xor_5_12[13]);
constraint 2*dummy_lower_xor_5_12[14] = (lower_rot_5_13[14] + lower_rot_6_1[14] + lower_xor_5_12[14]);
constraint 2*dummy_lower_xor_5_12[15] = (lower_rot_5_13[15] + lower_rot_6_1[15] + lower_xor_5_12[15]);
constraint pre_lower_modadd_5_7_0[0] = lower_modadd_6_0[0];
constraint pre_lower_modadd_5_7_0[1] = lower_modadd_6_0[1];
constraint pre_lower_modadd_5_7_0[2] = lower_modadd_6_0[2];
constraint pre_lower_modadd_5_7_0[3] = lower_modadd_6_0[3];
constraint pre_lower_modadd_5_7_0[4] = lower_modadd_6_0[4];
constraint pre_lower_modadd_5_7_0[5] = lower_modadd_6_0[5];
constraint pre_lower_modadd_5_7_0[6] = lower_modadd_6_0[6];
constraint pre_lower_modadd_5_7_0[7] = lower_modadd_6_0[7];
constraint pre_lower_modadd_5_7_0[8] = lower_modadd_6_0[8];
constraint pre_lower_modadd_5_7_0[9] = lower_modadd_6_0[9];
constraint pre_lower_modadd_5_7_0[10] = lower_modadd_6_0[10];
constraint pre_lower_modadd_5_7_0[11] = lower_modadd_6_0[11];
constraint pre_lower_modadd_5_7_0[12] = lower_modadd_6_0[12];
constraint pre_lower_modadd_5_7_0[13] = lower_modadd_6_0[13];
constraint pre_lower_modadd_5_7_0[14] = lower_modadd_6_0[14];
constraint pre_lower_modadd_5_7_0[15] = lower_modadd_6_0[15];
constraint pre_lower_modadd_5_7_1[0] = lower_rot_5_8[0];
constraint pre_lower_modadd_5_7_1[1] = lower_rot_5_8[1];
constraint pre_lower_modadd_5_7_1[2] = lower_rot_5_8[2];
constraint pre_lower_modadd_5_7_1[3] = lower_rot_5_8[3];
constraint pre_lower_modadd_5_7_1[4] = lower_rot_5_8[4];
constraint pre_lower_modadd_5_7_1[5] = lower_rot_5_8[5];
constraint pre_lower_modadd_5_7_1[6] = lower_rot_5_8[6];
constraint pre_lower_modadd_5_7_1[7] = lower_rot_5_8[7];
constraint pre_lower_modadd_5_7_1[8] = lower_rot_5_8[8];
constraint pre_lower_modadd_5_7_1[9] = lower_rot_5_8[9];
constraint pre_lower_modadd_5_7_1[10] = lower_rot_5_8[10];
constraint pre_lower_modadd_5_7_1[11] = lower_rot_5_8[11];
constraint pre_lower_modadd_5_7_1[12] = lower_rot_5_8[12];
constraint pre_lower_modadd_5_7_1[13] = lower_rot_5_8[13];
constraint pre_lower_modadd_5_7_1[14] = lower_rot_5_8[14];
constraint pre_lower_modadd_5_7_1[15] = lower_rot_5_8[15];
constraint forall(j in 0..15)(if eq_lower_modadd_5_7[j] = 1 then (sum([pre_lower_modadd_5_7_1[j], pre_lower_modadd_5_7_0[j], lower_modadd_5_7[j]]) mod 2) = Shi_pre_lower_modadd_5_7_0[j] else true endif) /\ lower_p[8] = (16-sum(eq_lower_modadd_5_7))*100;
constraint lower_rot_5_11[0] = lower_xor_5_12[9];
constraint lower_rot_5_11[1] = lower_xor_5_12[10];
constraint lower_rot_5_11[2] = lower_xor_5_12[11];
constraint lower_rot_5_11[3] = lower_xor_5_12[12];
constraint lower_rot_5_11[4] = lower_xor_5_12[13];
constraint lower_rot_5_11[5] = lower_xor_5_12[14];
constraint lower_rot_5_11[6] = lower_xor_5_12[15];
constraint lower_rot_5_11[7] = lower_xor_5_12[0];
constraint lower_rot_5_11[8] = lower_xor_5_12[1];
constraint lower_rot_5_11[9] = lower_xor_5_12[2];
constraint lower_rot_5_11[10] = lower_xor_5_12[3];
constraint lower_rot_5_11[11] = lower_xor_5_12[4];
constraint lower_rot_5_11[12] = lower_xor_5_12[5];
constraint lower_rot_5_11[13] = lower_xor_5_12[6];
constraint lower_rot_5_11[14] = lower_xor_5_12[7];
constraint lower_rot_5_11[15] = lower_xor_5_12[8];
constraint lower_rot_5_3[0] = lower_modadd_5_7[0];
constraint lower_rot_5_3[1] = lower_modadd_5_7[1];
constraint lower_rot_5_3[2] = lower_modadd_5_7[2];
constraint lower_rot_5_3[3] = lower_modadd_5_7[3];
constraint lower_rot_5_3[4] = lower_modadd_5_7[4];
constraint lower_rot_5_3[5] = lower_modadd_5_7[5];
constraint lower_rot_5_3[6] = lower_modadd_5_7[6];
constraint lower_rot_5_3[7] = lower_modadd_5_7[7];
constraint lower_rot_5_3[8] = lower_modadd_5_7[8];
constraint lower_rot_5_3[9] = lower_modadd_5_7[9];
constraint lower_rot_5_3[10] = lower_modadd_5_7[10];
constraint lower_rot_5_3[11] = lower_modadd_5_7[11];
constraint lower_rot_5_3[12] = lower_modadd_5_7[12];
constraint lower_rot_5_3[13] = lower_modadd_5_7[13];
constraint lower_rot_5_3[14] = lower_modadd_5_7[14];
constraint lower_rot_5_3[15] = lower_modadd_5_7[15];
constraint pre_lower_modadd_5_10_0[0] = lower_rot_5_13[0];
constraint pre_lower_modadd_5_10_0[1] = lower_rot_5_13[1];
constraint pre_lower_modadd_5_10_0[2] = lower_rot_5_13[2];
constraint pre_lower_modadd_5_10_0[3] = lower_rot_5_13[3];
constraint pre_lower_modadd_5_10_0[4] = lower_rot_5_13[4];
constraint pre_lower_modadd_5_10_0[5] = lower_rot_5_13[5];
constraint pre_lower_modadd_5_10_0[6] = lower_rot_5_13[6];
constraint pre_lower_modadd_5_10_0[7] = lower_rot_5_13[7];
constraint pre_lower_modadd_5_10_0[8] = lower_rot_5_13[8];
constraint pre_lower_modadd_5_10_0[9] = lower_rot_5_13[9];
constraint pre_lower_modadd_5_10_0[10] = lower_rot_5_13[10];
constraint pre_lower_modadd_5_10_0[11] = lower_rot_5_13[11];
constraint pre_lower_modadd_5_10_0[12] = lower_rot_5_13[12];
constraint pre_lower_modadd_5_10_0[13] = lower_rot_5_13[13];
constraint pre_lower_modadd_5_10_0[14] = lower_rot_5_13[14];
constraint pre_lower_modadd_5_10_0[15] = lower_rot_5_13[15];
constraint pre_lower_modadd_5_10_1[0] = lower_rot_5_11[0];
constraint pre_lower_modadd_5_10_1[1] = lower_rot_5_11[1];
constraint pre_lower_modadd_5_10_1[2] = lower_rot_5_11[2];
constraint pre_lower_modadd_5_10_1[3] = lower_rot_5_11[3];
constraint pre_lower_modadd_5_10_1[4] = lower_rot_5_11[4];
constraint pre_lower_modadd_5_10_1[5] = lower_rot_5_11[5];
constraint pre_lower_modadd_5_10_1[6] = lower_rot_5_11[6];
constraint pre_lower_modadd_5_10_1[7] = lower_rot_5_11[7];
constraint pre_lower_modadd_5_10_1[8] = lower_rot_5_11[8];
constraint pre_lower_modadd_5_10_1[9] = lower_rot_5_11[9];
constraint pre_lower_modadd_5_10_1[10] = lower_rot_5_11[10];
constraint pre_lower_modadd_5_10_1[11] = lower_rot_5_11[11];
constraint pre_lower_modadd_5_10_1[12] = lower_rot_5_11[12];
constraint pre_lower_modadd_5_10_1[13] = lower_rot_5_11[13];
constraint pre_lower_modadd_5_10_1[14] = lower_rot_5_11[14];
constraint pre_lower_modadd_5_10_1[15] = lower_rot_5_11[15];
constraint forall(j in 0..15)(if eq_lower_modadd_5_10[j] = 1 then (sum([pre_lower_modadd_5_10_1[j], pre_lower_modadd_5_10_0[j], lower_modadd_5_10[j]]) mod 2) = Shi_pre_lower_modadd_5_10_0[j] else true endif) /\ lower_p[9] = (16-sum(eq_lower_modadd_5_10))*100;
constraint 2*dummy_lower_xor_5_2[0] = (lower_rot_5_3[0] + lower_rot_5_11[0] + lower_xor_5_2[0]);
constraint 2*dummy_lower_xor_5_2[1] = (lower_rot_5_3[1] + lower_rot_5_11[1] + lower_xor_5_2[1]);
constraint 2*dummy_lower_xor_5_2[2] = (lower_rot_5_3[2] + lower_rot_5_11[2] + lower_xor_5_2[2]);
constraint 2*dummy_lower_xor_5_2[3] = (lower_rot_5_3[3] + lower_rot_5_11[3] + lower_xor_5_2[3]);
constraint 2*dummy_lower_xor_5_2[4] = (lower_rot_5_3[4] + lower_rot_5_11[4] + lower_xor_5_2[4]);
constraint 2*dummy_lower_xor_5_2[5] = (lower_rot_5_3[5] + lower_rot_5_11[5] + lower_xor_5_2[5]);
constraint 2*dummy_lower_xor_5_2[6] = (lower_rot_5_3[6] + lower_rot_5_11[6] + lower_xor_5_2[6]);
constraint 2*dummy_lower_xor_5_2[7] = (lower_rot_5_3[7] + lower_rot_5_11[7] + lower_xor_5_2[7]);
constraint 2*dummy_lower_xor_5_2[8] = (lower_rot_5_3[8] + lower_rot_5_11[8] + lower_xor_5_2[8]);
constraint 2*dummy_lower_xor_5_2[9] = (lower_rot_5_3[9] + lower_rot_5_11[9] + lower_xor_5_2[9]);
constraint 2*dummy_lower_xor_5_2[10] = (lower_rot_5_3[10] + lower_rot_5_11[10] + lower_xor_5_2[10]);
constraint 2*dummy_lower_xor_5_2[11] = (lower_rot_5_3[11] + lower_rot_5_11[11] + lower_xor_5_2[11]);
constraint 2*dummy_lower_xor_5_2[12] = (lower_rot_5_3[12] + lower_rot_5_11[12] + lower_xor_5_2[12]);
constraint 2*dummy_lower_xor_5_2[13] = (lower_rot_5_3[13] + lower_rot_5_11[13] + lower_xor_5_2[13]);
constraint 2*dummy_lower_xor_5_2[14] = (lower_rot_5_3[14] + lower_rot_5_11[14] + lower_xor_5_2[14]);
constraint 2*dummy_lower_xor_5_2[15] = (lower_rot_5_3[15] + lower_rot_5_11[15] + lower_xor_5_2[15]);
constraint 2*dummy_lower_xor_5_6[0] = (lower_modadd_5_10[0] + lower_rot_5_8[0] + lower_xor_5_6[0]);
constraint 2*dummy_lower_xor_5_6[1] = (lower_modadd_5_10[1] + lower_rot_5_8[1] + lower_xor_5_6[1]);
constraint 2*dummy_lower_xor_5_6[2] = (lower_modadd_5_10[2] + lower_rot_5_8[2] + lower_xor_5_6[2]);
constraint 2*dummy_lower_xor_5_6[3] = (lower_modadd_5_10[3] + lower_rot_5_8[3] + lower_xor_5_6[3]);
constraint 2*dummy_lower_xor_5_6[4] = (lower_modadd_5_10[4] + lower_rot_5_8[4] + lower_xor_5_6[4]);
constraint 2*dummy_lower_xor_5_6[5] = (lower_modadd_5_10[5] + lower_rot_5_8[5] + lower_xor_5_6[5]);
constraint 2*dummy_lower_xor_5_6[6] = (lower_modadd_5_10[6] + lower_rot_5_8[6] + lower_xor_5_6[6]);
constraint 2*dummy_lower_xor_5_6[7] = (lower_modadd_5_10[7] + lower_rot_5_8[7] + lower_xor_5_6[7]);
constraint 2*dummy_lower_xor_5_6[8] = (lower_modadd_5_10[8] + lower_rot_5_8[8] + lower_xor_5_6[8]);
constraint 2*dummy_lower_xor_5_6[9] = (lower_modadd_5_10[9] + lower_rot_5_8[9] + lower_xor_5_6[9]);
constraint 2*dummy_lower_xor_5_6[10] = (lower_modadd_5_10[10] + lower_rot_5_8[10] + lower_xor_5_6[10]);
constraint 2*dummy_lower_xor_5_6[11] = (lower_modadd_5_10[11] + lower_rot_5_8[11] + lower_xor_5_6[11]);
constraint 2*dummy_lower_xor_5_6[12] = (lower_modadd_5_10[12] + lower_rot_5_8[12] + lower_xor_5_6[12]);
constraint 2*dummy_lower_xor_5_6[13] = (lower_modadd_5_10[13] + lower_rot_5_8[13] + lower_xor_5_6[13]);
constraint 2*dummy_lower_xor_5_6[14] = (lower_modadd_5_10[14] + lower_rot_5_8[14] + lower_xor_5_6[14]);
constraint 2*dummy_lower_xor_5_6[15] = (lower_modadd_5_10[15] + lower_rot_5_8[15] + lower_xor_5_6[15]);
constraint lower_rot_5_1[0] = lower_xor_5_2[11];
constraint lower_rot_5_1[1] = lower_xor_5_2[12];
constraint lower_rot_5_1[2] = lower_xor_5_2[13];
constraint lower_rot_5_1[3] = lower_xor_5_2[14];
constraint lower_rot_5_1[4] = lower_xor_5_2[15];
constraint lower_rot_5_1[5] = lower_xor_5_2[0];
constraint lower_rot_5_1[6] = lower_xor_5_2[1];
constraint lower_rot_5_1[7] = lower_xor_5_2[2];
constraint lower_rot_5_1[8] = lower_xor_5_2[3];
constraint lower_rot_5_1[9] = lower_xor_5_2[4];
constraint lower_rot_5_1[10] = lower_xor_5_2[5];
constraint lower_rot_5_1[11] = lower_xor_5_2[6];
constraint lower_rot_5_1[12] = lower_xor_5_2[7];
constraint lower_rot_5_1[13] = lower_xor_5_2[8];
constraint lower_rot_5_1[14] = lower_xor_5_2[9];
constraint lower_rot_5_1[15] = lower_xor_5_2[10];
constraint lower_rot_5_5[0] = lower_xor_5_6[8];
constraint lower_rot_5_5[1] = lower_xor_5_6[9];
constraint lower_rot_5_5[2] = lower_xor_5_6[10];
constraint lower_rot_5_5[3] = lower_xor_5_6[11];
constraint lower_rot_5_5[4] = lower_xor_5_6[12];
constraint lower_rot_5_5[5] = lower_xor_5_6[13];
constraint lower_rot_5_5[6] = lower_xor_5_6[14];
constraint lower_rot_5_5[7] = lower_xor_5_6[15];
constraint lower_rot_5_5[8] = lower_xor_5_6[0];
constraint lower_rot_5_5[9] = lower_xor_5_6[1];
constraint lower_rot_5_5[10] = lower_xor_5_6[2];
constraint lower_rot_5_5[11] = lower_xor_5_6[3];
constraint lower_rot_5_5[12] = lower_xor_5_6[4];
constraint lower_rot_5_5[13] = lower_xor_5_6[5];
constraint lower_rot_5_5[14] = lower_xor_5_6[6];
constraint lower_rot_5_5[15] = lower_xor_5_6[7];
constraint pre_lower_modadd_5_0_0[0] = lower_rot_5_3[0];
constraint pre_lower_modadd_5_0_0[1] = lower_rot_5_3[1];
constraint pre_lower_modadd_5_0_0[2] = lower_rot_5_3[2];
constraint pre_lower_modadd_5_0_0[3] = lower_rot_5_3[3];
constraint pre_lower_modadd_5_0_0[4] = lower_rot_5_3[4];
constraint pre_lower_modadd_5_0_0[5] = lower_rot_5_3[5];
constraint pre_lower_modadd_5_0_0[6] = lower_rot_5_3[6];
constraint pre_lower_modadd_5_0_0[7] = lower_rot_5_3[7];
constraint pre_lower_modadd_5_0_0[8] = lower_rot_5_3[8];
constraint pre_lower_modadd_5_0_0[9] = lower_rot_5_3[9];
constraint pre_lower_modadd_5_0_0[10] = lower_rot_5_3[10];
constraint pre_lower_modadd_5_0_0[11] = lower_rot_5_3[11];
constraint pre_lower_modadd_5_0_0[12] = lower_rot_5_3[12];
constraint pre_lower_modadd_5_0_0[13] = lower_rot_5_3[13];
constraint pre_lower_modadd_5_0_0[14] = lower_rot_5_3[14];
constraint pre_lower_modadd_5_0_0[15] = lower_rot_5_3[15];
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
constraint forall(j in 0..15)(if eq_lower_modadd_5_0[j] = 1 then (sum([pre_lower_modadd_5_0_1[j], pre_lower_modadd_5_0_0[j], lower_modadd_5_0[j]]) mod 2) = Shi_pre_lower_modadd_5_0_0[j] else true endif) /\ lower_p[10] = (16-sum(eq_lower_modadd_5_0))*100;
constraint pre_lower_modadd_5_4_0[0] = lower_modadd_5_10[0];
constraint pre_lower_modadd_5_4_0[1] = lower_modadd_5_10[1];
constraint pre_lower_modadd_5_4_0[2] = lower_modadd_5_10[2];
constraint pre_lower_modadd_5_4_0[3] = lower_modadd_5_10[3];
constraint pre_lower_modadd_5_4_0[4] = lower_modadd_5_10[4];
constraint pre_lower_modadd_5_4_0[5] = lower_modadd_5_10[5];
constraint pre_lower_modadd_5_4_0[6] = lower_modadd_5_10[6];
constraint pre_lower_modadd_5_4_0[7] = lower_modadd_5_10[7];
constraint pre_lower_modadd_5_4_0[8] = lower_modadd_5_10[8];
constraint pre_lower_modadd_5_4_0[9] = lower_modadd_5_10[9];
constraint pre_lower_modadd_5_4_0[10] = lower_modadd_5_10[10];
constraint pre_lower_modadd_5_4_0[11] = lower_modadd_5_10[11];
constraint pre_lower_modadd_5_4_0[12] = lower_modadd_5_10[12];
constraint pre_lower_modadd_5_4_0[13] = lower_modadd_5_10[13];
constraint pre_lower_modadd_5_4_0[14] = lower_modadd_5_10[14];
constraint pre_lower_modadd_5_4_0[15] = lower_modadd_5_10[15];
constraint pre_lower_modadd_5_4_1[0] = lower_rot_5_5[0];
constraint pre_lower_modadd_5_4_1[1] = lower_rot_5_5[1];
constraint pre_lower_modadd_5_4_1[2] = lower_rot_5_5[2];
constraint pre_lower_modadd_5_4_1[3] = lower_rot_5_5[3];
constraint pre_lower_modadd_5_4_1[4] = lower_rot_5_5[4];
constraint pre_lower_modadd_5_4_1[5] = lower_rot_5_5[5];
constraint pre_lower_modadd_5_4_1[6] = lower_rot_5_5[6];
constraint pre_lower_modadd_5_4_1[7] = lower_rot_5_5[7];
constraint pre_lower_modadd_5_4_1[8] = lower_rot_5_5[8];
constraint pre_lower_modadd_5_4_1[9] = lower_rot_5_5[9];
constraint pre_lower_modadd_5_4_1[10] = lower_rot_5_5[10];
constraint pre_lower_modadd_5_4_1[11] = lower_rot_5_5[11];
constraint pre_lower_modadd_5_4_1[12] = lower_rot_5_5[12];
constraint pre_lower_modadd_5_4_1[13] = lower_rot_5_5[13];
constraint pre_lower_modadd_5_4_1[14] = lower_rot_5_5[14];
constraint pre_lower_modadd_5_4_1[15] = lower_rot_5_5[15];
constraint forall(j in 0..15)(if eq_lower_modadd_5_4[j] = 1 then (sum([pre_lower_modadd_5_4_1[j], pre_lower_modadd_5_4_0[j], lower_modadd_5_4[j]]) mod 2) = Shi_pre_lower_modadd_5_4_0[j] else true endif) /\ lower_p[11] = (16-sum(eq_lower_modadd_5_4))*100;
constraint 2*dummy_lower_xor_6_9[0] = (lower_cipher_output_6_14[0] + lower_cipher_output_6_14[48] + lower_xor_6_9[0]);
constraint 2*dummy_lower_xor_6_9[1] = (lower_cipher_output_6_14[1] + lower_cipher_output_6_14[49] + lower_xor_6_9[1]);
constraint 2*dummy_lower_xor_6_9[2] = (lower_cipher_output_6_14[2] + lower_cipher_output_6_14[50] + lower_xor_6_9[2]);
constraint 2*dummy_lower_xor_6_9[3] = (lower_cipher_output_6_14[3] + lower_cipher_output_6_14[51] + lower_xor_6_9[3]);
constraint 2*dummy_lower_xor_6_9[4] = (lower_cipher_output_6_14[4] + lower_cipher_output_6_14[52] + lower_xor_6_9[4]);
constraint 2*dummy_lower_xor_6_9[5] = (lower_cipher_output_6_14[5] + lower_cipher_output_6_14[53] + lower_xor_6_9[5]);
constraint 2*dummy_lower_xor_6_9[6] = (lower_cipher_output_6_14[6] + lower_cipher_output_6_14[54] + lower_xor_6_9[6]);
constraint 2*dummy_lower_xor_6_9[7] = (lower_cipher_output_6_14[7] + lower_cipher_output_6_14[55] + lower_xor_6_9[7]);
constraint 2*dummy_lower_xor_6_9[8] = (lower_cipher_output_6_14[8] + lower_cipher_output_6_14[56] + lower_xor_6_9[8]);
constraint 2*dummy_lower_xor_6_9[9] = (lower_cipher_output_6_14[9] + lower_cipher_output_6_14[57] + lower_xor_6_9[9]);
constraint 2*dummy_lower_xor_6_9[10] = (lower_cipher_output_6_14[10] + lower_cipher_output_6_14[58] + lower_xor_6_9[10]);
constraint 2*dummy_lower_xor_6_9[11] = (lower_cipher_output_6_14[11] + lower_cipher_output_6_14[59] + lower_xor_6_9[11]);
constraint 2*dummy_lower_xor_6_9[12] = (lower_cipher_output_6_14[12] + lower_cipher_output_6_14[60] + lower_xor_6_9[12]);
constraint 2*dummy_lower_xor_6_9[13] = (lower_cipher_output_6_14[13] + lower_cipher_output_6_14[61] + lower_xor_6_9[13]);
constraint 2*dummy_lower_xor_6_9[14] = (lower_cipher_output_6_14[14] + lower_cipher_output_6_14[62] + lower_xor_6_9[14]);
constraint 2*dummy_lower_xor_6_9[15] = (lower_cipher_output_6_14[15] + lower_cipher_output_6_14[63] + lower_xor_6_9[15]);
constraint lower_rot_6_13[0] = lower_cipher_output_6_14[32];
constraint lower_rot_6_13[1] = lower_cipher_output_6_14[33];
constraint lower_rot_6_13[2] = lower_cipher_output_6_14[34];
constraint lower_rot_6_13[3] = lower_cipher_output_6_14[35];
constraint lower_rot_6_13[4] = lower_cipher_output_6_14[36];
constraint lower_rot_6_13[5] = lower_cipher_output_6_14[37];
constraint lower_rot_6_13[6] = lower_cipher_output_6_14[38];
constraint lower_rot_6_13[7] = lower_cipher_output_6_14[39];
constraint lower_rot_6_13[8] = lower_cipher_output_6_14[40];
constraint lower_rot_6_13[9] = lower_cipher_output_6_14[41];
constraint lower_rot_6_13[10] = lower_cipher_output_6_14[42];
constraint lower_rot_6_13[11] = lower_cipher_output_6_14[43];
constraint lower_rot_6_13[12] = lower_cipher_output_6_14[44];
constraint lower_rot_6_13[13] = lower_cipher_output_6_14[45];
constraint lower_rot_6_13[14] = lower_cipher_output_6_14[46];
constraint lower_rot_6_13[15] = lower_cipher_output_6_14[47];
constraint lower_rot_6_8[0] = lower_xor_6_9[3];
constraint lower_rot_6_8[1] = lower_xor_6_9[4];
constraint lower_rot_6_8[2] = lower_xor_6_9[5];
constraint lower_rot_6_8[3] = lower_xor_6_9[6];
constraint lower_rot_6_8[4] = lower_xor_6_9[7];
constraint lower_rot_6_8[5] = lower_xor_6_9[8];
constraint lower_rot_6_8[6] = lower_xor_6_9[9];
constraint lower_rot_6_8[7] = lower_xor_6_9[10];
constraint lower_rot_6_8[8] = lower_xor_6_9[11];
constraint lower_rot_6_8[9] = lower_xor_6_9[12];
constraint lower_rot_6_8[10] = lower_xor_6_9[13];
constraint lower_rot_6_8[11] = lower_xor_6_9[14];
constraint lower_rot_6_8[12] = lower_xor_6_9[15];
constraint lower_rot_6_8[13] = lower_xor_6_9[0];
constraint lower_rot_6_8[14] = lower_xor_6_9[1];
constraint lower_rot_6_8[15] = lower_xor_6_9[2];
constraint 2*dummy_lower_xor_6_12[0] = (lower_rot_6_13[0] + lower_cipher_output_6_14[16] + lower_xor_6_12[0]);
constraint 2*dummy_lower_xor_6_12[1] = (lower_rot_6_13[1] + lower_cipher_output_6_14[17] + lower_xor_6_12[1]);
constraint 2*dummy_lower_xor_6_12[2] = (lower_rot_6_13[2] + lower_cipher_output_6_14[18] + lower_xor_6_12[2]);
constraint 2*dummy_lower_xor_6_12[3] = (lower_rot_6_13[3] + lower_cipher_output_6_14[19] + lower_xor_6_12[3]);
constraint 2*dummy_lower_xor_6_12[4] = (lower_rot_6_13[4] + lower_cipher_output_6_14[20] + lower_xor_6_12[4]);
constraint 2*dummy_lower_xor_6_12[5] = (lower_rot_6_13[5] + lower_cipher_output_6_14[21] + lower_xor_6_12[5]);
constraint 2*dummy_lower_xor_6_12[6] = (lower_rot_6_13[6] + lower_cipher_output_6_14[22] + lower_xor_6_12[6]);
constraint 2*dummy_lower_xor_6_12[7] = (lower_rot_6_13[7] + lower_cipher_output_6_14[23] + lower_xor_6_12[7]);
constraint 2*dummy_lower_xor_6_12[8] = (lower_rot_6_13[8] + lower_cipher_output_6_14[24] + lower_xor_6_12[8]);
constraint 2*dummy_lower_xor_6_12[9] = (lower_rot_6_13[9] + lower_cipher_output_6_14[25] + lower_xor_6_12[9]);
constraint 2*dummy_lower_xor_6_12[10] = (lower_rot_6_13[10] + lower_cipher_output_6_14[26] + lower_xor_6_12[10]);
constraint 2*dummy_lower_xor_6_12[11] = (lower_rot_6_13[11] + lower_cipher_output_6_14[27] + lower_xor_6_12[11]);
constraint 2*dummy_lower_xor_6_12[12] = (lower_rot_6_13[12] + lower_cipher_output_6_14[28] + lower_xor_6_12[12]);
constraint 2*dummy_lower_xor_6_12[13] = (lower_rot_6_13[13] + lower_cipher_output_6_14[29] + lower_xor_6_12[13]);
constraint 2*dummy_lower_xor_6_12[14] = (lower_rot_6_13[14] + lower_cipher_output_6_14[30] + lower_xor_6_12[14]);
constraint 2*dummy_lower_xor_6_12[15] = (lower_rot_6_13[15] + lower_cipher_output_6_14[31] + lower_xor_6_12[15]);
constraint pre_lower_modadd_6_7_0[0] = lower_cipher_output_6_14[0];
constraint pre_lower_modadd_6_7_0[1] = lower_cipher_output_6_14[1];
constraint pre_lower_modadd_6_7_0[2] = lower_cipher_output_6_14[2];
constraint pre_lower_modadd_6_7_0[3] = lower_cipher_output_6_14[3];
constraint pre_lower_modadd_6_7_0[4] = lower_cipher_output_6_14[4];
constraint pre_lower_modadd_6_7_0[5] = lower_cipher_output_6_14[5];
constraint pre_lower_modadd_6_7_0[6] = lower_cipher_output_6_14[6];
constraint pre_lower_modadd_6_7_0[7] = lower_cipher_output_6_14[7];
constraint pre_lower_modadd_6_7_0[8] = lower_cipher_output_6_14[8];
constraint pre_lower_modadd_6_7_0[9] = lower_cipher_output_6_14[9];
constraint pre_lower_modadd_6_7_0[10] = lower_cipher_output_6_14[10];
constraint pre_lower_modadd_6_7_0[11] = lower_cipher_output_6_14[11];
constraint pre_lower_modadd_6_7_0[12] = lower_cipher_output_6_14[12];
constraint pre_lower_modadd_6_7_0[13] = lower_cipher_output_6_14[13];
constraint pre_lower_modadd_6_7_0[14] = lower_cipher_output_6_14[14];
constraint pre_lower_modadd_6_7_0[15] = lower_cipher_output_6_14[15];
constraint pre_lower_modadd_6_7_1[0] = lower_rot_6_8[0];
constraint pre_lower_modadd_6_7_1[1] = lower_rot_6_8[1];
constraint pre_lower_modadd_6_7_1[2] = lower_rot_6_8[2];
constraint pre_lower_modadd_6_7_1[3] = lower_rot_6_8[3];
constraint pre_lower_modadd_6_7_1[4] = lower_rot_6_8[4];
constraint pre_lower_modadd_6_7_1[5] = lower_rot_6_8[5];
constraint pre_lower_modadd_6_7_1[6] = lower_rot_6_8[6];
constraint pre_lower_modadd_6_7_1[7] = lower_rot_6_8[7];
constraint pre_lower_modadd_6_7_1[8] = lower_rot_6_8[8];
constraint pre_lower_modadd_6_7_1[9] = lower_rot_6_8[9];
constraint pre_lower_modadd_6_7_1[10] = lower_rot_6_8[10];
constraint pre_lower_modadd_6_7_1[11] = lower_rot_6_8[11];
constraint pre_lower_modadd_6_7_1[12] = lower_rot_6_8[12];
constraint pre_lower_modadd_6_7_1[13] = lower_rot_6_8[13];
constraint pre_lower_modadd_6_7_1[14] = lower_rot_6_8[14];
constraint pre_lower_modadd_6_7_1[15] = lower_rot_6_8[15];
constraint forall(j in 0..15)(if eq_lower_modadd_6_7[j] = 1 then (sum([pre_lower_modadd_6_7_1[j], pre_lower_modadd_6_7_0[j], lower_modadd_6_7[j]]) mod 2) = Shi_pre_lower_modadd_6_7_0[j] else true endif) /\ lower_p[12] = (16-sum(eq_lower_modadd_6_7))*100;
constraint lower_rot_6_11[0] = lower_xor_6_12[9];
constraint lower_rot_6_11[1] = lower_xor_6_12[10];
constraint lower_rot_6_11[2] = lower_xor_6_12[11];
constraint lower_rot_6_11[3] = lower_xor_6_12[12];
constraint lower_rot_6_11[4] = lower_xor_6_12[13];
constraint lower_rot_6_11[5] = lower_xor_6_12[14];
constraint lower_rot_6_11[6] = lower_xor_6_12[15];
constraint lower_rot_6_11[7] = lower_xor_6_12[0];
constraint lower_rot_6_11[8] = lower_xor_6_12[1];
constraint lower_rot_6_11[9] = lower_xor_6_12[2];
constraint lower_rot_6_11[10] = lower_xor_6_12[3];
constraint lower_rot_6_11[11] = lower_xor_6_12[4];
constraint lower_rot_6_11[12] = lower_xor_6_12[5];
constraint lower_rot_6_11[13] = lower_xor_6_12[6];
constraint lower_rot_6_11[14] = lower_xor_6_12[7];
constraint lower_rot_6_11[15] = lower_xor_6_12[8];
constraint lower_rot_6_3[0] = lower_modadd_6_7[0];
constraint lower_rot_6_3[1] = lower_modadd_6_7[1];
constraint lower_rot_6_3[2] = lower_modadd_6_7[2];
constraint lower_rot_6_3[3] = lower_modadd_6_7[3];
constraint lower_rot_6_3[4] = lower_modadd_6_7[4];
constraint lower_rot_6_3[5] = lower_modadd_6_7[5];
constraint lower_rot_6_3[6] = lower_modadd_6_7[6];
constraint lower_rot_6_3[7] = lower_modadd_6_7[7];
constraint lower_rot_6_3[8] = lower_modadd_6_7[8];
constraint lower_rot_6_3[9] = lower_modadd_6_7[9];
constraint lower_rot_6_3[10] = lower_modadd_6_7[10];
constraint lower_rot_6_3[11] = lower_modadd_6_7[11];
constraint lower_rot_6_3[12] = lower_modadd_6_7[12];
constraint lower_rot_6_3[13] = lower_modadd_6_7[13];
constraint lower_rot_6_3[14] = lower_modadd_6_7[14];
constraint lower_rot_6_3[15] = lower_modadd_6_7[15];
constraint pre_lower_modadd_6_10_0[0] = lower_rot_6_13[0];
constraint pre_lower_modadd_6_10_0[1] = lower_rot_6_13[1];
constraint pre_lower_modadd_6_10_0[2] = lower_rot_6_13[2];
constraint pre_lower_modadd_6_10_0[3] = lower_rot_6_13[3];
constraint pre_lower_modadd_6_10_0[4] = lower_rot_6_13[4];
constraint pre_lower_modadd_6_10_0[5] = lower_rot_6_13[5];
constraint pre_lower_modadd_6_10_0[6] = lower_rot_6_13[6];
constraint pre_lower_modadd_6_10_0[7] = lower_rot_6_13[7];
constraint pre_lower_modadd_6_10_0[8] = lower_rot_6_13[8];
constraint pre_lower_modadd_6_10_0[9] = lower_rot_6_13[9];
constraint pre_lower_modadd_6_10_0[10] = lower_rot_6_13[10];
constraint pre_lower_modadd_6_10_0[11] = lower_rot_6_13[11];
constraint pre_lower_modadd_6_10_0[12] = lower_rot_6_13[12];
constraint pre_lower_modadd_6_10_0[13] = lower_rot_6_13[13];
constraint pre_lower_modadd_6_10_0[14] = lower_rot_6_13[14];
constraint pre_lower_modadd_6_10_0[15] = lower_rot_6_13[15];
constraint pre_lower_modadd_6_10_1[0] = lower_rot_6_11[0];
constraint pre_lower_modadd_6_10_1[1] = lower_rot_6_11[1];
constraint pre_lower_modadd_6_10_1[2] = lower_rot_6_11[2];
constraint pre_lower_modadd_6_10_1[3] = lower_rot_6_11[3];
constraint pre_lower_modadd_6_10_1[4] = lower_rot_6_11[4];
constraint pre_lower_modadd_6_10_1[5] = lower_rot_6_11[5];
constraint pre_lower_modadd_6_10_1[6] = lower_rot_6_11[6];
constraint pre_lower_modadd_6_10_1[7] = lower_rot_6_11[7];
constraint pre_lower_modadd_6_10_1[8] = lower_rot_6_11[8];
constraint pre_lower_modadd_6_10_1[9] = lower_rot_6_11[9];
constraint pre_lower_modadd_6_10_1[10] = lower_rot_6_11[10];
constraint pre_lower_modadd_6_10_1[11] = lower_rot_6_11[11];
constraint pre_lower_modadd_6_10_1[12] = lower_rot_6_11[12];
constraint pre_lower_modadd_6_10_1[13] = lower_rot_6_11[13];
constraint pre_lower_modadd_6_10_1[14] = lower_rot_6_11[14];
constraint pre_lower_modadd_6_10_1[15] = lower_rot_6_11[15];
constraint forall(j in 0..15)(if eq_lower_modadd_6_10[j] = 1 then (sum([pre_lower_modadd_6_10_1[j], pre_lower_modadd_6_10_0[j], lower_modadd_6_10[j]]) mod 2) = Shi_pre_lower_modadd_6_10_0[j] else true endif) /\ lower_p[13] = (16-sum(eq_lower_modadd_6_10))*100;
constraint 2*dummy_lower_xor_6_2[0] = (lower_rot_6_3[0] + lower_rot_6_11[0] + lower_xor_6_2[0]);
constraint 2*dummy_lower_xor_6_2[1] = (lower_rot_6_3[1] + lower_rot_6_11[1] + lower_xor_6_2[1]);
constraint 2*dummy_lower_xor_6_2[2] = (lower_rot_6_3[2] + lower_rot_6_11[2] + lower_xor_6_2[2]);
constraint 2*dummy_lower_xor_6_2[3] = (lower_rot_6_3[3] + lower_rot_6_11[3] + lower_xor_6_2[3]);
constraint 2*dummy_lower_xor_6_2[4] = (lower_rot_6_3[4] + lower_rot_6_11[4] + lower_xor_6_2[4]);
constraint 2*dummy_lower_xor_6_2[5] = (lower_rot_6_3[5] + lower_rot_6_11[5] + lower_xor_6_2[5]);
constraint 2*dummy_lower_xor_6_2[6] = (lower_rot_6_3[6] + lower_rot_6_11[6] + lower_xor_6_2[6]);
constraint 2*dummy_lower_xor_6_2[7] = (lower_rot_6_3[7] + lower_rot_6_11[7] + lower_xor_6_2[7]);
constraint 2*dummy_lower_xor_6_2[8] = (lower_rot_6_3[8] + lower_rot_6_11[8] + lower_xor_6_2[8]);
constraint 2*dummy_lower_xor_6_2[9] = (lower_rot_6_3[9] + lower_rot_6_11[9] + lower_xor_6_2[9]);
constraint 2*dummy_lower_xor_6_2[10] = (lower_rot_6_3[10] + lower_rot_6_11[10] + lower_xor_6_2[10]);
constraint 2*dummy_lower_xor_6_2[11] = (lower_rot_6_3[11] + lower_rot_6_11[11] + lower_xor_6_2[11]);
constraint 2*dummy_lower_xor_6_2[12] = (lower_rot_6_3[12] + lower_rot_6_11[12] + lower_xor_6_2[12]);
constraint 2*dummy_lower_xor_6_2[13] = (lower_rot_6_3[13] + lower_rot_6_11[13] + lower_xor_6_2[13]);
constraint 2*dummy_lower_xor_6_2[14] = (lower_rot_6_3[14] + lower_rot_6_11[14] + lower_xor_6_2[14]);
constraint 2*dummy_lower_xor_6_2[15] = (lower_rot_6_3[15] + lower_rot_6_11[15] + lower_xor_6_2[15]);
constraint 2*dummy_lower_xor_6_6[0] = (lower_modadd_6_10[0] + lower_rot_6_8[0] + lower_xor_6_6[0]);
constraint 2*dummy_lower_xor_6_6[1] = (lower_modadd_6_10[1] + lower_rot_6_8[1] + lower_xor_6_6[1]);
constraint 2*dummy_lower_xor_6_6[2] = (lower_modadd_6_10[2] + lower_rot_6_8[2] + lower_xor_6_6[2]);
constraint 2*dummy_lower_xor_6_6[3] = (lower_modadd_6_10[3] + lower_rot_6_8[3] + lower_xor_6_6[3]);
constraint 2*dummy_lower_xor_6_6[4] = (lower_modadd_6_10[4] + lower_rot_6_8[4] + lower_xor_6_6[4]);
constraint 2*dummy_lower_xor_6_6[5] = (lower_modadd_6_10[5] + lower_rot_6_8[5] + lower_xor_6_6[5]);
constraint 2*dummy_lower_xor_6_6[6] = (lower_modadd_6_10[6] + lower_rot_6_8[6] + lower_xor_6_6[6]);
constraint 2*dummy_lower_xor_6_6[7] = (lower_modadd_6_10[7] + lower_rot_6_8[7] + lower_xor_6_6[7]);
constraint 2*dummy_lower_xor_6_6[8] = (lower_modadd_6_10[8] + lower_rot_6_8[8] + lower_xor_6_6[8]);
constraint 2*dummy_lower_xor_6_6[9] = (lower_modadd_6_10[9] + lower_rot_6_8[9] + lower_xor_6_6[9]);
constraint 2*dummy_lower_xor_6_6[10] = (lower_modadd_6_10[10] + lower_rot_6_8[10] + lower_xor_6_6[10]);
constraint 2*dummy_lower_xor_6_6[11] = (lower_modadd_6_10[11] + lower_rot_6_8[11] + lower_xor_6_6[11]);
constraint 2*dummy_lower_xor_6_6[12] = (lower_modadd_6_10[12] + lower_rot_6_8[12] + lower_xor_6_6[12]);
constraint 2*dummy_lower_xor_6_6[13] = (lower_modadd_6_10[13] + lower_rot_6_8[13] + lower_xor_6_6[13]);
constraint 2*dummy_lower_xor_6_6[14] = (lower_modadd_6_10[14] + lower_rot_6_8[14] + lower_xor_6_6[14]);
constraint 2*dummy_lower_xor_6_6[15] = (lower_modadd_6_10[15] + lower_rot_6_8[15] + lower_xor_6_6[15]);
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
constraint forall(j in 0..15)(if eq_lower_modadd_6_0[j] = 1 then (sum([pre_lower_modadd_6_0_1[j], pre_lower_modadd_6_0_0[j], lower_modadd_6_0[j]]) mod 2) = Shi_pre_lower_modadd_6_0_0[j] else true endif) /\ lower_p[14] = (16-sum(eq_lower_modadd_6_0))*100;
constraint pre_lower_modadd_6_4_0[0] = lower_modadd_6_10[0];
constraint pre_lower_modadd_6_4_0[1] = lower_modadd_6_10[1];
constraint pre_lower_modadd_6_4_0[2] = lower_modadd_6_10[2];
constraint pre_lower_modadd_6_4_0[3] = lower_modadd_6_10[3];
constraint pre_lower_modadd_6_4_0[4] = lower_modadd_6_10[4];
constraint pre_lower_modadd_6_4_0[5] = lower_modadd_6_10[5];
constraint pre_lower_modadd_6_4_0[6] = lower_modadd_6_10[6];
constraint pre_lower_modadd_6_4_0[7] = lower_modadd_6_10[7];
constraint pre_lower_modadd_6_4_0[8] = lower_modadd_6_10[8];
constraint pre_lower_modadd_6_4_0[9] = lower_modadd_6_10[9];
constraint pre_lower_modadd_6_4_0[10] = lower_modadd_6_10[10];
constraint pre_lower_modadd_6_4_0[11] = lower_modadd_6_10[11];
constraint pre_lower_modadd_6_4_0[12] = lower_modadd_6_10[12];
constraint pre_lower_modadd_6_4_0[13] = lower_modadd_6_10[13];
constraint pre_lower_modadd_6_4_0[14] = lower_modadd_6_10[14];
constraint pre_lower_modadd_6_4_0[15] = lower_modadd_6_10[15];
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
constraint forall(j in 0..15)(if eq_lower_modadd_6_4[j] = 1 then (sum([pre_lower_modadd_6_4_1[j], pre_lower_modadd_6_4_0[j], lower_modadd_6_4[j]]) mod 2) = Shi_pre_lower_modadd_6_4_0[j] else true endif) /\ lower_p[15] = (16-sum(eq_lower_modadd_6_4))*100;
constraint onlyLargeSwitch_BCT_enum(array1d(0..16-1, [pre_upper_modadd_3_4_0[15],pre_upper_modadd_3_4_0[14],pre_upper_modadd_3_4_0[13],pre_upper_modadd_3_4_0[12],pre_upper_modadd_3_4_0[11],pre_upper_modadd_3_4_0[10],pre_upper_modadd_3_4_0[9],pre_upper_modadd_3_4_0[8],pre_upper_modadd_3_4_0[7],pre_upper_modadd_3_4_0[6],pre_upper_modadd_3_4_0[5],pre_upper_modadd_3_4_0[4],pre_upper_modadd_3_4_0[3],pre_upper_modadd_3_4_0[2],pre_upper_modadd_3_4_0[1],pre_upper_modadd_3_4_0[0]]), array1d(0..16-1, [pre_upper_modadd_3_4_1[15],pre_upper_modadd_3_4_1[14],pre_upper_modadd_3_4_1[13],pre_upper_modadd_3_4_1[12],pre_upper_modadd_3_4_1[11],pre_upper_modadd_3_4_1[10],pre_upper_modadd_3_4_1[9],pre_upper_modadd_3_4_1[8],pre_upper_modadd_3_4_1[7],pre_upper_modadd_3_4_1[6],pre_upper_modadd_3_4_1[5],pre_upper_modadd_3_4_1[4],pre_upper_modadd_3_4_1[3],pre_upper_modadd_3_4_1[2],pre_upper_modadd_3_4_1[1],pre_upper_modadd_3_4_1[0]]), array1d(0..16-1, [pre_lower_modadd_3_4_0[15],pre_lower_modadd_3_4_0[14],pre_lower_modadd_3_4_0[13],pre_lower_modadd_3_4_0[12],pre_lower_modadd_3_4_0[11],pre_lower_modadd_3_4_0[10],pre_lower_modadd_3_4_0[9],pre_lower_modadd_3_4_0[8],pre_lower_modadd_3_4_0[7],pre_lower_modadd_3_4_0[6],pre_lower_modadd_3_4_0[5],pre_lower_modadd_3_4_0[4],pre_lower_modadd_3_4_0[3],pre_lower_modadd_3_4_0[2],pre_lower_modadd_3_4_0[1],pre_lower_modadd_3_4_0[0]]), array1d(0..16-1, [pre_lower_modadd_3_4_1[15],pre_lower_modadd_3_4_1[14],pre_lower_modadd_3_4_1[13],pre_lower_modadd_3_4_1[12],pre_lower_modadd_3_4_1[11],pre_lower_modadd_3_4_1[10],pre_lower_modadd_3_4_1[9],pre_lower_modadd_3_4_1[8],pre_lower_modadd_3_4_1[7],pre_lower_modadd_3_4_1[6],pre_lower_modadd_3_4_1[5],pre_lower_modadd_3_4_1[4],pre_lower_modadd_3_4_1[3],pre_lower_modadd_3_4_1[2],pre_lower_modadd_3_4_1[1],pre_lower_modadd_3_4_1[0]]), 8, 16) = true;

constraint bct_compute(array1d(0..16-1, [pre_upper_modadd_3_4_0[0],pre_upper_modadd_3_4_0[1],pre_upper_modadd_3_4_0[2],pre_upper_modadd_3_4_0[3],pre_upper_modadd_3_4_0[4],pre_upper_modadd_3_4_0[5],pre_upper_modadd_3_4_0[6],pre_upper_modadd_3_4_0[7],pre_upper_modadd_3_4_0[8],pre_upper_modadd_3_4_0[9],pre_upper_modadd_3_4_0[10],pre_upper_modadd_3_4_0[11],pre_upper_modadd_3_4_0[12],pre_upper_modadd_3_4_0[13],pre_upper_modadd_3_4_0[14],pre_upper_modadd_3_4_0[15]]), array1d(0..16-1, [pre_upper_modadd_3_4_1[0],pre_upper_modadd_3_4_1[1],pre_upper_modadd_3_4_1[2],pre_upper_modadd_3_4_1[3],pre_upper_modadd_3_4_1[4],pre_upper_modadd_3_4_1[5],pre_upper_modadd_3_4_1[6],pre_upper_modadd_3_4_1[7],pre_upper_modadd_3_4_1[8],pre_upper_modadd_3_4_1[9],pre_upper_modadd_3_4_1[10],pre_upper_modadd_3_4_1[11],pre_upper_modadd_3_4_1[12],pre_upper_modadd_3_4_1[13],pre_upper_modadd_3_4_1[14],pre_upper_modadd_3_4_1[15]]), array1d(0..16-1, [pre_lower_modadd_3_4_0[0],pre_lower_modadd_3_4_0[1],pre_lower_modadd_3_4_0[2],pre_lower_modadd_3_4_0[3],pre_lower_modadd_3_4_0[4],pre_lower_modadd_3_4_0[5],pre_lower_modadd_3_4_0[6],pre_lower_modadd_3_4_0[7],pre_lower_modadd_3_4_0[8],pre_lower_modadd_3_4_0[9],pre_lower_modadd_3_4_0[10],pre_lower_modadd_3_4_0[11],pre_lower_modadd_3_4_0[12],pre_lower_modadd_3_4_0[13],pre_lower_modadd_3_4_0[14],pre_lower_modadd_3_4_0[15]]), array1d(0..16-1, [pre_lower_modadd_3_4_1[0],pre_lower_modadd_3_4_1[1],pre_lower_modadd_3_4_1[2],pre_lower_modadd_3_4_1[3],pre_lower_modadd_3_4_1[4],pre_lower_modadd_3_4_1[5],pre_lower_modadd_3_4_1[6],pre_lower_modadd_3_4_1[7],pre_lower_modadd_3_4_1[8],pre_lower_modadd_3_4_1[9],pre_lower_modadd_3_4_1[10],pre_lower_modadd_3_4_1[11],pre_lower_modadd_3_4_1[12],pre_lower_modadd_3_4_1[13],pre_lower_modadd_3_4_1[14],pre_lower_modadd_3_4_1[15]]), 16, middle_p[0]);

constraint onlyLargeSwitch_BCT_enum(array1d(0..16-1, [pre_upper_modadd_3_7_0[15],pre_upper_modadd_3_7_0[14],pre_upper_modadd_3_7_0[13],pre_upper_modadd_3_7_0[12],pre_upper_modadd_3_7_0[11],pre_upper_modadd_3_7_0[10],pre_upper_modadd_3_7_0[9],pre_upper_modadd_3_7_0[8],pre_upper_modadd_3_7_0[7],pre_upper_modadd_3_7_0[6],pre_upper_modadd_3_7_0[5],pre_upper_modadd_3_7_0[4],pre_upper_modadd_3_7_0[3],pre_upper_modadd_3_7_0[2],pre_upper_modadd_3_7_0[1],pre_upper_modadd_3_7_0[0]]), array1d(0..16-1, [pre_upper_modadd_3_7_1[15],pre_upper_modadd_3_7_1[14],pre_upper_modadd_3_7_1[13],pre_upper_modadd_3_7_1[12],pre_upper_modadd_3_7_1[11],pre_upper_modadd_3_7_1[10],pre_upper_modadd_3_7_1[9],pre_upper_modadd_3_7_1[8],pre_upper_modadd_3_7_1[7],pre_upper_modadd_3_7_1[6],pre_upper_modadd_3_7_1[5],pre_upper_modadd_3_7_1[4],pre_upper_modadd_3_7_1[3],pre_upper_modadd_3_7_1[2],pre_upper_modadd_3_7_1[1],pre_upper_modadd_3_7_1[0]]), array1d(0..16-1, [pre_lower_modadd_3_7_0[15],pre_lower_modadd_3_7_0[14],pre_lower_modadd_3_7_0[13],pre_lower_modadd_3_7_0[12],pre_lower_modadd_3_7_0[11],pre_lower_modadd_3_7_0[10],pre_lower_modadd_3_7_0[9],pre_lower_modadd_3_7_0[8],pre_lower_modadd_3_7_0[7],pre_lower_modadd_3_7_0[6],pre_lower_modadd_3_7_0[5],pre_lower_modadd_3_7_0[4],pre_lower_modadd_3_7_0[3],pre_lower_modadd_3_7_0[2],pre_lower_modadd_3_7_0[1],pre_lower_modadd_3_7_0[0]]), array1d(0..16-1, [pre_lower_modadd_3_7_1[15],pre_lower_modadd_3_7_1[14],pre_lower_modadd_3_7_1[13],pre_lower_modadd_3_7_1[12],pre_lower_modadd_3_7_1[11],pre_lower_modadd_3_7_1[10],pre_lower_modadd_3_7_1[9],pre_lower_modadd_3_7_1[8],pre_lower_modadd_3_7_1[7],pre_lower_modadd_3_7_1[6],pre_lower_modadd_3_7_1[5],pre_lower_modadd_3_7_1[4],pre_lower_modadd_3_7_1[3],pre_lower_modadd_3_7_1[2],pre_lower_modadd_3_7_1[1],pre_lower_modadd_3_7_1[0]]), 8, 16) = true;

constraint bct_compute(array1d(0..16-1, [pre_upper_modadd_3_7_0[0],pre_upper_modadd_3_7_0[1],pre_upper_modadd_3_7_0[2],pre_upper_modadd_3_7_0[3],pre_upper_modadd_3_7_0[4],pre_upper_modadd_3_7_0[5],pre_upper_modadd_3_7_0[6],pre_upper_modadd_3_7_0[7],pre_upper_modadd_3_7_0[8],pre_upper_modadd_3_7_0[9],pre_upper_modadd_3_7_0[10],pre_upper_modadd_3_7_0[11],pre_upper_modadd_3_7_0[12],pre_upper_modadd_3_7_0[13],pre_upper_modadd_3_7_0[14],pre_upper_modadd_3_7_0[15]]), array1d(0..16-1, [pre_upper_modadd_3_7_1[0],pre_upper_modadd_3_7_1[1],pre_upper_modadd_3_7_1[2],pre_upper_modadd_3_7_1[3],pre_upper_modadd_3_7_1[4],pre_upper_modadd_3_7_1[5],pre_upper_modadd_3_7_1[6],pre_upper_modadd_3_7_1[7],pre_upper_modadd_3_7_1[8],pre_upper_modadd_3_7_1[9],pre_upper_modadd_3_7_1[10],pre_upper_modadd_3_7_1[11],pre_upper_modadd_3_7_1[12],pre_upper_modadd_3_7_1[13],pre_upper_modadd_3_7_1[14],pre_upper_modadd_3_7_1[15]]), array1d(0..16-1, [pre_lower_modadd_3_7_0[0],pre_lower_modadd_3_7_0[1],pre_lower_modadd_3_7_0[2],pre_lower_modadd_3_7_0[3],pre_lower_modadd_3_7_0[4],pre_lower_modadd_3_7_0[5],pre_lower_modadd_3_7_0[6],pre_lower_modadd_3_7_0[7],pre_lower_modadd_3_7_0[8],pre_lower_modadd_3_7_0[9],pre_lower_modadd_3_7_0[10],pre_lower_modadd_3_7_0[11],pre_lower_modadd_3_7_0[12],pre_lower_modadd_3_7_0[13],pre_lower_modadd_3_7_0[14],pre_lower_modadd_3_7_0[15]]), array1d(0..16-1, [pre_lower_modadd_3_7_1[0],pre_lower_modadd_3_7_1[1],pre_lower_modadd_3_7_1[2],pre_lower_modadd_3_7_1[3],pre_lower_modadd_3_7_1[4],pre_lower_modadd_3_7_1[5],pre_lower_modadd_3_7_1[6],pre_lower_modadd_3_7_1[7],pre_lower_modadd_3_7_1[8],pre_lower_modadd_3_7_1[9],pre_lower_modadd_3_7_1[10],pre_lower_modadd_3_7_1[11],pre_lower_modadd_3_7_1[12],pre_lower_modadd_3_7_1[13],pre_lower_modadd_3_7_1[14],pre_lower_modadd_3_7_1[15]]), 16, middle_p[1]);

constraint onlyLargeSwitch_BCT_enum(array1d(0..16-1, [pre_upper_modadd_3_0_0[15],pre_upper_modadd_3_0_0[14],pre_upper_modadd_3_0_0[13],pre_upper_modadd_3_0_0[12],pre_upper_modadd_3_0_0[11],pre_upper_modadd_3_0_0[10],pre_upper_modadd_3_0_0[9],pre_upper_modadd_3_0_0[8],pre_upper_modadd_3_0_0[7],pre_upper_modadd_3_0_0[6],pre_upper_modadd_3_0_0[5],pre_upper_modadd_3_0_0[4],pre_upper_modadd_3_0_0[3],pre_upper_modadd_3_0_0[2],pre_upper_modadd_3_0_0[1],pre_upper_modadd_3_0_0[0]]), array1d(0..16-1, [pre_upper_modadd_3_0_1[15],pre_upper_modadd_3_0_1[14],pre_upper_modadd_3_0_1[13],pre_upper_modadd_3_0_1[12],pre_upper_modadd_3_0_1[11],pre_upper_modadd_3_0_1[10],pre_upper_modadd_3_0_1[9],pre_upper_modadd_3_0_1[8],pre_upper_modadd_3_0_1[7],pre_upper_modadd_3_0_1[6],pre_upper_modadd_3_0_1[5],pre_upper_modadd_3_0_1[4],pre_upper_modadd_3_0_1[3],pre_upper_modadd_3_0_1[2],pre_upper_modadd_3_0_1[1],pre_upper_modadd_3_0_1[0]]), array1d(0..16-1, [pre_lower_modadd_3_0_0[15],pre_lower_modadd_3_0_0[14],pre_lower_modadd_3_0_0[13],pre_lower_modadd_3_0_0[12],pre_lower_modadd_3_0_0[11],pre_lower_modadd_3_0_0[10],pre_lower_modadd_3_0_0[9],pre_lower_modadd_3_0_0[8],pre_lower_modadd_3_0_0[7],pre_lower_modadd_3_0_0[6],pre_lower_modadd_3_0_0[5],pre_lower_modadd_3_0_0[4],pre_lower_modadd_3_0_0[3],pre_lower_modadd_3_0_0[2],pre_lower_modadd_3_0_0[1],pre_lower_modadd_3_0_0[0]]), array1d(0..16-1, [pre_lower_modadd_3_0_1[15],pre_lower_modadd_3_0_1[14],pre_lower_modadd_3_0_1[13],pre_lower_modadd_3_0_1[12],pre_lower_modadd_3_0_1[11],pre_lower_modadd_3_0_1[10],pre_lower_modadd_3_0_1[9],pre_lower_modadd_3_0_1[8],pre_lower_modadd_3_0_1[7],pre_lower_modadd_3_0_1[6],pre_lower_modadd_3_0_1[5],pre_lower_modadd_3_0_1[4],pre_lower_modadd_3_0_1[3],pre_lower_modadd_3_0_1[2],pre_lower_modadd_3_0_1[1],pre_lower_modadd_3_0_1[0]]), 8, 16) = true;

constraint bct_compute(array1d(0..16-1, [pre_upper_modadd_3_0_0[0],pre_upper_modadd_3_0_0[1],pre_upper_modadd_3_0_0[2],pre_upper_modadd_3_0_0[3],pre_upper_modadd_3_0_0[4],pre_upper_modadd_3_0_0[5],pre_upper_modadd_3_0_0[6],pre_upper_modadd_3_0_0[7],pre_upper_modadd_3_0_0[8],pre_upper_modadd_3_0_0[9],pre_upper_modadd_3_0_0[10],pre_upper_modadd_3_0_0[11],pre_upper_modadd_3_0_0[12],pre_upper_modadd_3_0_0[13],pre_upper_modadd_3_0_0[14],pre_upper_modadd_3_0_0[15]]), array1d(0..16-1, [pre_upper_modadd_3_0_1[0],pre_upper_modadd_3_0_1[1],pre_upper_modadd_3_0_1[2],pre_upper_modadd_3_0_1[3],pre_upper_modadd_3_0_1[4],pre_upper_modadd_3_0_1[5],pre_upper_modadd_3_0_1[6],pre_upper_modadd_3_0_1[7],pre_upper_modadd_3_0_1[8],pre_upper_modadd_3_0_1[9],pre_upper_modadd_3_0_1[10],pre_upper_modadd_3_0_1[11],pre_upper_modadd_3_0_1[12],pre_upper_modadd_3_0_1[13],pre_upper_modadd_3_0_1[14],pre_upper_modadd_3_0_1[15]]), array1d(0..16-1, [pre_lower_modadd_3_0_0[0],pre_lower_modadd_3_0_0[1],pre_lower_modadd_3_0_0[2],pre_lower_modadd_3_0_0[3],pre_lower_modadd_3_0_0[4],pre_lower_modadd_3_0_0[5],pre_lower_modadd_3_0_0[6],pre_lower_modadd_3_0_0[7],pre_lower_modadd_3_0_0[8],pre_lower_modadd_3_0_0[9],pre_lower_modadd_3_0_0[10],pre_lower_modadd_3_0_0[11],pre_lower_modadd_3_0_0[12],pre_lower_modadd_3_0_0[13],pre_lower_modadd_3_0_0[14],pre_lower_modadd_3_0_0[15]]), array1d(0..16-1, [pre_lower_modadd_3_0_1[0],pre_lower_modadd_3_0_1[1],pre_lower_modadd_3_0_1[2],pre_lower_modadd_3_0_1[3],pre_lower_modadd_3_0_1[4],pre_lower_modadd_3_0_1[5],pre_lower_modadd_3_0_1[6],pre_lower_modadd_3_0_1[7],pre_lower_modadd_3_0_1[8],pre_lower_modadd_3_0_1[9],pre_lower_modadd_3_0_1[10],pre_lower_modadd_3_0_1[11],pre_lower_modadd_3_0_1[12],pre_lower_modadd_3_0_1[13],pre_lower_modadd_3_0_1[14],pre_lower_modadd_3_0_1[15]]), 16, middle_p[2]);

constraint onlyLargeSwitch_BCT_enum(array1d(0..16-1, [pre_upper_modadd_3_10_0[15],pre_upper_modadd_3_10_0[14],pre_upper_modadd_3_10_0[13],pre_upper_modadd_3_10_0[12],pre_upper_modadd_3_10_0[11],pre_upper_modadd_3_10_0[10],pre_upper_modadd_3_10_0[9],pre_upper_modadd_3_10_0[8],pre_upper_modadd_3_10_0[7],pre_upper_modadd_3_10_0[6],pre_upper_modadd_3_10_0[5],pre_upper_modadd_3_10_0[4],pre_upper_modadd_3_10_0[3],pre_upper_modadd_3_10_0[2],pre_upper_modadd_3_10_0[1],pre_upper_modadd_3_10_0[0]]), array1d(0..16-1, [pre_upper_modadd_3_10_1[15],pre_upper_modadd_3_10_1[14],pre_upper_modadd_3_10_1[13],pre_upper_modadd_3_10_1[12],pre_upper_modadd_3_10_1[11],pre_upper_modadd_3_10_1[10],pre_upper_modadd_3_10_1[9],pre_upper_modadd_3_10_1[8],pre_upper_modadd_3_10_1[7],pre_upper_modadd_3_10_1[6],pre_upper_modadd_3_10_1[5],pre_upper_modadd_3_10_1[4],pre_upper_modadd_3_10_1[3],pre_upper_modadd_3_10_1[2],pre_upper_modadd_3_10_1[1],pre_upper_modadd_3_10_1[0]]), array1d(0..16-1, [pre_lower_modadd_3_10_0[15],pre_lower_modadd_3_10_0[14],pre_lower_modadd_3_10_0[13],pre_lower_modadd_3_10_0[12],pre_lower_modadd_3_10_0[11],pre_lower_modadd_3_10_0[10],pre_lower_modadd_3_10_0[9],pre_lower_modadd_3_10_0[8],pre_lower_modadd_3_10_0[7],pre_lower_modadd_3_10_0[6],pre_lower_modadd_3_10_0[5],pre_lower_modadd_3_10_0[4],pre_lower_modadd_3_10_0[3],pre_lower_modadd_3_10_0[2],pre_lower_modadd_3_10_0[1],pre_lower_modadd_3_10_0[0]]), array1d(0..16-1, [pre_lower_modadd_3_10_1[15],pre_lower_modadd_3_10_1[14],pre_lower_modadd_3_10_1[13],pre_lower_modadd_3_10_1[12],pre_lower_modadd_3_10_1[11],pre_lower_modadd_3_10_1[10],pre_lower_modadd_3_10_1[9],pre_lower_modadd_3_10_1[8],pre_lower_modadd_3_10_1[7],pre_lower_modadd_3_10_1[6],pre_lower_modadd_3_10_1[5],pre_lower_modadd_3_10_1[4],pre_lower_modadd_3_10_1[3],pre_lower_modadd_3_10_1[2],pre_lower_modadd_3_10_1[1],pre_lower_modadd_3_10_1[0]]), 8, 16) = true;

constraint bct_compute(array1d(0..16-1, [pre_upper_modadd_3_10_0[0],pre_upper_modadd_3_10_0[1],pre_upper_modadd_3_10_0[2],pre_upper_modadd_3_10_0[3],pre_upper_modadd_3_10_0[4],pre_upper_modadd_3_10_0[5],pre_upper_modadd_3_10_0[6],pre_upper_modadd_3_10_0[7],pre_upper_modadd_3_10_0[8],pre_upper_modadd_3_10_0[9],pre_upper_modadd_3_10_0[10],pre_upper_modadd_3_10_0[11],pre_upper_modadd_3_10_0[12],pre_upper_modadd_3_10_0[13],pre_upper_modadd_3_10_0[14],pre_upper_modadd_3_10_0[15]]), array1d(0..16-1, [pre_upper_modadd_3_10_1[0],pre_upper_modadd_3_10_1[1],pre_upper_modadd_3_10_1[2],pre_upper_modadd_3_10_1[3],pre_upper_modadd_3_10_1[4],pre_upper_modadd_3_10_1[5],pre_upper_modadd_3_10_1[6],pre_upper_modadd_3_10_1[7],pre_upper_modadd_3_10_1[8],pre_upper_modadd_3_10_1[9],pre_upper_modadd_3_10_1[10],pre_upper_modadd_3_10_1[11],pre_upper_modadd_3_10_1[12],pre_upper_modadd_3_10_1[13],pre_upper_modadd_3_10_1[14],pre_upper_modadd_3_10_1[15]]), array1d(0..16-1, [pre_lower_modadd_3_10_0[0],pre_lower_modadd_3_10_0[1],pre_lower_modadd_3_10_0[2],pre_lower_modadd_3_10_0[3],pre_lower_modadd_3_10_0[4],pre_lower_modadd_3_10_0[5],pre_lower_modadd_3_10_0[6],pre_lower_modadd_3_10_0[7],pre_lower_modadd_3_10_0[8],pre_lower_modadd_3_10_0[9],pre_lower_modadd_3_10_0[10],pre_lower_modadd_3_10_0[11],pre_lower_modadd_3_10_0[12],pre_lower_modadd_3_10_0[13],pre_lower_modadd_3_10_0[14],pre_lower_modadd_3_10_0[15]]), array1d(0..16-1, [pre_lower_modadd_3_10_1[0],pre_lower_modadd_3_10_1[1],pre_lower_modadd_3_10_1[2],pre_lower_modadd_3_10_1[3],pre_lower_modadd_3_10_1[4],pre_lower_modadd_3_10_1[5],pre_lower_modadd_3_10_1[6],pre_lower_modadd_3_10_1[7],pre_lower_modadd_3_10_1[8],pre_lower_modadd_3_10_1[9],pre_lower_modadd_3_10_1[10],pre_lower_modadd_3_10_1[11],pre_lower_modadd_3_10_1[12],pre_lower_modadd_3_10_1[13],pre_lower_modadd_3_10_1[14],pre_lower_modadd_3_10_1[15]]), 16, middle_p[3]);

array[0..63] of var 0..1: upper_plaintext;
array[0..63] of var 0..1: lower_cipher_output_6_14;
array[0..15] of var 0..1: upper_modadd_0_0;
array[0..15] of var 0..1: upper_rot_0_1;
array[0..15] of var 0..1: upper_xor_0_2;
array[0..15] of var 0..1: upper_rot_0_3;
array[0..15] of var 0..1: upper_modadd_0_4;
array[0..15] of var 0..1: upper_rot_0_5;
array[0..15] of var 0..1: upper_xor_0_6;
array[0..15] of var 0..1: upper_modadd_0_7;
array[0..15] of var 0..1: upper_rot_0_8;
array[0..15] of var 0..1: upper_xor_0_9;
array[0..15] of var 0..1: upper_modadd_0_10;
array[0..15] of var 0..1: upper_rot_0_11;
array[0..15] of var 0..1: upper_xor_0_12;
array[0..15] of var 0..1: upper_rot_0_13;
array[0..63] of var 0..1: upper_intermediate_output_0_14;
array[0..15] of var 0..1: upper_modadd_1_0;
array[0..15] of var 0..1: upper_rot_1_1;
array[0..15] of var 0..1: upper_xor_1_2;
array[0..15] of var 0..1: upper_rot_1_3;
array[0..15] of var 0..1: upper_modadd_1_4;
array[0..15] of var 0..1: upper_rot_1_5;
array[0..15] of var 0..1: upper_xor_1_6;
array[0..15] of var 0..1: upper_modadd_1_7;
array[0..15] of var 0..1: upper_rot_1_8;
array[0..15] of var 0..1: upper_xor_1_9;
array[0..15] of var 0..1: upper_modadd_1_10;
array[0..15] of var 0..1: upper_rot_1_11;
array[0..15] of var 0..1: upper_xor_1_12;
array[0..15] of var 0..1: upper_rot_1_13;
array[0..63] of var 0..1: upper_intermediate_output_1_14;
array[0..15] of var 0..1: upper_modadd_2_0;
array[0..15] of var 0..1: upper_rot_2_1;
array[0..15] of var 0..1: upper_xor_2_2;
array[0..15] of var 0..1: upper_rot_2_3;
array[0..15] of var 0..1: upper_modadd_2_4;
array[0..15] of var 0..1: upper_rot_2_5;
array[0..15] of var 0..1: upper_xor_2_6;
array[0..15] of var 0..1: upper_modadd_2_7;
array[0..15] of var 0..1: upper_rot_2_8;
array[0..15] of var 0..1: upper_xor_2_9;
array[0..15] of var 0..1: upper_modadd_2_10;
array[0..15] of var 0..1: upper_rot_2_11;
array[0..15] of var 0..1: upper_xor_2_12;
array[0..15] of var 0..1: upper_rot_2_13;
array[0..63] of var 0..1: upper_intermediate_output_2_14;
array[0..15] of var 0..1: upper_modadd_3_0;
array[0..15] of var 0..1: upper_rot_3_1;
array[0..15] of var 0..1: upper_xor_3_2;
array[0..15] of var 0..1: upper_rot_3_3;
array[0..15] of var 0..1: upper_modadd_3_4;
array[0..15] of var 0..1: upper_rot_3_5;
array[0..15] of var 0..1: upper_xor_3_6;
array[0..15] of var 0..1: upper_modadd_3_7;
array[0..15] of var 0..1: upper_rot_3_8;
array[0..15] of var 0..1: upper_xor_3_9;
array[0..15] of var 0..1: upper_modadd_3_10;
array[0..15] of var 0..1: upper_rot_3_11;
array[0..15] of var 0..1: upper_xor_3_12;
array[0..15] of var 0..1: upper_rot_3_13;
array[0..63] of var 0..1: upper_intermediate_output_3_14;
array[0..15] of var 0..1: lower_xor_3_9;
array[0..15] of var 0..1: lower_rot_3_13;
array[0..63] of var 0..1: lower_intermediate_output_3_14;
array[0..15] of var 0..1: lower_rot_3_8;
array[0..15] of var 0..1: lower_xor_3_12;
array[0..15] of var 0..1: lower_modadd_3_7;
array[0..15] of var 0..1: lower_rot_3_11;
array[0..15] of var 0..1: lower_rot_3_3;
array[0..15] of var 0..1: lower_modadd_3_10;
array[0..15] of var 0..1: lower_xor_3_2;
array[0..15] of var 0..1: lower_xor_3_6;
array[0..15] of var 0..1: lower_rot_3_1;
array[0..15] of var 0..1: lower_rot_3_5;
array[0..15] of var 0..1: lower_modadd_3_0;
array[0..15] of var 0..1: lower_modadd_3_4;
array[0..15] of var 0..1: lower_xor_4_9;
array[0..15] of var 0..1: lower_rot_4_13;
array[0..63] of var 0..1: lower_intermediate_output_4_14;
array[0..15] of var 0..1: lower_rot_4_8;
array[0..15] of var 0..1: lower_xor_4_12;
array[0..15] of var 0..1: lower_modadd_4_7;
array[0..15] of var 0..1: lower_rot_4_11;
array[0..15] of var 0..1: lower_rot_4_3;
array[0..15] of var 0..1: lower_modadd_4_10;
array[0..15] of var 0..1: lower_xor_4_2;
array[0..15] of var 0..1: lower_xor_4_6;
array[0..15] of var 0..1: lower_rot_4_1;
array[0..15] of var 0..1: lower_rot_4_5;
array[0..15] of var 0..1: lower_modadd_4_0;
array[0..15] of var 0..1: lower_modadd_4_4;
array[0..15] of var 0..1: lower_xor_5_9;
array[0..15] of var 0..1: lower_rot_5_13;
array[0..63] of var 0..1: lower_intermediate_output_5_14;
array[0..15] of var 0..1: lower_rot_5_8;
array[0..15] of var 0..1: lower_xor_5_12;
array[0..15] of var 0..1: lower_modadd_5_7;
array[0..15] of var 0..1: lower_rot_5_11;
array[0..15] of var 0..1: lower_rot_5_3;
array[0..15] of var 0..1: lower_modadd_5_10;
array[0..15] of var 0..1: lower_xor_5_2;
array[0..15] of var 0..1: lower_xor_5_6;
array[0..15] of var 0..1: lower_rot_5_1;
array[0..15] of var 0..1: lower_rot_5_5;
array[0..15] of var 0..1: lower_modadd_5_0;
array[0..15] of var 0..1: lower_modadd_5_4;
array[0..15] of var 0..1: lower_xor_6_9;
array[0..15] of var 0..1: lower_rot_6_13;
array[0..15] of var 0..1: lower_rot_6_8;
array[0..15] of var 0..1: lower_xor_6_12;
array[0..15] of var 0..1: lower_modadd_6_7;
array[0..15] of var 0..1: lower_rot_6_11;
array[0..15] of var 0..1: lower_rot_6_3;
array[0..15] of var 0..1: lower_modadd_6_10;
array[0..15] of var 0..1: lower_xor_6_2;
array[0..15] of var 0..1: lower_xor_6_6;
array[0..15] of var 0..1: lower_rot_6_1;
array[0..15] of var 0..1: lower_rot_6_5;
array[0..15] of var 0..1: lower_modadd_6_0;
array[0..15] of var 0..1: lower_modadd_6_4;
array[0..28-1] of var int: p;
array[0..16-1] of var {0, 900, 200, 1100, 400, 1300, 600, 1500, 800, 100, 1000, 300, 1200, 500, 1400, 700}: upper_p;
constraint p[0] = upper_p[0];
constraint p[1] = upper_p[1];
constraint p[2] = upper_p[2];
constraint p[3] = upper_p[3];
constraint p[4] = upper_p[4];
constraint p[5] = upper_p[5];
constraint p[6] = upper_p[6];
constraint p[7] = upper_p[7];
constraint p[8] = upper_p[8];
constraint p[9] = upper_p[9];
constraint p[10] = upper_p[10];
constraint p[11] = upper_p[11];
var int: upper_weight = upper_p[0] + upper_p[1] + upper_p[2] + upper_p[3] + upper_p[4] + upper_p[5] + upper_p[6] + upper_p[7] + upper_p[8] + upper_p[9] + upper_p[10] + upper_p[11];
array[0..16-1] of var {0, 900, 200, 1100, 400, 1300, 600, 1500, 800, 100, 1000, 300, 1200, 500, 1400, 700}: lower_p;
constraint p[12] = lower_p[4];
constraint p[13] = lower_p[5];
constraint p[14] = lower_p[6];
constraint p[15] = lower_p[7];
constraint p[16] = lower_p[8];
constraint p[17] = lower_p[9];
constraint p[18] = lower_p[10];
constraint p[19] = lower_p[11];
constraint p[20] = lower_p[12];
constraint p[21] = lower_p[13];
constraint p[22] = lower_p[14];
constraint p[23] = lower_p[15];
var int: lower_weight = lower_p[4] + lower_p[5] + lower_p[6] + lower_p[7] + lower_p[8] + lower_p[9] + lower_p[10] + lower_p[11] + lower_p[12] + lower_p[13] + lower_p[14] + lower_p[15];
array[0..4-1] of var 0..3200: middle_p;
var int: middle_weight = sum(middle_p);
constraint p[24] = middle_p[0];
constraint p[25] = middle_p[1];
constraint p[26] = middle_p[2];
constraint p[27] = middle_p[3];
var int: weight = (2 * upper_weight) + (2 * lower_weight) + middle_weight;
solve:: int_search(p, smallest, indomain_min, complete) minimize weight;
output["upper_plaintext = "++ show(upper_plaintext) ++ "\n" ++"lower_cipher_output_6_14 = "++ show(lower_cipher_output_6_14) ++ "\n" ++"upper_modadd_0_0 = "++ show(upper_modadd_0_0)++ "\n" ++ "upper probability = "++ show(upper_p[0]/100) ++ "\n" ++"upper_rot_0_1 = "++ show(upper_rot_0_1)++ "\n" ++"upper_xor_0_2 = "++ show(upper_xor_0_2)++ "\n" ++"upper_rot_0_3 = "++ show(upper_rot_0_3)++ "\n" ++"upper_modadd_0_4 = "++ show(upper_modadd_0_4)++ "\n" ++ "upper probability = "++ show(upper_p[1]/100) ++ "\n" ++"upper_rot_0_5 = "++ show(upper_rot_0_5)++ "\n" ++"upper_xor_0_6 = "++ show(upper_xor_0_6)++ "\n" ++"upper_modadd_0_7 = "++ show(upper_modadd_0_7)++ "\n" ++ "upper probability = "++ show(upper_p[2]/100) ++ "\n" ++"upper_rot_0_8 = "++ show(upper_rot_0_8)++ "\n" ++"upper_xor_0_9 = "++ show(upper_xor_0_9)++ "\n" ++"upper_modadd_0_10 = "++ show(upper_modadd_0_10)++ "\n" ++ "upper probability = "++ show(upper_p[3]/100) ++ "\n" ++"upper_rot_0_11 = "++ show(upper_rot_0_11)++ "\n" ++"upper_xor_0_12 = "++ show(upper_xor_0_12)++ "\n" ++"upper_rot_0_13 = "++ show(upper_rot_0_13)++ "\n" ++"upper_intermediate_output_0_14 = "++ show(upper_intermediate_output_0_14)++ "\n" ++"upper_modadd_1_0 = "++ show(upper_modadd_1_0)++ "\n" ++ "upper probability = "++ show(upper_p[4]/100) ++ "\n" ++"upper_rot_1_1 = "++ show(upper_rot_1_1)++ "\n" ++"upper_xor_1_2 = "++ show(upper_xor_1_2)++ "\n" ++"upper_rot_1_3 = "++ show(upper_rot_1_3)++ "\n" ++"upper_modadd_1_4 = "++ show(upper_modadd_1_4)++ "\n" ++ "upper probability = "++ show(upper_p[5]/100) ++ "\n" ++"upper_rot_1_5 = "++ show(upper_rot_1_5)++ "\n" ++"upper_xor_1_6 = "++ show(upper_xor_1_6)++ "\n" ++"upper_modadd_1_7 = "++ show(upper_modadd_1_7)++ "\n" ++ "upper probability = "++ show(upper_p[6]/100) ++ "\n" ++"upper_rot_1_8 = "++ show(upper_rot_1_8)++ "\n" ++"upper_xor_1_9 = "++ show(upper_xor_1_9)++ "\n" ++"upper_modadd_1_10 = "++ show(upper_modadd_1_10)++ "\n" ++ "upper probability = "++ show(upper_p[7]/100) ++ "\n" ++"upper_rot_1_11 = "++ show(upper_rot_1_11)++ "\n" ++"upper_xor_1_12 = "++ show(upper_xor_1_12)++ "\n" ++"upper_rot_1_13 = "++ show(upper_rot_1_13)++ "\n" ++"upper_intermediate_output_1_14 = "++ show(upper_intermediate_output_1_14)++ "\n" ++"upper_modadd_2_0 = "++ show(upper_modadd_2_0)++ "\n" ++ "upper probability = "++ show(upper_p[8]/100) ++ "\n" ++"upper_rot_2_1 = "++ show(upper_rot_2_1)++ "\n" ++"upper_xor_2_2 = "++ show(upper_xor_2_2)++ "\n" ++"upper_rot_2_3 = "++ show(upper_rot_2_3)++ "\n" ++"upper_modadd_2_4 = "++ show(upper_modadd_2_4)++ "\n" ++ "upper probability = "++ show(upper_p[9]/100) ++ "\n" ++"upper_rot_2_5 = "++ show(upper_rot_2_5)++ "\n" ++"upper_xor_2_6 = "++ show(upper_xor_2_6)++ "\n" ++"upper_modadd_2_7 = "++ show(upper_modadd_2_7)++ "\n" ++ "upper probability = "++ show(upper_p[10]/100) ++ "\n" ++"upper_rot_2_8 = "++ show(upper_rot_2_8)++ "\n" ++"upper_xor_2_9 = "++ show(upper_xor_2_9)++ "\n" ++"upper_modadd_2_10 = "++ show(upper_modadd_2_10)++ "\n" ++ "upper probability = "++ show(upper_p[11]/100) ++ "\n" ++"upper_rot_2_11 = "++ show(upper_rot_2_11)++ "\n" ++"upper_xor_2_12 = "++ show(upper_xor_2_12)++ "\n" ++"upper_rot_2_13 = "++ show(upper_rot_2_13)++ "\n" ++"upper_intermediate_output_2_14 = "++ show(upper_intermediate_output_2_14)++ "\n" ++"upper_modadd_3_0 = "++ show(upper_modadd_3_0)++ "\n" ++ "middle probability = "++ show(middle_p[2]/100) ++ "\n" ++"upper_rot_3_1 = "++ show(upper_rot_3_1)++ "\n" ++"upper_xor_3_2 = "++ show(upper_xor_3_2)++ "\n" ++"upper_rot_3_3 = "++ show(upper_rot_3_3)++ "\n" ++"upper_modadd_3_4 = "++ show(upper_modadd_3_4)++ "\n" ++ "middle probability = "++ show(middle_p[0]/100) ++ "\n" ++"upper_rot_3_5 = "++ show(upper_rot_3_5)++ "\n" ++"upper_xor_3_6 = "++ show(upper_xor_3_6)++ "\n" ++"upper_modadd_3_7 = "++ show(upper_modadd_3_7)++ "\n" ++ "middle probability = "++ show(middle_p[1]/100) ++ "\n" ++"upper_rot_3_8 = "++ show(upper_rot_3_8)++ "\n" ++"upper_xor_3_9 = "++ show(upper_xor_3_9)++ "\n" ++"upper_modadd_3_10 = "++ show(upper_modadd_3_10)++ "\n" ++ "middle probability = "++ show(middle_p[3]/100) ++ "\n" ++"upper_rot_3_11 = "++ show(upper_rot_3_11)++ "\n" ++"upper_xor_3_12 = "++ show(upper_xor_3_12)++ "\n" ++"upper_rot_3_13 = "++ show(upper_rot_3_13)++ "\n" ++"upper_intermediate_output_3_14 = "++ show(upper_intermediate_output_3_14)++ "\n" ++"lower_xor_3_9 = "++ show(lower_xor_3_9)++ "\n" ++"lower_rot_3_13 = "++ show(lower_rot_3_13)++ "\n" ++"lower_intermediate_output_3_14 = "++ show(lower_intermediate_output_3_14)++ "\n" ++"lower_rot_3_8 = "++ show(lower_rot_3_8)++ "\n" ++"lower_xor_3_12 = "++ show(lower_xor_3_12)++ "\n" ++"lower_modadd_3_7 = "++ show(lower_modadd_3_7)++ "\n" ++ "lower_rot_3_11 = "++ show(lower_rot_3_11)++ "\n" ++"lower_rot_3_3 = "++ show(lower_rot_3_3)++ "\n" ++"lower_modadd_3_10 = "++ show(lower_modadd_3_10)++ "\n" ++ "lower_xor_3_2 = "++ show(lower_xor_3_2)++ "\n" ++"lower_xor_3_6 = "++ show(lower_xor_3_6)++ "\n" ++"lower_rot_3_1 = "++ show(lower_rot_3_1)++ "\n" ++"lower_rot_3_5 = "++ show(lower_rot_3_5)++ "\n" ++"lower_modadd_3_0 = "++ show(lower_modadd_3_0)++ "\n" ++ "lower_modadd_3_4 = "++ show(lower_modadd_3_4)++ "\n" ++ "lower_xor_4_9 = "++ show(lower_xor_4_9)++ "\n" ++"lower_rot_4_13 = "++ show(lower_rot_4_13)++ "\n" ++"lower_intermediate_output_4_14 = "++ show(lower_intermediate_output_4_14)++ "\n" ++"lower_rot_4_8 = "++ show(lower_rot_4_8)++ "\n" ++"lower_xor_4_12 = "++ show(lower_xor_4_12)++ "\n" ++"lower_modadd_4_7 = "++ show(lower_modadd_4_7)++ "\n" ++ "lower probability = "++ show(lower_p[4]/100) ++ "\n" ++"lower_rot_4_11 = "++ show(lower_rot_4_11)++ "\n" ++"lower_rot_4_3 = "++ show(lower_rot_4_3)++ "\n" ++"lower_modadd_4_10 = "++ show(lower_modadd_4_10)++ "\n" ++ "lower probability = "++ show(lower_p[5]/100) ++ "\n" ++"lower_xor_4_2 = "++ show(lower_xor_4_2)++ "\n" ++"lower_xor_4_6 = "++ show(lower_xor_4_6)++ "\n" ++"lower_rot_4_1 = "++ show(lower_rot_4_1)++ "\n" ++"lower_rot_4_5 = "++ show(lower_rot_4_5)++ "\n" ++"lower_modadd_4_0 = "++ show(lower_modadd_4_0)++ "\n" ++ "lower probability = "++ show(lower_p[6]/100) ++ "\n" ++"lower_modadd_4_4 = "++ show(lower_modadd_4_4)++ "\n" ++ "lower probability = "++ show(lower_p[7]/100) ++ "\n" ++"lower_xor_5_9 = "++ show(lower_xor_5_9)++ "\n" ++"lower_rot_5_13 = "++ show(lower_rot_5_13)++ "\n" ++"lower_intermediate_output_5_14 = "++ show(lower_intermediate_output_5_14)++ "\n" ++"lower_rot_5_8 = "++ show(lower_rot_5_8)++ "\n" ++"lower_xor_5_12 = "++ show(lower_xor_5_12)++ "\n" ++"lower_modadd_5_7 = "++ show(lower_modadd_5_7)++ "\n" ++ "lower probability = "++ show(lower_p[8]/100) ++ "\n" ++"lower_rot_5_11 = "++ show(lower_rot_5_11)++ "\n" ++"lower_rot_5_3 = "++ show(lower_rot_5_3)++ "\n" ++"lower_modadd_5_10 = "++ show(lower_modadd_5_10)++ "\n" ++ "lower probability = "++ show(lower_p[9]/100) ++ "\n" ++"lower_xor_5_2 = "++ show(lower_xor_5_2)++ "\n" ++"lower_xor_5_6 = "++ show(lower_xor_5_6)++ "\n" ++"lower_rot_5_1 = "++ show(lower_rot_5_1)++ "\n" ++"lower_rot_5_5 = "++ show(lower_rot_5_5)++ "\n" ++"lower_modadd_5_0 = "++ show(lower_modadd_5_0)++ "\n" ++ "lower probability = "++ show(lower_p[10]/100) ++ "\n" ++"lower_modadd_5_4 = "++ show(lower_modadd_5_4)++ "\n" ++ "lower probability = "++ show(lower_p[11]/100) ++ "\n" ++"lower_xor_6_9 = "++ show(lower_xor_6_9)++ "\n" ++"lower_rot_6_13 = "++ show(lower_rot_6_13)++ "\n" ++"lower_rot_6_8 = "++ show(lower_rot_6_8)++ "\n" ++"lower_xor_6_12 = "++ show(lower_xor_6_12)++ "\n" ++"lower_modadd_6_7 = "++ show(lower_modadd_6_7)++ "\n" ++ "lower probability = "++ show(lower_p[12]/100) ++ "\n" ++"lower_rot_6_11 = "++ show(lower_rot_6_11)++ "\n" ++"lower_rot_6_3 = "++ show(lower_rot_6_3)++ "\n" ++"lower_modadd_6_10 = "++ show(lower_modadd_6_10)++ "\n" ++ "lower probability = "++ show(lower_p[13]/100) ++ "\n" ++"lower_xor_6_2 = "++ show(lower_xor_6_2)++ "\n" ++"lower_xor_6_6 = "++ show(lower_xor_6_6)++ "\n" ++"lower_rot_6_1 = "++ show(lower_rot_6_1)++ "\n" ++"lower_rot_6_5 = "++ show(lower_rot_6_5)++ "\n" ++"lower_modadd_6_0 = "++ show(lower_modadd_6_0)++ "\n" ++ "lower probability = "++ show(lower_p[14]/100) ++ "\n" ++"lower_modadd_6_4 = "++ show(lower_modadd_6_4)++ "\n" ++ "lower probability = "++ show(lower_p[15]/100) ++ "\n" ++"Upper weight = " ++ show(upper_weight/100) ++ "\n" ++"Lower weight = " ++ show(lower_weight/100) ++ "\n" ++"Middle weight = " ++ show(middle_weight/100) ++ "\n" ++"Trail weight = " ++ show(weight/100)  ];

    include "table.mzn";
    int:num_workers_bct = 4;
    int: num_rows_bct = 16;
    int: num_cols_bct = 9;
    array[0..num_cols_bct-1] of var 0..1: b_bct;
    array[0..num_workers_bct-1,0..num_rows_bct-1,0..num_cols_bct-1] of 0..1: bct_table =
         array3d(0..num_workers_bct-1,0..num_rows_bct-1,0..num_cols_bct-1,
      [
      0, 0, 0, 0, 1, 0, 0, 0, 0,
    1, 0, 0, 0, 1, 1, 0, 0, 1,
    0, 1, 0, 0, 1, 1, 0, 0, 1,
    1, 1, 0, 0, 1, 1, 0, 0, 1,
    0, 0, 1, 0, 1, 0, 1, 0, 1,
    1, 0, 1, 0, 1, 0, 0, 1, 1,
    0, 1, 1, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 1, 1, 0, 1, 0, 1,
    1, 0, 0, 1, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 0, 0, 0, 0, 0,
    1, 1, 0, 1, 1, 0, 0, 1, 1,
    0, 0, 1, 1, 1, 0, 1, 0, 1,
    1, 0, 1, 1, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 0, 0, 1, 1,
    1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 1, 0, 0, 1,
    1, 0, 0, 0, 1, 1, 0, 0, 1,
    0, 1, 0, 0, 1, 1, 0, 0, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 0,
    0, 0, 1, 0, 0, 0, 0, 0, 0,
    1, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 0, 0, 1, 1, 0, 1,
    1, 1, 1, 0, 0, 1, 0, 1, 1,
    0, 0, 0, 1, 0, 1, 1, 0, 1,
    1, 0, 0, 1, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 0, 0, 0, 0, 0,
    1, 1, 0, 1, 0, 1, 0, 1, 1,
    0, 0, 1, 1, 0, 0, 0, 0, 0,
    1, 0, 1, 1, 0, 1, 1, 0, 1,
    0, 1, 1, 1, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 0, 1, 0, 1, 1,
    0, 0, 0, 0, 1, 0, 1, 0, 1,
    1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 1, 1, 0, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 0, 1, 0, 1, 0, 1,
    1, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 0, 0, 1, 1, 0, 1,
    0, 0, 0, 1, 1, 0, 1, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 1,
    0, 1, 0, 1, 0, 0, 0, 0, 0,
    1, 1, 0, 1, 0, 0, 0, 0, 0,
    0, 0, 1, 1, 0, 0, 1, 0, 0,
    1, 0, 1, 1, 0, 0, 1, 1, 1,
    0, 1, 1, 1, 0, 0, 1, 1, 1,
    1, 1, 1, 1, 0, 0, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 1, 0, 0, 1, 1,
    0, 1, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 0, 0, 0, 1, 0, 1, 1,
    0, 0, 1, 0, 1, 0, 0, 1, 1,
    1, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 0, 0, 1, 0, 1, 1,
    0, 0, 0, 1, 0, 0, 0, 0, 0,
    1, 0, 0, 1, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 0, 0, 1, 1,
    1, 1, 0, 1, 0, 1, 0, 1, 1,
    0, 0, 1, 1, 0, 0, 1, 1, 1,
    1, 0, 1, 1, 0, 0, 1, 1, 1,
    0, 1, 1, 1, 0, 0, 1, 1, 1,
    1, 1, 1, 1, 0, 0, 0, 1, 0
      ]);

    predicate onlyLargeSwitch_BCT_enum(
      array[int] of var 0..1: dL,
      array[int] of var 0..1:dR,
      array[int] of var 0..1: nL,
      array[int] of var 0..1:nR,
      int: halfNum,
      int: branchSizeBCT,
    ) =
      let {
        array[0..branchSizeBCT - 1, 0..3] of var bool: dp ,
        array[0..branchSizeBCT - 2] of var bool: isHalf ;
        array[0..branchSizeBCT-2, 0..15] of var bool: matrix;
        array[0..branchSizeBCT-2, 0..3] of var bool: halfSize;
        array[0..branchSizeBCT-2] of var bool: ifEnforced;
        array[0..branchSizeBCT-2, 0..3] of var bool: enforcedLiterals;
        array[0..branchSizeBCT-2, 0..15] of var bool: literals;
      } in
      (sum(isHalf) <= halfNum) /\
      (dp[0, 0] == true) /\
      (dp[0, 1] == false) /\
      (dp[0, 2] == false) /\
      (dp[0, 3] == false) /\
      forall(i in 0..branchSizeBCT-2) (
        forall(cn in 0..3) (
          let {
            array[0..8] of var 0..1: column = array1d(0..8, [dL[i], dR[i], nL[i], nR[i], matrix[i, 0*4+cn], matrix[i, 1*4+cn], matrix[i, 2*4+cn], matrix[i, 3*4+cn], halfSize[i, cn]])
          } in
          BVAssign_bct(column, cn)
        ) /\
        (dp[i + 1, 0] \/ dp[i + 1, 1] \/ dp[i + 1, 2] \/ dp[i + 1, 3]) /\

        forall(j in 0..3) (
          (ifEnforced[i] == not(isHalf[i])) /\
          (not(ifEnforced[i]) \/ not(dp[i,j]) \/ matrix[i, j*4+j]) /\
          (not(ifEnforced[i]) \/ not(dp[i,j]) \/ dp[i+1,j]) /\
          sum([not(ifEnforced[i]), not(dp[i,j]), matrix[i, j * 4 + j]]) >= 1 /\
          sum([not(ifEnforced[i]), not(dp[i,j]), dp[i + 1,j]]) >= 1
        ) /\
        forall(j in 0..3) (
          (enforcedLiterals[i,j] -> (not(matrix[i,j * 4 + j]) /\ dp[i,j])) /\
          (not(enforcedLiterals[i,j]) -> (matrix[i,j * 4 + j] \/ not(dp[i,j])))
        ) /\
        (ifEnforced[i] \/ enforcedLiterals[i,0] \/ enforcedLiterals[i,1] \/ enforcedLiterals[i,2] \/ enforcedLiterals[i,3]) /\
        forall(r in 0..3) (
          forall(cc in 0..3) (
            (literals[i, r * 4 + cc] -> (matrix[i, r * 4 + cc] /\ dp[i, cc])) /\
            (not(literals[i, r * 4 + cc]) -> (not(matrix[i,r * 4 + cc]) \/ not(dp[i,cc]))) /\
            (matrix[i,r * 4 + cc] >=  literals[i,r * 4 + cc]) /\
            (dp[i,cc] >=           literals[i,r * 4 + cc])  /\
            sum([ literals[i, r * 4 + cc], true ]) >= sum([ matrix[i, r * 4 + cc], dp[i,cc] ])
          ) /\
          (dp[i + 1,r] -> (literals[i,r * 4 + 0] \/ literals[i,r * 4 + 1] \/ literals[i,r * 4 + 2] \/ literals[i,r * 4 + 3])) /\
          (not(dp[i + 1,r]) -> (not(literals[i,r * 4 + 0]) /\ not(literals[i,r * 4 + 1]) /\ not(literals[i,r * 4 + 2]) /\ not(literals[i,r * 4 + 3]))) /\
          forall(li in 0..3) ( dp[i + 1,r] >= literals[i, r * 4 + li] ) /\
          (sum([ literals[i,r * 4 + 0], literals[i,r * 4 + 1], literals[i,r * 4 + 2], literals[i,r * 4 + 3] ]) >= dp[i + 1,r])
        )

      )
      ;
    predicate BVAssign_bct(array[0..num_cols_bct-1] of var 0..1: column, int: index) =
        let {
            array[int] of set of int: indices = [index..index, 0..num_rows_bct-1, 0..num_cols_bct-1];
            array[int,int] of int: extractedFromTable = slice_2d(bct_table, indices, 0..num_rows_bct-1, 0..num_cols_bct-1);
        } in
        table(column, extractedFromTable);
    

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
    array[0..15] of var 0..1: dL,
    array[0..15] of var 0..1: dR,
    array[0..15] of var 0..1: nL,
    array[0..15] of var 0..1: nR,
    int: branchSize,
    var 0..3200: bct_minus_log_2
) =
let {
    array[1..branchSize-1,0..3] of var 0.0..1.0: dp_bct;
    array[1..branchSize-1] of var 0..15: tmp0;
    var 0.0..1.0: bct_value;
} in
(
    ( 
        tmp0[1] == nR[branchSize-1]*8 + nL[branchSize-1]*4 + dR[branchSize-1]*2 + dL[branchSize-1]*1
    ) /\
    forall(j in 0..3)(
        dp_bct[1,j] == int2float(tables_bct[tmp0[1],j,0]) / 4.0
    ) /\
    forall(i in 2..branchSize-1)(
        tmp0[i] == nR[branchSize-i]*8 + nL[branchSize-i]*4 + dR[branchSize-i]*2 + dL[branchSize-i]*1
    ) /\
    forall(i in 2..branchSize-1, j in 0..3)(
            dp_bct[i,j] == sum(k in 0..3)(
                 dp_bct[i-1,k] * int2float(tables_bct[tmp0[i],j,k]) 
            ) / 4.0
    ) /\
    (
        bct_value == sum(state in 0..3)( dp_bct[branchSize-1,state] )
    ) /\
    (
        approx_prob_log(bct_value,bct_minus_log_2)
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
constraint sum(lower_cipher_output_6_14)>0;
