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

