
# ****************************************************************************
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


def get_word_operations():

    functions_with_window_size = """
    % Left rotation of X by val positions
    function array[int] of var bool: LRot(array[int] of var bool: X, int: val)=
    let {
        int:  n= length(X);
    } in
    array1d(0..n-1, [X[(j+val) mod n] | j in 0..n-1]);

    % Right rotation of X by val positions
    function array[int] of var bool: RRot(array[int] of var bool: X, int: val)=
    let {
        int:  n= length(X);
    } in
    array1d(0..n-1, [X[(n+j-val) mod n] | j in 0..n-1]);

    function array[int] of var bool: RSHIFT(array[int] of var bool: X, int: val)=
    let {
        int:  n= length(X);
    } in
    array1d(0..n-1, [ if j <= val-1 then false else X[j-val] endif| j in 0..n-1]);


    function array[int] of var bool: LSHIFT(array[int] of var bool: X, int: val)=
    let {
        int:  n= length(X);
    } in

    array1d(0..n-1, [ if j <= n-val-1 then X[j+val] else false endif| j in 0..n-1]);


    function array[int] of var bool: RSHIFT_BY_VARIABLE_AMOUNT(array[int] of var bool: X, var int: val)=
    let {
        int:  n= length(X);
    } in
    array1d(0..n-1, [ if j <= val-1 then false else X[j-val] endif| j in 0..n-1]);


    function array[int] of var bool: LSHIFT_BY_VARIABLE_AMOUNT(array[int] of var bool: X, var int: val)=
    let {
        int:  n= length(X);
    } in

    array1d(0..n-1, [ if j <= n-val-1 then X[j+val] else false endif| j in 0..n-1]);

    predicate modular_addition_word(array [int] of var bool : A, array [int] of var bool : B, array [int] of var bool : C, array [int] of var bool : d_list, int: window_size_by_round) =
    let {
        int:  n= length(A);
    } in
    forall (j in 0..n-2) (modular_addition_bit_level_sat(A[j], B[j], C[j], A[j+1], B[j+1], C[j+1], d_list[j])) /\\
     if window_size_by_round!=-1 then
     n_window_heuristic_constraints(A,B,C,n,window_size_by_round)
     endif
     /\\
     xorall([A[n-1],B[n-1],C[n-1]]) = false;

    predicate at_most_k(array [int] of var bool : x, int: k) =
    let {
    int:  n= length(x);
    array [1..n, 1..k] of var bool : s;
    }
    in
      (not x[1] \\/ s[1,1]) /\\
      forall(j in 2..k)(not s[1, j]) /\\
      forall(i in 2..n-1)(
        (not x[i]\\/s[i,1]) /\\
        (not s[i-1,1] \\/ s[i,1]) /\\
        forall(j in 2..k) (
          (not x[i]\\/not s[i-1,j-1]\\/s[i,j]) /\\
          (not s[i-1,j]\\/s[i,j])
        )/\\
        (not x[i]\\/ not s[i-1,k])
      ) /\\
      (not x[n] \\/ not s[n-1,k]);

    predicate n_window_heuristic_constraints(array [int] of var bool : A, array [int] of var bool : B, array [int] of var bool : C, int:n, int: k) =
      forall(i in 0..n-1-k)(not(
      forall(j in 0..k)(
        xorall([A[i+j], B[i+j], C[i+j]])
      )
    ));

    function array[int] of var bool: XOR3(array[int] of var bool: X, array[int] of var bool: Y, array[int] of var bool: Z)=
    let {
        int:  n= length(X);
    } in
    array1d(0..n-1, [if xorall([X[j],Y[j],Z[j]]) = true then true else false endif | j in 0..n-1]);

    predicate xor_bit(var bool:a, var bool:b, var bool:c) =
      (a \\/ b \\/ not c) /\\
      (a \\/ not b \\/ c) /\\
      (not a \\/  b \\/  c) /\\
      (not a \\/ not b \\/ not c);

    function var bool: eq(var bool:a,var bool:b,var int:c) = (if (a=b /\\ b=c) then false else true endif);

    predicate modular_addition_bit_level_sat(var bool:a,var bool:b,var bool:c,var bool:a1,var bool:b1,var bool:c1, var bool:w) =
    ((a     \\/     b \\/ not c \\/     a1 \\/     b1 \\/     c1))/\\
     ((a     \\/ not b \\/     c \\/     a1 \\/     b1 \\/     c1))/\\
     ((not a \\/     b \\/     c \\/     a1 \\/     b1 \\/     c1))/\\
     ((not a \\/ not b \\/ not c \\/     a1 \\/     b1 \\/     c1))/\\
     ((a     \\/ b     \\/     c \\/ not a1 \\/ not b1 \\/ not c1))/\\
     ((a     \\/ not b \\/ not c \\/ not a1 \\/ not b1 \\/ not c1))/\\
     ((not a \\/ b     \\/ not c \\/ not a1 \\/ not b1 \\/ not c1))/\\
     ((not a \\/ not b \\/     c \\/ not a1 \\/ not b1 \\/ not c1))/\\
    ((not a1 \\/ c1     \\/   w) ) /\\
    ((b1     \\/ not c1 \\/   w) ) /\\
    ((a1     \\/ not b1 \\/   w) ) /\\
    ((a1     \\/     b1 \\/  c1 \\/ not w) ) /\\
    ((not a1 \\/ not b1 \\/ not c1 \\/ not w) );

    predicate xor_word(array [int] of var bool : A, array [int] of var bool : B, array [int] of var bool : C) =
    let {
    int:  n= length(A);

    } in
    forall (j in 0..n-1) (
     xor_bit(A[j],B[j],C[j])
    );

    """

    return functions_with_window_size
