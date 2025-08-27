# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
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
    function array[int] of var 0..1: LRot(array[int] of var 0..1: X, int: val)=
    let {
        int:  n= length(X);
    } in
    array1d(0..n-1, [X[(j+val) mod n] | j in 0..n-1]);

    % Right rotation of X by val positions
    function array[int] of var 0..1: RRot(array[int] of var 0..1: X, int: val)=
    let {
        int:  n= length(X);
    } in
    array1d(0..n-1, [X[(n+j-val) mod n] | j in 0..n-1]);

    function array[int] of var 0..1: RSHIFT(array[int] of var 0..1: X, int: val)=
    let {
        int:  n= length(X);
    } in
    array1d(0..n-1, [ if j <= val-1 then 0 else X[j-val] endif| j in 0..n-1]);


    function array[int] of var 0..1: LSHIFT(array[int] of var 0..1: X, int: val)=
    let {
        int:  n= length(X);
    } in

    array1d(0..n-1, [ if j <= n-val-1 then X[j+val] else 0 endif| j in 0..n-1]);


    function array[int] of var 0..1: RSHIFT_BY_VARIABLE_AMOUNT(array[int] of var 0..1: X, var int: val)=
    let {
        int:  n= length(X);
    } in
    array1d(0..n-1, [ if j <= val-1 then 0 else X[j-val] endif| j in 0..n-1]);


    function array[int] of var 0..1: LSHIFT_BY_VARIABLE_AMOUNT(array[int] of var 0..1: X, var int: val)=
    let {
        int:  n= length(X);
    } in

    array1d(0..n-1, [ if j <= n-val-1 then X[j+val] else 0 endif| j in 0..n-1]);

    predicate modular_addition_word(array [int] of var 0..1 : A, array [int] of var 0..1 : B, array [int] of var 0..1 : C, array [int] of var 0..1 : d_list, var 0..1:dummy_xor, int: window_size_by_round) =
    let {
        int:  n= length(A);
    } in
    forall (j in 0..n-2) (
     modular_addition(A[j+1],B[j+1],C[j+1],A[j],B[j],C[j],d_list[j])) /\\
     if window_size_by_round!=-1 then
     n_window_heuristic_constraints(A,B,C,n,window_size_by_round)
     endif
     /\\
     dummy_xor >= A[n-1] /\\
     dummy_xor >= B[n-1] /\\
     dummy_xor >= C[n-1] /\\
     A[n-1]+B[n-1]+C[n-1] >= 2*dummy_xor /\\
     A[n-1]+B[n-1]+C[n-1] <= 2 ;

    predicate n_window_heuristic_constraints(array [int] of var 0..1 : A, array [int] of var 0..1 : B, array [int] of var 0..1 : C, int:n, int: nn) =
    forall(j in nn+1..n-1) (sum(array1d([(A[j-i]+B[j-i]+C[j-i])mod 2|i in 1..nn+1])) <= nn);

    function array[int] of var 0..1: XOR3(array[int] of var 0..1: X, array[int] of var 0..1: Y, array[int] of var 0..1: Z)=
    let {
        int:  n= length(X);
    } in
    array1d(0..n-1, [(X[j]+Y[j]+Z[j]) mod 2 | j in 0..n-1]);

    predicate xor_bit(var int:a, var int:b, var int:c, var 0..1:dummy_xor) =
    dummy_xor >= a /\\
    dummy_xor >= b /\\
    dummy_xor >= c /\\
    a + b + c >= 2*dummy_xor /\\
    a + b + c <= 2;

    function var 0..1: eq(var 0..1:a,var 0..1:b,var int:c) = (if (a=b /\\ b=c) then 0 else 1 endif);

    predicate modular_addition(var 0..1:a,var 0..1:b,var 0..1:c,var 0..1:a1,var 0..1:b1,var 0..1:c1, var 0..1:d) =
    b-1*c + d >= 0 /\\
    a+-b + d >= 0 /\\
    -a + c + d >= 0 /\\
    -a-b-c-d >= -3 /\\
    a +b +c-d >= 0 /\\
    -b +a1 +b1 +c1 + d >= 0 /\\
    b +a1-b1 +c1 + d >= 0 /\\
    b-a1 +b1 +c1 + d >= 0 /\\
    a +a1 +b1-c1 + d >= 0 /\\
    c-a1-b1-c1 + d >= -2 /\\
    -b +a1-b1-c1 + d >= -2 /\\
    -b-a1 +b1-c1 + d >= -2 /\\
    -b-a1-b1 +c1 + d >= -2;


    predicate modular_addition_tii(var 0..1:a,var 0..1:b,var 0..1:c,var 0..1:a1,var 0..1:b1,var 0..1:c1, var 0..1:d) =
    1*a+0*b+-1*c+0*a1+0*b1+0*c1+1*d>=-0/\\
    0*a+-1*b+1*c+0*a1+0*b1+0*c1+1*d>=-0/\\
    -1*a+1*b+0*c+0*a1+0*b1+0*c1+1*d>=-0/\\
    -1*a+-1*b+-1*c+0*a1+0*b1+0*c1+-1*d>=-3/\\
    1*a+1*b+1*c+0*a1+0*b1+0*c1+-1*d>=-0/\\
    1*a+1*b+1*c+-3*a1+-3*b1+-3*c1+2*d>=-6/\\
    -1*a+-1*b+-1*c+3*a1+-3*b1+-3*c1+2*d>=-6/\\
    -1*a+-1*b+-1*c+-3*a1+3*b1+-3*c1+2*d>=-6/\\
    -1*a+-1*b+-1*c+-3*a1+-3*b1+3*c1+2*d>=-6/\\
    1*a+1*b+1*c+3*a1+3*b1+-3*c1+2*d>=-0/\\
    1*a+1*b+1*c+3*a1+-3*b1+3*c1+2*d>=-0/\\
    1*a+1*b+1*c+-3*a1+3*b1+3*c1+2*d>=-0/\\
    0*a+0*b+-1*c+1*a1+1*b1+1*c1+1*d>=-0;


    predicate xor_word(array [int] of var 0..1 : A, array [int] of var 0..1 : B, array [int] of var 0..1 : C, array [int] of var 0..1 : dummy_xor) =
    let {
    int:  n= length(A);

    } in
    forall (j in 0..n-1) (
     xor_bit(A[j],B[j],C[j], dummy_xor[j])
    );


    %function array[0..n-1] of var 0..1: SUM3(array[0..n-1] of var 0..1: X, array[0..n-1] of var 0..1: Y, array[0..n-1] of var 0..1: Z)=
    %array1d(0..n-1, [(X[j]+Y[j]+Z[j]) mod 2 | j in 0..n-1]);


    """

    return functions_with_window_size
