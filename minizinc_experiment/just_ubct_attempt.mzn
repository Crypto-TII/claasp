include "table.mzn";

% ---------- costanti / tabelle ----------------
int: num_workers_ubct = 4;
int: num_rows = 32;
int: num_cols_ubct = 10;
int: num_cols_last_table_ubct = 7;

% ubct_table[worker, row, col]
array[0..num_workers_ubct-1, 0..num_rows-1, 0..num_cols_ubct-1] of 0..1: ubct_table =
    array3d(0..num_workers_ubct-1, 0..num_rows-1, 0..num_cols_ubct-1,
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

% last table 8x7
array[0..7, 0..num_cols_last_table_ubct-1] of 0..1: last_table_ubct =
    array2d(0..7, 0..num_cols_last_table_ubct-1,
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

% ---------- predicate che copia la logica C++ nella forma dichiarativa ----------
%
% onlyLargeSwitch_UBCT_enum(
%   dL, dR, nL, nR, dLL: input bit-vectors (arrays of var 0..1),
%   halfNum: massimo numero di isHalf = true,
%   branchSize: dimensione (numero di livelli - 1)
% )
%
predicate BVAssign_ubct(array[int] of var 0..1: column, int: cn) =
    % column ha lunghezza num_cols_ubct (0..9)
    % cn è 0..3 (sceglie quale sotto-tabella usare)
    exists(r in 0..num_rows-1) (
        forall(k in 0..num_cols_ubct-1) (
            column[k] = ubct_table[cn, r, k]
        )
    );

predicate BVAssign_last_table_ubct(array[0..num_cols_last_table_ubct-1] of var bool: isValid) =
    % isValid è array di var bool lunghezza 7 (0..6)
    exists(r in 0..7) (
        forall(k in 0..num_cols_last_table_ubct-1) (
            bool2int(isValid[k]) = last_table_ubct[r, k]
        )
    );

predicate onlyLargeSwitch_UBCT_enum(
    array[int] of var 0..1: dL,
    array[int] of var 0..1: dR,
    array[int] of var 0..1: nL,
    array[int] of var 0..1: nR,
    array[int] of var 0..1: dLL,
    int: halfNum,
    int: branchSize
) =
let {
    % dp[i,j]  for i=0..branchSize-1, j=0..3
    array[0..branchSize-1, 0..3] of var bool: dp,
    % isHalf[0..branchSize-2]
    array[0..branchSize-2] of var bool: isHalf,
    % per livello i abbiamo matrix 16 bool (4x4)
    array[0..branchSize-2, 0..15] of var bool: matrix,
    % halfSize[i, cn] corrisponde al halfSize var usato in C++
    array[0..branchSize-2, 0..3] of var bool: halfSize,
    array[0..branchSize-2] of var bool: ifEnforced,
    array[0..branchSize-2, 0..3] of var bool: enforcedLiterals,
    array[0..branchSize-2, 0..15] of var bool: literals,
    array[0..3] of var bool: lastLiterals,
    array[0..num_cols_last_table_ubct-1] of var bool: isValid
} in
(
    % somma di isHalf <= halfNum
    sum([ bool2int(isHalf[i]) | i in 0..branchSize-2 ]) <= halfNum
    /\
    % inizializzazione dp[0]
    dp[0,0] = true /\ dp[0,1] = false /\ dp[0,2] = false /\ dp[0,3] = false
    /\
    forall(i in 0..branchSize-2) (
        let {
            % per ogni cn (0..3) costruiamo la column e applichiamo BVAssign_ubct(column, cn)
            % column = [ dL[i], dR[i], nL[i], nR[i], dLL[i], matrix[i,0*4+cn], matrix[i,1*4+cn], matrix[i,2*4+cn], matrix[i,3*4+cn], halfSize[i,cn] ]
            array[0..9] of var 0..1: column0 = array1d(0..9, [dL[i], dR[i], nL[i], nR[i], dLL[i],
                                                              bool2int(matrix[i,0*4+0]), bool2int(matrix[i,1*4+0]),
                                                              bool2int(matrix[i,2*4+0]), bool2int(matrix[i,3*4+0]),
                                                              bool2int(halfSize[i,0])]),
            array[0..9] of var 0..1: column1 = array1d(0..9, [dL[i], dR[i], nL[i], nR[i], dLL[i],
                                                              bool2int(matrix[i,0*4+1]), bool2int(matrix[i,1*4+1]),
                                                              bool2int(matrix[i,2*4+1]), bool2int(matrix[i,3*4+1]),
                                                              bool2int(halfSize[i,1])]),
            array[0..9] of var 0..1: column2 = array1d(0..9, [dL[i], dR[i], nL[i], nR[i], dLL[i],
                                                              bool2int(matrix[i,0*4+2]), bool2int(matrix[i,1*4+2]),
                                                              bool2int(matrix[i,2*4+2]), bool2int(matrix[i,3*4+2]),
                                                              bool2int(halfSize[i,2])]),
            array[0..9] of var 0..1: column3 = array1d(0..9, [dL[i], dR[i], nL[i], nR[i], dLL[i],
                                                              bool2int(matrix[i,0*4+3]), bool2int(matrix[i,1*4+3]),
                                                              bool2int(matrix[i,2*4+3]), bool2int(matrix[i,3*4+3]),
                                                              bool2int(halfSize[i,3])])
        } in
        (
            % BVAssign per ogni cn
            BVAssign_ubct(column0, 0) /\
            BVAssign_ubct(column1, 1) /\
            BVAssign_ubct(column2, 2) /\
            BVAssign_ubct(column3, 3)
            /\
            % almeno un dp[i+1,*] true (equivalente model.AddBoolOr)
            (dp[i+1,0] \/ dp[i+1,1] \/ dp[i+1,2] \/ dp[i+1,3])
            /\
            % ifEnforced = not isHalf[i]
            ifEnforced[i] = not isHalf[i]
            /\
            % per ogni j: (not(ifEnforced) \/ not(dp[i,j]) \/ matrix[i, j*4+j])
            forall(j in 0..3) (
                (not ifEnforced[i] \/ not dp[i,j] \/ matrix[i, j*4+j])
                /\
                (not ifEnforced[i] \/ not dp[i,j] \/ dp[i+1,j])
                /\
                % rappresentazione MILP-like lineare
                ( bool2int(not ifEnforced[i]) + bool2int(not dp[i,j]) + bool2int(matrix[i, j*4+j]) >= 1 )
                /\
                ( bool2int(not ifEnforced[i]) + bool2int(not dp[i,j]) + bool2int(dp[i+1,j]) >= 1 )
            )
            /\
            % enforcedLiterals: equivalent to AddBoolAnd / AddBoolOr
            forall(j in 0..3) (
                (enforcedLiterals[i,j] -> (not matrix[i, j*4+j] /\ dp[i,j]))
                /\
                (not enforcedLiterals[i,j] -> (matrix[i, j*4+j] \/ not dp[i,j]))
            )
            /\
            ( ifEnforced[i] \/ enforcedLiterals[i,0] \/ enforcedLiterals[i,1] \/ enforcedLiterals[i,2] \/ enforcedLiterals[i,3] )
            /\
            % literals and their implications + linear constraints
            forall(r in 0..3) (
                (
                    forall(cc in 0..3) (
                        (literals[i, r*4 + cc] -> (matrix[i, r*4 + cc] /\ dp[i, cc]))
                        /\
                        (not literals[i, r*4 + cc] -> (not matrix[i, r*4 + cc] \/ not dp[i, cc]))
                        /\
                        ( bool2int(matrix[i, r*4 + cc]) >= bool2int(literals[i, r*4 + cc]) )
                        /\
                        ( bool2int(dp[i, cc]) >= bool2int(literals[i, r*4 + cc]) )
                        /\
                        ( bool2int(literals[i, r*4 + cc]) + 1 >= bool2int(matrix[i, r*4 + cc]) + bool2int(dp[i, cc]) )
                    )
                )
                /\
                % dp[i+1,r] -> OR over literals[r,*]
                ( dp[i+1,r] -> (literals[i, r*4 + 0] \/ literals[i, r*4 + 1] \/ literals[i, r*4 + 2] \/ literals[i, r*4 + 3]) )
                /\
                ( not dp[i+1,r] -> (not literals[i, r*4 + 0] /\ not literals[i, r*4 + 1] /\ not literals[i, r*4 + 2] /\ not literals[i, r*4 + 3]) )
                /\
                forall(li in 0..3) (
                    ( bool2int(dp[i+1,r]) >= bool2int(literals[i, r*4 + li]) )
                )
                /\
                ( sum([ bool2int(literals[i, r*4 + 0]), bool2int(literals[i, r*4 + 1]), bool2int(literals[i, r*4 + 2]), bool2int(literals[i, r*4 + 3]) ]) >= bool2int(dp[i+1,r]) )
            )
        )
    )
    /\
    % last validation: isValid[0..2] == dL/R/dLL[last]
    ( isValid[0] = (dL[branchSize-1] = 1) ) /\
    ( isValid[1] = (dR[branchSize-1] = 1) ) /\
    ( isValid[2] = (dLL[branchSize-1] = 1) )
    /\
    BVAssign_last_table_ubct(isValid)
    /\
    % lastLiterals construction
    forall(i in 0..3) (
        ( lastLiterals[i] -> (dp[branchSize-1,i] /\ isValid[3 + i]) )
        /\
        ( not lastLiterals[i] -> (not dp[branchSize-1,i] \/ not isValid[3 + i]) )
    )
    /\
    ( lastLiterals[0] \/ lastLiterals[1] \/ lastLiterals[2] \/ lastLiterals[3] )
);

% -----------------------------------------------------------------
% Esempio di come usare il predicato (commentato)
% -----------------------------------------------------------------
% Se vuoi testare il predicato devi fornire:
% - dL,dR,nL,nR,dLL come array di var 0..1 della stessa dimensione branchSize
% - halfNum e branchSize
%
% Esempio (soddisfacimento): (decommenta se vuoi eseguire una prova)
%
% int: branchSize_ex = 4;
% array[0..branchSize_ex-1] of var 0..1: dL_ex;
% array[0..branchSize_ex-1] of var 0..1: dR_ex;
% array[0..branchSize_ex-1] of var 0..1: nL_ex;
% array[0..branchSize_ex-1] of var 0..1: nR_ex;
% array[0..branchSize_ex-1] of var 0..1: dLL_ex;
% int: halfNum_ex = 2;
%
% constraint onlyLargeSwitch_UBCT_enum(dL_ex, dR_ex, nL_ex, nR_ex, dLL_ex, halfNum_ex, branchSize_ex);
% solve satisfy;
%
% -----------------------------------------------------------------
% array[0..15] of var 0..1: pre_upper_modadd_0_1_0 = array1d(0..16-1, [0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);
% array[0..15] of var 0..1: pre_upper_modadd_0_1_1 = array1d(0..16-1, [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
% array[0..15] of var 0..1: pre_lower_modadd_0_1_0 = array1d(0..16-1, [0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0]);
% array[0..15] of var 0..1: pre_lower_modadd_0_1_1 = array1d(0..16-1, [0,0,0,0,1,0,0,0,0,0,0,1,1,1,0,0]);
% array[0..15] of var 0..1: upper_modadd_0_1 = array1d(0..16-1,[1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);

array[0..15] of var 0..1: pre_upper_modadd_0_1_0 = array1d(0..16-1, [0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0]);
array[0..15] of var 0..1: pre_upper_modadd_0_1_1 = array1d(0..16-1, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
array[0..15] of var 0..1: pre_lower_modadd_0_1_0 = array1d(0..16-1, [0,0,0,0,1,1,1,0,0,0,0,0,0,0,0,0]);
array[0..15] of var 0..1: pre_lower_modadd_0_1_1 = array1d(0..16-1, [0,0,1,1,1,0,0,0,0,0,0,1,0,0,0,0]);
array[0..15] of var 0..1: upper_modadd_0_1 = array1d(0..16-1,[0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,1]);


% array[0..15] of var 0..1: upper_modadd_0_1 = array1d(0..16-1,[1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0]);
% array[0..15] of var 0..1: upper_modadd_0_1 = array1d(0..16-1,[1,0,1,1,1,1,1,1,0,0,0,0,0,0,0,0]);

constraint onlyLargeSwitch_UBCT_enum(array1d(0..16-1, [pre_upper_modadd_0_1_0[15],pre_upper_modadd_0_1_0[14],pre_upper_modadd_0_1_0[13],pre_upper_modadd_0_1_0[12],pre_upper_modadd_0_1_0[11],pre_upper_modadd_0_1_0[10],pre_upper_modadd_0_1_0[9],pre_upper_modadd_0_1_0[8],pre_upper_modadd_0_1_0[7],pre_upper_modadd_0_1_0[6],pre_upper_modadd_0_1_0[5],pre_upper_modadd_0_1_0[4],pre_upper_modadd_0_1_0[3],pre_upper_modadd_0_1_0[2],pre_upper_modadd_0_1_0[1],pre_upper_modadd_0_1_0[0]]), array1d(0..16-1, [pre_upper_modadd_0_1_1[15],pre_upper_modadd_0_1_1[14],pre_upper_modadd_0_1_1[13],pre_upper_modadd_0_1_1[12],pre_upper_modadd_0_1_1[11],pre_upper_modadd_0_1_1[10],pre_upper_modadd_0_1_1[9],pre_upper_modadd_0_1_1[8],pre_upper_modadd_0_1_1[7],pre_upper_modadd_0_1_1[6],pre_upper_modadd_0_1_1[5],pre_upper_modadd_0_1_1[4],pre_upper_modadd_0_1_1[3],pre_upper_modadd_0_1_1[2],pre_upper_modadd_0_1_1[1],pre_upper_modadd_0_1_1[0]]), array1d(0..16-1, [pre_lower_modadd_0_1_0[15],pre_lower_modadd_0_1_0[14],pre_lower_modadd_0_1_0[13],pre_lower_modadd_0_1_0[12],pre_lower_modadd_0_1_0[11],pre_lower_modadd_0_1_0[10],pre_lower_modadd_0_1_0[9],pre_lower_modadd_0_1_0[8],pre_lower_modadd_0_1_0[7],pre_lower_modadd_0_1_0[6],pre_lower_modadd_0_1_0[5],pre_lower_modadd_0_1_0[4],pre_lower_modadd_0_1_0[3],pre_lower_modadd_0_1_0[2],pre_lower_modadd_0_1_0[1],pre_lower_modadd_0_1_0[0]]), array1d(0..16-1, [pre_lower_modadd_0_1_1[15],pre_lower_modadd_0_1_1[14],pre_lower_modadd_0_1_1[13],pre_lower_modadd_0_1_1[12],pre_lower_modadd_0_1_1[11],pre_lower_modadd_0_1_1[10],pre_lower_modadd_0_1_1[9],pre_lower_modadd_0_1_1[8],pre_lower_modadd_0_1_1[7],pre_lower_modadd_0_1_1[6],pre_lower_modadd_0_1_1[5],pre_lower_modadd_0_1_1[4],pre_lower_modadd_0_1_1[3],pre_lower_modadd_0_1_1[2],pre_lower_modadd_0_1_1[1],pre_lower_modadd_0_1_1[0]]), array1d(0..16-1, [upper_modadd_0_1[15],upper_modadd_0_1[14],upper_modadd_0_1[13],upper_modadd_0_1[12],upper_modadd_0_1[11],upper_modadd_0_1[10],upper_modadd_0_1[9],upper_modadd_0_1[8],upper_modadd_0_1[7],upper_modadd_0_1[6],upper_modadd_0_1[5],upper_modadd_0_1[4],upper_modadd_0_1[3],upper_modadd_0_1[2],upper_modadd_0_1[1],upper_modadd_0_1[0]]), 1, 16);