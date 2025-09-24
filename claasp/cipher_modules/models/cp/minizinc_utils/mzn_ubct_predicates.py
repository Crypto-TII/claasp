def get_ubct_operations():
    ubct_string = """
    include \"table.mzn\";
    int: num_workers = 4;
    int: num_rows = 32;
    int: num_cols_last_table = 7;
    int: num_cols = 10;
    array[0..num_cols-1] of var 0..1: b;
    array[0..num_workers-1,0..num_rows-1,0..num_cols-1] of 0..1: ubct_table =
         array3d(0..num_workers-1,0..num_rows-1,0..num_cols-1,
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
    
    array[0..7,0..num_cols_last_table-1] of 0..1: last_table =
         array2d(0..7,0..num_cols_last_table-1,
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
            array[0..7] of var bool: lastLiterals;
            array[0..6] of var bool: isValid;
        } in
        (sum(isHalf) <= halfNum) /\\
        (dp[0, 0] == true) /\\
        (dp[0, 1] == false) /\\
        (dp[0, 2] == false) /\\
        (dp[0, 3] == false) /\\
        forall(i in 0..branchSize-2) (
            forall(cn in 0..3) (
                 let {
                    array[0..9] of var 0..1: column = array1d(0..9, [dL[i], dR[i], nL[i], nR[i], dLL[i], matrix[i, 0*4+cn], matrix[i, 1*4+cn], matrix[i,2*4+cn], matrix[i, 3*4+cn], halfSize[i, cn]])
                } in
                BVAssign(column, cn)
            ) /\\
            (
                dp[i + 1, 0] \\/ dp[i + 1, 1] \\/ dp[i + 1, 2] \\/ dp[i + 1, 3]
            ) /\\
            forall(j in 0..3) (
                (ifEnforced[i] == not(isHalf[i])) /\\
                (not(ifEnforced[i]) \\/ not(dp[i,j]) \\/ matrix[i, j*4+j]) /\\
                (not(ifEnforced[i]) \\/ not(dp[i,j]) \\/ dp[i+1,j]) /\\
                sum([not(ifEnforced[i]), not(dp[i,j]), matrix[i, j * 4 + j]]) >= 1 /\\
                sum([not(ifEnforced[i]), not(dp[i,j]), dp[i + 1,j]]) >= 1
            ) /\\
            forall(j in 0..3) (
                (enforcedLiterals[i,j] -> (not(matrix[i,j * 4 + j]) /\\ dp[i,j])) /\\
                (not(enforcedLiterals[i,j]) -> (matrix[i,j * 4 + j] \\/ not(dp[i,j])))
            ) /\\ 
            (
                ifEnforced[i] \\/ enforcedLiterals[i,0] \\/ enforcedLiterals[i,1] \\/ enforcedLiterals[i,2] \\/ enforcedLiterals[i,3]
            ) /\\
            forall(r in 0..3) (
                forall(cc in 0..3) (
                    (literals[i, r * 4 + cc] -> (matrix[i, r * 4 + cc] /\\ dp[i, cc])) /\\
                    (not(literals[i, r * 4 + cc]) -> (not(matrix[i,r * 4 + cc]) \\/ not(dp[i,cc]))) /\\
                    (matrix[i,r * 4 + cc] >=  literals[i,r * 4 + cc]) /\\
                    (dp[i,cc] >=           literals[i,r * 4 + cc])  /\\
                    sum([ literals[i, r * 4 + cc], true ]) >= sum([ matrix[i, r * 4 + cc], dp[i,cc] ])
                ) /\\
                (
                    dp[i + 1,r] -> (literals[i,r * 4 + 0] \\/ literals[i,r * 4 + 1] \\/ literals[i,r * 4 + 2] \\/ literals[i,r * 4 + 3])
                ) /\\
                (
                    not(dp[i + 1,r]) -> (not(literals[i,r * 4 + 0]) /\\ not(literals[i,r * 4 + 1]) /\\ not(literals[i,r * 4 + 2]) /\\ not(literals[i,r * 4 + 3]))
                ) /\\
                forall(li in 0..3) (
                    dp[i + 1,r] >= literals[i, r * 4 + li] 
                ) /\\
                (
                    sum([ literals[i,r * 4 + 0], literals[i,r * 4 + 1], literals[i,r * 4 + 2], literals[i,r * 4 + 3] ]) >= dp[i + 1,r]
                )
            )
        ) /\\
        (
            isValid[0] == dL[branchSize - 1] /\\
            isValid[1] == dR[branchSize - 1] /\\
            isValid[2] == dLL[branchSize -1] 
        ) /\\
            (BVAssign_last_table(isValid))
        /\\
        forall(i in 0..3) (
            (
                lastLiterals[i] -> (dp[branchSize-1,i] /\\ isValid[3 + i])
            ) /\\
            (
                not(lastLiterals[i]) -> (not(dp[branchSize-1,i]) \\/ not(isValid[3 + i]))
            )
        ) /\\
        (
            lastLiterals[0] \\/ lastLiterals[1] \\/ lastLiterals[2] \\/ lastLiterals[3]
        );         

        predicate BVAssign(array[0..num_cols-1] of var 0..1: column, int: index) =
        let {
            array[int] of set of int: indices = [index..index, 0..num_rows-1, 0..num_cols-1];
            array[int,int] of int: extractedFromTable = slice_2d(ubct_table, indices, 0..num_rows-1, 0..num_cols-1);
        } in
        table(column, extractedFromTable);

        predicate BVAssign_last_table(
            array[0..num_cols_last_table-1] of var bool: isValid
        ) =  table(isValid, last_table);  
    """
    return ubct_string