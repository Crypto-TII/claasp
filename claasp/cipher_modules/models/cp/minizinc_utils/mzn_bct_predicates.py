def get_bct_operations():
    """Return MiniZinc source for modular-addition boomerang connectivity.

    The transition tables follow Wang, Wang and Sun, *SAT-aided Automatic
    Search of Boomerang Distinguishers for ARX Ciphers*, ToSC 2023(1),
    https://doi.org/10.46586/tosc.v2023.i1.152-191. Connectivity uses bits
    from least to most significant; probability evaluation takes CLAASP's
    most-significant-bit-first arrays and ignores the final carry.

    INPUT: None.

    OUTPUT: string of MiniZinc declarations and predicates; include it once
    in the model. These helpers generate source and do not invoke a solver.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.cp.minizinc_utils.mzn_bct_predicates import get_bct_operations
        sage: import minizinc  # optional - minizinc
        sage: model = minizinc.Model()  # optional - minizinc
        sage: model.add_string(get_bct_operations())  # optional - minizinc
        sage: model.add_string('solve satisfy;')  # optional - minizinc
        sage: result = minizinc.Instance(minizinc.Solver.lookup('gecode'), model).solve()  # optional - minizinc
        sage: str(result.status)  # optional - minizinc
        'SATISFIED'
    """
    bct_string = """
    include \"table.mzn\";
    int:num_workers_bct = 4;
    int: num_rows_bct = 16;
    int: num_cols_bct = 9;

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

    predicate only_large_switch_bct_enum(
      array[int] of var 0..1: d_l,
      array[int] of var 0..1:d_r,
      array[int] of var 0..1: n_l,
      array[int] of var 0..1:n_r,
      int: half_num,
      int: branch_size_bct,
    ) =
      let {
        array[0..branch_size_bct - 1, 0..3] of var bool: dp ,
        array[0..branch_size_bct - 2] of var bool: is_half ;
        array[0..branch_size_bct-2, 0..15] of var bool: matrix;
        array[0..branch_size_bct-2, 0..3] of var bool: half_size;
        array[0..branch_size_bct-2] of var bool: if_enforced;
        array[0..branch_size_bct-2, 0..3] of var bool: enforced_literals;
        array[0..branch_size_bct-2, 0..15] of var bool: literals;
      } in
      (sum(is_half) <= half_num) /\\
      (dp[0, 0] == true) /\\
      (dp[0, 1] == false) /\\
      (dp[0, 2] == false) /\\
      (dp[0, 3] == false) /\\
      forall(i in 0..branch_size_bct-2) (
        forall(cn in 0..3) (
          let {
            array[0..8] of var 0..1: column = array1d(0..8, [d_l[i], d_r[i], n_l[i], n_r[i], matrix[i, 0*4+cn], matrix[i, 1*4+cn], matrix[i, 2*4+cn], matrix[i, 3*4+cn], half_size[i, cn]])
          } in
          bv_assign_bct(column, cn)
        ) /\\
        (dp[i + 1, 0] \\/ dp[i + 1, 1] \\/ dp[i + 1, 2] \\/ dp[i + 1, 3]) /\\

        forall(j in 0..3) (
          (if_enforced[i] == not(is_half[i])) /\\
          (not(if_enforced[i]) \\/ not(dp[i,j]) \\/ matrix[i, j*4+j]) /\\
          (not(if_enforced[i]) \\/ not(dp[i,j]) \\/ dp[i+1,j]) /\\
          sum([not(if_enforced[i]), not(dp[i,j]), matrix[i, j * 4 + j]]) >= 1 /\\
          sum([not(if_enforced[i]), not(dp[i,j]), dp[i + 1,j]]) >= 1
        ) /\\
        forall(j in 0..3) (
          (enforced_literals[i,j] -> (not(matrix[i,j * 4 + j]) /\\ dp[i,j])) /\\
          (not(enforced_literals[i,j]) -> (matrix[i,j * 4 + j] \\/ not(dp[i,j])))
        ) /\\
        (if_enforced[i] \\/ enforced_literals[i,0] \\/ enforced_literals[i,1] \\/ enforced_literals[i,2] \\/ enforced_literals[i,3]) /\\
        forall(r in 0..3) (
          forall(cc in 0..3) (
            (literals[i, r * 4 + cc] -> (matrix[i, r * 4 + cc] /\\ dp[i, cc])) /\\
            (not(literals[i, r * 4 + cc]) -> (not(matrix[i,r * 4 + cc]) \\/ not(dp[i,cc]))) /\\
            (matrix[i,r * 4 + cc] >=  literals[i,r * 4 + cc]) /\\
            (dp[i,cc] >=           literals[i,r * 4 + cc])  /\\
            sum([ literals[i, r * 4 + cc], true ]) >= sum([ matrix[i, r * 4 + cc], dp[i,cc] ])
          ) /\\
          (dp[i + 1,r] -> (literals[i,r * 4 + 0] \\/ literals[i,r * 4 + 1] \\/ literals[i,r * 4 + 2] \\/ literals[i,r * 4 + 3])) /\\
          (not(dp[i + 1,r]) -> (not(literals[i,r * 4 + 0]) /\\ not(literals[i,r * 4 + 1]) /\\ not(literals[i,r * 4 + 2]) /\\ not(literals[i,r * 4 + 3]))) /\\
          forall(li in 0..3) ( dp[i + 1,r] >= literals[i, r * 4 + li] ) /\\
          (sum([ literals[i,r * 4 + 0], literals[i,r * 4 + 1], literals[i,r * 4 + 2], literals[i,r * 4 + 3] ]) >= dp[i + 1,r])
        )

      )
      ;
    predicate bv_assign_bct(array[0..num_cols_bct-1] of var 0..1: column, int: index) =
        let {
            array[int] of set of int: indices = [index..index, 0..num_rows_bct-1, 0..num_cols_bct-1];
            array[int,int] of int: extracted_from_table = slice_2d(bct_table, indices, 0..num_rows_bct-1, 0..num_cols_bct-1);
        } in
        table(column, extracted_from_table);
    """
    return bct_string