import math

def get_continuous_operations():
    """
    Returns the MiniZinc code required for continuous correlation propagation.

    This implementation follows the continuous approximation model for ARX
    operations introduced in [BGGMP2023]_.
    """
    return """
    float: lower = -1.0;
    float: upper = 1.0;

    % --- XOR Operation ---
    % Corresponds to equation 5 in the reference paper
    function var lower..upper: continuous_xor_bit(var lower..upper: x, var lower..upper: y) = -1*x*y;

    function array [int] of var lower..upper: continuous_xor(array [int] of var float: aa,array [int] of var float: bb, array [int] of var float: output_diff) = 
    let {
        int: n = length(aa);
        constraint output_diff = array1d(0..n-1, [continuous_xor_bit(aa[i], bb[i])|i in 0..n-1]);
    } in 
    output_diff;

    % --- Modular Addition ---
    % Corresponds to equation 3
    function var lower..upper: continuous_maj_bit(var lower..upper: x, var lower..upper: y, var lower..upper: z) = 0.25*(x+y+z+x*y*z);

    % Corresponds to equation 4
    function array [int] of var lower..upper: continuous_modadd(array [int] of var float: aa,array [int] of var float: bb,array [int] of var float: output_diff)= let { 
        int: n = length(aa); 
        array [0..n-1] of var lower..upper: carry_diff; 
        constraint carry_diff[n-1] = -1; 
        constraint forall(i in 0..n-2)(carry_diff[n-i-2] = continuous_maj_bit(aa[n-i-1], bb[n-i-1], carry_diff[n-i-1])); 
        constraint output_diff = reverse(array1d(0..n-1,[continuous_xor_bit(continuous_xor_bit(aa[n-i-1], bb[n-i-1]), carry_diff[n-i-1]) |i in 0..n-1])); 
    } in 
    output_diff;

    % --- Rotations ---
    function array[int] of var lower..upper: continuous_LRot(array[int] of var lower..upper: X, int: val, array[int] of var lower..upper: output_LRot)=
    let {
        int: n = length(X);
        constraint output_LRot = array1d(0..n-1, [X[(j+val) mod n] | j in 0..n-1]);
    } in 
    output_LRot;

    function array[int] of var lower..upper: continuous_RRot(array[int] of var lower..upper: X, int: val, array[int] of var lower..upper: output_RRot)=
    let {
        int: n = length(X);
        constraint output_RRot = array1d(0..n-1, [X[(n+j-val) mod n] | j in 0..n-1]);
    } in 
    output_RRot;

    % --- Casting/Helpers ---
    function array [int] of var lower..upper: cast(array [int] of var 0..1:int_var) = 
    let {
        int: n = length(int_var);
    } in 
        array1d(0..n-1, [if int_var[i] = 0 then -1.0 else 1.0 endif|i in 0..n-1]);
    """


def active_bit_correlation_expression(mask_expr, correlation_expr):
    """Return the masked active-bit expression used in continuous correlation products."""
    return (
        f"if {mask_expr} = 0 then 1.0 "
        f"else {mask_expr} * abs({correlation_expr}) endif"
    )


def piecewise_log2_approximation_expression(correlation_expr, scale=1.0, else_value="0.0"):
    """Return the shared piecewise linear approximation of -log2(correlation)."""
    scale_prefix = "" if math.isclose(scale, 1.0) else f"{scale} * "
    return (
        f"{scale_prefix}(\n"
        f"if {correlation_expr} <= 0.001021453702391378 then\n"
        f"-19931.57001201849*{correlation_expr}+29.89737278555626\n"
        f"elseif {correlation_expr} <= 0.004151650554233785 /\\ {correlation_expr} > 0.001021453702391378 then\n"
        f"-584.962260272084*{correlation_expr}+10.13570866882117\n"
        f"elseif {correlation_expr} <= 0.01359667098324998 /\\ {correlation_expr} > 0.004151650554233785 then\n"
        f"-192.6450521799878*{correlation_expr}+8.506944714410169\n"
        f"elseif {correlation_expr} <= 0.05399137458004444 /\\ {correlation_expr} > 0.01359667098324998 then\n"
        f"-50.62607129324977*{correlation_expr}+6.575959357916722\n"
        f"elseif {correlation_expr} <= 0.1420480516058986 /\\ {correlation_expr} > 0.05399137458004444 then\n"
        f"-11.87410019056137*{correlation_expr}+4.483687170396419\n"
        f"elseif {correlation_expr} <= 0.2463455066216964 /\\ {correlation_expr} > 0.1420480516058986 then\n"
        f"-8.613130253286352*{correlation_expr}+4.020472744461092\n"
        f"elseif {correlation_expr} <= 0.595815289564374 /\\ {correlation_expr} > 0.2463455066216964 then\n"
        f"-3.761918786389538*{correlation_expr}+2.825398597919413\n"
        f"elseif {correlation_expr} <= 0.998000001 /\\ {correlation_expr} > 0.595815289564374 then\n"
        f"-1.444862453710759*{correlation_expr}+1.44486100812744\n"
        f"else\n"
        f"{else_value}\n"
        f"endif\n"
        ")"
    )