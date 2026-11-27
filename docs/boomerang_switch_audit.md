# Boomerang switch audit

This note maps the CLAASP switch code to the definitions in Wang, Wang and
Sun, [*SAT-aided Automatic Search of Boomerang Distinguishers for ARX
Ciphers*](https://doi.org/10.46586/tosc.v2023.i1.152-191), Definition 4 and
Appendix A. The check uses exhaustive four-path evaluation of a two-bit
lifted addition and of a one-bit AND. It checks local table entries; it does
not prove that multiplying entries gives a full-cipher probability.

## Four executions

`mzn_boomerang_value_constraints.py` makes four exact forward copies. Copies
0/1 and 2/3 have the upper input difference; copies 0/2 and 1/3 have the
lower output difference. All four share the non-data inputs, including the
master key. Each selected internal difference is imposed on both relevant
pairs. The module docstring gives a concrete identity-permutation quartet.

## Lifted modular addition

The paper's permutation is `F(L,R)=((L+R) mod 2^n,R)`. In
`_add_modular_switch`:

1. `pre_upper_*_0` and `pre_upper_*_1` are the two parts of the upper input
   difference `(Delta_l,Delta_r)`.
2. The lower component output and `pre_lower_*_1` are the lower output
   difference `(Nabla_l,Nabla_r)` of the lifted permutation.
3. UBCT adds the upper sum difference `Delta'_l`. LBCT adds the lower
   difference `Nabla'_l` of the first input operand. EBCT adds both.
4. `_switch_constraint(..., index=None)` reverses the bit arrays so the
   connectivity tables run from least to most significant bit. The call with
   `index` passes the original most-significant-bit-first arrays to the
   probability evaluator.
5. Lifted subtraction is `F` inverse, so upper and lower directions and the
   UBCT/LBCT labels exchange.

The exhaustive two-bit checks found two mistakes in the probability
evaluators. The UBCT final-state condition used `Nabla_l,Nabla_r` where the
published condition uses `Delta_l,Delta_r`. Also, the final-state conditions
of UBCT, LBCT and EBCT read array index `1`, although the evaluators' arrays
are most-significant-bit first and the final condition concerns index `0`.
The corresponding connectivity tables receive reversed arrays and use their
last index, which is consistent. The evaluator conditions are corrected and
tested against direct counts. The `only_large_switch_*` predicates retain
their published search restriction; passing a local table test does not make
the restricted search complete.

## Bitwise AND

For `f(x,y)=xy`, the upper input difference is `(a,b)` and the lower input
difference is `(c,d)`. Four-path closure requires the second derivative
`ad xor bc = 0`; because the values are bits, the MiniZinc equality `a*d =
b*c` expresses exactly this condition. BCT retains neither output and its
local closure weight is zero. UBCT retains the upper output and uses its
one-bit DDT weight. LBCT does the same for the lower output. EBCT retains
both; when both input directions are nonzero, closure makes the directions
equal, so the retained outputs must agree. The surrounding DDT constraints
handle a zero input direction. The 64 possible assignments of the four input
and two output difference bits are checked against direct enumeration for
all four switch kinds. This is exact for an isolated AND bit. Applied to
separate AND components, it can exclude valid XOR cancellations, so the
exact four-execution layer is needed for a complete cipher check.

## Logarithm weight

The historical piecewise rule was named an upper bound but was not one. For
example, at probability `0.7` it returned `0.43` bits although
`-log2(0.7)` is about `0.515` bits. It also jumped from `32` to about `9.53`
bits at probability `0.0010214537`. The new rule uses convex secants, rounded
up to hundredths of a bit, down to probability `2^-20`. It uses upper steps
down to `2^-32` and caps smaller probabilities at 32 bits. This is an upper
bound only for probabilities at least `2^-32`; it remains a local search
weight, not a boomerang probability. Regression tests cover every power-of-two
boundary, the old discontinuity and the near-one interval.

Because corrected table and logarithm weights can change trail rankings,
searches archived under the previous revision must keep their code version
recorded and must be rerun before claiming that a new search reproduces their
model weights. Four-execution counts and direct quartet measurements of
already specified trails do not use the local logarithm approximation.

## API policy

The boomerang API uses the current `*_boomerang_trail_*` and
`measure_boomerang_differential_*` names. CLAASP does not provide aliases or
other legacy behavior for earlier research-script method names. Reproduction
scripts should call the current API or record the CLAASP revision they require.
