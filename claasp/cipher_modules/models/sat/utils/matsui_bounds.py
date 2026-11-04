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

r"""
Matsui's bounding conditions for SAT searches of lowest weight trails.

Let `B_\ell` be the lowest weight of a trail over `\ell` rounds (`B_0 = 0`). If the rounds are identical, any
`\ell` consecutive rounds of an `r`-round trail weigh at least `B_\ell`. Hence, if the whole trail weighs at most
`W`, every window of consecutive rounds `p, \ldots, q` (`1 \leq p \leq q \leq r`, not the whole cipher) weighs at
most

.. MATH::

    W - B_{p - 1} - B_{r - q},

because the rounds `1, \ldots, p - 1` before the window weigh at least `B_{p - 1}` and the rounds
`q + 1, \ldots, r` after it weigh at least `B_{r - q}`. Every trail of weight at most `W` satisfies these
inequalities, so adding them does not remove any trail; it only lets the solver discard partial trails much
earlier. This is the method of [SWW2021]_.

The functions of this module only produce clauses in the CLAASP internal format (see :ref:`sat-standard`) and
are independent of any model. The models use them through dedicated methods, e.g.
:py:meth:`~claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model.SatXorDifferentialModel.find_lowest_weight_xor_differential_trail_with_matsui_bounds`.

**Encoding.** The weight variables are ordered round by round and summed with the sequential counter by Sinz
(see :py:func:`sequential_counter_with_all_prefixes`), whose variable ``s[i][j]`` is forced to be true as soon as
the first ``i + 1`` weight variables sum to at least ``j + 1``. A window made of the weight variables of indices
``a, ..., b`` and bounded by ``Y`` (with ``0 <= Y < W``) is encoded as follows:

* if the window starts from the first round (``a = 0``), by the unit clause ``-s[b][Y]``: the first ``b + 1``
  variables sum to at most ``Y``;
* otherwise, by the clauses ``-s[b][t + Y - 1] s[a - 1][t - 1]`` for ``t = 1, ..., W - Y``: if the first
  ``b + 1`` variables sum to at least ``t + Y``, the first ``a`` ones sum to at least ``t``.

If ``Y >= W``, the window is already bounded by the counter and no clause is needed. If ``Y < 0``, no trail of
weight at most ``W`` exists, and an unsatisfiable pair of unit clauses is returned.

**Soundness.** The counter only forces its variables upwards: the solver may set some ``s[i][j]`` to true even if
the sum is lower. Such a spurious value can never be used to satisfy a window clause for a trail violating the
window. Indeed, let ``P`` be the true weight before the window and ``S > Y`` the true weight of the window. The
clause with ``t = P + S - Y`` (valid, since ``P + S <= W``) requires ``s[a - 1][P + S - Y - 1]``, i.e. claiming at
least ``P + S - Y > P`` before the window. The counter propagates the claim through the window, so that the claimed
sum at ``b`` grows by ``S`` and the clauses require a higher claim at ``a - 1`` again: each step raises the claim by
``S - Y >= 1`` until it exceeds ``W``, where the counter clauses ``-x_i -s[i - 1][W - 1]`` give a conflict.

**Worked example.** Consider 4 rounds of PRESENT in the single-key setting, with the lowest weights
`B_1, B_2, B_3 = 2, 4, 8`. The bounds are the input of the search and are the same for all the iterations: only the
tested weight `W` changes. The search starts from `W = \max(B_1 + B_3, B_2 + B_2) = 10` and tries `W = 10, 11, 12`,
finding a trail at `W = 12`: it makes 3 solver calls, while
:py:meth:`~claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model.SatXorDifferentialModel.find_lowest_weight_xor_differential_trail`
makes 13 (for `W = 0, \ldots, 12`). Each round has 68 weight variables (17 S-boxes, 16 in the state and 1 in the
key schedule, with 4 weight variables each), so that the weight variables of round `k` have indices
``68(k - 1), ..., 68k - 1`` and the rounds end at the indices ``67``, ``135``, ``203`` and ``271``. With the default
prefix, the counter variable ``s[i][j]`` is ``matsui_i_j``.

The propagation model is the same in both searches; only the weight constraints differ. At ``W = 12``, the classical
model has a single counter for ``sum(weight variables) <= 12``, which does not say how the weight is distributed among
the rounds, while the Matsui model has 12 more counter variables and 57 more clauses::

    sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
    sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
    sage: from claasp.cipher_modules.models.sat.utils.matsui_bounds import matsui_weight_constraints
    sage: sat = SatXorDifferentialModel(PresentBlockCipher(number_of_rounds=4))
    sage: sat.build_xor_differential_trail_model()
    sage: hw_variables_by_round = sat._hw_variables_by_round()
    sage: [len(round_variables) for round_variables in hw_variables_by_round]
    [68, 68, 68, 68]
    sage: classical_variables, classical_constraints = sat.weight_constraints(12)
    sage: len(classical_variables), len(classical_constraints)
    (3252, 6763)
    sage: matsui_variables, matsui_constraints = matsui_weight_constraints(hw_variables_by_round, 12, [2, 4, 8])
    sage: len(matsui_variables), len(matsui_constraints)
    (3264, 6820)

* **Counter: 12 more variables and 24 more clauses.** It is the same counter by Sinz, but it also keeps the
  row of the sum of all the weight variables (``matsui_271_0, ..., matsui_271_11``), needed by the windows ending
  at the last round::

      sage: matsui_variables[-12:] == [f"matsui_271_{j}" for j in range(12)]
      True

* **Windows: 33 more clauses.** Each window of rounds `p, \ldots, q` is bounded by `Y = W - B_{p-1} - B_{4-q}`
  (with `B_0 = 0`) and needs `W - Y = B_{p-1} + B_{4-q}` clauses, i.e. the same number for every `W`: the windows
  starting from the first round need a single unit clause ``-s[b][Y]``, the other ones the clauses
  ``-s[b][t + Y - 1] s[a - 1][t - 1]``, one for each ``t = 1, ..., W - Y`` (see the encoding above).

  ===============  =============================  ==========================  =========
  window           `Y = W - B_{p-1} - B_{4-q}`    `Y` for `W = 10, 11, 12`    clauses
  ===============  =============================  ==========================  =========
  round 1          `W - 0 - 8`                    2, 3, 4                     1 (unit)
  rounds 1 to 2    `W - 0 - 4`                    6, 7, 8                     1 (unit)
  rounds 1 to 3    `W - 0 - 2`                    8, 9, 10                    1 (unit)
  round 2          `W - 2 - 4`                    4, 5, 6                     6
  rounds 2 to 3    `W - 2 - 2`                    6, 7, 8                     4
  rounds 2 to 4    `W - 2 - 0`                    8, 9, 10                    2
  round 3          `W - 4 - 2`                    4, 5, 6                     6
  rounds 3 to 4    `W - 4 - 0`                    6, 7, 8                     4
  round 4          `W - 8 - 0`                    2, 3, 4                     8
  ===============  =============================  ==========================  =========

  The window made of all the rounds is not in the table, since it is bounded by the counter. At ``W = 12``, the
  first three clauses bound round 1 by 4, rounds 1 to 2 by 8 and rounds 1 to 3 by 10::

      sage: matsui_constraints[-33:-30]
      ['-matsui_67_4', '-matsui_135_8', '-matsui_203_10']

  The window made of rounds 2 and 3 covers the weight variables of indices ``a = 68, ..., b = 203`` and is
  bounded by `Y = 12 - 2 - 2 = 8`, giving the 4 clauses ``-matsui_203_{t + 7} matsui_67_{t - 1}`` for
  ``t = 1, ..., 4``: if rounds 1 to 3 weigh at least ``t + 8``, round 1 weighs at least ``t``. A partial trail in
  which round 1 weighs 2 and rounds 2 and 3 weigh 9 violates the clause with ``t = 3`` (rounds 1 to 3 weigh 11, but
  round 1 weighs less than 3), so it is discarded as soon as the first 3 rounds are known, while the classical model
  only discards it when the weight of round 4 (at least `B_1 = 2`) exceeds the total weight 12.
"""

INFEASIBLE_SUFFIX = "infeasible"


def sequential_counter_with_all_prefixes(variables, weight, prefix):
    """
    Return the clauses of the sequential counter by Sinz for ``sum(variables) <= weight``.

    The counter variable ``f"{prefix}_{i}_{j}"`` is forced to be true whenever
    ``variables[0] + ... + variables[i] >= j + 1``, for ``i = 0, ..., len(variables) - 1`` (i.e. also for the sum
    of all the variables) and ``j = 0, ..., weight - 1``.

    INPUT:

    - ``variables`` -- **list of strings**; the variables to be summed
    - ``weight`` -- **integer**; the maximum value of the sum, at least 1
    - ``prefix`` -- **string**; the prefix of the counter variables

    OUTPUT:

    A tuple ``(counter_variables, constraints)``.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.matsui_bounds import sequential_counter_with_all_prefixes
        sage: sequential_counter_with_all_prefixes(['x0', 'x1'], 1, 's')
        (['s_0_0', 's_1_0'], ['-x0 s_0_0', '-x1 s_1_0', '-s_0_0 s_1_0', '-x1 -s_0_0'])
    """
    if weight < 1:
        raise ValueError("The weight of the counter must be at least 1.")
    s = [[f"{prefix}_{i}_{j}" for j in range(weight)] for i in range(len(variables))]
    constraints = [f"-{variables[0]} {s[0][0]}"]
    constraints.extend(f"-{s[0][j]}" for j in range(1, weight))
    for i in range(1, len(variables)):
        constraints.append(f"-{variables[i]} {s[i][0]}")
        constraints.extend(f"-{s[i - 1][j]} {s[i][j]}" for j in range(weight))
        constraints.extend(f"-{variables[i]} -{s[i - 1][j - 1]} {s[i][j]}" for j in range(1, weight))
        constraints.append(f"-{variables[i]} -{s[i - 1][weight - 1]}")
    counter_variables = [variable for row in s for variable in row]

    return counter_variables, constraints


def matsui_bounds_with_zero(matsui_bounds, number_of_rounds):
    """
    Return ``[0, B_1, ..., B_{number_of_rounds - 1}]`` from ``matsui_bounds = [B_1, B_2, ...]``.

    Entries beyond ``B_{number_of_rounds - 1}`` are ignored.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.matsui_bounds import matsui_bounds_with_zero
        sage: matsui_bounds_with_zero([2, 4, 8, 12], 4)
        [0, 2, 4, 8]
    """
    if len(matsui_bounds) < number_of_rounds - 1:
        raise ValueError(
            f"matsui_bounds must contain the lowest weights of 1, ..., {number_of_rounds - 1} rounds, "
            f"got {len(matsui_bounds)} values."
        )
    bounds = [0] + [int(bound) for bound in matsui_bounds[: number_of_rounds - 1]]
    if any(bound < 0 for bound in bounds):
        raise ValueError("matsui_bounds must be non-negative.")

    return bounds


def matsui_lower_bound(matsui_bounds, number_of_rounds):
    r"""
    Return the lower bound `\max_{1 \leq a < r} (B_a + B_{r - a})` on the weight of `r` rounds.

    Any trail over `r` identical rounds splits into a trail over the first `a` rounds and one over the last
    `r - a` rounds, which weigh at least `B_a` and `B_{r - a}`.

    INPUT:

    - ``matsui_bounds`` -- **list of integers**; ``matsui_bounds[l - 1]`` is the lowest weight `B_l` of `l` rounds,
      for `l = 1, \ldots, r - 1`; further entries are ignored
    - ``number_of_rounds`` -- **integer**; the number of rounds `r`

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.matsui_bounds import matsui_lower_bound
        sage: matsui_lower_bound([2, 4, 8], 4)
        10
        sage: matsui_lower_bound([], 1)
        0
    """
    bounds = matsui_bounds_with_zero(matsui_bounds, number_of_rounds)

    return max((bounds[a] + bounds[number_of_rounds - a] for a in range(1, number_of_rounds)), default=0)


def matsui_weight_constraints(hw_variables_by_round, weight, matsui_bounds, prefix="matsui"):
    r"""
    Return the constraints for ``sum(weight variables) <= weight`` together with Matsui's bounding conditions.

    See the description of the module for the encoding.

    INPUT:

    - ``hw_variables_by_round`` -- **list of lists of strings**; ``hw_variables_by_round[i]`` is the list of the
      weight variables of round `i` (`0 \leq i < r`); a round may have no weight variable
    - ``weight`` -- **integer**; the maximum weight `W` of the trail
    - ``matsui_bounds`` -- **list of integers**; ``matsui_bounds[l - 1]`` is the lowest weight `B_l` of `l` rounds,
      for `l = 1, \ldots, r - 1`; further entries are ignored
    - ``prefix`` -- **string** (default: `matsui`); the prefix of the new variables

    OUTPUT:

    A tuple ``(variables, constraints)``.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.sat.utils.matsui_bounds import matsui_weight_constraints
        sage: variables, constraints = matsui_weight_constraints([['x0', 'x1'], ['x2', 'x3']], 2, [1])
        sage: variables
        ['matsui_0_0', 'matsui_0_1', 'matsui_1_0', 'matsui_1_1', 'matsui_2_0', 'matsui_2_1', 'matsui_3_0', 'matsui_3_1']
        sage: constraints[-2:]  # round 0 weighs at most 2 - B_1 = 1; round 1 weighs at most 2 - B_1 = 1
        ['-matsui_1_1', '-matsui_3_1 matsui_1_0']

        # below the lowest weight, the constraints are unsatisfiable
        sage: matsui_weight_constraints([['x0', 'x1'], ['x2', 'x3']], 1, [2])
        (['matsui_infeasible'], ['matsui_infeasible', '-matsui_infeasible'])
    """
    number_of_rounds = len(hw_variables_by_round)
    bounds = matsui_bounds_with_zero(matsui_bounds, number_of_rounds)
    hw_variables = [variable for round_variables in hw_variables_by_round for variable in round_variables]
    if weight == 0:
        return [], [f"-{variable}" for variable in hw_variables]

    # windows[(first_round, last_round)] = maximum weight of the rounds first_round, ..., last_round (0-indexed,
    # i.e. p = first_round + 1 and q = last_round + 1 in the formula of the module description)
    windows = {}
    for first_round in range(number_of_rounds):
        for last_round in range(first_round, number_of_rounds):
            if (first_round, last_round) != (0, number_of_rounds - 1):
                windows[first_round, last_round] = (
                    weight - bounds[first_round] - bounds[number_of_rounds - 1 - last_round]
                )
    if any(window_bound < 0 for window_bound in windows.values()):
        infeasible = f"{prefix}_{INFEASIBLE_SUFFIX}"
        return [infeasible], [infeasible, f"-{infeasible}"]

    # round_start[i] = index in hw_variables of the first weight variable of round i
    round_start = [0]
    for round_variables in hw_variables_by_round:
        round_start.append(round_start[-1] + len(round_variables))

    variables, constraints = sequential_counter_with_all_prefixes(hw_variables, weight, prefix)
    for (first_round, last_round), window_bound in windows.items():
        a, b = round_start[first_round], round_start[last_round + 1] - 1
        if window_bound >= weight or b < a:
            continue
        if a == 0:
            constraints.append(f"-{prefix}_{b}_{window_bound}")
        else:
            constraints.extend(
                f"-{prefix}_{b}_{t + window_bound - 1} {prefix}_{a - 1}_{t - 1}"
                for t in range(1, weight - window_bound + 1)
            )

    return variables, constraints
