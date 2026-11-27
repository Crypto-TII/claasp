"""A capped, conservative piecewise approximation to ``-log2(prob)``."""


def get_approx_logarithm_operation():
    """Return a MiniZinc predicate for a hundredth-bit upper approximation.

    For ``k <= 20``, the interval ``[2^-k, 2^-(k-1)]`` uses the line
    ``k + 1 - 2^k * prob`` joining its exact endpoint weights. Since
    ``-log2`` is convex, this secant is an upper bound on the interval;
    rounding upward preserves it in hundredths of a bit. For ``21 <= k <= 32``
    the predicate uses the simpler upper step ``k`` bits. The error is at
    most 0.1 bit above ``2^-20`` and less than one bit down to ``2^-32``.
    Smaller probabilities and zero are capped at 32 bits, so the cap is not
    an upper bound below ``2^-32``. This is a search weight,
    not a four-execution boomerang probability. See Bellini et al., *Fully
    Automated Differential-Linear Attacks Against ARX Ciphers*, CT-RSA 2023,
    DOI 10.1007/978-3-031-30872-7_10, for piecewise probability modeling.

    INPUT: None.

    OUTPUT: MiniZinc source defining ``approx_prob_log`` for probabilities in
    ``[0, 1]`` and integer weights in ``[0, 3200]``.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.cp.minizinc_utils.mzn_approx_logarithm_predicate import get_approx_logarithm_operation
        sage: import minizinc  # optional - minizinc
        sage: model = minizinc.Model()  # optional - minizinc
        sage: model.add_string(get_approx_logarithm_operation())  # optional - minizinc
        sage: model.add_string('var 0..3200: weight; constraint approx_prob_log(0.5, weight); solve satisfy;')  # optional - minizinc
        sage: result = minizinc.Instance(minizinc.Solver.lookup('gecode'), model).solve()  # optional - minizinc
        sage: result['weight']  # optional - minizinc
        100
    """
    branches = []
    # FlatZinc backends use signed 32-bit integers in some conversions;
    # large secant coefficients can overflow when the float is unconstrained.
    for bits in range(1, 33):
        threshold = 2.0 ** -bits
        keyword = "if" if bits == 1 else "elseif"
        weight = (f"ceil(({bits + 1} - {float(1 << bits):.1f} * prob) * 100)"
                  if bits <= 20 else str(bits * 100))
        branches.append(
            f"{keyword} prob >= {threshold:.17g} then {weight}"
        )
    expression = "\n        ".join(branches)
    return (
        "predicate approx_prob_log(\n"
        "    var 0.0..1.0: prob,\n"
        "    var 0..3200: minus_log2_prob\n"
        ") = minus_log2_prob = (\n"
        f"        {expression}\n"
        "        else 3200 endif\n"
        ");\n"
    )
