def get_approx_logarithm_operation():
    """Return MiniZinc source for the historical piecewise probability-to-weight approximation.

    Input probabilities are in [0, 1]; integer output weights are in hundredths
    of a bit. Probabilities at most 0.001021453702391378 map to 3200.
    This is a search heuristic, not an exact logarithm or certified error bound.
    For the piecewise-linear modeling approach, see Bellini et al., *Fully
    Automated Differential-Linear Attacks Against ARX Ciphers*, CT-RSA 2023,
    pp. 252-276, https://doi.org/10.1007/978-3-031-30872-7_10. The coefficients
    and saturation threshold here are those of the original paper implementation.

    INPUT: None.

    OUTPUT: string of MiniZinc declarations and predicates; include it once
    in the model. These helpers generate source and do not invoke a solver.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.cp.minizinc_utils.mzn_approx_logarithm_predicate import get_approx_logarithm_operation
        sage: isinstance(get_approx_logarithm_operation(), str)
        True
    """
    string = """
predicate approx_prob_log(
        var 0.0..1.0: prob,
        var 0..3200: minus_log2_prob
) = (
    minus_log2_prob == if prob <= 0.001021453702391378 then
                          3200
                    elseif prob <= 0.004151650554233785 /\\ prob > 0.001021453702391378 then
                          floor((-584.962260272084*prob+10.13570866882117)*100)
                    elseif prob <= 0.01359667098324998 /\\ prob > 0.004151650554233785 then
                          floor((-192.6450521799878*prob+8.506944714410169)*100)
                    elseif prob <= 0.05399137458004444 /\\ prob > 0.01359667098324998 then
                           floor((-50.62607129324977*prob+6.575959357916722)*100)
                    elseif prob <= 0.1420480516058986 /\\ prob > 0.05399137458004444 then
                           floor((-11.87410019056137*prob+4.483687170396419)*100)
                    elseif prob <= 0.2463455066216964 /\\ prob > 0.1420480516058986 then
                           floor((-8.613130253286352*prob+4.020472744461092)*100)
                    elseif prob <= 0.595815289564374 /\\ prob > 0.2463455066216964 then
                           floor((-3.761918786389538*prob+2.825398597919413)*100)
                    elseif prob <= 0.998000001 /\\ prob > 0.595815289564374 then
                          floor((-1.444862453710759*prob+1.44486100812744)*100)
                    else
                          0
                    endif
);
    """
    return string