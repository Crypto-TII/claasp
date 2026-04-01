def get_approx_logarithm_operation_lower_bound():
    string = """
predicate approx_prob_log(
        var 0.0..1.0: prob,
        var 0..3200: minus_log2_prob
) = (
    minus_log2_prob ==  if prob < 0.000001 then
                            3200
                        elseif prob <= 0.001 /\\ prob >= 0.000001 then
                            floor((-9975.760016613431 * prob + 19.941568569324174)*100)
                        elseif prob <= 0.004 /\\ prob > 0.001 then
                            floor((-666.6666666666666 * prob + 10.632117027821168)*100)
                        elseif prob <= 0.014 /\\ prob > 0.004 then
                            floor((-180.7354922057604 * prob + 8.688392330171544)*100)
                        elseif prob <= 0.053 /\\ prob > 0.014 then
                            floor((-49.245176838301244 * prob + 6.847528111047116)*100)
                        elseif prob <= 0.142 /\\ prob > 0.053 then
                            floor((-15.975699686667065 * prob + 5.084849116337398)*100)
                        elseif prob <= 0.246 /\\ prob > 0.142 then
                            floor((-7.623299489760664 * prob + 3.8980664880404327)*100)
                        elseif prob <= 0.595 /\\ prob > 0.246 then
                            floor((-3.650898441241519 * prob + 2.920984031604402)*100)
                        elseif prob <= 0.998 /\\ prob > 0.595 then
                            floor((-1.8505238404281055 * prob + 1.849048341716919)*100)
                        else
                            0
                        endif
);
    """
    return string

def get_approx_logarithm_operation_upper_bound():
    string = """
predicate approx_prob_log_upper_bound(
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