def get_approx_logarithm_operation():
    string = """
    predicate approx_prob_log(
        var float: prob,
        var int: minus_log2_prob
    ) = (
        minus_log2_prob = 
                            % if prob <= 0.1420480516058986 then
                            %    3200
                            if prob <= 0.001021453702391378 then
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