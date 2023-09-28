from sage.numerical.mip import MixedIntegerLinearProgram

def anf_ascon_sbox(model, bin_var):

    ########## Copying (create var for each occurence of xi)
    for i in range(7):
        model.add_constraint(bin_var["x0"] >= bin_var["x0_" + str(i)])
    model.add_constraint(sum(bin_var["x0_" + str(i)] for i in range(7)) >= bin_var["x0"])

    for i in range(12):
        model.add_constraint(bin_var["x1"] >= bin_var["x1_" + str(i)])
    model.add_constraint(sum(bin_var["x1_" + str(i)] for i in range(7)) >= bin_var["x1"])

    for i in range(7):
        model.add_constraint(bin_var["x2"] >= bin_var["x2_" + str(i)])
    model.add_constraint(sum(bin_var["x2_" + str(i)] for i in range(7)) >= bin_var["x2"])

    for i in range(8):
        model.add_constraint(bin_var["x3"] >= bin_var["x3_" + str(i)])
    model.add_constraint(sum(bin_var["x3_" + str(i)] for i in range(7)) >= bin_var["x3"])

    for i in range(8):
        model.add_constraint(bin_var["x4"] >= bin_var["x4_" + str(i)])
    model.add_constraint(sum(bin_var["x4_" + str(i)] for i in range(7)) >= bin_var["x4"])

    ########### Constraints for each of the 5 equations (ai for each occurence of products)
    model.add_constraint(bin_var["a0"] == bin_var["x4_0"]), model.add_constraint(bin_var["a0"] == bin_var["x1_0"]) # x4x1
    model.add_constraint(bin_var["a1"] == bin_var["x2_0"]), model.add_constraint(bin_var["a1"] == bin_var["x1_1"]) # x2x1
    model.add_constraint(bin_var["a2"] == bin_var["x0_0"]), model.add_constraint(bin_var["a2"] == bin_var["x1_2"]) # x0x1
    model.add_constraint(
        bin_var["y0"] == bin_var["a0"] + bin_var["a1"] + bin_var["a2"] + bin_var["x3_0"] + bin_var["x2_1"] + bin_var[
            "x1_3"] + bin_var["x0_1"])

    model.add_constraint(bin_var["a3"] == bin_var["x3_1"]), model.add_constraint(bin_var["a3"] == bin_var["x2_2"]) # x3x2
    model.add_constraint(bin_var["a4"] == bin_var["x3_2"]), model.add_constraint(bin_var["a4"] == bin_var["x1_4"]) # x3x1
    model.add_constraint(bin_var["a5"] == bin_var["x2_3"]), model.add_constraint(bin_var["a5"] == bin_var["x1_5"]) # x2x1
    model.add_constraint(
        bin_var["y1"] == bin_var["a3"] + bin_var["a4"] + bin_var["a5"] + bin_var["x4_1"] + bin_var["x3_3"] + bin_var[
            "x2_4"] + bin_var["x1_6"] + bin_var["x0_2"])

    model.add_constraint(bin_var["a6"] == bin_var["x4_2"]), model.add_constraint(bin_var["a6"] == bin_var["x3_4"]) # x4x3
    model.add_constraint(
        bin_var["y2"] >= bin_var["a6"] + bin_var["x4_3"] + bin_var["x2_5"] + bin_var["x1_7"])

    model.add_constraint(bin_var["a7"] == bin_var["x4_4"]), model.add_constraint(bin_var["a7"] == bin_var["x0_3"]) # x4x0
    model.add_constraint(bin_var["a8"] == bin_var["x3_5"]), model.add_constraint(bin_var["a8"] == bin_var["x0_4"]) # x3x0
    model.add_constraint(
        bin_var["y3"] == bin_var["a7"] + bin_var["a8"] + bin_var["x4_5"] + bin_var["x3_6"] + bin_var[
            "x1_8"] + bin_var["x2_6"] + bin_var["x0_5"])

    model.add_constraint(bin_var["a9"] == bin_var["x4_6"]), model.add_constraint(bin_var["a9"] == bin_var["x1_9"]) # x4x1
    model.add_constraint(bin_var["a10"] == bin_var["x0_6"]), model.add_constraint(bin_var["a10"] == bin_var["x1_10"]) # x0x1
    model.add_constraint(
        bin_var["y4"] == bin_var["a9"] + bin_var["a10"] + bin_var["x4_7"] + bin_var["x3_7"] + bin_var["x1_11"])


def term_enumuration_sbox(target):
    model = MixedIntegerLinearProgram(maximization=False, solver="GLPK")
    bin_var = model.new_variable(binary=True)
    anf_ascon_sbox(model, bin_var)

    model.add_constraint(bin_var["ll"] == sum(bin_var["y" + str(i)] for i in range(5)))
    model.add_constraint(bin_var["ll"] == 1)
    model.add_constraint(bin_var["y" + str(target)] == 1)
    # model.add_constraint(bin_var["x4"] >= 1)
    # model.add_constraint(bin_var["x3"] <= 0)
    # model.add_constraint(bin_var["x2"] >= 1)
    # model.add_constraint(bin_var["x1"] <= 0)
    # model.add_constraint(bin_var["x0"] <= 0)
    # model.set_objective(None)

    looking_for_other_solutions = 1
    while looking_for_other_solutions:
        try:
            model.solve()
            var = model.get_values(bin_var)
        except Exception:
            looking_for_other_solutions = 0

    return var
