import re

def parse_list(name, text):
    pattern = rf"{name}\s*=\s*\[([^\]]+)\]"
    match = re.search(pattern, text)
    if not match:
        return None
    return [int(x.strip()) for x in match.group(1).split(",")]

def format_array(name, values):
    return f"array[0..nbit-1] of var 0..1: {name} = array1d(0..nbit-1, {values});"

def get(name, text):
    lst = parse_list(name, text)
    if lst is None:
        raise ValueError(f"Lista '{name}' non trovata")
    return lst

def main(input_text):
    # --- BLOCCO 1 ---
    dL_1 = get("upper_rot_1_6", input_text)
    dR_1 = get("upper_xor_0_4", input_text)
    nL_1 = get("lower_xor_1_8", input_text)
    nR_1 = get("lower_rot_1_9", input_text)
    dLL_1 = get("upper_modadd_1_7", input_text)

    # --- BLOCCO 2 ---
    dL_2 = get("upper_rot_2_6", input_text)
    dR_2 = get("upper_xor_1_10", input_text)
    nL_2 = get("lower_xor_2_8", input_text)
    nR_2 = get("lower_rot_2_9", input_text)
    nLL_2 = get("lower_modadd_2_7", input_text)

    nbit = len(dL_1)

    print(f"int: nbit = {nbit};\n")

    # --- STAMPA BLOCCO 1 ---
    print("%%% BLOCCO 1 %%%")
    print(format_array("dL", dL_1))
    print(format_array("dR", dR_1))
    print(format_array("nL", nL_1))
    print(format_array("nR", nR_1))
    print(format_array("dLL", dLL_1))

    # --- STAMPA BLOCCO 2 ---
    print("\n%%% BLOCCO 2 %%%")
    print(format_array("dL", dL_2))
    print(format_array("dR", dR_2))
    print(format_array("nL", nL_2))
    print(format_array("nR", nR_2))
    print(format_array("nLL", nLL_2))


if __name__ == "__main__":
    input_text = """
upper_plaintext = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
upper_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
upper_xor_1_5 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
upper_xor_2_5 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_cipher_output_3_12 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_xor_3_5 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_xor_2_5 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_xor_1_5 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
upper_rot_0_0 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
upper_modadd_0_1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
upper probability = 0.0
upper_xor_0_2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
upper_rot_0_3 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
upper_xor_0_4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
upper_intermediate_output_0_6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
upper_rot_1_6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
upper_modadd_1_7 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
middle probability = 0.0
upper_xor_1_8 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
upper_rot_1_9 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]
upper_xor_1_10 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0]
upper_intermediate_output_1_12 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0]
lower_xor_1_8 = [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_xor_1_10 = [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
lower_rot_1_9 = [0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0]
lower_modadd_1_7 = [1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0]
lower_rot_1_6 = [1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0]
lower_intermediate_output_1_12 = [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
upper_rot_2_6 = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
upper_modadd_2_7 = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0]
middle probability = 0.0
upper_xor_2_8 = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0]
upper_rot_2_9 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0]
upper_xor_2_10 = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0]
upper_intermediate_output_2_12 = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0]
lower_xor_2_8 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
lower_xor_2_10 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
lower_rot_2_9 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
lower_modadd_2_7 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0]
lower_rot_2_6 = [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_intermediate_output_2_12 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_xor_3_8 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_xor_3_10 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_rot_3_9 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower_modadd_3_7 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
lower probability = 0.0
lower_rot_3_6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
Upper weight = 0.0
Lower weight = 0.0
Middle weight = 0.0
Trail weight = 0.0
----------
==========
%%%mzn-stat: objective=0
%%%mzn-stat: objectiveBound=0
%%%mzn-stat: nodes=6369
%%%mzn-stat: solveTime=2344.0934
%%%mzn-stat-end
%%%mzn-stat: nSolutions=1
%%%mzn-stat-end
"""
    main(input_text)