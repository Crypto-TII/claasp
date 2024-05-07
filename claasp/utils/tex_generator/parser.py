import os
import textwrap

class Drawer:
    def __init__(self, attributes):
        self.R = attributes["R"]
        self.block_size = attributes["block_size"]
        self.rounds = attributes["rounds"]
        self.output_file_name = os.path.join(os.path.dirname(__file__),"simon.tex")
        self.fillcolor = {'0': "zero", '1': "one", '?': "unknown"}

    def draw(self):
        """
        Generate the attack shape
        """
        contents = ""
        contents += textwrap.dedent(r"""
            \documentclass[varwidth=100cm]{standalone}
            \usepackage{tikz}
            \usepackage{simon}
            \begin{document}
            \begin{figure}
                \centering
                \begin{tikzpicture}[>=latex,fillopts/.style={black},raster/.style={gray!50}]
                    \simoncompactfalse % vertically less compact layout
                    \SimonInit[""" + str(self.block_size) + """]""") + "\n"
        for r in range(0, self.R):
            state = self.rounds[r]
            output = {key: "" for key in ["left", "right", "rot8", "rot1", "rot2", "key", "and", "xor1"]}
            for key in output.keys():
                for i in range(self.block_size // 2):
                    if state[key][i] != '0':
                        output[key] += r"\Fill[{0}]{{s{1}}}".format(self.fillcolor[state[key][i]], i)

            contents += r"""
            \SimonRound{""" + str(r + 1) + """}
                {""" + output["left"] + r"""} % left
                {""" + output["right"] + r"""} % right
                {""" + output["rot1"] + r"""} % rot1
                {""" + output["rot8"] + r"""} % rot8
                {""" + output["rot2"] + r"""} % rot2
                {""" + output["key"] + r"""} % key
                {""" + output["and"] + r"""} % and
                {""" + output["xor1"] + r"""} % xor1""" + "\n"

        contents += r"""    \end{tikzpicture}""" + "\n"
        if self.R > 1:
            contents += r"""\caption{""" + str(self.R) + r" rounds of \SIMON[" + str(self.block_size) + "].}\n"
        else:
            contents += r"""\caption{""" + str(self.R) + r" round of \SIMON[" + str(self.block_size) + "].}\n"
        contents += r"""\end{figure}""" + "\n"
        contents += r"""\end{document}""" + "\n"
        with open(self.output_file_name, "w") as f:
            f.write(contents)




def read_from_trail(data):
    """
    - intermediate_i_0 is the roundkey
    - rot_i_1 is rotation by 1
    - rot_i_2 is rotation by 8
    - rot_i_3 is rotation by 2
    - and_i_4 is the result of (rot_i_1 & rot_i_2)
    - xor_i_5 is the result of and_i_4 xor rot_i_3
    - xor_1_6 is the result of (right_state xor xor_i_5 xor roundkey)
    """
    attributes = {}
    r = {}

    # Safely evaluate the string as Python code
    try:
        # Assuming 'data' is the dictionary containing your loaded data
        cipher = data['cipher']
        attributes['R'] = cipher.number_of_rounds
        attributes['block_size'] = cipher.block_bit_size
        plaintext = data['components_values']['plaintext']['value']
        ciphertext = data['components_values'][list(data['components_values'].keys())[-1]]['value']

        n = len(plaintext)
        half = n//2
        offset = 0

        for index in range(cipher.number_of_rounds):

            if index > 3:
                offset = 5

            # Construct key and output index strings
            # then extract values from the data dictionary
            if index == 0:
                output = plaintext
            elif index == cipher.number_of_rounds -1:
                output = ciphertext
            else:
                output_index = f"intermediate_output_{index - 1}_7"
                output = data['components_values'][output_index]['value']

            key_index = f"intermediate_output_{index}_{offset}"
            key = data['components_values'][key_index]['value']

            rot1 = data['components_values'][f'rot_{index}_{1 + offset}']['value']
            rot8 = data['components_values'][f'rot_{index}_{2 + offset}']['value']
            rot2 = data['components_values'][f'rot_{index}_{3 + offset}']['value']
            andv = data['components_values'][f'and_{index}_{4 + offset}']['value']
            xor1 = data['components_values'][f'xor_{index}_{5 + offset}']['value']
            xor2 = data['components_values'][f'xor_{index}_{6 + offset}']['value']

            # Split the output into left and right parts
            left = output[:half]
            right = output[half:]

            # Add attributes to the rounds dictionary
            r[index] = {
                'left': left,
                'right': right,
                'key': key,
                'output': output,
                'rot1': rot1,
                'rot8': rot8,
                'rot2': rot2,
                'and': andv,
                'xor1': xor1,
                'xor2': xor2
            }

            # Update the index
            index += 1
        attributes['rounds'] = r


    except Exception as e:
        print("Error evaluating the data:", e)
    return attributes
