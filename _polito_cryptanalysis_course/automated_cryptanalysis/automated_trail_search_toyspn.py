from sage.all import *
from sage.crypto.sbox import SBox
from claasp.ciphers.toys.toyspn1 import ToySPN1
from claasp.utils.utils import pprint_dictionary
toyspn1 = ToySPN1(number_of_rounds=2)


# Explore the valide transitions of the S-Box, i.e. its DDT

sbox_component = toyspn1.component_from(0, 2)
sbox_toyspn1 = SBox(sbox_component.description)
print(f'{sbox_toyspn1 = }:')
print('DDT:')
print(f'{sbox_toyspn1.difference_distribution_table()}')


# Compute the number of non-trivial possible differentials in the Sbox

from claasp.cipher_modules.models.milp.utils.generate_sbox_inequalities_for_trail_search import * 
sbox_ineqs = convex_hull(sbox_toyspn1)
print("Number of non-trivial possible differentials:", len(sbox_ineqs[2].vertices()))
for vertex in sbox_ineqs[2].vertices():
    print(vertex)

# Generate the convex hull (inequalities)representing the entries of the DDT with value 2

print("Number of inequalities:", len(sbox_ineqs[2].Hrepresentation())) 
sbox_ineqs[2].Hrepresentation()

# Reduce the number of inequalities

reduced_sbox_ineqs = cutting_off_milp(sbox_ineqs)
print("Number of reduced inequalities", len(reduced_sbox_ineqs[2])) 
for reduced_sbox_ineq in reduced_sbox_ineqs[2]:
    print(reduced_sbox_ineq)

# Encode the variables and the probability values

vars_milp = []
for i in range(8):
    vars_milp.append(var(f'x_{i}'))

input_size = 3

M = 10 * input_size
dict_constraints = []
for reduced_sbox_ineq in reduced_sbox_ineqs[2]:
    ineqs_temp = reduced_sbox_ineq+[1]
    ineqs = ineqs_temp[1:7]
    print(str(sum([a*b for a,b in zip(ineqs,vars_milp)])) + str(" + ") + str(ineqs_temp[0]) + str(" >= 0"))

# 

vars_milp = []
for i in range(8):
    vars_milp.append(var(f'x_{i}'))

input_size = 3
M = 10 * input_size
dict_constraints = []
for reduced_sbox_ineq in reduced_sbox_ineqs[2]:
    ineqs_temp = reduced_sbox_ineq+[1]
    ineqs = ineqs_temp[1:7]
    print(str(sum([a*b for a,b in zip(ineqs,vars_milp)])) + str(" + ") + str(ineqs_temp[0]) + str(" + M*(1-x_7)") + str(" >= 0")) 


# Constraints to see if the S-Box is active or not
# We use the variable x_6. The system below gives either:
# x_6 = 0 and all other variables equal to 0
# x_6 = 1 and any other value of x_0,...,x_5 different from 0

print('x_6 <= x_0 + x_1 + x_2')
print('x_0 <= x_6')
print('x_1 <= x_6')
print('x_2 <= x_6')
print('x_3 <= x_6')
print('x_4 <= x_6')
print('x_5 <= x_6')

print(f'\nMILP constraints - S-Box:')

from claasp.cipher_modules.models.milp.milp_model import MilpModel 
milp = MilpModel(toyspn1)
milp.init_model_in_sage_milp_class()
variables, constraints = sbox_component.milp_small_xor_differential_probability_constraints( milp.binary_variable, milp.integer_variable, milp._non_linear_component_id)
for constraint in constraints:
    print(constraint)

print(f'\nMILP constraints - XOR:')

xor_component = toyspn1.component_from(0, 0)
variables, constraints = xor_component.milp_xor_differential_propagation_constraints(milp) 
print(len(constraints))
for constraint in constraints: 
    print(constraint)

print(f'\nMILP constraints - toyspn1:')

from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel 
milp = MilpXorDifferentialModel(toyspn1)
milp.init_model_in_sage_milp_class()
milp.add_constraints_to_build_in_sage_milp_class()
milp_toyspn1 = milp._model
print("Number of variables:", milp_toyspn1.number_of_variables()) 
print("Number of constraints:", milp_toyspn1.number_of_constraints()) 
for i in range(len(milp._model_constraints)):
    print(f'{i:3d}: {milp._model_constraints[i]}')
print("\n")
print("\n")
print("\n")
print("\n")


p = MixedIntegerLinearProgram(maximization=False, solver="GLPK")
w = p.new_variable(integer=True, nonnegative=True)
p.add_constraint(w[0] + w[1] + w[2] - 14*w[3] == 0)
p.add_constraint(w[1] + 2*w[2] - 8*w[3] == 0)
p.add_constraint(2*w[2] - 3*w[3] == 0)
p.add_constraint(w[0] - w[1] - w[2] >= 0)
p.add_constraint(w[3] >= 1)
p.set_objective(w[3])
p.show()

print('Objective Value: {}'.format(p.solve()))
for i, v in sorted(p.get_values(w, convert=ZZ, tolerance=1e-3).items()):
    print(f'w_{i} = {v}')

