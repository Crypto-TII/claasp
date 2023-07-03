from sage.all import *
from sage.crypto.sbox import SBox
from sage.geometry.polyhedron.constructor import Polyhedron

def to_bits(n, x, big_endian=False):
    if big_endian:
        return ZZ(x).digits(base=2, padto=n)
    return ZZ(x).digits(base=2, padto=n)[::-1]

big_endian=False

s = SBox([0, 5, 3, 2, 6, 1, 4, 7]) # Xoodoo and ToySPN sbox, entries are 0, 2, 8
s = SBox([5, 3, 4, 6, 2, 7, 0, 1]) # Sbox with entries are 0, 2, 4, 8

print(f'{s = }:')
print('DDT:')
ddt = s.difference_distribution_table()
print(f'{ddt}')
n, m = s.input_size(), s.output_size()

# List of non-zero unique entries in the ddt
# In the case of toyspn sbox this is 8 and 2 (only 2 is non-trivial)
nonzero_entries_in_matrix = list(set(ddt.coefficients())) 

# For each non-zero entry, list all the input/output differences corresponding to that entry:
# For example, 1 goes to 5 with probability 2/8,
# so the point (001,101) will be listed as an input/output difference with DDT entry 2.
dict_points = {}
for value in nonzero_entries_in_matrix:
    dict_points[value] = []
for i in range(0, 1 << n):
    for o in range(0, 1 << m):
        if i+o > 0 and ddt[i][o] != 0:
            dict_points[ddt[i][o]].append(to_bits(n, i, big_endian) + to_bits(n, o, big_endian))

# Use the points above to build a polyhedron for each unique nonzero entry of the DDT
# In our case, only the nonzero entry 2 is interesting
# DEF: a polyhedron is a convex (possibly unbounded) set in Euclidean space 
# cut out by a finite set of linear inequalities and linear equations.
# Given the set of points, Sagemath allows to retrieve the set of inequalities defining the polyhedron.
dict_polyhedron = {}
for value in nonzero_entries_in_matrix:
    if dict_points[value]:
        dict_polyhedron[value] = Polyhedron(vertices=dict_points[value])

# Let's print the inequalities corresponding to the entry 2
# PS: the H(alf-space/Hyperplane)-representation describes a polyhedron as 
# the common solution set of a finite number of 
# linear inequalities A*x+b >=0, and
# linear equations C*x + d = 0
p = dict_polyhedron[2]
print(f'inequalities corresponding to the entry 2:')
for inequality in p.Hrepresentation():
    print(f'{inequality} <==> {inequality.repr_pretty()}')

# Let's add the inequalities in a MILP system of constraints
# See: https://doc.sagemath.org/html/en/reference/numerical/sage/numerical/mip.html#sage.numerical.mip.MixedIntegerLinearProgram.add_constraint
milp = MixedIntegerLinearProgram(maximization=True, solver="GLPK")
x = milp.new_variable(integer=True, nonnegative=True)
ineqs = p.Hrepresentation()
matrix_inequalities = matrix([ineqs[i][1:7] for i in range(len(ineqs))])
constant_terms_vector = [-ineqs[i][0] for i in range(len(ineqs))]
milp.add_constraint(matrix_inequalities * x >= constant_terms_vector)
milp.show()
milp.solve()
solution = milp.get_values(x)
print(f'One solution: {solution}')

# Now, let's remove one solution at a time and find the next one
for i in range(28):
    milp.add_constraint(sum(-(2*solution[i]-1)*x[i] for i in range(6)) + sum(solution[i] for i in range(6))-1 >= 0)
    try:
        milp.solve()
        solution = milp.get_values(x)
        print(f'Solution {i}: {solution}')
    except:
        print("There is no valid solution")
