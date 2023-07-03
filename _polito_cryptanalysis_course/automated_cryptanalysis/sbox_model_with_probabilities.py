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
nonzero_entries_in_matrix = list(set(ddt.coefficients())) 


M = 2*n
milp = MixedIntegerLinearProgram(maximization=False, solver="GLPK")
# x0, ..., x5 are used for input-output bits
# x6 for the Q_2 variable corresponding to the  2-DDT entry
# x7 for the Q_4 variable corresponding to the  4-DDT entry
# x8 for the Q variable indicating that the sbox is active
x = milp.new_variable(integer=True, nonnegative=True)

for i in range(ddt.nrows()):
    for j in range(ddt.ncols()):
        if ddt[i][j] != 0:
            v = to_bits(n, i) + to_bits(n, j)
            if ddt[i][j] == 2: 
                ineq = sum(v[h] - (2*v[h]-1)*x[h] for h in range(2*n)) + M*(1-x[6])
                print(f'{v = } : {ineq = }')
                milp.add_constraint(ineq >= 1)
            if ddt[i][j] == 4:
                ineq = sum(v[h] - (2*v[h]-1)*x[h] for h in range(2*n)) + M*(1-x[7])
                print(f'{v = } : {ineq = }')
                milp.add_constraint(ineq >= 1)

for i in range(9):
    milp.add_constraint(x[i] <= 1)


milp.add_constraint(x[6] + x[7] - x[8] == 0)
milp.add_constraint(sum(x[i] for i in range(6)) >= 1)
milp.set_objective(2*x[6] + 1*x[7])
milp.show()

print(f'Minimum value of the bjective function {milp.solve()}')
solution = milp.get_values(x)
print(f'One solution: {solution}')

"""
# Now, let's remove one solution at a time and find the next one
for i in range(28):
    milp.add_constraint(sum(-(2*solution[i]-1)*x[i] for i in range(6)) + sum(solution[i] for i in range(6))-1 >= 0)
    try:
        milp.solve()
        solution = milp.get_values(x)
        print(f'Solution {i}: {solution}')
    except:
        print("There is no valid solution")
"""