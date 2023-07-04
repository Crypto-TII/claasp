from sage.all import *

p = MixedIntegerLinearProgram(maximization=True, solver="GLPK")
x = p.new_variable(integer=True, nonnegative=True)
y = p.new_variable(integer=False, nonnegative=True)
p.add_constraint(-2*x[0] + 2*y[0] -1 >= 0)
p.add_constraint(-8*x[0] + 10*y[0] -13 <= 0)
p.add_constraint(x[0] >= 0)
p.add_constraint(y[0] >= 0)
p.set_objective(x[0] + y[0])
p.show()

print(f'Objective Value: max(x+y) = {p.solve()}')
print(f'Solutions: \n\tx = {p.get_values(x)[0]} \n\ty = {p.get_values(y)[0]}')

p = MixedIntegerLinearProgram(maximization=True, solver="GLPK")
x = p.new_variable(integer=True, nonnegative=True)
p.add_constraint(-2*x[0] + 2*x[1] -1 >= 0)
p.add_constraint(-8*x[0] + 10*x[1] -13 <= 0)
p.add_constraint(x[0] >= 0)
p.add_constraint(x[1] >= 0)
p.set_objective(None)
p.show()
p.solve()

print(f'Objective Value: None = {p.solve()}')
print(f'Solutions: \n\tx = {p.get_values(x)}')


# To model the point (1,0), we exclude all other points (0,0), (0,1), (1,1)
p = MixedIntegerLinearProgram(maximization=True, solver="GLPK")
x = p.new_variable(integer=True, nonnegative=True)
p.add_constraint(x[0] + x[1] >= 1)
p.add_constraint(x[0] + (1 - x[1]) >= 1)
p.add_constraint((1 - x[0]) + (1 - x[1]) >= 1)
p.set_objective(None)
p.show()
p.solve()

print(f'Solutions: \n\tx = {p.get_values(x)}')
