from sage.crypto.boolean_function import BooleanFunction as BF
from sage.crypto.boolean_function import ZZ
from sage.rings.integer import Integer
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing
# from sage.rings.polynomial.pbori import BooleanPolynomialRing


def inner_product(x, e):
    sum = 1
    for i in range(len(f'{e:b}')):
        sum = sum + (((x >> i) % 2) * ((e >> i) % 2))
    return sum


def inner_power(x, e):
    product = 1
    for i in range(len(f'{e:b}')):
        product = product * (((x >> i) % 2) ** ((e >> i) % 2))
    return product


def set_indicator(x, X):
    if x in X:
        return 1


def parity_set(X, n):
    """
    X is a subset of F_2^n
    return U(X) = {u in F_2^n | \sum_{x \in X} x^u = 1}
    Example:
        sage: X = [0b000001, 0b000010, 0b000011]
        sage: parity_set(X, 6)
    """
    ps = []
    for u in range(2**n):
        s = sum([inner_power(x, u) for x in X])
        if s == 1:
            ps.append(f'{u:0{n}b}')
    return ps

class BooleanFunction(BF):
    def support(self):
        n = self.nvariables()
        support = []
        for i in range(2**n):
            X = ZZ(i).digits(base=2, padto=n)
            t = self(X)
            if t == 1:
                support.append(sum(X[i]*2**i for i in range(len(X)-1,-1,-1)))
        return support

    def graph(self):
        n = self.nvariables()
        graph = []
        for i in range(2 ** n):
            X = ZZ(i).digits(base=2, padto=n)
            graph.append([f'{i:0{n}b}', f'{int(self(X))}' ])
        return graph


# R.<x1,x2,x3> = BooleanPolynomialRing()
R = BooleanPolynomialRing(Integer(3), names=('x1','x2','x3',)); (x1,x2,x3,) = R._first_ngens(3)

# R = BooleanPolynomialRing()
# f = BooleanFunction([1,0,1])
f = BooleanFunction(x1*x2 + x3)
n = f.nvariables()
print(f'{f.algebraic_normal_form() = }')
# ', '.join([f'{s:0{n}b}' for s in boolean_function_support(f)])
print('support = ' + ', '.join([f'{s:0{n}b}' for s in f.support()]))
print(f'{f.graph() = }')
print(f'{parity_set(f.support(),n) = }')


