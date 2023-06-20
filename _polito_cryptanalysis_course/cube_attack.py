import math

# from sage.all__sagemath_objects import Integer
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing


def toyspn_chi(x0, x1, x2):
    y0 = x0 + (1 + x1) * x2
    y1 = x1 + (1 + x2) * x0
    y2 = x2 + (1 + x0) * x1
    return y0, y1, y2


def toyspn_round(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=False):
    x0 = x0 + k0
    x1 = x1 + k1
    x2 = x2 + k2
    x3 = x3 + k3
    x4 = x4 + k4
    x5 = x5 + k5
    if verb:
        print(f'after xor: {x0}{x1}{x2}{x3}{x4}{x5}')
    y0, y1, y2 = toyspn_chi(x0, x1, x2)
    y3, y4, y5 = toyspn_chi(x3, x4, x5)
    if verb:
        print(f'after sbox: {y0}{y1}{y2}{y3}{y4}{y5}')
        print(f'after rotl: {y5}{y0}{y1}{y2}{y3}{y4}')
    return y5, y0, y1, y2, y3, y4


def toyspn_update_key(k0, k1, k2, k3, k4, k5):
    return k5, k0, k1, k2, k3, k4


def toyspn_rotr1(x0, x1, x2, x3, x4, x5):
    return x5, x0, x1, x2, x3, x4

def toyspn2_cipher(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=False):
    if verb:
        print(f'input:      {x0}{x1}{x2}{x3}{x4}{x5}')
        print(f'key:        {k0}{k1}{k2}{k3}{k4}{k5}')
    k0, k1, k2, k3, k4, k5 = toyspn_update_key(k0, k1, k2, k3, k4, k5)
    x0, x1, x2, x3, x4, x5 = toyspn_round(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=verb)
    k0, k1, k2, k3, k4, k5 = toyspn_update_key(k0, k1, k2, k3, k4, k5)
    x0, x1, x2, x3, x4, x5 = toyspn_round(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=verb)

    return x0, x1, x2, x3, x4, x5


R = BooleanPolynomialRing(12, names=('x0','x1','x2','x3','x4','x5', 'k0','k1','k2','k3','k4','k5')); (x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5) = R._first_ngens(12)

f0, f1, f2, f3, f4, f5 = toyspn2_cipher(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5)