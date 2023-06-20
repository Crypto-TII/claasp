#!/usr/bin/env sage

# Frequency (Monobit) Test

def frequency_monobit_test(eps):
    n = len(eps)
    sn = sum(2*int(eps[i])-1 for i in range(n))
    sobs = abs(sn)/sqrt(n).n()

    # See https://doc.sagemath.org/html/en/reference/functions/sage/functions/error.html#sage.functions.error.Function_erfc
    # for erfc (complementary error function)
    pvalue = erfc(sobs/sqrt(2)).n()

    if pvalue < 0.01:
        return n, sn, sobs, pvalue, "non-random"
    else:
        return n, sn, sobs, pvalue, "random"

eps = "1011010101"
n, sn, sobs, pvalue, conclusion = frequency_monobit_test(eps)
print(f'{eps = }')
print(f'{n = }')
print(f'{sn = }')
print(f'{sobs = }')
print(f'{pvalue = }')
print(f'{conclusion = }')

eps = "1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000"
n, sn, sobs, pvalue, conclusion = frequency_monobit_test(eps)
print(f'{eps = }')
print(f'{n = }')
print(f'{sn = }')
print(f'{sobs = }')
print(f'{pvalue = }')
print(f'{conclusion = }')

eps = "0000001001000000100100100000010101100000010100001000000010110010001001000000010010000010000000100000"
n, sn, sobs, pvalue, conclusion = frequency_monobit_test(eps)
print(f'{eps = }')
print(f'{n = }')
print(f'{sn = }')
print(f'{sobs = }')
print(f'{pvalue = }')
print(f'{conclusion = }')


# Uniform Distribution of P-values evaluated by Goodneess-of-Fit Test

F = [6, 12, 9, 12, 8, 7, 8, 12, 15, 11]
s = 100
m = 10 # number of bins
chi_square = sum( (F[i] - s/m)^2/(s/m) for i in range(m) ).n()
gamma_inc(9/2, chi_square/2)/gamma(9/2).n()                                                                                                                                                                            
0.616305224983365