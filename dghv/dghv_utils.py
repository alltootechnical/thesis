import gmpy2
from gmpy2 import mpz,mpq,mpfr,mpc
zero = mpz(0)
one = mpz(1)
two = mpz(2)

Lambda = 42
alpha = 42
rho = 16
beta = 12
sigma = 42
eta = 1088
gamma = 160000
tau = 158
Theta = 144
theta = 15
n = 4
kappa = 161569 + 2 + n
e = 0

def sort_utility(array, l, m, r):
    n_1 = m - l + 1
    n_2 = r - m
    L = [mpz(array[l + i]) for i in range(n_1)]
    R = [mpz(array[m + 1 + j]) for i in range(n_2)]

    i = 0
    j = 0
    k = l
    while i < n_1 and j < n_2:
        if L[i] < R[j]:
            array[k] = L[i]
            k += 1
            i += 1
        else
            array[k] = R[j]
            k += 1
            j += 1
    
    while i < n_1:
        array[k] = L[i]
        k += 1
        i += 1
    
    while j < n_2:
        array[k] = R[j]
        k += 1
        j += 1

def sort_huge_numbers(array, l, r):
    if l < r:
        m = (l + r)//2
        sort_huge_numbers(array, l, m)
        sort_huge_numbers(array, m + 1, r)
        sort_utility(array, l, m, r)

def bit_size(x):
    temp = 0
    if x < 0:
        tmp = gmpy2.mul(x, -1)
    else:
        tmp = mpz(x)
    
    while tmp > 0:
        tmp = gmpy2.fdiv(tmp, two)
        temp += 1
    
    return temp

def mpz_mod_modified(op1, op2)
    rop = gmpy2.f_mod(op1,op2)
    temp = gmpy2.f_div(op2, two)
    if rop > temp:
        rop = gmpy2.sub(rop, op2)
    return rop

def generate_random(x, bitsize, include_negative_range, seeded, full_range):
