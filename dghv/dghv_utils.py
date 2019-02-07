import gmpy2
from gmpy2 import mpz
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
    R = [mpz(array[m + 1 + j]) for j in range(n_2)]

    i = 0
    j = 0
    k = l
    while i < n_1 and j < n_2:
        if L[i] < R[j]:
            array[k] = L[i]
            k += 1
            i += 1
        else:
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
        m = (l + r) // 2
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

def mpz_mod_modified(op1, op2):
    rop = gmpy2.f_mod(op1, op2)
    temp = gmpy2.f_div(op2, two)
    if rop > temp:
        rop = gmpy2.sub(rop, op2)
    return rop

def generate_random(bit_size, include_negative_range, seeded, full_range):
    if not seeded:
        gmpy2.random_state()
    x = zero
    if full_range:
        x = gmpy2.mul_2exp(one, bit_size - 1)
    tmp = 0
    if bit_size < 33:
        tmp = gmpy2.get_random()
        temp = (1 << bit_size)
        x = gmpy2.f_mod(tmp, temp)
        if include_negative_range:
            tmp = gmpy2.mul_2exp(one, bit_size - 1)
            x = gmpy2.sub(x, tmp)
        return x
    for i in range(bit_size - 32, 0 - 1, -32):
        tmp = gmpy2.get_random()
        tmp = gmpy2.mul_2exp(tmp, i)
        x = gmpy2.add(x, tmp)
    x = gmpy2.add(x, gmpy2.get_random())
    if include_negative_range:
        tmp = gmpy2.mul_2exp(one, bit_size - 1)
        x = gmpy2.sub(x, tmp)
    return x
        
def generate_x(sk):
    gmpy2.random_state()
    q, r = 0, 0
    q = generate_random(gamma - eta, False, False, False)
    r = generate_random(rho, True, False, False)
    x = gmpy2.mul(q, sk)
    x = gmpy2.add(r, x)
    return x

def generate_x_i(sk, length):
    tmp, q, r = 0, 0, 0
    q = gmpy2.mul_2exp(one, length - 1)
    gmpy2.random_state()
    for i in range(length - 32, 0 - 1, -32):
        tmp = gmpy2.get_random()
        tmp = gmpy2.mul_2exp(tmp, i)
        q = gmpy2.add(tmp, q)
    q = gmpy2.add(q, gmpy2.get_random())
    r = generate_random(rho, True, False, False)
    x_i = gmpy2.mul(q, sk)
    x_i = gmpy2.add(r, x_i)
    return x_i
    
def generate_sparse_matrix(u_1, modified_secret_key, x_p):
    gmpy2.random_state()
    Theta_vector = [0 for _ in range(Theta)]
    for i in range(1, Theta):
        Theta_vector[i] = generate_random(kappa + 1, False, True, False)
    modified_secret_key[0] = True
    for i in range(1, Theta):
        modified_secret_key[i] = False
    count = theta - 1
    gmpy2.random_state()
    while count > 0:
        index = gmpy2.get_random() % Theta
        if not modified_secret_key[index]:
            modified_secret_key[index] = True
            count -= 1
    sum_ = zero
    temp = gmpy2.mul_2exp(one, kappa + 1)
    for i in range(1, Theta):
        if modified_secret_key[i]:
            sum_ = gmpy2.add(sum_, Theta_vector[i])
    sum_ = gmpy2.mod(sum_, temp)
    u_1 = gmpy2.sub(x_p, sum_)
    if u_1 < zero:
        u_1 = gmpy2.add(temp, u_1)
    return

