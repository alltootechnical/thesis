import gmpy2
from gmpy2 import mpz
from pathlib import Path
from dghv_utils import *

class binary_real:
    def __init__(self, num, den, Precision):
        self.initialize(num, den, Precision)

    def initialize(self, num, den, Precision):
        num = mpz(num)
        den = mpz(den)
        self.precision = Precision
        quotient = gmpy2.f_div(num, den)
        if gmpy2.is_odd(quotient):
            self.decimal = 1
        else:
            self.decimal = 0
        remainder = gmpy2.fmod(num, den)

        self.value = []
        remainder *= 2
        i = 0
        while i < self.precision:
            if remainder < den:
                remainder *= 2
                self.value.append(False)
            elif remainder > den:
                self.value.append(True)
                remainder -= den
                remainder *= 2
            elif remainder == den:
                self.value.append(True)
                remainder -= den
            elif remainder == 0:
                self.value.append(False)
            i += 1

    def custom_setup(self, dec, prec, val):
        self.decimal = dec
        self.precision = prec
        self.value = val

    def __add__(self, other):
        dec = (self.decimal + other.decimal) % 2
        prec = self.precision
        bits = []

        carry = False
        for i in range(prec):
            if int(self.value[prec - i - 1]) + int(other.value[prec - i - 1]) + int(carry) == 3:
                bits.append(True)
                carry = True
            elif int(self.value[prec - i - 1]) + int(other.value[prec - i - 1]) + int(carry) == 2:
                bits.append(False)
                carry = True
            else:
                bits.append(self.value[prec - i - 1] or other.value[prec - i - i] or carry)
                carry = False

        if carry is True:
            dec = (dec + 1) % 2

        bits.reverse()

        result = binary_real(1, 1, prec)
        result.custom_setup(dec, prec, bits)
        return result


class cryptosystem:
    def __init__(self):
        self.sk = mpz(0)
        self.pk = [mpz(0) for i in range(2 * beta + 1)]
        self.seed = 0
        self.u_1 = mpz(0)
        self.modified_secret_key = [mpz(0) for i in range(Theta)]
        self.encrypted_sk = [mpz(0) for i in range(Theta)]

        sk_file_check = Path('secret_key.txt')
        if not sk_file_check.is_file():
            print('generating secret key')
            sk_file = open('secret_key.txt', 'w')
            self.generate_secret_key()
            sk_file.write(self.sk.digits())
            sk_file.close()
        else:
            print('loading secret key')
            sk_file = open('secret_key.txt', 'r')
            self.sk = mpz(sk_file.read())
            sk_file.close()
        print('secret key:', self.sk)

        pk_file_check = Path('short_public_key.txt')
        if not pk_file_check.is_file():
            pk_file = open('short_public_key.txt', 'w')
            self.generate_public_key()
            pk_file.writelines("%s\n" % str(pk_i.digits()) for pk_i in self.pk)
            print('public key generated,', len(self.pk), 'elements')
            #print([str(pk_i) for pk_i in self.pk])
            pk_file.close()
        else:
            pk_file = open('short_public_key.txt', 'r')
            self.pk = [mpz(element.rstrip()) for element in pk_file.readlines()]
            print('public key loaded,', len(self.pk), 'elements')
            pk_file.close()

        enc_sk_file_check = Path('encrypted_sk_and_seed.txt')
        if not enc_sk_file_check.is_file():
            x_p = mpz(gmpy2.mul_2exp(1, kappa))
            x_p = mpz(gmpy2.f_div(x_p, self.sk))
            self.seed, self.u_1 = generate_sparse_matrix(self.u_1, self.modified_secret_key, x_p)
            for i in range(Theta):
                if self.modified_secret_key[i] is True:
                    self.encrypted_sk[i] = self.symmetric_encryption(self.encrypted_sk[i], 1)
                else:
                    self.encrypted_sk[i] = self.symmetric_encryption(self.encrypted_sk[i], 0)
            enc_sk_file = open('encrypted_sk_and_seed.txt', 'w')
            enc_sk_file.write('%s\n' %  str(self.seed))
            enc_sk_file.write('%s\n' % str(self.u_1))
            for i in range(Theta):
                enc_sk_file.write('%s\n' % str(self.encrypted_sk[i]))
            enc_sk_file.close()
        else:
            enc_sk_file = open('encrypted_sk_and_seed.txt', 'r')
            file_contents = [element.rstrip() for element in enc_sk_file.readlines()]
            self.seed = int(file_contents[0])
            self.u_1 = mpz(file_contents[1])
            temp = mpz()
            for i in range(Theta):
                self.encrypted_sk[i] = mpz(file_contents[i+2])
                temp = self.decrypt_bit(self.encrypted_sk[i])
                if temp == 1:
                    self.modified_secret_key[i] = True
                else:
                    self.modified_secret_key[i] = False
            enc_sk_file.close()

    def generate_secret_key(self):
        tmp = mpz()
        self.sk = gmpy2.mul_2exp(1, eta - 1)
        random_state = gmpy2.random_state(mpz(time.time()))
        i = eta - 32
        while i >= 0:
            tmp = gmpy2.mpz_random(random_state, RAND_MAX)
            tmp = gmpy2.mul_2exp(tmp, i)
            self.sk += tmp
            i -= 32
        self.sk += gmpy2.mpz_random(random_state, RAND_MAX)
        self.sk = mpz(self.sk * 2 + 1)

    def generate_public_key(self):
        tmp = mpz()
        self.pk[0] = self.sk
        temp = (gamma - eta) // (Lambda**2) + 1

        for i in range(temp):
            print('public key generation phase 1/2: iteration', i + 1, 'of', temp)
            tmp = generate_random( Lambda**2, False, False, True)
            tmp = gmpy2.next_prime(tmp)
            self.pk[0] *= tmp

        for i in range(1, 2 * beta + 1):
            print('public key generation phase 2/2: iteration', i + 1, 'of', 2 * beta + 1)
            self.pk[i] = generate_x(self.pk[i], self.sk)
            while self.pk[i] >= self.pk[0]:
                self.pk[i] = generate_x(self.pk[i], self.sk)

    def encrypt_bit(self, bit):
        tmp, temp, test = mpz(), mpz(), mpz()
        ct = mpz(bit)
        tmp = generate_random(sigma, True, False, False)
        tmp *= 2
        ct += tmp
        for i in range(1, beta + 1):
            for j in range(1, beta + 1):
                tmp = generate_random(alpha, False, False, False)
                temp = self.pk[2 * j] * self.pk[2 * i - 1]
                temp %= self.pk[0]
                tmp *= temp
                tmp %= self.pk[0]
                tmp *= 2
                tmp %= self.pk[0]
                ct += tmp
                ct += self.pk[0]
        return ct

    def symmetric_encryption(self, ct, m):
        ct = generate_x(ct, self.sk)
        ct *= 2
        ct += m
        return ct

    def decrypt_bit(self, ct):
        m = mpz_mod_modified(ct, self.sk)
        m %= 2
        return m

    def AND_GATE(self, ct_1, ct_2):
        return (ct_1 * ct_2) % self.pk[0]

    def XOR_GATE(self, ct_1, ct_2):
        return (ct_1 + ct_2) % self.pk[0]

    def NOT_GATE(self, ct_1):
        return self.XOR_GATE(ct_1, 1)

    def OR_GATE(self, ct_1, ct_2):
        return self.NOT_GATE(self.AND_GATE(self.NOT_GATE(ct_1), self.NOT_GATE(ct_2)))

    def recrypt_util(self, encrypted_z, ct, PKC):
        global global_random_state
        u_i = [mpz() for i in range(Theta)]
        u_i[0] = mpz(self.u_1)
        global_random_state = gmpy2.random_state(self.seed)

        for i in range(1, Theta):
            u_i[i] = generate_random(kappa + 1, False, True, False)

        z_i = []
        den = mpz(gmpy2.mul_2exp(1, kappa))
        Sum = binary_real(zero, one, n + e)

        for i in range(Theta):
            num = u_i[i] * ct
            z_i.append(binary_real(num, den, n + e))

        for i in range(Theta):
            for j in range(n + 1 + e):
                if j == 0:
                    if z_i[i].decimal == 1:
                        encrypted_z[i][j] = mpz(1)
                    else:
                        encrypted_z[i][j] = mpz(0)
                else:
                    if z_i[i].value[j - 1] is True:
                        encrypted_z[i][j] = mpz(1)
                    else:
                        encrypted_z[i][j] = mpz(0)

def two_for_three_trick(a, b, c, pkc):
    temp_1, temp_2, temp_3 = mpz(), mpz(), mpz()
    temp_2 = pkc.XOR_GATE(a, b)
    temp_2 = pkc.XOR_GATE(temp_2, c)
    temp_1 = pkc.AND_GATE(a, b)
    temp_3 = pkc.XOR_GATE(a, b)
    temp_3 = pkc.AND_GATE(temp_3, c)
    temp_1 = pkc.XOR_GATE(temp_1, temp_3)
    return temp_1, temp_2

class ciphertext:
    def __init__(self, pkc=None, m=None):
        self.value = mpz()
        if not(pkc is None) and m is None:
            self.pkc = pkc
        elif not(pkc is None) and not(m is None):
            self.degree = 1
            self.pkc = pkc
            self.value = mpz(pkc.encrypt_bit(m))
            #print('encrypting bit', m)

    def decrypt(self):
        return self.pkc.decrypt_bit(self.value)

    def initialize(self, pkc, m):
        self.value = pkc.encrypt_bit(m)
        self.degree = 1
        self.pkc = pkc

    def custom_setup(self, val, deg, pkc):
        self.value = mpz(val)
        self.degree = deg
        self.pkc = pkc

    def __add__(self, other):
        result = ciphertext(self.pkc)
        result.value = self.pkc.XOR_GATE(self.value, other.value)
        result.degree = max(self.degree, other.degree)
        return result

    def __mul__(self, other):
        result = ciphertext(self.pkc)
        result.value = self.pkc.AND_GATE(self.value, other.value)
        result.degree = self.degree + other.degree
        return result

    def __xor__(self, other):
        result = ciphertext(self.pkc)
        result.value = self.pkc.OR_GATE(self.value, other.value)
        result.degree = self.degree + other.degree
        return result

    def __invert__(self):
        result = ciphertext(self.pkc)
        result.value = pkc.NOT_GATE(self.value)
        result.degree = self.degree
        return result

    def recrypt(self, pkc):
        encrypted_z = [[mpz() for j in range(n + 1 + e)] for i in range(Theta)]
        pkc.recrypt_util(encrypted_z, self.value, pkc)
        temp = mpz()
        a = [[ciphertext() for j in range(n + 1 + e)] for i in range(Theta)]
        for i in range(Theta):
            for j in range(n + 1 + e):
                encrypted_z[i][j] = pkc.AND_GATE(encrypted_z[i][j], pkc.encrypted_sk[i])
                a[i][j].custom_setup(encrypted_z[i][j], 2, pkc)

        dp = [[ciphertext() for j in range(Theta + 1)] for i in range(2**(n - 1) + 1)]
        W = [[ciphertext() for j in range(n + 1)] for i in range(n + 1 + e)]
        for i in range(1, 2**(n - 1) + 1):
            dp[i][0].custom_setup(0, 1, pkc)
        for i in range(Theta + 1):
            dp[0][i].custom_setup(1, 1, pkc)
        for k in range(n + 1 + e):
            for i in range(1, 2**(n - 1) + 1):
                for j in range(1, Theta + 1):
                    dp[i][j] = a[j - 1][k] * dp[i - 1][j - 1]
                    dp[i][j] = dp[i][j] + dp[i][j - 1]

            if k < n:
                for i in range(k + 1):
                    W[k][i].custom_setup(dp[2**(k - i)][Theta].value, dp[2**(k - i)][Theta].degree, pkc)
            else:
                for i in range(k + 1 - n, n + 1):
                    W[k][i].custom_setup(dp[2**(k - i)][Theta].value, dp[2**(k - i)][Theta].degree, pkc)

        k = 0
        l = 0
        size = n + 1 + e
        while size > 2:
            k = 0
            l = 0
            while size > k + 2:
                W[l + 1][0].value = pkc.XOR_GATE(W[k][0].value, W[k + 1][0].value)
                W[l + 1][0].value = pkc.XOR_GATE(W[l + 1][0].value, W[k + 2][0].value)

                for j in range(1, n + 1):
                    W[l][j - 1].value, W[l + 1][j].value = two_for_three_trick(W[k][j].value, W[k + 1][j].value, W[k + 2][j].value, pkc)
                W[l][n].value = mpz(0)
                l += 2
                k += 3

            if k + 2 == size:
                for j in range(n + 1):
                    W[l][j].value = mpz(W[k][j].value)
                    W[l + 1][j].value = mpz(W[k + 1][j].value)
                l += 2
            elif k + 1 == size:
                for j in range(n + 1):
                    W[l][j].value = mpz(W[k][j].value)
                l += 1
            size = l

        c_p_bit = pkc.AND_GATE(W[0][1].value, W[1][1].value)
        c_p_bit = pkc.XOR_GATE(c_p_bit, W[1][0].value)
        c_p_bit = pkc.XOR_GATE(c_p_bit, W[0][0].value)
        if self.value % 2 == 0:
            c_p_bit += 1
        self.value = c_p_bit
        self.pkc = pkc
        return


# driver
# pkc = cryptosystem()
# a = ciphertext(pkc, 0)
# b = ciphertext(pkc, 1)
# print('0 + 0:', (a+a).decrypt())
# print('1 + 0:', (b+a).decrypt())
# print('0 + 1:', (a+b).decrypt())
# print('1 + 1:', (b+b).decrypt())
# print('0 * 0:', (a*a).decrypt())
# print('1 * 0:', (b*a).decrypt())
# print('0 * 1:', (a*b).decrypt())
# print('1 * 1:', (b*b).decrypt())
# c = ciphertext(pkc, 1)
# for i in range(10):
    #print('+',i%2,'=')
    # c = c + ciphertext(pkc, i%2)
    #c.recrypt(pkc)
    # print(c.decrypt())
    # c.recrypt(pkc)

