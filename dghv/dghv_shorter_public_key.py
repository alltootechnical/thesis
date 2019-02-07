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
            if int(self.value[prec - i - 1]) + int(other.value[prec - i - i]) + int(carry) == 3:
                bits.append(True)
                carry = True
            elif int(self.value[prec - i - 1]) + int(other.value[prec - i - i]) + int(carry) == 2:
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
            sk_file = open('secret_key.txt', 'w')
            self.generate_secret_key()
            sk_file.write(self.sk)
            sk_file.close()
        else:
            sk_file = open('secret_key.txt', 'r')
            self.sk = mpz(sk_file.read())
            sk_file.close()

        pk_file_check = Path('short_public_key.txt')
        if not pk_file_check.is_file():
            pk_file = open('short_public_key.txt', 'w')
            self.generate_public_key()
            for pk_i in self.pk:
                pk_file.write(pk_i)
            pk_file.close()
        else:
            pk_file = open('short_public_key.txt', 'r')
            for i in range(2 * beta + 1):
                self.pk[i] = mpz(pk_file.read())
            pk_file.close()

        enc_sk_file_check = Path('encrypted_sk_and_seed.txt')
        if not enc_sk_file_check.is_file():
            x_p = mpz(2) ** kappa
            x_p = gmpy2.f_div(x_p, sk)
            seed = generate_sparse_matrix(u_1, self.modified_secret_key, x_p)
            for i in range(Theta):
                if self.modified_secret_key[i] is True:
                    self.encrypted_sk[i] = symmetric_encryption(1)
                else:
                    self.encrypted_sk[i] = symmetric_encryption(0)
            enc_sk_file = open('short_public_key.txt', 'w')
            enc_sk_file.write(seed)
            enc_sk_file.write(u_1)
            for i in range(Theta):
                enc_sk_file.write(self.encrypted_sk[i])
            enc_sk_file.close()
        else:
            enc_sk_file = open('short_public_key.txt', 'r')
            seed = enc_sk_file.read()
            self.u_1 = enc_sk_file.read()

        # continue from line 222

    def generate_secret_key(self):
        tmp = mpz()
        self.sk = mpz(2)**(eta - mpz(1))
        gmpy2.random_state()
        i = eta - 32
        while i >= 0:
            tmp = gmpy2.mpz_random()
            tmp = tmp * (2**i)
            self.sk += tmp
        self.sk += gmpy2.mpz_random()
        self.sk = self.sk * 2 + 1

    def generate_public_key(self):
        tmp = mpz()
        temp = (gamma - eta) // (Lambda**2) + 1
        for i in range(temp):
            generate_random(tmp, Lambda**2, False, False, True)
            tmp = gmpy2.mpz_nextprime(tmp)
            self.pk[0] *= tmp

        for i in range(1, 2 * beta + 1):
            generate_x(self.pk[i], self.sk)
            while self.pk[i] >= self.pk[0]:
                generate_x(pk[i], sk)

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
                ct += pk[0]
        return ct

    def symmetric_encryption(self, m):
        ct = generate_x(self.sk)
        ct *= 2
        ct += m
        return ct

    def decrypt_bit(self, m, ct):
        m = mpz_mod_modified(ct, self.sk)
        m %= 2
        return m

    def AND_GATE(self, ct_1, ct_2):
        return (ct_1 * ct_2) % self.pk[0]
    
    def XOR_GATE(self, ct_1, ct_2):
        return (ct_1 + ct_2) % self.pk[0]
    
    def NOT_GATE(self, ct_1):
        return XOR_GATE(ct_1, 1)

    def OR_GATE(self, ct_1, ct_2):
        return NOT_GATE(AND_GATE(NOT_GATE(ct_1), NOT_GATE(ct_2)))
    
    def recrypt_util(self, encrypted_z, ct, PKC):
        u_i = [mpz() for i in range(Theta)]
        u_i[0] = self.u_1
        gmpy2.random_state()

        for i in range(1, Theta):
            u_i[i] = generate_random(kappa + 1, False, True, False)

        z_i = []
        den = mpz(2 ** kappa)
        Sum = binary_real(den, one, kappa)

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
    temp_2 = pkc.XOR_GATE(a,b)
    temp_2 = pkc.XOR_GATE(temp_2, c)
    temp_1 = pkc.AND_GATE(a, b)
    temp_3 = pkc.XOR_GATE(a, b)
    temp_3 = pkc.AND_GATE(temp_3, c)
    temp_1 = pkc.XOR_GATE(temp_1, temp_3)
    return temp_1, temp2

class ciphertext:
    def __init__(self, pkc=None, m=None):
        self.value = mpz()
        if not(pkc is None) and m is None:
            self.pkc = pkc
        elif not(pkc is None) and not(m is None):
            self.degree = 1
            self.pkc = pkc
            self.value = mpz(pkc.encrypt_bit(m))

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

    def __mult__(self, other):
        result = ciphertext(self.pkc)
        result.value = self.pkc.AND_GATE(self.value, other.value)
        result.degree = self.degree + other.degree
        return result

    def __xor__(self, other):
        result = ciphertext(self.pkc)
        result.value = self.pkc.OR_GATE(self.value, other.value)
        result.degree = self.degree + other.degree
        return result
    
    def __not__(self):
        result = ciphertext(self.pkc)
        result.value = pkc.NOT_GATE(self.value)
        result.degree = self.degree
        return result
    
    def recrypt(self, pkc):
        encrypted_z = [[mpz() for j in range(n + 1  + e)] for i in range(Theta)]
        pkc.recrypt_util(encrypted_z, self.value, pkc)
        # continue from line 531