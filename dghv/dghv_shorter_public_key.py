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
                    symmetric_encryption(self.encrypted_sk[i], 1)
                else:
                    symmetric_encryption(self.encrypted_sk[i], 0)
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

    def encrypt_bit(ct, bit):
        tmp, temp, test = mpz(), mpz(), mpz()
        ct = mpz(bit)
        generate_random(tmp, sigma, True, False, False)
        tmp *= 2
        ct += tmp
        for i in range(1, beta + 1):
            for j in range(1, beta + 1):
                generate_random(tmp, alpha, False, False, False)
                temp = self.pk[2 * j] * self.pk[2 * i - 1]
                temp %= self.pk[0]
                tmp *= temp
                tmp %= self.pk[0]
                tmp *= 2
                tmp %= self.pk[0]
                ct += tmp
                ct += pk[0]

    def symmetric_encryption(ct, m):
        generate_x(ct, self.sk)
        ct *= 2
        ct += m

    def decrypt_bit(m, ct):
        m = mpz_mod_modified(ct, self.sk)
        m %= 2
        