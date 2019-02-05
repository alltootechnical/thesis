import gmpy2
from gmpy2 import mpz,mpq,mpfr,mpc
from pathlib import Path
import dghv_utils

class binary_real:
    def __init__(self):
        return

    def __init__(self, num, den, Precision):
        self.initialize(num, den, Precision)

    def initialize(self, num, den, Precision):
        num = mpz(num)
        den = mpz(den)
        self.precision = Precision
        quotient = gmpy2.f_div(num,den)
        if gmpy2.is_odd(quotient):
            self.decimal = 1
        else:
            self.decimal = 0
        remainder = gmpy2.fmod(num,den)

        self.value = []
        remainder *= 2
        i = 0
        while i < self.precision:
            if remainder < den:
                remainder *= 2
                value.append(False)
            elif remainer > den:
                value.append(True)
                remainder -= den
                remainder *= 2
            elif remainder == den:
                value.append(True)
                remainder -= den
            elif remainder == 0:
                value.append(False)
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
            if int(self.value[prec - i - 1]) + int(x.value[prec - i - i]) + int(carry) == 3:
                bits.append(True)
                carry = True
            elif int(self.value[prec - i - 1]) + int(x.value[prec - i - i]) + int(carry) == 2:
                bits.append(False)
                carry = True
            else:
                bits.append( self.value[prec - i - 1] or x.value[prec - i - i] or carry)
                carry = False
        
        if carry == True:
            dec = (dec + 1) % 2

        bits.reverse()

        result = binary_real()
        result.custom_setup(dec, prec, bits)
        return result

class cryptosystem:
    def __init__(self):
        self.sk = mpz(0)
        self.pk = [mpz(0) for i in range(2*beta + 1)]
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
            for i in range(2*beta + 1):
                self.pk[i] = mpz(pk_file.read())
            pk_file.close()
        

        # continue from line 191

    def generate_secret_key(self):
        tmp = mpz()
        self.sk = mpz(2)**(eta-mpz(1))
        gmpy2.random_state()
        i = eta - 32
        while i >= 0:
            tmp = gmpy2.mpz_random()
            tmp = tmp*(2**i)
            self.sk += tmp
        self.sk += gmpy2.mpz_random()
        self.sk = self.sk*2 + 1

    def generate_public_key(self):
        tmp = mpz()
        temp = (gamma - eta)//(Lambda**2) + 1
        for i in range(temp):
            generate_random(tmp, Lambda**2, False, False, True)
            tmp = gmpy2.mpz_nextprime(tmp)
            self.pk[0] *= tmp
