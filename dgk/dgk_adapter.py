import math
import sys
import bitstring
from dgk import *

class DGK_FP(object):
    
    def __init__(self):
        self.pubkey, self.privatekey = dgk_keygen(1024, 32)
        self.BASE = 16
        self.LOG2_BASE = math.log(self.BASE, 2)
        self.FLOAT_MANTISSA_BITS = sys.float_info.mant_dig
        self.boundary = (self.pubkey.n)

    def fp2pair(self,scalar):
        if isinstance(scalar, int):
            exponent = 0
        elif isinstance(scalar, float):
            bin_flt_exponent = math.frexp(scalar)[1]
            bin_lsb_exponent = bin_flt_exponent - self.FLOAT_MANTISSA_BITS
            exponent = math.floor(bin_lsb_exponent / self.LOG2_BASE)
        neg = False
        if scalar < 0:
            neg = True
            scalar = -scalar
        int_rep = int(round(scalar * pow(self.BASE, -exponent)))
        if neg:
            int_rep = int_rep + self.boundary
        return {'mantissa':int_rep, 'exponent':exponent}

    def pair2fp(self,pair):
        neg = False
        if pair['mantissa'] >= self.boundary:
            neg = True
            pair['mantissa'] -= self.boundary
        result = pair['mantissa'] * pow(self.BASE, pair['exponent'])
        if neg:
            result = -result
        return result

    def encrypt(self,fp):
        pair = self.fp2pair(fp)
        pair['mantissa'] = dgk_encrypt_plain(self.pubkey, pair['mantissa'])
        return pair

    def decrypt(self,pair):
        pair['mantissa'] = dgk_decrypt(self.pubkey, self.privatekey, pair['mantissa'])
        return self.pair2fp(pair)

    def add(self,a,b):
        if a['exponent'] <= b['exponent']:
            mantissa = add_dgk_ct(self.pubkey, a['mantissa'],scalar_mul_dgk(self.pubkey, b['mantissa'], int(self.BASE**(b['exponent']-a['exponent']))))
            exponent = a['exponent']
        else:
            mantissa = add_dgk_ct(self.pubkey, b['mantissa'],scalar_mul_dgk(self.pubkey, a['mantissa'], int(self.BASE**(a['exponent']-b['exponent']))))
            exponent = b['exponent']
        return {'mantissa':mantissa, 'exponent':exponent}
    
    def addc(self,a,k):
        b = self.fp2pair(k)
        if a['exponent'] <= b['exponent']:
            mantissa = scalar_add_dgk(self.pubkey, a['mantissa'],b['mantissa']*int(self.BASE**(b['exponent']-a['exponent'])))
            exponent = a['exponent']
        else:
            mantissa = scalar_add_dgk(self.pubkey, scalar_mul_dgk(self.pubkey, a['mantissa'], int(self.BASE**(a['exponent']-b['exponent']))), b['mantissa'])
            exponent = b['exponent']
        return {'mantissa':mantissa, 'exponent':exponent}
    
    def multiplyc(self,a,k):
        b = self.fp2pair(k)
        mantissa = scalar_mul_dgk(self.pubkey, a['mantissa'],b['mantissa'])
        exponent = a['exponent'] + b['exponent']
        return {'mantissa':mantissa, 'exponent':exponent}

dgk = DGK_FP()
a = dgk.encrypt(5.5)
b = dgk.encrypt(-7)
c = dgk.add(a,b)
d = dgk.multiplyc(a,6)
print(dgk.decrypt(a))
print(dgk.decrypt(b))
print(dgk.decrypt(c))
print(dgk.decrypt(d))