import math
import random
import sys
import bitstring
from dghv_shorter_public_key import cryptosystem as dghv_system
from dghv_shorter_public_key import ciphertext as  dghv_text
""" class DGHV_FP(object):
    
    def __init__(self):
        self.dp = DasguptaPalInteger()
        self.R_k = self.dp.R_k
        self.BASE = 16
        self.LOG2_BASE = math.log(self.BASE, 2)
        self.FLOAT_MANTISSA_BITS = sys.float_info.mant_dig

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
            int_rep = -int_rep
        return {'mantissa':int_rep, 'exponent':exponent}

    def pair2fp(self,pair):
        neg = False
        if pair['mantissa'] < 0:
            neg = True
            pair['mantissa'] = -pair['mantissa']
        result = pair['mantissa'] * pow(self.BASE, pair['exponent'])
        if neg:
            result = -result
        return result

    def encrypt(self,fp):
        pair = self.fp2pair(fp)
        pair['mantissa'] = self.dp.encrypt(pair['mantissa'])
        return pair

    def decrypt(self,pair):
        pair['mantissa'] = self.dp.decrypt(pair['mantissa'])
        return self.pair2fp(pair)

    def add(self,a,b):
        if a['exponent'] <= b['exponent']:
            mantissa = self.dp.add(a['mantissa'],self.dp.multiplyc(b['mantissa'], int(self.BASE**(b['exponent']-a['exponent']))))
            exponent = a['exponent']
        else:
            mantissa = self.dp.add(b['mantissa'],self.dp.multiplyc(a['mantissa'], int(self.BASE**(a['exponent']-b['exponent']))))
            exponent = b['exponent']
        return {'mantissa':mantissa, 'exponent':exponent}
    
    def addc(self,a,k):
        b = self.fp2pair(k)
        if a['exponent'] <= b['exponent']:
            mantissa = self.dp.addc(a['mantissa'],b['mantissa']*int(self.BASE**(b['exponent']-a['exponent'])))
            exponent = a['exponent']
        else:
            mantissa = self.dp.addc(self.dp.multiplyc(a['mantissa'], int(self.BASE**(a['exponent']-b['exponent']))),b['mantissa'])
            exponent = b['exponent']
        return {'mantissa':mantissa, 'exponent':exponent}
    
    def multiply(self,a,b):
        mantissa = self.dp.multiply(a['mantissa'],b['mantissa'])
        exponent = a['exponent'] + b['exponent']
        return {'mantissa':mantissa, 'exponent':exponent}
    
    def multiplyc(self,a,k):
        b = self.fp2pair(k)
        mantissa = self.dp.multiplyc(a['mantissa'],b['mantissa'])
        exponent = a['exponent'] + b['exponent']
        return {'mantissa':mantissa, 'exponent':exponent}
    
    def negate(self,a):
        return {'mantissa':self.dp.negate(a['mantissa']), 'exponent':a['exponent']} """
class DGHV_Integer(object):
    def __init__(self):
        self.system = dghv_system()
        self.n = 8
        print('dghv initialized')

    # pairwise add poly
    def add_poly(self, p1, p2):
        result = [p1[i]+p2[i] for i in range(len(p1))]
        return result

    # dghv encrypt/decrypt
    def encrypt(self, m):
        print('encrypting',m)
        bits = self.n
        s = bin(m & int("1"*bits, 2))[2:]
        binstring = ("{0:0>%s}" % (bits)).format(s)[::-1]
        print(binstring)
        return [dghv_text(self.system, int(i)) for i in binstring]

    def decrypt(self, c):
        num = []
        for ci in c:
            num.append(ci.decrypt())
        num.reverse()
        return bitstring.BitArray(num).int

    def refresh(self, c):
        for ci in c:
            ci.recrypt(self.system)
    
    # binary operation primitives
    def xor_bits(self, x, y):
        return x + y

    def and_bits(self, x, y):
        return x * y

    def not_bits(self, x):
        return ~x

    def or_bits(self, x, y):
        return x^y
    
    def shift_poly(self, p, x):
        return ([dghv_text(self.system, 0) for i in range(x)] + p)[:self.n]
    def nby1_poly(self, p, x):
        return [and_bits(a,x) for a in p]
    
    def add(self, A,B):
        result = []
        carry = dghv_text(self.system, 0)
        for i in range(len(A)):
            print('addition round', i)
            a = A[i]
            b = B[i]
            c = carry
            
            sum_bit = a+b+c
            carry = self.or_bits(a*b,c*(a+b))
            
            result.append(sum_bit)
            
        self.refresh(result)
        return result
    
    def addc(self,p1,k):
        return self.add(p1, self.encrypt(k))
    
    def multiply(self,p1,p2):
        product = [0]*self.n
        for i in range(len(p2)):
            partial_sum = self.shift_poly(self.nby1_poly(p1,p2[i]),i)
            product = self.add(product, partial_sum)
        product = self.refresh(product)[:self.n]
        return product
    
    def multiplyc(self,p1,k):
        return self.multiply(p1, self.encrypt(k))
    
    def negate(self,p):
        p = [self.not_bits(p[i]) for i in range(self.n)]
        p = self.add(p,self.encrypt(1))
        return self.refresh(p)

dghvcs = DGHV_Integer()
a = dghvcs.encrypt(5)
b = dghvcs.encrypt(7)
c = dghvcs.add(a,b)
d = dghvcs.multiply(a,b)
print(dghvcs.decrypt(a))
print(dghvcs.decrypt(b))
print(dghvcs.decrypt(c))
print(dghvcs.decrypt(d))