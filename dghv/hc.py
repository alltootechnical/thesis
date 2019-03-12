import phe as paillier
import random
from Pyfhel import Pyfhel, PyCtxt, PyPtxt
from DasguptaPal import DasguptaPalInteger
class HomomorphicCryptosystem(object):
    
    def __init__(self, hc_type):
        self.hc_type = hc_type
        if self.hc_type == 'paillier':
            self.hc_obj = paillier
        elif self.hc_type == 'bgv':
            self.hc_obj = Pyfhel()
        elif self.hc_type == 'dp':
            self.hc_obj = DasguptaPalInteger()
        else:
            raise NotImplementedError('Cryptosystem {hc_type} not yet supported...')
    
    def keygen(self, length=256):
        if self.hc_type == 'paillier':
            self.pubkey, self.privkey = self.hc_obj.generate_paillier_keypair(n_length=length)
        elif self.hc_type == 'bgv':
            self.hc_obj.contextGen(p=257)
            self.hc_obj.keyGen()
            self.hc_obj.relinKeyGen(16, 16)
        elif self.hc_type == 'dp':
            # nothing 
            self
        else:
            raise NotImplementedError
    
    def encrypt(self, num):
        if self.hc_type == 'paillier':
            return self.pubkey.encrypt(num)
        elif self.hc_type == 'bgv':
            return self.hc_obj.encryptFrac(float(num))
        elif self.hc_type == 'dp':
            return self.hc_obj.encrypt(num)
        else:
            raise NotImplementedError
            
    def decrypt(self, enc_num):
        if self.hc_type == 'paillier':
            return self.privkey.decrypt(enc_num)
        elif self.hc_type == 'bgv':
            return self.hc_obj.decryptFrac(enc_num)
        elif self.hc_type == 'dp':
            return self.hc_obj.decrypt(enc_num)
        else:
            raise NotImplementedError
    
    def add(self, x, y):
        if self.hc_type == 'paillier':
            return x + y
        elif self.hc_type == 'bgv':
            return self.hc_obj.add(x, y, in_new_ctxt=True)
        elif self.hc_type == 'dp':
            return self.hc_obj.add(x,y)
        else:
            raise NotImplementedError
            
    def add_c(self, x, k):
        if self.hc_type == 'paillier':
            return x + k
        elif self.hc_type == 'bgv':
            return self.hc_obj.add_plain(x, self.hc_obj.encodeFrac(k), in_new_ctxt=True)
        elif self.hc_type == 'dp':
            return self.hc_obj.add(x,self.encrypt(k))
        else:
            raise NotImplementedError
            
    def mul(self, x, y):
        if self.hc_type == 'paillier':
            x2 = self.power(x,2)
            y2 = self.power(y,2)
            xy = self.encrypt(self.decrypt(x+y)**2)
            return xy - x2 - y2
        elif self.hc_type == 'bgv':
            return self.hc_obj.multiply(x, y, in_new_ctxt=True)
        else:
            raise NotImplementedError
            
    def mul_c(self, x, k):
        if self.hc_type == 'paillier':
            return x * k
        elif self.hc_type == 'bgv':
            return self.hc_obj.multiply_plain(x, self.hc_obj.encodeFrac(k), in_new_ctxt=True)
        elif self.hc_type == 'dp':
            return self.hc_obj.mult(x,self.encrypt(k))
        else:
            raise NotImplementedError
            
    # for convenience
    def negate(self, x):
        if self.hc_type == 'paillier':
            return -1 * x
        elif self.hc_type == 'bgv':
            return self.hc_obj.negate(x, in_new_ctxt=True)
        else:
            raise NotImplementedError
    
    def sub(self, x, y):
        if self.hc_type == 'paillier':
            return x - y
        elif self.hc_type == 'bgv':
            return self.hc_obj.sub(x, y, in_new_ctxt=True)
        else:
            raise NotImplementedError
            
    def sub_c(self, x, k):
        if self.hc_type == 'paillier':
            return x - k
        elif self.hc_type == 'bgv':
            return self.hc_obj.sub_plain(x, self.hc_obj.encodeFrac(k), in_new_ctxt=True)
        else:
            raise NotImplementedError
            
    def div(self, x, y):
        if self.hc_type == 'paillier':
            # fake implementation
            return self.encrypt(self.decrypt(x)/self.decrypt(y))
        elif self.hc_type == 'bgv':
            # this is actually an open problem, thus this implementation is 'fake'
            return self.hc_obj.multiply_plain(x, self.hc_obj.encodeFrac(1/self.decrypt(y)), in_new_ctxt=True)
        else:
            raise NotImplementedError
            
    def div_c(self, x, k):
        if self.hc_type == 'paillier':
            return x * (1/k)
        elif self.hc_type == 'bgv':
            return self.hc_obj.multiply_plain(x, self.hc_obj.encodeFrac(1/k), in_new_ctxt=True)
        else:
            raise NotImplementedError
            
    def power(self, x, p):
        if self.hc_type == 'paillier':
            if(p==2):
                r = random.randint(1,255)
                c = self.encrypt(self.decrypt(x+r)**2)
                result = c - (2*r*x + r**2)
                return result
            else:
                y = x
                res = self.encrypt(1)
                while p > 0:
                    if p%2 == 1: 
                        res = self.mul(res, y)
                    y = self.power(y,2)
                    p = p // 2
                return res
        elif self.hc_type == 'bgv':
            #self.hc_obj.relinKeyGen(16, 16)
            #return self.hc_obj.power(x, p, in_new_ctxt=True)
            y = x
            res = self.encrypt(1)
            while p > 0:
                if p%2 == 1: 
                    res = self.hc_obj.multiply(res, y, in_new_ctxt=True)
                y = self.hc_obj.square(y, in_new_ctxt=True)
                p = p // 2
            return res
        else:
            raise NotImplementedError