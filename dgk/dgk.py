import gmpy2
from gmpy2 import mpz
import time

global_random_state = None

# utils.cpp
def aby_prng(Len):
    """Generates a random mpz with bitlength Len."""
    global global_random_state
    if global_random_state is None:
        global_random_state = gmpy2.random_state(int(time.time()))
    result = mpz(0)
    for i in range(Len):
        if gmpy2.mpz_random(global_random_state, 2) == 1:
            result += gmpy2.exp2(i)
    return mpz(result)


# new in python 3.7 - "structs"
from dataclasses import dataclass

# dgk.h

# This represents a DGK public key.
@dataclass
class dgk_pubkey:
    bits: int   # key bits e.g., 1024
    lbits: int  # share (message) length e.g., 32
    n: mpz      # public modulus n = pq
    u: mpz
    g: mpz
    h: mpz

@dataclass
class dgk_prvkey:
    vp: mpz
    vq: mpz
    p: mpz
    q: mpz
    p_minusone: mpz
    q_minusone: mpz
    pinv: mpz
    qinv: mpz

# dgk.cpp

DGK_CHECKSIZE = 0

# number of test encryptions and decryptions that are performed to verify a generated key. This will take time, but more are better.
KEYTEST_ITERATIONS = 1000

powtwo = []
gvpvqp = []

# Return public key
def dgk_complete_pubkey(modulusbits, lbits, n, g, h):
    return dgk_pubkey(modulusbits, 2 * lbits + 2, mpz(n), mpz(1 << (2 * lbits + 2)), mpz(g), mpz(h))

def dgk_keygen(modulusbits, lbits):
    pub = dgk_pubkey(0,0,0,0,0,0)
    prv = dgk_prvkey(0,0,0,0,0,0,0,0)

    lbits = lbits * 2 + 2

    pub.bits = modulusbits
    pub.lbits = lbits

    # vp and vq are primes
    prv.vp = aby_prng(160)
    prv.vp = gmpy2.next_prime(prv.vp)

    prv.vq = aby_prng(160)
    prv.vq = gmpy2.next_prime(prv.vq)

    while prv.vp == prv.vq:
        prv.vq = gmpy2.next_prime(prv.vq)

    # u = 2 ^ lbits
    pub.u = mpz(gmpy2.exp2(lbits))
    
    # p
    found = False
    while not found:
        f1 = aby_prng(modulusbits // 2 - 160 - lbits)
        f1 = gmpy2.next_prime(f1)

        prv.p = mpz(pub.u * prv.vp)
        prv.p *= f1
        prv.p += 1
        found = gmpy2.is_prime(prv.p, 50)

    # q
    found = False
    while not found:
        f2 = aby_prng(modulusbits // 2 - 159 - lbits)
        f2 = gmpy2.next_prime(f2)

        prv.q = mpz(pub.u * prv.vq)
        prv.q *= f2
        prv.q += 1
        found = gmpy2.is_prime(prv.q, 50)

    # p-1, q-1
    prv.p_minusone = prv.p - 1
    prv.q_minusone = prv.q - 1

    # n = pq
    pub.n = mpz(prv.p * prv.q)

    # xp
    exp1 = mpz(gmpy2.exp2(lbits - 1))

    exp1 *= prv.vp
    exp1 *= f1
    exp2 = mpz(prv.vp * pub.u)
    exp3 = mpz(f1 * pub.u)

    found = False
    while not found:
        xp = mpz(aby_prng(prv.p.bit_length() + 128))
        xp %= prv.p

        tmp = gmpy2.powmod(xp, exp1, prv.p)
        if tmp != 1:
            tmp = gmpy2.powmod(xp, exp2, prv.p)
            if tmp != 1:
                tmp = gmpy2.powmod(xp, exp3, prv.p)
                if tmp != 1:
                    found = True
    
    # xq
    exp1 = mpz(gmpy2.exp2(lbits - 1))

    exp1 *= prv.vq
    exp1 *= f2
    exp2 = mpz(prv.vq * pub.u)
    exp3 = mpz(f2 * pub.u)

    found = False
    while not found:
        xq = aby_prng(prv.q.bit_length() + 128)
        xq %= prv.q

        tmp = gmpy2.powmod(xq, exp1, prv.q)
        if tmp != 1:
            tmp = gmpy2.powmod(xq, exp2, prv.q)
            if tmp != 1:
                tmp = gmpy2.powmod(xq, exp3, prv.q)
                if tmp != 1:
                    found = True
    
    # compute CRT: g = xp*q*(q^{-1} mod p) + xq*p*(p^{-1} mod q) mod n
    prv.qinv = gmpy2.invert(prv.q, prv.p)
    prv.pinv = gmpy2.invert(prv.p, prv.q)
    pub.g = (xp * prv.q * prv.qinv + xq * prv.p * prv.pinv) % pub.n

    # line 206
    tmp = mpz(f1 * f2)
    pub.g = gmpy2.powmod(pub.g, tmp, pub.n)

    pub.h = mpz(aby_prng(mpz(pub.n).bit_length() + 128))
    pub.h %= pub.n

    tmp *= pub.u
    pub.h = gmpy2.powmod(pub.h, tmp, pub.n)

    # array holding powers of two
    for i in range(lbits):
        powtwo.append(mpz(gmpy2.exp2(i)))

    f1 = gmpy2.powmod(pub.g, prv.vp, prv.p)

    tmp2 = pub.u - 1

    for i in range(lbits):
        gvpvqptmp = mpz(gmpy2.powmod(f1, powtwo[i], prv.p))
        gvpvqptmp = mpz(gmpy2.powmod(gvpvqptmp, tmp2, prv.p))
        gvpvqp.append(gvpvqptmp)

    return pub, prv

# def dgk_encrypt_db(pub, plaintext):
#     r = aby_prng(400)
#     return dbpowmod(pub.h, r, pub.g, plaintext, pub.n)

def dgk_encrypt_plain(pub, plaintext):
    r = aby_prng(400)
    r = gmpy2.powmod(pub.h, r, pub.n)
    res = gmpy2.powmod(pub.g, plaintext, pub.n)

    res = res * r % pub.n

    return res

def dgk_decrypt(pub, prv, ciphertext):
    xi = []
    y = gmpy2.powmod(ciphertext, prv.vp, prv.p)
    res = mpz(0)
    for i in range(pub.lbits):
        yi = gmpy2.powmod(y, powtwo[pub.lbits - 1 - i], prv.p)
        if yi == 1:
            xi.append(0)
        else:
            xi.append(1)
            y = (y * gvpvqp[i]) % prv.p
    
    for i in range(pub.lbits):
        if xi[i] == 1:
            res += powtwo[i]
    
    return res

def add_dgk_ct(pub, x, y):
    return (x * y) % pub.n

def scalar_add_dgk(pub, x, k):
    return (x * gmpy2.powmod(pub.g,k,pub.n)) % pub.n

def scalar_mul_dgk(pub, x, k):
    return gmpy2.powmod(x,k,pub.n)

# pubkey, privatekey = dgk_keygen(1024, 32)
# a = dgk_encrypt_plain(pubkey, 74)
# b = dgk_encrypt_plain(pubkey, 56)
# c = dgk_decrypt(pubkey,privatekey,a*b*b*b*b%pubkey.n)
# d = dgk_decrypt(pubkey,privatekey,a ** 3)
# print('a:',a)
# print('b:',b)
# print('c:',c, 74+56+56+56+56)
# print('d:',d, 74*3)
# print(dgk_decrypt(pubkey,privatekey, scalar_add_dgk(pubkey,a,8)))
