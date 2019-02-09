import gmpy2
from gmpy2 import mpz
import time

global_random_state = None

def ceil_divide(x, y):
    return ((((x) + (y) - 1) / (y)))


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
