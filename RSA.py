import random
import math
from hashlib import sha3_256
import sys
sys.setrecursionlimit(1500)
import OAEP
def spawn_prime(size):

    while True:
        x = random.randrange(1 << (size-1), (1 << size) - 1)
        if is_prime(x):
            return x


def is_prime(n):
    k = 0
    m = n - 1

    while m % 2 == 0:
        k += 1
        m >>= 1

    for i in range(40):

        a = random.randrange(2, n - 1)
        x = pow(a, m, n)

        if x == 1 or x == n - 1:
            continue

        for i in range(k - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        return False

    return True


def spawn_e(oDn):
    while True:
        e = random.randrange(2, oDn)
        if math.gcd(oDn, e) == 1:
            break
    return e


def spawn_d(e, oDn):
    return modularInversion(e, oDn)[1] % oDn



def modularInversion(e, oDn):
    if e == 0:
        return (oDn, 0, 1)
    else:
        a, b, c = modularInversion(oDn % e, e)
        return (a, c - (oDn // e) * b, b) # back substitution


def spawn_keys():

    p = spawn_prime(1024)
    q = spawn_prime(1024)
    n = p * q
    oDn = (p - 1) * (q - 1)

    e = spawn_e(oDn)
    d = spawn_d(e, oDn)

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


def rsa(key, msg):
    n, exp = key
    k = (n.bit_length() + 7) // 8
    m = int.from_bytes(msg, "big")
    c = pow(m, exp, n)

    return c.to_bytes(k, "big")


def cypher(chave, msg):
    ciphered_text = OAEP.cypher_oaep(chave[0], msg)

    return rsa(chave, ciphered_text)


def decypher(key, ciphered_text):
    msg = rsa(key, ciphered_text)

    return OAEP.decypher_oaep(key[0], msg)


def sign(private_key, data):
    hash = sha3_256(data).digest()

    return rsa(private_key, hash)


def signature_check(public_key, data,signature):
    hash = sha3_256(data).digest()
    signature_ok = rsa(public_key, signature)[-32:] == hash

    return signature_ok