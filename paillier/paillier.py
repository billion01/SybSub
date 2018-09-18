import math
import primes
import random
def invmod(a, p, maxiter=1000000):
    """The multiplicitive inverse of a in the integers modulo p:
         a * b == 1 mod p
       Returns b.
       (http://code.activestate.com/recipes/576737-inverse-modulo-p/)"""
    if a == 0:
        raise ValueError('0 has no inverse mod %d' % p)
    r = a
    d = 1
    for i in xrange(min(p, maxiter)):
        d = ((p // r + 1) * d) % p
        r = (d * a) % p
        if r == 1:
            break
    else:
        raise ValueError('%d has no inverse mod %d' % (a, p))
    return d

def modpow(base, exponent, modulus):
    """Modular exponent:
         c = b ^ e mod m
       Returns c.
       (http://www.programmish.com/?p=34)"""
    result = 1
    while exponent > 0:
        if exponent & 1 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

class PrivateKey(object):

    def __init__(self, p, q,s,w,r_m):
        self.l = (p-1) * (q-1)
        self.s=s
        self.w=w
        self.r_m=r_m

    def __repr__(self):
        return '<PrivateKey: %s %s %s %s>' % (self.l, self.s, self.w, self.r_m)

class PublicKey(object):

    @classmethod
    def from_n(cls, n):
        return cls(n)

    def __init__(self, n,p,q):
        self.n = n
        self.m=invmod((p-1) * (q-1), n)
        self.n_sq = n * n
        self.g = n + 1


    def __repr__(self):
        return '<PublicKey: %s %s %s %s>' % (self.n, self.m, self.n,self.g)

def generate_keypair(bits,l):
    p = primes.generate_prime(bits / 2)
    q = primes.generate_prime(bits / 2)
    n = p * q
    s=math.floor(math.log(n,2))
    w=random.randint(l+1,s-2)
    r_m=random.randint(2,math.pow(2,w-l)-1)
    return PrivateKey(p, q, s,w,r_m), PublicKey(n,p,q)


def encrypt(pub,priv, plain):
    while True:
        r = primes.generate_prime(long(round(math.log(pub.n, 2))))
        if r > 0 and r < pub.n:
            break
    x = pow(r, priv.l*pub.n, pub.n_sq)
    cipher = (pow(pub.g, priv.l*plain, pub.n_sq) * x) % pub.n_sq
    return cipher

def e_add(pub, a, b):
    """Add one encrypted integer to another"""
    return a * b % pub.n_sq

def e_add_const(pub, a, n):
    """Add constant n to an encrypted integer"""
    return a * modpow(pub.g, n, pub.n_sq) % pub.n_sq

def e_mul_const(pub, a, n):
    """Multiplies an ancrypted integer by a constant"""
    return modpow(a, n, pub.n_sq)

def decrypt(pub, cipher):
   # x = pow(cipher, priv.l, pub.n_sq) - 1
    x=cipher % pub.n_sq-1
    plain = ((x // pub.n) * pub.m) % pub.n
    return plain

