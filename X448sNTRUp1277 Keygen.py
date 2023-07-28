# key encapsulation Python example
import oqs
from base64 import b64encode
import secrets
import time
import base64
import hashlib
import oqs.rand as rand

#Define Curve448
def FiniteField(p):
    class Fp:
        def __init__(self, val: int):
            assert isinstance(val, int)
            self.val = val
        def __add__(self, other):
            return Fp((self.val + other.val) % Fp.p)
        def __sub__(self, other):
            return Fp((self.val - other.val) % Fp.p)
        def __mul__(self, other):
            return Fp((self.val * other.val) % Fp.p)
        def __rmul__(self, n):
            return Fp((self.val * n) % Fp.p)
        def __pow__(self, e):
            return Fp(pow(self.val, e, Fp.p))
        def __repr__(self):
            return hex(self.val)
        def __int__(self):
            return int(self.val)
    Fp.p = p
    return Fp

# 5.  The X25519 and X448 Functions

def decodeLittleEndian(b, bits):
    return sum([ b[i] << 8*i for i in range((bits+7)//8) ])

def decodeUCoordinate(u, bits):
    u_list = [b for b in u]
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1 << (bits % 8)) - 1
    return decodeLittleEndian(u_list, bits)

def encodeUCoordinate(u, bits):
    return bytearray([ (u >> 8*i) & 0xff for i in range((bits+7)//8) ])

def decodeScalar25519(k):
    k_list = [b for b in k]
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decodeLittleEndian(k_list, 255)

def decodeScalar448(k):
    k_list = [b for b in k]
    k_list[0] &= 252
    k_list[55] |= 128
    return decodeLittleEndian(k_list, 448)

def cswap(swap, x_2, x_3):
    "Conditional swap in constant time."
    dummy = swap * (x_2 - x_3)
    x_2 = x_2 - dummy
    x_3 = x_3 + dummy
    return x_2, x_3

def mul(k: int, u: int, bits: int, p: int, a24: int):
    Fp = FiniteField(p)
    x_1 = Fp(u)
    x_2 = Fp(1)
    z_2 = Fp(0)
    x_3 = Fp(u)
    z_3 = Fp(1)
    swap = 0

    for t in range(bits-1, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        (x_2, x_3) = cswap(swap, x_2, x_3)
        (z_2, z_3) = cswap(swap, z_2, z_3)
        swap = k_t

        A = x_2 + z_2
        AA = A**2
        B = x_2 - z_2
        BB = B**2
        E = AA - BB
        C = x_3 + z_3
        D = x_3 - z_3
        DA = D * A
        CB = C * B
        x_3 = (DA + CB)**2
        z_3 = x_1 * (DA - CB)**2
        x_2 = AA * BB
        z_2 = E * (AA + a24 * E)

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    res = x_2 * (z_2**(p - 2))
    return res

def x448(k: bytes, u: bytes):
    # Curve448 for the ~224-bit security level.
    bits = 448
    k = decodeScalar448(k)
    u = decodeUCoordinate(u, bits)
    p = 2**448 - 2**224 - 1
    a24 = 39081
    res = mul(k, u, bits, p, a24)
    return encodeUCoordinate(int(res), bits)
base_point = encodeUCoordinate(5, bits=448)



print ("Input text entropy for key generation")
entropy = bytearray(input().encode())

# Key Generation Using NIST Level 5 algorithm Streamlined NTRU Prime 1277 and Curve448

kemalg1 = "sntrup1277"

seed1 = (hashlib.blake2b(bytearray(secrets.token_bytes(64))+entropy+bytearray(hex(int(time.time_ns())), 'utf-8')).digest())[:48]
rand.randombytes_nist_kat_init_256bit(seed1)
rand.randombytes_switch_algorithm("NIST-KAT")


seed2 = (bytearray(hashlib.blake2b(bytearray(secrets.token_bytes(64))+entropy+bytearray(hex(int(time.time_ns())), 'utf-8')).digest()))[:56]
client = oqs.KeyEncapsulation(kemalg1)
publickey1 =client.generate_keypair()
secretkey1 = client.export_secret_key()


secretkey2 = seed2
publickey2 = x448(secretkey2, base_point)

print ("Public key:", b64encode(publickey1+publickey2).decode())
print ()
print ("Secret Key:",  b64encode(secretkey1+secretkey2).decode())

input()
