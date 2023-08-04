import oqs
from base64 import b64encode
from base64 import b64decode
import secrets
import hashlib

#First Define Finite Fields used in Curve448
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

#X448 Functions
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

#Define X448 key exchange
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

#Define hash with counter
def hashexpand(key, counter):
    hasher = hashlib.blake2b()
    hasher.update(key + counter.to_bytes(8, 'big'))
    return hasher.digest()

#Define using Blake2 as a stream cipher from hashing a key and counter, using the output as keystream
def blake2bencrypt(key, plaintext):
    ciphertext = bytearray()
    keystream = bytearray()
    counter = 0

    while len(keystream) < len(plaintext):
        keystream.extend(hashexpand(key, counter))
        counter += 1

    for i in range(len(plaintext)):
        ciphertext.append(plaintext[i] ^ keystream[i])

    return ciphertext

# Key Decapsulation Using NIST Level 5 algorithm Streamlined NTRU Prime 1277 and ECIES X448

kemalg = "sntrup1277"

print ("Input Your Secret Key:")

rawsecretkeys = input().encode()
secretkeysbytes = b64decode(rawsecretkeys)

secretkey1 = secretkeysbytes[:3059]
secretkey2 = secretkeysbytes[-56:]
print()

print ("Input Ciphertext:")

rawciphertext = input().encode()
rawbytes = b64decode(rawciphertext)

ciphertextbytes = rawbytes[0:1903]
ciphertext3 = rawbytes[1903:]



ciphertext1 = ciphertextbytes[:1847]
ciphertext2 = ciphertextbytes[-56:]

ntruprime = oqs.KeyEncapsulation(kemalg, secretkey1)

shared_secret1 = ntruprime.decap_secret(ciphertext1)


shared_secret2 = x448(secretkey2, ciphertext2)
sharedkeys = (shared_secret1+shared_secret2)
key1 = bytearray(hashlib.blake2b(sharedkeys).digest())

message = (blake2bencrypt(key1, ciphertext3))

print()
print ("Plaintext:", message.decode())
input()
