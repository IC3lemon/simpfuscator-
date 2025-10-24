import random
from Crypto.Util.number import *
# put more shit here
xor_dec_func = """
void decrypt_xor(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] = data[i] ^ key;
    }
}"""

rsa_dec_func = """
long long pow_mod(long long base, long long exp, long long mod) {
    long long res = 1;
    base %= mod;
    while (exp > 0) {
        if (exp % 2 == 1) res = (res * base) % mod;
        base = (base * base) % mod;
        exp /= 2;
    }
    return res;
}

void decrypt_rsa(unsigned char *data, size_t len, long long d, long long n) {
    for (size_t i = 0; i < len; i++) {
        data[i] = (unsigned char)pow_mod((long long)data[i], d, n);
    }
}"""

def encrypt_xor(shellcode : bytes):
    key = [random.randint(0x1, 0xff), 0]
    enc = bytes(a ^ key[0] for a in shellcode)
    return enc, key

def encrypt_rsa(shellcode : bytes):
    while True:
        try:
            p, q = getPrime(4), getPrime(4)
            n = p*q
            assert 0 < n < 256
            e = getPrime(3)
            assert e != 2
            d = inverse(e, (p-1)*(q-1)) 
            break
        except Exception as e:
            continue
    key = (d, n)
        
    enc = bytes(pow(a, e, n) for a in shellcode)
    
    # (d, n)
    return enc, key