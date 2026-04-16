"""
RSA implementation from scratch (no third-party libraries).

Key generation:
  1. Generate two large primes p and q using Miller-Rabin test
  2. n = p * q
  3. φ(n) = (p-1) * (q-1)
  4. Choose e = 65537 (standard public exponent)
  5. Compute d = e⁻¹ mod φ(n) via extended Euclidean algorithm

Encryption: c = m^e mod n
Decryption: m = c^d mod n
"""

import random
import math


def miller_rabin(n: int, k: int = 10) -> bool:
    """Probabilistic primality test (Miller-Rabin, k rounds)."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x in (1, n - 1):
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Generate a random prime number of the given bit length."""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if miller_rabin(p):
            return p


def mod_inverse(e: int, phi: int) -> int:
    """
    Compute modular inverse: e⁻¹ mod phi
    Uses the extended Euclidean algorithm (iterative).
    """
    old_r, r = phi, e
    old_s, s = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    if old_r != 1:
        raise ValueError("Modular inverse does not exist (gcd != 1)")

    return old_s % phi


def generate_keypair(bits: int = 512) -> tuple[dict, dict]:
    """
    Generate RSA key pair.

    Returns:
        public_key  = {'e': e, 'n': n}
        private_key = {'d': d, 'n': n}
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)

    n   = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2

    d = mod_inverse(e, phi)

    return {'e': e, 'n': n}, {'d': d, 'n': n}


def encrypt(m: int, pub_key: dict) -> int:
    """RSA-encrypt integer m with public key. Returns ciphertext integer."""
    if not (0 <= m < pub_key['n']):
        raise ValueError("Message integer must be in range [0, n)")
    return pow(m, pub_key['e'], pub_key['n'])


def decrypt(c: int, priv_key: dict) -> int:
    """RSA-decrypt ciphertext integer c with private key. Returns plaintext integer."""
    return pow(c, priv_key['d'], priv_key['n'])
