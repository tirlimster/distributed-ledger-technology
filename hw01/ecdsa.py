import secrets
import hashlib

# Domain parameters for secp256k1
p = 2**256 - 2**32 - 977  # prime modulus of the field
a = 0  # curve coefficient a
b = 7  # curve coefficient b

# Generator (base point) for secp256k1
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

# Order of the base point
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def modinv(a: int, m: int) -> int:
    """Compute the modular inverse of a modulo m using the Extended Euclidean Algorithm."""
    if a == 0:
        raise ZeroDivisionError("Inverse of 0 does not exist")
    old_r, r = a % m, m
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise Exception("No modular inverse exists")
    return old_s % m


def mod_exp(base: int, exp: int, m: int) -> int:
    """Efficient modular exponentiation using binary exponentiation."""
    result = 1
    base %= m
    while exp > 0:
        if exp & 1:
            result = (result * base) % m
        base = (base * base) % m
        exp //= 2
    return result


def point_add(P: tuple | None, Q: tuple | None) -> tuple | None:
    """Add two points P and Q on the elliptic curve.
    The point at infinity is represented as None.
    """
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    # If points are inverses of each other, return identity (None)
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P != Q:
        lam = ((y2 - y1) % p) * modinv((x2 - x1) % p, p) % p
    else:
        lam = (3 * x1 * x1 + a) % p * modinv((2 * y1) % p, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return x3, y3


def scalar_mul(k: int, P: tuple) -> tuple | None:
    """Multiply point P by scalar k using the double-and-add algorithm."""
    result = None  # The identity element
    addend = P
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k //= 2
    return result


def generate_key_pair():
    """Generate an ECDSA key pair (private key, public key)."""
    priv_key = secrets.randbelow(n - 1) + 1  # Random integer in [1, n-1]
    pub_key = scalar_mul(priv_key, G)
    return priv_key, pub_key


def hash_message(msg: bytes) -> int:
    """Hash a message using SHA-256 and convert it to an integer modulo n."""
    if isinstance(msg, str):
        msg = msg.encode("utf-8")
    h_bytes = hashlib.sha256(msg).digest()
    return int.from_bytes(h_bytes, byteorder="big") % n


def sign_message(message: bytes, private_key: int) -> tuple:
    """Generate an ECDSA signature (r, s) for the given message using the private key."""
    h = hash_message(message)
    while True:
        # Choose random ephemeral key k in [1, n-1]
        k = secrets.randbelow(n - 1) + 1
        R = scalar_mul(k, G)
        if R is None:
            continue
        x1, y1 = R
        r = x1 % n
        if r == 0:
            continue
        try:
            k_inv = modinv(k, n)
        except Exception:
            continue
        s = (k_inv * (h + r * private_key)) % n
        if s == 0:
            continue
        return (r, s)


def verify_signature(message: bytes, public_key: tuple, signature: tuple) -> bool:
    """Verify the ECDSA signature (r, s) for the given message and public key."""
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False
    h = hash_message(message)
    try:
        w = modinv(s, n)
    except Exception:
        return False
    u1 = (h * w) % n
    u2 = (r * w) % n
    X = point_add(scalar_mul(u1, G), scalar_mul(u2, public_key))
    if X is None:
        return False
    x_coord, _ = X
    return (x_coord % n) == r

