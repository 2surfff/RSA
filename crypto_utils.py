"""
Utility functions for the secure chat:

  - Symmetric (XOR) cipher for message encryption/decryption
  - SHA-256 hashing (from standard library) for message integrity
  - Length-prefixed socket send/recv helpers
  - pack_secure / unpack_secure for the full (hash, encrypted_msg) protocol
"""

import hashlib
import json
import os

def generate_symmetric_key(length: int = 32) -> bytes:
    """Generate cryptographically random symmetric key of `length` bytes."""
    return os.urandom(length)


def xor_cipher(data: bytes, key: bytes) -> bytes:
    """
    XOR stream cipher with a repeating key.
    Symmetric: xor_cipher(xor_cipher(data, key), key) == data
    """
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def compute_hash(data: bytes) -> str:
    """Compute SHA-256 hash of data; return lowercase hex digest."""
    return hashlib.sha256(data).hexdigest()


def verify_hash(data: bytes, expected: str) -> bool:
    """Return True if SHA-256 of data matches expected hex digest."""
    return compute_hash(data) == expected


def send_data(sock, data: bytes) -> None:
    """Send bytes prefixed with a 4-byte big-endian length header."""
    sock.sendall(len(data).to_bytes(4, 'big') + data)


def _recv_exact(sock, n: int) -> bytes:
    """Read exactly n bytes from socket (handles partial reads)."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf


def recv_data(sock) -> bytes:
    """Receive a length-prefixed message; return the payload bytes."""
    length = int.from_bytes(_recv_exact(sock, 4), 'big')
    return _recv_exact(sock, length)

def pack_secure(plaintext: bytes, key: bytes) -> bytes:
    """
    Build a secure message payload:
      1. Compute SHA-256 hash of plaintext
      2. XOR-encrypt plaintext with symmetric key
      3. Serialise to JSON: {'hash': <hex>, 'data': <hex-encoded ciphertext>}

    Returns the JSON-encoded bytes (to be sent via send_data).
    """
    msg_hash  = compute_hash(plaintext)
    encrypted = xor_cipher(plaintext, key)
    return json.dumps({
        'hash': msg_hash,
        'data': encrypted.hex()
    }).encode()


def unpack_secure(payload: bytes, key: bytes) -> tuple[bytes, bool]:
    """
    Unpack and verify a secure message payload:
      1. Parse JSON to extract hash and ciphertext
      2. XOR-decrypt ciphertext with symmetric key
      3. Recompute SHA-256 hash of decrypted plaintext
      4. Compare with received hash

    Returns (plaintext: bytes, integrity_ok: bool)
    """
    parsed    = json.loads(payload.decode())
    received_hash = parsed['hash']
    encrypted     = bytes.fromhex(parsed['data'])

    plaintext    = xor_cipher(encrypted, key)
    integrity_ok = verify_hash(plaintext, received_hash)

    return plaintext, integrity_ok
