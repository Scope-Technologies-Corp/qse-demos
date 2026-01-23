#!/usr/bin/env python3
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.abspath(os.path.dirname(__file__)), '.env'))

def derive_key_from_qrng_b64(qrng_b64: str) -> bytes:
    """
    Condition QRNG bytes into a 256-bit key.
    We also mix in OS randomness as a safety belt (optional but good practice).
    """
    qrng = base64.b64decode(qrng_b64, validate=True)

    # Conditioning / key derivation: SHA-256("qrng-demo-v1" || qrng || os_urandom)
    # (For production, HKDF is also a great choice.)
    mix = b"qrng-demo-v1" + qrng + os.urandom(32)
    return hashlib.sha256(mix).digest()


def main():

    qrng_b64 = os.getenv("SRNG_BASE64")
    if not qrng_b64:
        raise SystemExit("Set QRNG_B64 to your base64 QRNG entropy first.")

    key = derive_key_from_qrng_b64(qrng_b64)
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)
    aad = b"demo-aad"
    pt = b"With high entropy, seed brute force is infeasible."
    ct = aesgcm.encrypt(nonce, pt, aad)

    print("Nonce (hex):", nonce.hex())
    print("Ciphertext+tag (hex):", ct.hex()[:80] + f"... (len={len(ct)})")
    print()
    print("Key fingerprint (sha256(key)):", hashlib.sha256(key).hexdigest())
    print()
    print("Why brute force fails:")
    print("- Weak demo used ~timestamp window (hundreds/thousands of guesses).")
    print("- QRNG seed material is typically 256+ bits of unpredictability.")
    print("  Even 128-bit min-entropy is already out of reach for brute force.")


if __name__ == "__main__":
    main()
