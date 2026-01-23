#!/usr/bin/env python3
"""
Demonstration (safe): weak/guessable seed collapses keyspace.
We derive an AES-GCM key from a low-entropy seed, encrypt, then brute-force the seed window.

This illustrates the same *entropy* point you'd make with RSA keygen,
without providing RSA key-recovery tooling.
"""
import itertools
import os
import string
import time
import struct
import hashlib
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.abspath(os.path.dirname(__file__)), '.env'))

def kdf_from_seed_u64(seed_u64: int) -> bytes:
    """
    Derive 256-bit key from a 64-bit integer seed (seed is the weak point).
    KDF: SHA-256("demo-v1" || seed_le)
    """
    seed_le = struct.pack("<Q", seed_u64)
    return hashlib.sha256(b"demo-v1" + seed_le).digest()  # 32 bytes


@dataclass
class Packet:
    seed_hint: int         # what the defender "thinks" seed is (for demo printing)
    nonce: bytes
    ciphertext: bytes


def encrypt_with_weak_seed(plaintext: bytes, with_time=True) -> Packet:
    # Intentionally weak seed: current UNIX time (seconds).
    # Attacker can guess it within a small window.

    seed = int(time.time())
    key = kdf_from_seed_u64(seed)
    if not with_time:
        key = os.getenv("SRNG_BASE64").encode()
    # key = os.getenv("QRNG_BASE64").encode()


    aesgcm = AESGCM(key)

    nonce = os.urandom(12)  # nonce can be public
    aad = b"demo-aad"        # associated data can also be public
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return Packet(seed_hint=seed, nonce=nonce, ciphertext=ciphertext)


def brute_force_seed(packet: Packet, window_seconds: int = 60, with_time=True) -> tuple[int|str, bytes, int] | None:
    """
    Attacker assumes the seed is a timestamp near 'now'.
    Try seeds in [now-window, now+window] and attempt AES-GCM decrypt.
    """

    aad = b"demo-aad"
    tries = 0
    if with_time:
        now = int(time.time())
        for guess in range(now - window_seconds, now + window_seconds + 1):
            tries += 1
            key = kdf_from_seed_u64(guess)
            aesgcm = AESGCM(key)
            try:
                pt = aesgcm.decrypt(packet.nonce, packet.ciphertext, aad)
                return guess, pt, tries
            except Exception:
                pass
    else:
        for tup in itertools.product(string.hexdigits, repeat=32):
            tries += 1
            candidate = ''.join(tup)
            if tries % 1000 == 0:
                print(candidate)
            aesgcm = AESGCM(candidate.encode())
            try:
                pt = aesgcm.decrypt(packet.nonce, packet.ciphertext, aad)
                return candidate, pt, tries
            except Exception:
                pass

    return None


def main():
    secret_message = b"TOP SECRET: entropy matters. Low seed space collapses security."
    time_demo = True
    pkt = encrypt_with_weak_seed(secret_message, with_time=time_demo)

    print("=== Defender output (what would be transmitted/stored) ===")
    print(f"(For demo) Actual weak seed (timestamp): {pkt.seed_hint}")
    print(f"Nonce (hex): {pkt.nonce.hex()}")
    print(f"Ciphertext+tag (hex): {pkt.ciphertext.hex()[:80]}... (len={len(pkt.ciphertext)})")
    print()

    print("=== Attacker brute force ===")
    t0 = time.time()
    result = brute_force_seed(pkt, window_seconds=120, with_time=time_demo)
    t1 = time.time()

    if result is None:
        print("Failed to recover (unexpected for this demo).")
        return

    guessed_seed, recovered, tries = result
    print(f"Recovered seed: {guessed_seed}")
    print(f"Recovered plaintext: {recovered!r}")
    print(f"Took {t1 - t0:.4f} seconds in a ±120s window.")


if __name__ == "__main__":
    main()
