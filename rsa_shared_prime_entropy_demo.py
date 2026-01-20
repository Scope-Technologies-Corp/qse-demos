#!/usr/bin/env python3
"""
RSA entropy demo (safe / audit-style):

1) Generate many RSA public moduli (n = p*q) in two modes:
   - WEAK: p comes from a low-entropy seed space -> p repeats across many keys
   - QRNG: p and q come from 256-byte QRNG-derived per-key material -> repetition disappears

2) Scan the public moduli for shared factors using gcd(n_i, n_j).
   If gcd > 1 and < min(n_i, n_j), both keys are compromised (they share a prime factor).

This script does NOT compute full private keys (no 'd' derivation, no decryption/signing),
and is intended as a demo / audit harness to show the impact of entropy quality.

Requirements: Python 3.10+ (no external packages).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import itertools
import math
import os
import struct
import sys
import time
from dataclasses import dataclass
from typing import Optional


# ------------------------
# RNG helpers
# ------------------------

class XorShift64:
    """Small deterministic RNG for demo purposes (NOT cryptographically secure)."""
    def __init__(self, seed: int):
        self.state = seed & ((1 << 64) - 1)
        if self.state == 0:
            self.state = 0x9E3779B97F4A7C15  # avoid zero lockup

    def next_u64(self) -> int:
        x = self.state
        x ^= (x << 13) & ((1 << 64) - 1)
        x ^= (x >> 7) & ((1 << 64) - 1)
        x ^= (x << 17) & ((1 << 64) - 1)
        self.state = x & ((1 << 64) - 1)
        return self.state

    def randbits(self, k: int) -> int:
        out = 0
        bits = 0
        while bits < k:
            out = (out << 64) | self.next_u64()
            bits += 64
        return out >> (bits - k)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Minimal HKDF-Extract+Expand (SHA-256)."""
    prk = hmac_sha256(salt, ikm)
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """Minimal HMAC-SHA256."""
    block = 64
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    key = key.ljust(block, b"\x00")
    o_key = bytes((b ^ 0x5C) for b in key)
    i_key = bytes((b ^ 0x36) for b in key)
    return hashlib.sha256(o_key + hashlib.sha256(i_key + msg).digest()).digest()


# ------------------------
# Prime generation (Miller-Rabin)
# ------------------------

_SMALL_PRIMES = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113
]

def is_probable_prime(n: int, rng: XorShift64, rounds: int = 10) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # write n-1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Miller-Rabin rounds
    for _ in range(rounds):
        a = 2 + (rng.next_u64() % (n - 3))
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int, rng: XorShift64) -> int:
    """Generate a probable prime of 'bits' length."""
    assert bits >= 64
    while True:
        # force top bit and odd
        candidate = rng.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rng):
            return candidate


# ------------------------
# RSA public material (demo only)
# ------------------------

@dataclass
class PublicKeyDemo:
    idx: int
    n: int
    mode: str
    # For reporting only (does not enable private key construction)
    p_fingerprint: str
    q_fingerprint: str


def fp_u64(x: int) -> str:
    """Short fingerprint for reporting (hash of integer bytes)."""
    xb = x.to_bytes((x.bit_length() + 7) // 8, "big", signed=False)
    return hashlib.sha256(xb).hexdigest()[:16]


def make_key_weak(idx: int, bits: int, seed_space_bits: int, q_uniqueness: int) -> PublicKeyDemo:
    """
    Weak entropy model:
      - p seeded ONLY from a tiny seed space (e.g., 12-16 bits) -> p repeats often
      - q seeded with (same weak seed + idx) so q varies -> different n share prime p
    """
    mask = (1 << seed_space_bits) - 1

    # "Device seed" (tiny space) – e.g. timestamp seconds truncated
    base = int(time.time()) & mask

    # p repeats across many keys because it depends only on tiny seed space
    rng_p = XorShift64(seed=base ^ 0xA5A5A5A5A5A5A5A5)
    p = gen_prime(bits // 2, rng_p)

    # q varies per key so we get many different n that share the same p
    # (still fundamentally weak because seed is tiny + predictable)
    mixed = (base + (idx * q_uniqueness)) & ((1 << 64) - 1)
    rng_q = XorShift64(seed=mixed ^ 0x5A5A5A5A5A5A5A5A)
    q = gen_prime(bits // 2, rng_q)

    if p == q:
        # extremely unlikely; regenerate q with a different tweak
        rng_q = XorShift64(seed=(mixed ^ 0xDEADBEEFDEADBEEF) & ((1 << 64) - 1))
        q = gen_prime(bits // 2, rng_q)

    return PublicKeyDemo(idx=idx, n=p * q, mode="WEAK", p_fingerprint=fp_u64(p), q_fingerprint=fp_u64(q))


def make_key_qrng(idx: int, bits: int, qrng_256: bytes) -> PublicKeyDemo:
    """
    Strong entropy model:
      - Derive per-key seeds from the 256-byte QRNG sample via HKDF with idx as 'info'
      - Generate p and q from independent derived seeds
    """
    info_p = b"rsa-demo-p|" + struct.pack(">I", idx)
    info_q = b"rsa-demo-q|" + struct.pack(">I", idx)

    seed_p = hkdf_sha256(ikm=qrng_256, salt=b"rsa-demo-salt-v1", info=info_p, length=8)
    seed_q = hkdf_sha256(ikm=qrng_256, salt=b"rsa-demo-salt-v1", info=info_q, length=8)

    sp = int.from_bytes(seed_p, "big")
    sq = int.from_bytes(seed_q, "big")

    rng_p = XorShift64(sp ^ 0x1234567890ABCDEF)
    rng_q = XorShift64(sq ^ 0x0FEDCBA098765432)

    p = gen_prime(bits // 2, rng_p)
    q = gen_prime(bits // 2, rng_q)
    if p == q:
        # again unlikely; tweak q deterministically
        rng_q = XorShift64((sq ^ 0xCAFEBABECAFEBABE) & ((1 << 64) - 1))
        q = gen_prime(bits // 2, rng_q)

    return PublicKeyDemo(idx=idx, n=p * q, mode="QRNG", p_fingerprint=fp_u64(p), q_fingerprint=fp_u64(q))


def parse_qrng_b64(b64_text: str) -> bytes:
    raw = base64.b64decode(b64_text.strip(), validate=True)
    if len(raw) < 256:
        raise ValueError(f"QRNG decoded bytes are too short: {len(raw)} < 256")
    return raw[:256]


# ------------------------
# Shared-factor scan (audit)
# ------------------------

@dataclass
class SharedFactorFinding:
    i: int
    j: int
    gcd_bits: int


def scan_shared_factors(keys: list[PublicKeyDemo], max_findings: int = 20) -> tuple[list[SharedFactorFinding], set[int]]:
    """
    O(n^2) gcd scan, adequate for stage sizes (e.g., 100–500 keys).
    Returns:
      - list of example findings
      - set of indices in 'keys' list that are vulnerable
    """
    findings: list[SharedFactorFinding] = []
    vulnerable: set[int] = set()

    for a, b in itertools.combinations(range(len(keys)), 2):
        na = keys[a].n
        nb = keys[b].n
        g = math.gcd(na, nb)
        if 1 < g < min(na, nb):
            vulnerable.add(a)
            vulnerable.add(b)
            if len(findings) < max_findings:
                findings.append(SharedFactorFinding(i=a, j=b, gcd_bits=g.bit_length()))
    return findings, vulnerable


def main() -> int:
    ap = argparse.ArgumentParser(description="RSA shared-prime entropy demo (audit-style).")
    ap.add_argument("--count", type=int, default=200, help="How many keys per mode to generate (default: 200).")
    ap.add_argument("--bits", type=int, default=512, help="RSA modulus size for demo (default: 512; NOT secure).")
    ap.add_argument("--seed-space-bits", type=int, default=12, help="Weak seed space bits (default: 12).")
    ap.add_argument("--qrng-stdin", action="store_true", help="Read QRNG base64 from stdin.")
    ap.add_argument("--qrng-env", type=str, default="QRNG_B64", help="Env var holding QRNG base64 (default: QRNG_B64).")
    ap.add_argument("--max-findings", type=int, default=10, help="Max example findings to print (default: 10).")
    args = ap.parse_args()

    if args.bits < 256 or args.bits % 2 != 0:
        print("ERROR: --bits should be even and >= 256 for the demo.", file=sys.stderr)
        return 2

    # Read QRNG
    if args.qrng_stdin:
        qrng_b64 = sys.stdin.read().strip()
        if not qrng_b64:
            print("ERROR: --qrng-stdin set but stdin empty.", file=sys.stderr)
            return 2
    else:
        qrng_b64 = os.environ.get(args.qrng_env, "").strip()
        if not qrng_b64:
            print(f"ERROR: Provide QRNG base64 via --qrng-stdin or export {args.qrng_env}.", file=sys.stderr)
            return 2

    try:
        qrng_256 = parse_qrng_b64(qrng_b64)
    except Exception as e:
        print(f"ERROR: Bad QRNG base64: {e}", file=sys.stderr)
        return 2

    print("\n" + "=" * 78)
    print("RSA SHARED-PRIME DEMO (WEAK entropy vs QRNG entropy)")
    print("=" * 78)
    print(f"Keys per mode: {args.count}")
    print(f"Demo RSA modulus size: {args.bits} bits (DEMO ONLY; not a secure size)")
    print(f"Weak seed space: 2^{args.seed_space_bits} possibilities (tiny/guessable)")
    print("QRNG input: 256 bytes (2048 raw bits) per request\n")

    # Generate keys
    t0 = time.time()
    weak_keys = [make_key_weak(i, args.bits, args.seed_space_bits, q_uniqueness=31) for i in range(args.count)]
    t1 = time.time()
    qrng_keys = [make_key_qrng(i, args.bits, qrng_256) for i in range(args.count)]
    t2 = time.time()

    print(f"Generated WEAK keys in  {t1 - t0:.2f}s")
    print(f"Generated QRNG keys in  {t2 - t1:.2f}s\n")

    # Scan for shared factors
    print("-" * 78)
    print("Scanning WEAK keys for shared factors (gcd(n_i, n_j) > 1)")
    print("-" * 78)
    s0 = time.time()
    weak_findings, weak_vuln = scan_shared_factors(weak_keys, max_findings=args.max_findings)
    s1 = time.time()

    print(f"Scan time: {s1 - s0:.2f}s")
    print(f"Vulnerable keys: {len(weak_vuln)} / {len(weak_keys)}")

    if weak_findings:
        print("\nExample shared-factor pairs (showing gcd size only):")
        for f in weak_findings:
            print(f"  key[{f.i}] <-> key[{f.j}] : gcd ~ {f.gcd_bits} bits")
    else:
        print("\nNo shared factors found (try increasing --count or reducing --seed-space-bits).")

    # Extra: show prime fingerprint collisions (public-ish demo metric)
    p_counts = {}
    for k in weak_keys:
        p_counts[k.p_fingerprint] = p_counts.get(k.p_fingerprint, 0) + 1
    top_p = sorted(p_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    print("\nTop repeated p fingerprints in WEAK mode (fingerprints only):")
    for fp, c in top_p:
        if c > 1:
            print(f"  p_fp={fp} repeated {c} times")

    print("\n" + "-" * 78)
    print("Scanning QRNG keys for shared factors (gcd(n_i, n_j) > 1)")
    print("-" * 78)
    s2 = time.time()
    qrng_findings, qrng_vuln = scan_shared_factors(qrng_keys, max_findings=args.max_findings)
    s3 = time.time()

    print(f"Scan time: {s3 - s2:.2f}s")
    print(f"Vulnerable keys: {len(qrng_vuln)} / {len(qrng_keys)}")
    if qrng_findings:
        print("\nUnexpected findings in QRNG mode (should be ~0 in this demo):")
        for f in qrng_findings:
            print(f"  key[{f.i}] <-> key[{f.j}] : gcd ~ {f.gcd_bits} bits")
    else:
        print("\nNo shared factors found in QRNG mode ✅")

    # Summary narrative
    print("\n" + "=" * 78)
    print("STAGE TAKEAWAY")
    print("=" * 78)
    print(
        "If two RSA public moduli share a prime factor, BOTH keys are mathematically compromised.\n"
        "Weak entropy makes prime reuse likely (especially across devices/VMs started similarly).\n"
        "Feeding high-quality entropy (your QRNG 256-byte sample) eliminates that class of failure.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
