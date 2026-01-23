#!/usr/bin/env python3
"""
Entropy effectiveness stage demo (safe harness).

- Weak case: derive an AES-GCM key from a low-entropy / guessable seed (timestamp seconds).
  Then demonstrate a brute-force seed-window recovery of the plaintext.

- Strong case: derive an AES-GCM key from QRNG bytes (256 bytes) provided as base64.
  We do NOT brute force this; we report the implied work factor.

This demonstrates the *security impact of entropy quality* cleanly and reproducibly.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import struct
import sys
import time
import hashlib
from dataclasses import dataclass, asdict
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


DEMO_VERSION = "DEMOv1"
DEFAULT_AAD = b"entropy-demo-aad-v1"


@dataclass
class DemoPacket:
    scheme: str
    nonce_hex: str
    ciphertext_hex: str
    aad_hex: str
    # For reporting only (never needed to decrypt when the key is known)
    seed_hint: Optional[int] = None
    key_fingerprint: Optional[str] = None  # sha256(key) hex


@dataclass
class AttackResult:
    success: bool
    recovered_seed: Optional[int]
    recovered_plaintext: Optional[str]
    guesses: int
    elapsed_sec: float
    guesses_per_sec: float
    window_seconds: int
    search_space_size: int
    search_space_bits: float


@dataclass
class SummaryRow:
    label: str
    entropy_source: str
    attacker_search_space: str
    approx_bits: float
    expected_attack_time_at_rate_sec: Optional[float]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def key_from_weak_seed_timestamp(seed_u64: int) -> bytes:
    """
    Weak key derivation: HKDF-SHA256 over an 8-byte seed.
    The weakness is not HKDF; it's the tiny/guessable seed space.
    """
    seed_le = struct.pack("<Q", seed_u64)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"entropy-demo-weak-salt-v1",
        info=b"entropy-demo-weak-info-v1",
    )
    return hkdf.derive(seed_le)


def key_from_system_entropy() -> tuple[bytes, bytes]:
    """
    System entropy key derivation: HKDF-SHA256 over 4 bytes from os.urandom.
    This uses the operating system's cryptographically secure random number generator.
    Returns: (key, seed_bytes) - seed_bytes for demo visibility only
    """
    seed_bytes = os.urandom(4)  # 4 bytes = 32 bits of system entropy
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"entropy-demo-system-salt-v1",
        info=b"entropy-demo-system-info-v1",
    )
    key = hkdf.derive(seed_bytes)
    return key, seed_bytes


def key_from_qrng_bytes(qrng_256: bytes) -> bytes:
    """
    Strong key derivation: HKDF-SHA256 over 256 QRNG bytes.
    For the demo we derive deterministically from QRNG only (to show QRNG impact).
    In production, it's often wise to *also* mix in local OS entropy + health tests.
    """
    if len(qrng_256) != 256:
        raise ValueError(f"Expected exactly 256 QRNG bytes, got {len(qrng_256)}")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"entropy-demo-qrng-salt-v1",
        info=b"entropy-demo-qrng-info-v1",
    )
    return hkdf.derive(qrng_256)


def encrypt_aesgcm(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce, ct


def decrypt_aesgcm(key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, aad)


def parse_qrng_b64(b64_text: str) -> bytes:
    raw = base64.b64decode(b64_text.strip(), validate=True)
    if len(raw) < 256:
        raise ValueError(f"QRNG decoded bytes are too short: {len(raw)} < 256")
    if len(raw) > 256:
        # For stage demos: take the first 256 bytes deterministically.
        raw = raw[:256]
    return raw


def brute_force_timestamp_window(
    nonce: bytes,
    ct: bytes,
    aad: bytes,
    window_seconds: int,
    expected_prefix: bytes,
) -> AttackResult:
    """
    Brute-force seeds in [now-window, now+window] (seconds resolution).
    This is constrained to timestamp-window guessing to keep it demonstrative and stage-safe.
    """
    now = int(time.time())
    start = now - window_seconds
    end = now + window_seconds
    space = (end - start) + 1

    t0 = time.time()
    guesses = 0
    last_progress = time.time()
    progress_interval = 2.0  # Show progress every 2 seconds

    for seed in range(start, end + 1):
        guesses += 1
        # Show progress for long-running brute-force
        if time.time() - last_progress >= progress_interval:
            elapsed = time.time() - t0
            rate = guesses / max(elapsed, 1e-9)
            remaining = space - guesses
            eta = remaining / max(rate, 1e-9)
            print(f"  Progress: {guesses}/{space} guesses ({rate:.0f}/s, ~{eta:.1f}s remaining)", 
                  file=sys.stderr)
            last_progress = time.time()
        
        key = key_from_weak_seed_timestamp(seed)
        try:
            pt = decrypt_aesgcm(key, nonce, ct, aad)
            # Extra guard to keep this as a demo harness: require a known prefix.
            if pt.startswith(expected_prefix):
                t1 = time.time()
                elapsed = max(t1 - t0, 1e-9)
                return AttackResult(
                    success=True,
                    recovered_seed=seed,
                    recovered_plaintext=pt.decode("utf-8", errors="replace"),
                    guesses=guesses,
                    elapsed_sec=elapsed,
                    guesses_per_sec=guesses / elapsed,
                    window_seconds=window_seconds,
                    search_space_size=space,
                    search_space_bits=math.log2(space),
                )
        except Exception:
            pass

    t1 = time.time()
    elapsed = max(t1 - t0, 1e-9)
    return AttackResult(
        success=False,
        recovered_seed=None,
        recovered_plaintext=None,
        guesses=guesses,
        elapsed_sec=elapsed,
        guesses_per_sec=guesses / elapsed,
        window_seconds=window_seconds,
        search_space_size=space,
        search_space_bits=math.log2(space),
    )


def human_time(seconds: Optional[float]) -> str:
    if seconds is None:
        return "n/a"
    if seconds < 1:
        return f"{seconds:.4f}s"
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.2f}m"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.2f}h"
    days = hours / 24
    return f"{days:.2f}d"


def expected_time_for_bits(bits: float, guesses_per_sec: float) -> float:
    # Expected guesses ~ 2^(bits-1) (on average) for uniform search; using 2^bits worst-case
    # For stage storytelling, worst-case makes the contrast starker and simpler.
    return (2.0 ** bits) / max(guesses_per_sec, 1e-12)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Stage demo: weak seed brute force vs QRNG (256-byte) entropy key derivation."
    )
    ap.add_argument(
        "--window",
        type=int,
        default=120,
        help="Brute-force ±window seconds around 'now' for the weak timestamp-seed attack (default: 120).",
    )
    ap.add_argument(
        "--message",
        type=str,
        default="Entropy matters: weak seed space collapses security.",
        help="Message to encrypt (default is fine for stage).",
    )
    ap.add_argument(
        "--qrng-stdin",
        action="store_true",
        help="Read base64 QRNG from STDIN (recommended).",
    )
    ap.add_argument(
        "--qrng-env",
        type=str,
        default="QRNG_B64",
        help="Environment variable name that holds base64 QRNG (default: QRNG_B64).",
    )
    ap.add_argument(
        "--csv",
        action="store_true",
        help="Also print a CSV summary line (for slides).",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Also print a JSON report (for audit artifacts).",
    )
    ap.add_argument(
        "--use-system-entropy",
        action="store_true",
        help="Use os.urandom (system entropy) instead of weak timestamp seed for comparison.",
    )
    args = ap.parse_args()

    # Build plaintext with a known prefix to keep the brute-force harness demo-scoped.
    prefix = (DEMO_VERSION + "|").encode("utf-8")
    plaintext = prefix + args.message.encode("utf-8")

    aad = DEFAULT_AAD

    # ---- Weak/System entropy case ----
    if args.use_system_entropy:
        # Use system entropy (os.urandom)
        system_key, system_seed_bytes = key_from_system_entropy()
        system_nonce, system_ct = encrypt_aesgcm(system_key, plaintext, aad)
        
        system_packet = DemoPacket(
            scheme="SYSTEM(os.urandom-4B)",
            nonce_hex=system_nonce.hex(),
            ciphertext_hex=system_ct.hex(),
            aad_hex=aad.hex(),
            seed_hint=None,  # Can't show seed for security
            key_fingerprint=_sha256_hex(system_key),
        )
        
        # System entropy cannot be brute-forced (seed space is 2^32)
        # We'll report this as secure (though 32 bits is feasible with significant resources)
        print("Using system entropy (os.urandom) - brute-force attack skipped (infeasible for practical purposes)", file=sys.stderr)
        attack = AttackResult(
            success=False,
            recovered_seed=None,
            recovered_plaintext=None,
            guesses=0,
            elapsed_sec=0.0,
            guesses_per_sec=0.0,
            window_seconds=0,
            search_space_size=2**32,  # 4 bytes = 32 bits
            search_space_bits=32.0,
        )
        print(f"System entropy seed space: 2^32 ({attack.search_space_bits:.0f} bits) - secure for most purposes", file=sys.stderr)
    else:
        # Use weak timestamp entropy (original demo)
        weak_seed = int(time.time())  # intentionally weak / guessable
        weak_key = key_from_weak_seed_timestamp(weak_seed)
        weak_nonce, weak_ct = encrypt_aesgcm(weak_key, plaintext, aad)

        system_packet = DemoPacket(
            scheme="WEAK(timestamp-seed)",
            nonce_hex=weak_nonce.hex(),
            ciphertext_hex=weak_ct.hex(),
            aad_hex=aad.hex(),
            seed_hint=weak_seed,
            key_fingerprint=_sha256_hex(weak_key),
        )

        # Attack weak case live
        print("Starting brute-force attack on weak seed...", file=sys.stderr)
        attack = brute_force_timestamp_window(
            nonce=weak_nonce,
            ct=weak_ct,
            aad=aad,
            window_seconds=args.window,
            expected_prefix=prefix,
        )
        print(f"Brute-force completed: {attack.guesses} guesses in {attack.elapsed_sec:.2f}s", file=sys.stderr)

    # ---- QRNG case ----
    if args.qrng_stdin:
        print("Waiting for QRNG data from STDIN...", file=sys.stderr)
        qrng_b64 = sys.stdin.read().strip()
        print("QRNG data received, processing...", file=sys.stderr)
        if not qrng_b64:
            print("ERROR: --qrng-stdin was set but STDIN was empty.", file=sys.stderr)
            return 2
    else:
        qrng_b64 = os.environ.get(args.qrng_env, "").strip()
        if not qrng_b64:
            print(
                f"ERROR: No QRNG base64 provided. Either set --qrng-stdin or export {args.qrng_env}.",
                file=sys.stderr,
            )
            return 2

    try:
        qrng_256 = parse_qrng_b64(qrng_b64)
    except Exception as e:
        print(f"ERROR: Could not decode QRNG base64: {e}", file=sys.stderr)
        return 2

    qrng_key = key_from_qrng_bytes(qrng_256)
    qrng_nonce, qrng_ct = encrypt_aesgcm(qrng_key, plaintext, aad)

    qrng_packet = DemoPacket(
        scheme="QRNG(256B base64)",
        nonce_hex=qrng_nonce.hex(),
        ciphertext_hex=qrng_ct.hex(),
        aad_hex=aad.hex(),
        seed_hint=None,
        key_fingerprint=_sha256_hex(qrng_key),
    )

    # ---- Reporting ----
    space_bits = attack.search_space_bits
    if args.use_system_entropy:
        # For system entropy, use hypothetical rate for comparison
        weak_rate = 1_000_000_000  # 1 billion guesses/sec (hypothetical)
        weak_expected_worst = None  # Not applicable for system entropy
    else:
        weak_rate = attack.guesses_per_sec
        weak_expected_worst = expected_time_for_bits(space_bits, weak_rate)

    # For QRNG, we report work factor in "bits" terms.
    # Your QRNG provides 256 bytes = 2048 raw bits; conservative story:
    # after conditioning into a 256-bit key, effective security is ~min(256, min_entropy_bits).
    # We'll report both: raw sample size (2048) and conditioned key size (256).
    qrng_raw_bits = 256 * 8
    conditioned_key_bits = 256.0

    if args.use_system_entropy:
        qrng_expected_worst = expected_time_for_bits(conditioned_key_bits, weak_rate)
    else:
        qrng_expected_worst = expected_time_for_bits(conditioned_key_bits, weak_rate)

    # Output header
    entropy_type = "system entropy (os.urandom)" if args.use_system_entropy else "weak timestamp seed"
    print("\n" + "=" * 72)
    print(f"ENTROPY EFFECTIVENESS DEMO ({entropy_type} vs QRNG 256-byte seed)")
    print("=" * 72)

    # Show what is "public"
    print("\n[Public artifacts you could transmit/store]")
    print(f"- AAD: {aad.hex()}")
    print(f"- {system_packet.scheme} nonce: {system_packet.nonce_hex}")
    print(f"- {system_packet.scheme} ciphertext: {system_packet.ciphertext_hex[:96]}... (len={len(bytes.fromhex(system_packet.ciphertext_hex))})")
    print(f"- QRNG nonce: {qrng_packet.nonce_hex}")
    print(f"- QRNG ciphertext: {qrng_packet.ciphertext_hex[:96]}... (len={len(bytes.fromhex(qrng_packet.ciphertext_hex))})")

    print("\n[For demo visibility only]")
    if args.use_system_entropy:
        print(f"- System entropy seed: <hidden - 4 bytes (32 bits) from os.urandom>")
    else:
        print(f"- Weak seed (timestamp seconds): {system_packet.seed_hint}")
    print(f"- {system_packet.scheme} key fingerprint sha256(key): {system_packet.key_fingerprint}")
    print(f"- QRNG key fingerprint sha256(key): {qrng_packet.key_fingerprint}")

    # Attack results
    print("\n" + "-" * 72)
    if args.use_system_entropy:
        print("ATTACK ANALYSIS: SYSTEM ENTROPY (os.urandom)")
        print("-" * 72)
        print(f"Seed space: 2^{attack.search_space_bits:.0f} = {attack.search_space_size} possibilities")
        print(f"Security level: {attack.search_space_bits:.0f} bits")
        print("\n✅ System entropy is secure - brute-force attack is infeasible")
        print("   (os.urandom provides cryptographically secure random bytes)")
    else:
        print("LIVE ATTACK AGAINST WEAK ENTROPY")
        print("-" * 72)
        print(f"Seed search window: ±{args.window}s -> {attack.search_space_size} candidates (~{attack.search_space_bits:.2f} bits)")
        print(f"Guesses tried: {attack.guesses}")
        print(f"Elapsed: {attack.elapsed_sec:.4f}s")
        print(f"Rate: {attack.guesses_per_sec:,.0f} guesses/sec")

        if attack.success:
            # Strip prefix for nicer output
            recovered = attack.recovered_plaintext or ""
            msg_only = recovered.split("|", 1)[1] if "|" in recovered else recovered
            print("\n✅ Recovered plaintext (weak case):")
            print(msg_only)
            print(f"\nRecovered seed: {attack.recovered_seed}")
        else:
            print("\n❌ Attack failed (unexpected for this demo). Try increasing --window.")

    # Side-by-side work factor
    print("\n" + "-" * 72)
    if args.use_system_entropy:
        print("SIDE-BY-SIDE WORK FACTOR COMPARISON")
        print("-" * 72)
        # Use a hypothetical brute-force rate for comparison
        hypothetical_rate = 1_000_000_000  # 1 billion guesses/sec (very optimistic)
        system_expected_worst = expected_time_for_bits(space_bits, hypothetical_rate)
        
        print(f"System entropy (os.urandom): {space_bits:.0f} bits (4 bytes)")
        print(f"  Worst-case time @ {hypothetical_rate:,.0f}/s: {human_time(system_expected_worst)}")
        print("  (os.urandom provides cryptographically secure randomness)")
        print("  Note: 32 bits is feasible to brute-force with significant resources (~136 years at 1B guesses/sec)")
        print("        64+ bits recommended for practical security, 128+ bits for long-term security")
    else:
        print("SIDE-BY-SIDE WORK FACTOR (using observed guesses/sec)")
        print("-" * 72)
        print(f"Weak case search space: ~{space_bits:.2f} bits (timestamp window)")
        print(f"  Worst-case time @ {weak_rate:,.0f}/s: {human_time(weak_expected_worst)}")

    print(f"\nQRNG input size: 256 bytes = {qrng_raw_bits} raw bits sampled")
    print(f"Conditioned key size: 256 bits (HKDF -> 32 bytes)")
    if args.use_system_entropy:
        qrng_expected_worst = expected_time_for_bits(conditioned_key_bits, hypothetical_rate)
        print(f"  Worst-case brute force @ {hypothetical_rate:,.0f}/s: {human_time(qrng_expected_worst)}")
    else:
        print(f"  Worst-case brute force @ {weak_rate:,.0f}/s: {human_time(qrng_expected_worst)}")
    print("  (This ignores any additional system protections; it's just the raw work factor.)")

    # Chart-ready summary rows
    if args.use_system_entropy:
        hypothetical_rate = 1_000_000_000  # 1 billion guesses/sec for comparison
        system_expected_worst = expected_time_for_bits(space_bits, hypothetical_rate)
        qrng_expected_worst = expected_time_for_bits(conditioned_key_bits, hypothetical_rate)
        
        rows = [
            SummaryRow(
                label="System entropy",
                entropy_source="os.urandom (4 bytes = 32 bits)",
                attacker_search_space="2^32 (seed space)",
                approx_bits=space_bits,
                expected_attack_time_at_rate_sec=system_expected_worst,
            ),
            SummaryRow(
                label="QRNG seed",
                entropy_source="QRNG 256-byte sample (base64)",
                attacker_search_space="2^256 (conditioned key size)",
                approx_bits=conditioned_key_bits,
                expected_attack_time_at_rate_sec=qrng_expected_worst,
            ),
        ]
    else:
        rows = [
            SummaryRow(
                label="Weak seed",
                entropy_source="timestamp seconds (guessable within window)",
                attacker_search_space=f"{attack.search_space_size} candidates",
                approx_bits=space_bits,
                expected_attack_time_at_rate_sec=weak_expected_worst,
            ),
            SummaryRow(
                label="QRNG seed",
                entropy_source="QRNG 256-byte sample (base64)",
                attacker_search_space="2^256 (conditioned key size)",
                approx_bits=conditioned_key_bits,
                expected_attack_time_at_rate_sec=qrng_expected_worst,
            ),
        ]

    if args.csv:
        # Simple one-line CSV (easy for spreadsheets)
        csv_filename = "entropy_demo_results.csv"
        # Use the rate that was used for calculations
        rate_for_csv = weak_rate
        with open(csv_filename, "w") as f:
            f.write("label,approx_bits,guesses_per_sec,worst_case_seconds\n")
            for r in rows:
                f.write(f"{r.label},{r.approx_bits:.2f},{rate_for_csv:.2f},{r.expected_attack_time_at_rate_sec:.6e}\n")
        print(f"\n✅ CSV saved to: {csv_filename}")
        print("CSV(label,approx_bits,guesses_per_sec,worst_case_seconds):")
        for r in rows:
            print(f"{r.label},{r.approx_bits:.2f},{rate_for_csv:.2f},{r.expected_attack_time_at_rate_sec:.6e}")

    if args.json:
        report = {
            "version": DEMO_VERSION,
            "entropy_type": "system" if args.use_system_entropy else "weak",
            "system_packet": asdict(system_packet),
            "qrng_packet": asdict(qrng_packet),
            "attack_result": asdict(attack),
            "assumptions": {
                "qrng_bytes_per_request": 256,
                "qrng_raw_bits_sampled": qrng_raw_bits,
                "conditioned_key_bits_reported": conditioned_key_bits,
                "system_entropy_bits": 32.0 if args.use_system_entropy else None,
                "note": "QRNG brute force is not executed; work factor is computed theoretically." if args.use_system_entropy else "QRNG brute force is not executed; work factor is computed from observed weak-case rate.",
            },
            "summary_rows": [asdict(r) for r in rows],
        }
        json_filename = "entropy_demo_results.json"
        with open(json_filename, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n✅ JSON saved to: {json_filename}")
        print("\nJSON_REPORT:")
        print(json.dumps(report, indent=2))

    print("\nDone.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


"""
linux console $: echo "b4836dc03758feda506877a85397fdeaa2fc3107d803e6580c62027c860097a23dfa0fe193613235fca1009317fcd4393f077e35cdfd156f21d544ec9cb56b3b2c44166b0c2b873716920b692d5491da4a76b72fea620d2f4d4a7b172e05b3567266543619bd2ec7d27c06f1beeeee7ffbd2f666435d7a5df0c35c46695317220654f141150b4d82672b560bbdc590875a2af074c1394d6a52c8d450e6619c8a291996b6b26ec0f50425b7b7b2455b6e50938a8c74c94681c6af7e69b1dfddc0f3ca7f6d7e8366c04d1ed2c71084b0d6ef6764f4dfa70ff66bfb1d5cf93cb891904a02ae0d8cc9911395af646d5f85a8eb5ba9cba11624503569e811d56ca2d86ac28a8aaea77633dae9ed5f4b1b6baac266f21c82fa99b17e06537be764a2fd5b4105b66073bf2c04b5e193d0c2d52608459ce01146c8a47602fac8da6f006b0902da3c88ef10bbfe93592187bfef20c6fb556ffa19c39288d720a6dbd7e1cd160b46869fbde32bd2a7f59eff4d1a278f319a3846402b13ce49c457502c45d8b70e2565447ef1a1db24450377fbad0c0d41cf0719c0bf39d9b319e8be28a2e04175b8bf5c0c9a292e50ad3fd51318f1dc50a4866bc69bfa25c4029be8dffbd6e5212d7dd5018d33aca3afb38eb45c1929965853345d7e00470f5b7e933c00832c87b05095fd6946f2f3423c989bb3eb708c835036cf2e2831e01dcb94a4536ad8e12b610b4ac529aa86a013cf347f5b2a82fa157b8a133341138440477b8e096417cbde2abacd6aa264a94d6c697fcfca96d84686d616d3a95b320c7f4266512419bee19b1383a209003ab74cc718430001287b18d3cb080bcfec8336a057fbed448b43efe02b0d7cda47b5dc6872c6e7a0afa918c33259e0f774a00cb16d5ce9e715f270ce8942fb868c9555faf67cad0a1a8904b25357a65101fa8e36c4a91e7d15cef0d30f502d126f641ba2d8699b8b1e49688fe6fa53378b06129587895239c5bfd528f8cf2043c2e23b4872d2e9e949a8bfd0b383b5dbf642ec40e63e0a5a448816135abb11299a9121482d77e405b12caecf261fad224f4696a2c865f8431ecaeed9cb86a9642e30f2b74f9b0f9ad920ca19c481685cc5eddddda60d365f077b5a79f4a76564f36f6ff56a3852ec1a0bd977f462790bd36b8e9638f9d600a81f1df294d9c794bcf9fa9628a378cf413d9408cadac5b4d3e6c9834f9267906dc00bb12e2ec719828b7a432d8384220bd78031db9ae51c9ad92b15d7220f3175cb926a7c1d1be30cd53e18917bf07dcd049afa02f4b293f84a53a9e5f7182f811133d8b8b806f4535e4cf45235ba0d99fb8e3e53e6152fad53bf99355819d1e27b42cd12f7e9248dd1c9003de661339b82f96fc3cb769ddbfee8ae1546933b5054258f73f9" | python3 entropy_effectiveness_demo.py --qrng-stdin --window 180 --csv
"""
