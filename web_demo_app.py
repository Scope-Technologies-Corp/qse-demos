#!/usr/bin/env python3
"""
Web-based UI for QRNG Entropy Demos
Beautiful presentation interface for webinar demonstrations
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import base64
import json
import math
import os
import struct
import subprocess
import shutil
import time
import hashlib
import threading
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import sys
from pathlib import Path

# Import functions from existing demos
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
CORS(app)

# Import demo functions from existing files
sys.path.insert(0, os.path.dirname(__file__))

DEMO_VERSION = "DEMOv1"
DEFAULT_AAD = b"entropy-demo-aad-v1"


# ============================================================================
# Core Functions (from entropy_effectiveness_demo.py)
# ============================================================================

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def key_from_weak_seed_timestamp(seed_u64: int) -> bytes:
    seed_le = struct.pack("<Q", seed_u64)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"entropy-demo-weak-salt-v1",
        info=b"entropy-demo-weak-info-v1",
    )
    return hkdf.derive(seed_le)


def key_from_system_entropy() -> tuple[bytes, bytes]:
    seed_bytes = os.urandom(4)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"entropy-demo-system-salt-v1",
        info=b"entropy-demo-system-info-v1",
    )
    key = hkdf.derive(seed_bytes)
    return key, seed_bytes


def key_from_qrng_bytes(qrng_256: bytes) -> bytes:
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
        raw = raw[:256]
    return raw


def brute_force_timestamp_window(
    nonce: bytes,
    ct: bytes,
    aad: bytes,
    window_seconds: int,
    expected_prefix: bytes,
    progress_callback=None,
) -> Dict[str, Any]:
    now = int(time.time())
    start = now - window_seconds
    end = now + window_seconds
    space = (end - start) + 1

    t0 = time.time()
    guesses = 0
    last_progress = time.time()
    progress_interval = 0.1  # Update more frequently for better visualization

    # Track some example seeds being tried for visualization
    example_seeds_tried = []
    
    for seed in range(start, end + 1):
        guesses += 1
        
        # Collect example seeds for visualization (first 5, middle, last 5)
        if guesses <= 5 or (guesses == space // 2) or (guesses >= space - 5):
            example_seeds_tried.append({
                'seed': seed,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(seed)),
                'attempt': guesses
            })
        
        if progress_callback and time.time() - last_progress >= progress_interval:
            elapsed = time.time() - t0
            rate = guesses / max(elapsed, 1e-9)
            remaining = space - guesses
            eta = remaining / max(rate, 1e-9)
            current_seed_info = {
                'seed': seed,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(seed)),
                'human_readable': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(seed))
            }
            progress_callback({
                'guesses': guesses,
                'total': space,
                'rate': rate,
                'eta': eta,
                'progress': (guesses / space) * 100,
                'current_seed': current_seed_info,
                'example_seeds': example_seeds_tried[-10:] if len(example_seeds_tried) > 10 else example_seeds_tried
            })
            last_progress = time.time()
        
        key = key_from_weak_seed_timestamp(seed)
        try:
            pt = decrypt_aesgcm(key, nonce, ct, aad)
            if pt.startswith(expected_prefix):
                t1 = time.time()
                elapsed = max(t1 - t0, 1e-9)
                return {
                    'success': True,
                    'recovered_seed': seed,
                    'recovered_seed_timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(seed)),
                    'recovered_plaintext': pt.decode("utf-8", errors="replace"),
                    'guesses': guesses,
                    'elapsed_sec': elapsed,
                    'guesses_per_sec': guesses / elapsed,
                    'window_seconds': window_seconds,
                    'search_space_size': space,
                    'search_space_bits': math.log2(space),
                    'start_timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start)),
                    'end_timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end)),
                    'current_timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)),
                }
        except Exception:
            pass

    t1 = time.time()
    elapsed = max(t1 - t0, 1e-9)
    return {
        'success': False,
        'recovered_seed': None,
        'recovered_plaintext': None,
        'guesses': guesses,
        'elapsed_sec': elapsed,
        'guesses_per_sec': guesses / elapsed,
        'window_seconds': window_seconds,
        'search_space_size': space,
        'search_space_bits': math.log2(space),
        'start_timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start)),
        'end_timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end)),
        'current_timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)),
    }


def expected_time_for_bits(bits: float, guesses_per_sec: float) -> float:
    return (2.0 ** bits) / max(guesses_per_sec, 1e-12)


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
    if days < 365:
        return f"{days:.2f}d"
    years = days / 365
    return f"{years:.2e} years"


# ============================================================================
# RSA Demo Functions (from rsa_shared_prime_entropy_demo.py)
# ============================================================================

class XorShift64:
    def __init__(self, seed: int):
        self.state = seed & ((1 << 64) - 1)
        if self.state == 0:
            self.state = 0x9E3779B97F4A7C15

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


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    block = 64
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    key = key.ljust(block, b"\x00")
    o_key = bytes((b ^ 0x5C) for b in key)
    i_key = bytes((b ^ 0x36) for b in key)
    return hashlib.sha256(o_key + hashlib.sha256(i_key + msg).digest()).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac_sha256(salt, ikm)
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


_SMALL_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def is_probable_prime(n: int, rng: XorShift64, rounds: int = 10) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

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
    assert bits >= 64
    while True:
        candidate = rng.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rng):
            return candidate


def fp_u64(x: int) -> str:
    xb = x.to_bytes((x.bit_length() + 7) // 8, "big", signed=False)
    return hashlib.sha256(xb).hexdigest()[:16]


def make_key_weak(idx: int, bits: int, seed_space_bits: int, q_uniqueness: int) -> Dict[str, Any]:
    mask = (1 << seed_space_bits) - 1
    base = int(time.time()) & mask
    rng_p = XorShift64(seed=base ^ 0xA5A5A5A5A5A5A5A5)
    p = gen_prime(bits // 2, rng_p)
    mixed = (base + (idx * q_uniqueness)) & ((1 << 64) - 1)
    rng_q = XorShift64(seed=mixed ^ 0x5A5A5A5A5A5A5A5A)
    q = gen_prime(bits // 2, rng_q)
    if p == q:
        rng_q = XorShift64(seed=(mixed ^ 0xDEADBEEFDEADBEEF) & ((1 << 64) - 1))
        q = gen_prime(bits // 2, rng_q)
    return {'idx': idx, 'n': p * q, 'mode': 'WEAK', 'p_fingerprint': fp_u64(p), 'q_fingerprint': fp_u64(q)}


def make_key_qrng(idx: int, bits: int, qrng_256: bytes) -> Dict[str, Any]:
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
        rng_q = XorShift64((sq ^ 0xCAFEBABECAFEBABE) & ((1 << 64) - 1))
        q = gen_prime(bits // 2, rng_q)
    return {'idx': idx, 'n': p * q, 'mode': 'QRNG', 'p_fingerprint': fp_u64(p), 'q_fingerprint': fp_u64(q)}


def scan_shared_factors(keys: list, max_findings: int = 20) -> tuple:
    findings = []
    vulnerable = set()
    import itertools
    for a, b in itertools.combinations(range(len(keys)), 2):
        na = keys[a]['n']
        nb = keys[b]['n']
        g = math.gcd(na, nb)
        if 1 < g < min(na, nb):
            vulnerable.add(a)
            vulnerable.add(b)
            if len(findings) < max_findings:
                findings.append({'i': a, 'j': b, 'gcd_bits': g.bit_length()})
    return findings, vulnerable


# ============================================================================
# Flask Routes
# ============================================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/entropy-demo', methods=['POST'])
def entropy_demo():
    """Run entropy effectiveness demo"""
    data = request.json
    message = data.get('message', 'Entropy matters: weak seed space collapses security.')
    window = int(data.get('window', 120))
    qrng_b64 = data.get('qrng_b64', '').strip()
    use_system_entropy = data.get('use_system_entropy', False)
    
    if not qrng_b64:
        return jsonify({'error': 'QRNG base64 data required'}), 400
    
    try:
        qrng_256 = parse_qrng_b64(qrng_b64)
    except Exception as e:
        return jsonify({'error': f'Invalid QRNG data: {str(e)}'}), 400
    
    prefix = (DEMO_VERSION + "|").encode("utf-8")
    plaintext = prefix + message.encode("utf-8")
    aad = DEFAULT_AAD
    
    # Initialize progress_updates for both paths
    progress_updates = []
    
    # Weak/System entropy case
    weak_seed = None
    weak_seed_timestamp = None
    
    if use_system_entropy:
        system_key, system_seed_bytes = key_from_system_entropy()
        system_nonce, system_ct = encrypt_aesgcm(system_key, plaintext, aad)
        attack = {
            'success': False,
            'recovered_seed': None,
            'recovered_plaintext': None,
            'guesses': 0,
            'elapsed_sec': 0.0,
            'guesses_per_sec': 0.0,
            'window_seconds': 0,
            'search_space_size': 2**32,
            'search_space_bits': 32.0,
        }
        entropy_type = 'system'
    else:
        weak_seed = int(time.time())
        weak_seed_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(weak_seed))
        weak_key = key_from_weak_seed_timestamp(weak_seed)
        weak_nonce, weak_ct = encrypt_aesgcm(weak_key, plaintext, aad)
        system_nonce, system_ct = weak_nonce, weak_ct
        system_key = weak_key
        
        # Run brute force attack (progress_updates already initialized above)
        def progress_cb(update):
            progress_updates.append(update)
        
        attack = brute_force_timestamp_window(
            nonce=weak_nonce,
            ct=weak_ct,
            aad=aad,
            window_seconds=window,
            expected_prefix=prefix,
            progress_callback=progress_cb,
        )
        entropy_type = 'weak'
        
        # Add the actual seed used for comparison
        attack['actual_seed_used'] = weak_seed
        attack['actual_seed_timestamp'] = weak_seed_timestamp
    
    # QRNG case
    qrng_key = key_from_qrng_bytes(qrng_256)
    qrng_nonce, qrng_ct = encrypt_aesgcm(qrng_key, plaintext, aad)
    
    # Calculate work factors
    space_bits = attack['search_space_bits']
    weak_rate = attack['guesses_per_sec'] if attack['guesses_per_sec'] > 0 else 1_000_000_000
    
    qrng_raw_bits = 256 * 8
    conditioned_key_bits = 256.0
    qrng_expected_worst = expected_time_for_bits(conditioned_key_bits, weak_rate)
    
    if use_system_entropy:
        system_expected_worst = expected_time_for_bits(space_bits, weak_rate)
    else:
        weak_expected_worst = expected_time_for_bits(space_bits, weak_rate)
    
    result = {
        'entropy_type': entropy_type,
        'system_packet': {
            'scheme': 'SYSTEM(os.urandom-4B)' if use_system_entropy else 'WEAK(timestamp-seed)',
            'nonce_hex': system_nonce.hex(),
            'ciphertext_hex': system_ct.hex(),
            'aad_hex': aad.hex(),
            'seed_hint': weak_seed if not use_system_entropy else None,
            'seed_timestamp': weak_seed_timestamp if not use_system_entropy else None,
            'key_fingerprint': _sha256_hex(system_key if use_system_entropy else weak_key),
        },
        'qrng_packet': {
            'scheme': 'QRNG(256B base64)',
            'nonce_hex': qrng_nonce.hex(),
            'ciphertext_hex': qrng_ct.hex(),
            'aad_hex': aad.hex(),
            'key_fingerprint': _sha256_hex(qrng_key),
        },
        'attack_result': attack,
        'work_factors': {
            'weak': {
                'search_space_bits': space_bits,
                'expected_time_sec': weak_expected_worst if not use_system_entropy else system_expected_worst,
                'expected_time_human': human_time(weak_expected_worst if not use_system_entropy else system_expected_worst),
            },
            'qrng': {
                'raw_bits': qrng_raw_bits,
                'conditioned_bits': conditioned_key_bits,
                'expected_time_sec': qrng_expected_worst,
                'expected_time_human': human_time(qrng_expected_worst),
            },
        },
        'progress_updates': progress_updates,
    }
    
    return jsonify(result)


@app.route('/api/rsa-demo', methods=['POST'])
def rsa_demo():
    """Run RSA shared prime demo"""
    data = request.json
    count = int(data.get('count', 200))
    bits = int(data.get('bits', 512))
    seed_space_bits = int(data.get('seed_space_bits', 12))
    qrng_b64 = data.get('qrng_b64', '').strip()
    max_findings = int(data.get('max_findings', 10))
    
    if not qrng_b64:
        return jsonify({'error': 'QRNG base64 data required'}), 400
    
    try:
        qrng_256 = parse_qrng_b64(qrng_b64)
    except Exception as e:
        return jsonify({'error': f'Invalid QRNG data: {str(e)}'}), 400
    
    if bits < 256 or bits % 2 != 0:
        return jsonify({'error': 'bits should be even and >= 256'}), 400
    
    # Generate keys
    t0 = time.time()
    weak_keys = [make_key_weak(i, bits, seed_space_bits, q_uniqueness=31) for i in range(count)]
    t1 = time.time()
    qrng_keys = [make_key_qrng(i, bits, qrng_256) for i in range(count)]
    t2 = time.time()
    
    # Scan for shared factors
    s0 = time.time()
    weak_findings, weak_vuln = scan_shared_factors(weak_keys, max_findings=max_findings)
    s1 = time.time()
    
    s2 = time.time()
    qrng_findings, qrng_vuln = scan_shared_factors(qrng_keys, max_findings=max_findings)
    s3 = time.time()
    
    # Prime fingerprint collisions
    p_counts = {}
    for k in weak_keys:
        p_counts[k['p_fingerprint']] = p_counts.get(k['p_fingerprint'], 0) + 1
    top_p = sorted(p_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    
    result = {
        'weak_keys': {
            'count': count,
            'generation_time': t1 - t0,
            'vulnerable_count': len(weak_vuln),
            'findings': weak_findings,
            'scan_time': s1 - s0,
            'top_p_fingerprints': [{'fp': fp, 'count': c} for fp, c in top_p if c > 1],
        },
        'qrng_keys': {
            'count': count,
            'generation_time': t2 - t1,
            'vulnerable_count': len(qrng_vuln),
            'findings': qrng_findings,
            'scan_time': s3 - s2,
        },
        'parameters': {
            'bits': bits,
            'seed_space_bits': seed_space_bits,
        },
    }
    
    return jsonify(result)


@app.route('/api/qrng-simple', methods=['POST'])
def qrng_simple():
    """Simple QRNG key derivation demo"""
    data = request.json
    qrng_b64 = data.get('qrng_b64', '').strip()
    
    if not qrng_b64:
        return jsonify({'error': 'QRNG base64 data required'}), 400
    
    try:
        qrng = base64.b64decode(qrng_b64, validate=True)
        if len(qrng) < 256:
            return jsonify({'error': 'QRNG data too short'}), 400
    except Exception as e:
        return jsonify({'error': f'Invalid QRNG data: {str(e)}'}), 400
    
    # Derive key
    mix = b"qrng-demo-v1" + qrng[:256] + os.urandom(32)
    key = hashlib.sha256(mix).digest()
    
    # Encrypt
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    aad = b"demo-aad"
    pt = b"With high entropy, seed brute force is infeasible."
    ct = aesgcm.encrypt(nonce, pt, aad)
    
    result = {
        'nonce_hex': nonce.hex(),
        'ciphertext_hex': ct.hex(),
        'ciphertext_preview': ct.hex()[:80] + f"... (len={len(ct)})",
        'key_fingerprint': hashlib.sha256(key).hexdigest(),
        'message': 'With high entropy, seed brute force is infeasible.',
    }
    
    return jsonify(result)


# ============================================================================
# STS Demo Functions
# ============================================================================

# Import STS API module
try:
    sys.path.insert(0, str(Path(__file__).parent / "sts-2.1.2"))
    from sts_api import (
        generate_entropy_sequences,
        run_sts_for_source,
        parse_sts_report,
        compare_sts_results,
        generate_scorecard,
        load_scorecard,
        find_sts_results_base,
    )
    STS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: STS API not available: {e}", file=sys.stderr)
    STS_AVAILABLE = False


@app.route('/api/sts/scorecard', methods=['GET'])
def sts_scorecard():
    """Get existing STS scorecard results"""
    if not STS_AVAILABLE:
        return jsonify({'error': 'STS functionality not available'}), 503
    
    try:
        results_base = find_sts_results_base()
        scorecard_path = results_base / "scorecard.json"
        
        scorecard = load_scorecard(scorecard_path)
        if not scorecard:
            return jsonify({'error': 'No scorecard found. Run STS tests first.'}), 404
        
        return jsonify(scorecard)
    except Exception as e:
        return jsonify({'error': f'Failed to load scorecard: {str(e)}'}), 500


@app.route('/api/sts/available', methods=['GET'])
def sts_available():
    """Check if STS results are available"""
    if not STS_AVAILABLE:
        return jsonify({
            'available': False,
            'reason': 'STS functionality not available'
        })
    
    try:
        results_base = find_sts_results_base()
        scorecard_path = results_base / "scorecard.json"
        qse_report_path = results_base / "qse" / "finalAnalysisReport.txt"
        system_report_path = results_base / "system" / "finalAnalysisReport.txt"
        
        has_scorecard = scorecard_path.exists()
        has_qse = qse_report_path.exists()
        has_system = system_report_path.exists()
        
        return jsonify({
            'available': has_scorecard or (has_qse and has_system),
            'has_scorecard': has_scorecard,
            'has_qse_report': has_qse,
            'has_system_report': has_system,
        })
    except Exception as e:
        return jsonify({
            'available': False,
            'reason': str(e)
        })


@app.route('/api/sts/generate-entropy', methods=['POST'])
def sts_generate_entropy():
    """Generate entropy sequences for STS testing"""
    if not STS_AVAILABLE:
        return jsonify({'error': 'STS functionality not available'}), 503
    
    data = request.json
    source = data.get('source', 'system')  # 'qse' or 'system'
    sequences = int(data.get('sequences', 100))
    seq_length_bits = int(data.get('seq_length_bits', 1_000_000))
    endpoint = data.get('endpoint', os.environ.get('ENTROPY_ENDPOINT', ''))
    
    if source == 'qse' and not endpoint:
        return jsonify({'error': 'QSE endpoint required for QSE entropy generation'}), 400
    
    if sequences <= 0 or sequences > 1000:
        return jsonify({'error': 'sequences must be between 1 and 1000'}), 400
    
    if seq_length_bits <= 0 or seq_length_bits > 10_000_000:
        return jsonify({'error': 'seq_length_bits must be between 1 and 10,000,000'}), 400
    
    try:
        # Determine output directory
        sts_dir = Path(__file__).parent / "sts-2.1.2"
        out_dir = sts_dir / "entropy-streams"
        
        # Generate entropy sequences
        out_path, generated_files = generate_entropy_sequences(
            source=source,
            sequences=sequences,
            seq_length_bits=seq_length_bits,
            out_dir=out_dir,
            endpoint=endpoint if source == 'qse' else None,
        )
        
        return jsonify({
            'success': True,
            'source': source,
            'sequences': sequences,
            'seq_length_bits': seq_length_bits,
            'output_dir': str(out_path),
            'files_generated': len(generated_files),
        })
    except Exception as e:
        return jsonify({'error': f'Failed to generate entropy: {str(e)}'}), 500


@app.route('/api/sts/run-tests', methods=['POST'])
def sts_run_tests():
    """
    Run NIST STS pipeline using run_pipeline_auto.sh script.
    This runs the full end-to-end pipeline automatically:
    1. Generate QSE + System entropy
    2. Concatenate into single files
    3. Run ./assess for both (automated)
    4. Parse reports, compare, generate scorecard
    """
    data = request.json
    sequences = int(data.get('sequences', 100))
    seq_length_bits = int(data.get('seq_length_bits', 1_000_000))
    endpoint = data.get('endpoint', '').strip()
    
    if not endpoint:
        return jsonify({'error': 'QSE endpoint is required'}), 400
    
    sts_dir = Path(__file__).parent / "sts-2.1.2"
    script_path = sts_dir / "run_pipeline_auto.sh"
    
    if not script_path.exists():
        return jsonify({'error': f'Automated pipeline script not found: {script_path}'}), 500
    
    assess_binary = sts_dir / "assess"
    if not assess_binary.exists():
        return jsonify({
            'error': 'STS binary not found. Run "make" in sts-2.1.2 directory first.'
        }), 500
    
    # Prepare environment with the endpoint
    # Ensure it ends with /get for the API
    endpoint_for_env = endpoint.rstrip('/')
    if not endpoint_for_env.endswith('/get'):
        endpoint_for_env = endpoint_for_env + '/get'
    
    env = os.environ.copy()
    env['ENTROPY_ENDPOINT'] = endpoint_for_env
    # Force unbuffered output for Python scripts
    env['PYTHONUNBUFFERED'] = '1'
    
    # Build command - try to use stdbuf for line buffering (may not be available on macOS)
    # Fallback to regular bash if stdbuf fails
    output_lines = []
    
    try:
        app.logger.info(f"Running STS pipeline script: {script_path}")
        app.logger.info(f"ENTROPY_ENDPOINT={endpoint_for_env}")
        
        # Try with stdbuf first (for better real-time output)
        # If stdbuf is not available, fall back to regular execution
        try:
            # Check if stdbuf is available
            subprocess.run(['which', 'stdbuf'], check=True, capture_output=True)
            use_stdbuf = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            use_stdbuf = False
        
        if use_stdbuf:
            cmd = [
                'stdbuf', '-oL', '-eL',  # Line buffered stdout and stderr
                'bash',
                str(script_path),
                '--seq-length', str(seq_length_bits),
                '--sequences', str(sequences),
            ]
        else:
            cmd = [
                'bash',
                str(script_path),
                '--seq-length', str(seq_length_bits),
                '--sequences', str(sequences),
            ]
        
        app.logger.info(f"Command: {' '.join(cmd)}")
        
        # Run the script and capture output with line buffering
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(sts_dir),
            env=env,
            text=True,
            bufsize=1,  # Line buffered
        )
        
        # Read output line by line - capture ALL lines
        line_count = 0
        while True:
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                continue
            line = line.rstrip('\n\r')
            output_lines.append(line)
            line_count += 1
            app.logger.info(f"[STS] {line}")
            # Log every 100 lines to track progress
            if line_count % 100 == 0:
                app.logger.info(f"[STS] Captured {line_count} output lines so far...")
        
        # Ensure process is fully terminated
        return_code = process.wait()
        app.logger.info(f"[STS] Process completed. Total lines captured: {len(output_lines)}, Exit code: {return_code}")
        
        app.logger.info(f"Pipeline finished with exit code: {process.returncode}")
        
        # Check if scorecard was generated (success indicator)
        scorecard_path = sts_dir / "sts-results" / "scorecard.json"
        scorecard = None
        
        if scorecard_path.exists():
            with open(scorecard_path, 'r') as f:
                scorecard = json.load(f)
        
        # Return results
        app.logger.info(f"[STS] Returning {len(output_lines)} output lines to frontend")
        return jsonify({
            'success': scorecard is not None,
            'exit_code': process.returncode,
            'output': output_lines,
            'output_line_count': len(output_lines),  # Help frontend verify all output was received
            'scorecard': scorecard,
            'scorecard_path': str(scorecard_path) if scorecard else None,
        })
        
    except Exception as e:
        import traceback
        app.logger.error(f"Pipeline error: {e}")
        return jsonify({
            'error': f'Failed to run STS pipeline: {str(e)}',
            'output': output_lines,
            'traceback': traceback.format_exc() if app.debug else None
        }), 500


@app.route('/api/sts/status', methods=['GET'])
def sts_status():
    """Get status of STS operations (for future async implementation)"""
    # For now, STS runs synchronously, so this just returns available status
    if not STS_AVAILABLE:
        return jsonify({'status': 'unavailable'})
    
    return jsonify({
        'status': 'ready',
        'available': True,
    })


@app.route('/api/sts/report-html', methods=['GET'])
def sts_report_html():
    """Serve the generated HTML scorecard report"""
    sts_dir = Path(__file__).parent / "sts-2.1.2"
    report_path = sts_dir / "sts-results" / "scorecard.html"
    
    if not report_path.exists():
        return "<html><body><h1>Report Not Found</h1><p>No scorecard.html has been generated yet. Please run the STS pipeline first.</p></body></html>", 404
    
    # Read and serve the HTML file
    with open(report_path, 'r') as f:
        content = f.read()
    
    return content, 200, {'Content-Type': 'text/html'}


# ============================================================================
# Dieharder API Endpoints
# ============================================================================

@app.route('/api/dieharder/scorecard', methods=['GET'])
def dieharder_scorecard():
    """Get existing Dieharder scorecard results"""
    try:
        dieharder_dir = Path(__file__).parent / "dieharder"
        scorecard_path = dieharder_dir / "dieharder-results" / "scorecard.json"
        
        if not scorecard_path.exists():
            return jsonify({'error': 'No scorecard found. Run Dieharder tests first.'}), 404
        
        with open(scorecard_path, 'r') as f:
            scorecard = json.load(f)
        
        return jsonify(scorecard)
    except Exception as e:
        return jsonify({'error': f'Failed to load scorecard: {str(e)}'}), 500


@app.route('/api/dieharder/available', methods=['GET'])
def dieharder_available():
    """Check if Dieharder results are available"""
    try:
        dieharder_dir = Path(__file__).parent / "dieharder"
        scorecard_path = dieharder_dir / "dieharder-results" / "scorecard.json"
        qse_report_path = dieharder_dir / "dieharder-results" / "qse" / "report.json"
        system_report_path = dieharder_dir / "dieharder-results" / "system" / "report.json"
        
        has_scorecard = scorecard_path.exists()
        has_qse = qse_report_path.exists()
        has_system = system_report_path.exists()
        
        return jsonify({
            'available': has_scorecard or (has_qse and has_system),
            'has_scorecard': has_scorecard,
            'has_qse_report': has_qse,
            'has_system_report': has_system,
        })
    except Exception as e:
        return jsonify({
            'available': False,
            'reason': str(e)
        })


@app.route('/api/dieharder/run-tests', methods=['POST'])
def dieharder_run_tests():
    """
    Run Dieharder pipeline using run_pipeline_auto.sh script.
    This runs the full end-to-end pipeline automatically:
    1. Generate QSE + System entropy
    2. Concatenate into single files
    3. Run dieharder for both (automated)
    4. Parse reports, compare, generate scorecard
    """
    data = request.json
    sequences = int(data.get('sequences', 100))
    seq_length_bits = int(data.get('seq_length_bits', 1_000_000))
    endpoint = data.get('endpoint', '').strip()
    
    if not endpoint:
        return jsonify({'error': 'QSE endpoint is required'}), 400
    
    dieharder_dir = Path(__file__).parent / "dieharder"
    script_path = dieharder_dir / "run_pipeline_auto.sh"
    
    if not script_path.exists():
        return jsonify({'error': f'Automated pipeline script not found: {script_path}'}), 500
    
    # Check for dieharder binary
    dieharder_bin = Path(__file__).parent / "dieharder" / "dieharder" / "dieharder"
    if not dieharder_bin.exists():
        # Try system-wide dieharder
        if not shutil.which('dieharder'):
            return jsonify({
                'error': 'Dieharder binary not found. Build it in dieharder/dieharder/ or install system-wide.'
            }), 500
    
    # Prepare environment with the endpoint
    # Ensure it ends with /get for the API
    endpoint_for_env = endpoint.rstrip('/')
    if not endpoint_for_env.endswith('/get'):
        endpoint_for_env = endpoint_for_env + '/get'
    
    env = os.environ.copy()
    env['ENTROPY_ENDPOINT'] = endpoint_for_env
    # Force unbuffered output for Python scripts
    env['PYTHONUNBUFFERED'] = '1'
    
    # Build command - try to use stdbuf for line buffering (may not be available on macOS)
    # Fallback to regular bash if stdbuf fails
    output_lines = []
    
    try:
        app.logger.info(f"Running Dieharder pipeline script: {script_path}")
        app.logger.info(f"ENTROPY_ENDPOINT={endpoint_for_env}")
        
        # Try with stdbuf first (for better real-time output)
        # If stdbuf is not available, fall back to regular execution
        try:
            # Check if stdbuf is available
            subprocess.run(['which', 'stdbuf'], check=True, capture_output=True)
            use_stdbuf = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            use_stdbuf = False
        
        if use_stdbuf:
            cmd = [
                'stdbuf', '-oL', '-eL',  # Line buffered stdout and stderr
                'bash',
                str(script_path),
                '--seq-length', str(seq_length_bits),
                '--sequences', str(sequences),
            ]
        else:
            cmd = [
                'bash',
                str(script_path),
                '--seq-length', str(seq_length_bits),
                '--sequences', str(sequences),
            ]
        
        app.logger.info(f"Command: {' '.join(cmd)}")
        
        # Run the script and capture output with line buffering
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(dieharder_dir),
            env=env,
            text=True,
            bufsize=1,  # Line buffered
        )
        
        # Read output line by line - capture ALL lines
        line_count = 0
        while True:
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                continue
            line = line.rstrip('\n\r')
            output_lines.append(line)
            line_count += 1
            app.logger.info(f"[Dieharder] {line}")
            # Log every 100 lines to track progress
            if line_count % 100 == 0:
                app.logger.info(f"[Dieharder] Captured {line_count} output lines so far...")
        
        # Ensure process is fully terminated
        return_code = process.wait()
        app.logger.info(f"[Dieharder] Process completed. Total lines captured: {len(output_lines)}, Exit code: {return_code}")
        
        app.logger.info(f"Pipeline finished with exit code: {process.returncode}")
        
        # Check if scorecard was generated (success indicator)
        scorecard_path = dieharder_dir / "dieharder-results" / "scorecard.json"
        scorecard = None
        
        if scorecard_path.exists():
            with open(scorecard_path, 'r') as f:
                scorecard = json.load(f)
        
        # Return results
        app.logger.info(f"[Dieharder] Returning {len(output_lines)} output lines to frontend")
        return jsonify({
            'success': scorecard is not None,
            'exit_code': process.returncode,
            'output': output_lines,
            'output_line_count': len(output_lines),  # Help frontend verify all output was received
            'scorecard': scorecard,
            'scorecard_path': str(scorecard_path) if scorecard else None,
        })
        
    except Exception as e:
        import traceback
        app.logger.error(f"Pipeline error: {e}")
        return jsonify({
            'error': f'Failed to run Dieharder pipeline: {str(e)}',
            'output': output_lines,
            'traceback': traceback.format_exc() if app.debug else None
        }), 500


@app.route('/api/dieharder/report-html', methods=['GET'])
def dieharder_report_html():
    """Serve the generated HTML scorecard report"""
    dieharder_dir = Path(__file__).parent / "dieharder"
    report_path = dieharder_dir / "dieharder-results" / "scorecard.html"
    
    if not report_path.exists():
        return "<html><body><h1>Report Not Found</h1><p>No scorecard.html has been generated yet. Please run the Dieharder pipeline first.</p></body></html>", 404
    
    # Read and serve the HTML file
    with open(report_path, 'r') as f:
        content = f.read()
    
    return content, 200, {'Content-Type': 'text/html'}


if __name__ == '__main__':
    import socket
    
    # Try to find an available port (start with 5001 to avoid macOS AirPlay conflict)
    def find_free_port(start_port=5001):
        for port in range(start_port, start_port + 10):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('', port))
                    return port
            except OSError:
                continue
        return 5001  # Fallback
    
    port = find_free_port(5001)
    print(f"\n🚀 Starting QRNG Entropy Demos Web Application...")
    print(f"📡 Server running at: http://localhost:{port}")
    print(f"🌐 For remote access: http://0.0.0.0:{port}")
    print(f"\nPress Ctrl+C to stop the server\n")
    
    app.run(debug=True, host='0.0.0.0', port=port)
