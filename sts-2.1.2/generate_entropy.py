#!/usr/bin/env python3
"""
Generate NIST-ready entropy sequences (.bin) using bulk entropy endpoint or local generator.

Improvements:
- requests.Session keep-alive + pooling
- retries + exponential backoff
- separate connect/read timeouts
- MUCH faster hex->bytes conversion (no giant bitstrings)
- ALWAYS cleans old seq_*.bin files before generating (fresh runs only)
"""

import argparse
import glob
import os
import secrets
import sys
import time
from typing import Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ENTROPY_ENDPOINT_ENV = "ENTROPY_ENDPOINT"


# ----------------------------
# Helpers
# ----------------------------

def bytes_to_size_path(byte_count: int) -> str:
    if byte_count % 1000 == 0:
        return f"{byte_count // 1000}k"
    return f"{byte_count}b"


def trim_to_bits(data: bytes, bit_length: int) -> bytes:
    """Trim (or mask) bytes to exactly bit_length bits."""
    if bit_length <= 0:
        return b""
    full_bytes = bit_length // 8
    rem_bits = bit_length % 8

    if rem_bits == 0:
        return data[:full_bytes]

    # Need one extra byte to keep remaining bits
    out = bytearray(data[: full_bytes + 1])
    mask = 0xFF & (0xFF << (8 - rem_bits))  # keep top rem_bits
    out[-1] &= mask
    return bytes(out)


def local_entropy_bytes(bit_length: int) -> bytes:
    byte_count = (bit_length + 7) // 8
    data = secrets.token_bytes(byte_count)
    return trim_to_bits(data, bit_length)


def make_session(pool_size: int = 50) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=10,
        connect=10,
        read=10,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=pool_size,
        pool_maxsize=pool_size,
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"Connection": "keep-alive"})
    return s


def normalize_endpoint(base_url: str) -> str:
    base_url = base_url.rstrip("/")
    if not base_url.endswith("/get"):
        base_url = base_url + "/get"
    return base_url


def fetch_bulk_bytes(
    session: requests.Session,
    base_url: str,
    size_path: str,
    timeout: Tuple[int, int],
) -> bytes:
    """
    GET entropy from: base_url/get/size_path
    Expected response: {"success": true, "response": "<hex>"}
    Returns raw bytes decoded from hex.
    """
    base_url = normalize_endpoint(base_url)
    size_path = size_path.strip().lstrip("/")
    url = f"{base_url}/{size_path}"

    r = session.get(url, timeout=timeout)

    try:
        payload = r.json()
    except Exception:
        raise RuntimeError(f"Non-JSON response (HTTP {r.status_code}): {r.text[:200]}")

    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {payload}")

    if not payload.get("success", False):
        raise RuntimeError(f"API returned success=false: {payload}")

    hex_data = payload.get("response")
    if not isinstance(hex_data, str) or not hex_data:
        raise RuntimeError("Response missing 'response' hex field")

    try:
        return bytes.fromhex(hex_data.strip())
    except ValueError as e:
        raise RuntimeError(f"Invalid hex in response: {e}")


def clean_old_sequences(out_dir: str) -> int:
    """
    Delete ALL seq_*.bin files in out_dir regardless of seq-length.
    """
    pattern = os.path.join(out_dir, "seq_*.bin")
    files = glob.glob(pattern)

    deleted = 0
    for fp in files:
        try:
            os.remove(fp)
            deleted += 1
        except OSError:
            pass

    return deleted


# ----------------------------
# Main
# ----------------------------

def main() -> int:
    default_base_url = os.environ.get(ENTROPY_ENDPOINT_ENV, "").strip()

    p = argparse.ArgumentParser(description="Generate NIST-ready entropy sequences (.bin).")
    p.add_argument("--endpoint", default=default_base_url, help=f"Base endpoint (default: ${ENTROPY_ENDPOINT_ENV}).")
    p.add_argument("--use", choices=["qse", "local"], default="qse", help="Entropy source.")
    p.add_argument("--seq-length", type=int, default=1_000_000, help="Bits per sequence.")
    p.add_argument("--sequences", type=int, default=100, help="Number of sequences.")
    p.add_argument("--out-dir", default="entropy-streams", help="Output base directory.")
    p.add_argument("--size", default=None, help="Optional endpoint size path (e.g., 125k).")
    p.add_argument("--connect-timeout", type=int, default=10, help="HTTP connect timeout (seconds).")
    p.add_argument("--read-timeout", type=int, default=300, help="HTTP read timeout (seconds).")
    p.add_argument("--sleep-ms", type=int, default=0, help="Optional sleep between API calls (ms).")
    args = p.parse_args()

    if args.seq_length <= 0 or args.sequences <= 0:
        print("seq-length and sequences must be positive", file=sys.stderr)
        return 1

    if args.use == "qse" and not args.endpoint:
        print(
            f"Missing base endpoint. Set it via:\n"
            f'  export {ENTROPY_ENDPOINT_ENV}="http://.../entropy/get"\n'
            f"or pass --endpoint explicitly.",
            file=sys.stderr,
        )
        return 1

    source_folder = "qse" if args.use == "qse" else "system"
    out_dir = os.path.join(args.out_dir, source_folder)
    os.makedirs(out_dir, exist_ok=True)

    # ALWAYS delete old sequences before generating
    deleted = clean_old_sequences(out_dir)
    if deleted > 0:
        print(f"🧹 Cleaned {deleted} old files from: {out_dir}")
    else:
        print(f"🧹 No old seq_*.bin files found in: {out_dir}")

    seq_bytes_needed = (args.seq_length + 7) // 8
    size_path = args.size if args.size else bytes_to_size_path(seq_bytes_needed)

    timeout = (args.connect_timeout, args.read_timeout)
    session = make_session(pool_size=50)

    if args.use == "qse":
        ep = normalize_endpoint(args.endpoint)
        print(f"Using bulk endpoint: {ep}/{size_path}")
        print(f"Sequence size: {args.seq_length} bits (~{seq_bytes_needed} bytes)")
        print(f"Timeouts: connect={args.connect_timeout}s read={args.read_timeout}s, retries=on")
        if args.sleep_ms:
            print(f"Sleep between calls: {args.sleep_ms}ms")

    for i in range(1, args.sequences + 1):
        out_path = os.path.join(out_dir, f"seq_{i:04d}_{args.seq_length}bits.bin")

        try:
            if args.use == "qse":
                raw = fetch_bulk_bytes(session, args.endpoint, size_path, timeout=timeout)
                if len(raw) < seq_bytes_needed:
                    raise RuntimeError(f"API returned {len(raw)} bytes, need >= {seq_bytes_needed}")
                trimmed = trim_to_bits(raw, args.seq_length)
                summary = f"{args.seq_length} bits via bulk endpoint ({size_path})"
                if args.sleep_ms > 0:
                    time.sleep(args.sleep_ms / 1000.0)
            else:
                trimmed = local_entropy_bytes(args.seq_length)
                summary = f"{args.seq_length} bits via local generator"

            with open(out_path, "wb") as f:
                f.write(trimmed)

            print(f"[{i}/{args.sequences}] Wrote {summary} -> {out_path} ({len(trimmed)} bytes)")

        except Exception as exc:
            print(f"[{i}/{args.sequences}] Failed: {exc}", file=sys.stderr)
            return 1

    print("\n✅ Done.")
    print(f"Output folder: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())