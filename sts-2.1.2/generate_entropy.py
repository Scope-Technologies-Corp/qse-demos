#!/usr/bin/env python3
"""
Generate NIST-ready entropy sequences (.bin) using bulk entropy endpoint or local generator.

Usage:
    # QSE entropy (requires endpoint)
    export ENTROPY_ENDPOINT="http://scopesvr.fractalarmor.com:8888/entropy"
    python3 generate_entropy.py --use qse --seq-length 1000000 --sequences 100

    # Or pass endpoint directly:
    python3 generate_entropy.py --use qse --endpoint http://scopesvr.fractalarmor.com:8888/entropy --seq-length 1000000 --sequences 100

    # Local system entropy
    python3 generate_entropy.py --use local --seq-length 1000000 --sequences 100

Output:
    entropy-streams/qse/seq_0001_1000000bits.bin ... seq_0100_1000000bits.bin
    entropy-streams/system/seq_0001_1000000bits.bin ... seq_0100_1000000bits.bin

Note: The script automatically adds "/get" to the endpoint if not present.
      e.g., "http://scopesvr.fractalarmor.com:8888/entropy" becomes
            "http://scopesvr.fractalarmor.com:8888/entropy/get/125k"
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import secrets

ENTROPY_ENDPOINT_ENV = "ENTROPY_ENDPOINT"


def hex_to_bits(hex_str: str) -> str:
    """Convert a hex string to a string of '0'/'1' bits."""
    hex_str = hex_str.strip().lower()
    if not hex_str:
        return ""
    try:
        int(hex_str, 16)
    except ValueError as exc:
        raise ValueError("Response is not valid hex") from exc
    return "".join(f"{int(ch, 16):04b}" for ch in hex_str)


def bits_to_bytes(bit_str: str) -> bytes:
    """Convert a '0'/'1' bitstring into raw bytes. Pads to full bytes."""
    if not bit_str:
        return b""
    remainder = len(bit_str) % 8
    if remainder != 0:
        bit_str += "0" * (8 - remainder)
    return int(bit_str, 2).to_bytes(len(bit_str) // 8, byteorder="big")


def local_entropy_bits(bit_length: int) -> str:
    """Generate entropy locally using secrets.token_bytes and return bits."""
    byte_count = (bit_length + 7) // 8
    data = secrets.token_bytes(byte_count)
    bit_str = "".join(f"{byte:08b}" for byte in data)
    return bit_str[:bit_length]


def bytes_to_size_path(byte_count: int) -> str:
    """
    Convert bytes to API path value:
      - divisible by 1000 -> Xk
      - else -> Xb
    Examples:
      125000 -> 125k
      123456 -> 123456b
    """
    if byte_count % 1000 == 0:
        return f"{byte_count // 1000}k"
    return f"{byte_count}b"


def fetch_bulk_hex(base_url: str, size_path: str) -> str:
    """
    GET entropy from: base_url/get/size_path
    
    Example: base_url="http://scopesvr.fractalarmor.com:8888/entropy", size_path="125k"
    Results in: http://scopesvr.fractalarmor.com:8888/entropy/get/125k
    
    Expected response: {"success": true, "response": "<hex>"}
    """
    base_url = base_url.rstrip("/")
    size_path = size_path.strip().lstrip("/")
    
    # Add /get if not present
    if not base_url.endswith("/get"):
        base_url = base_url + "/get"
    
    url = f"{base_url}/{size_path}"

    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8").strip()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP error {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Response was not valid JSON") from exc

    if not parsed.get("success", False):
        raise RuntimeError(f"API returned success=false: {parsed}")

    hex_data = parsed.get("response")
    if not isinstance(hex_data, str):
        raise RuntimeError("Response missing 'response' hex field")

    return hex_data.strip()


def main() -> int:
    default_base_url = os.environ.get(ENTROPY_ENDPOINT_ENV, "").strip()

    parser = argparse.ArgumentParser(
        description="Generate NIST-ready entropy sequences (.bin) using bulk entropy endpoint or local generator."
    )

    parser.add_argument(
        "--endpoint",
        default=default_base_url,
        help=f"Base endpoint (default: ${ENTROPY_ENDPOINT_ENV}). Example: http://scopesvr.fractalarmor.com:8888/entropy",
    )

    parser.add_argument(
        "--use",
        choices=["qse", "local"],
        default="qse",
        help="Entropy source: 'qse' to call bulk endpoint, 'local' to use secrets.token_bytes.",
    )

    parser.add_argument(
        "--seq-length",
        type=int,
        default=1_000_000,
        help="Bits per sequence (default: 1,000,000 bits).",
    )

    parser.add_argument(
        "--sequences",
        type=int,
        default=100,
        help="Number of sequences to generate (default: 100).",
    )

    parser.add_argument(
        "--out-dir",
        default="entropy-streams",
        help="Output base directory (default: entropy-streams).",
    )

    parser.add_argument(
        "--size",
        default=None,
        help="Optional endpoint size path (e.g., 1k, 125k, 1m). If omitted, computed from seq-length.",
    )

    args = parser.parse_args()

    if args.seq_length <= 0:
        print("seq-length must be positive", file=sys.stderr)
        return 1

    if args.sequences <= 0:
        print("sequences must be positive", file=sys.stderr)
        return 1

    if args.use == "qse" and not args.endpoint:
        print(
            f"Missing base endpoint. Set it via:\n"
            f"  export {ENTROPY_ENDPOINT_ENV}=\"http://api:8888/entropy/get\"\n"
            f"or pass --endpoint explicitly.",
            file=sys.stderr,
        )
        return 1

    source_folder = "qse" if args.use == "qse" else "system"
    out_dir = os.path.join(args.out_dir, source_folder)
    os.makedirs(out_dir, exist_ok=True)

    # Compute how many bytes we need for one sequence
    seq_bytes = (args.seq_length + 7) // 8
    size_path = args.size if args.size else bytes_to_size_path(seq_bytes)

    if args.use == "qse":
        endpoint_base = args.endpoint.rstrip("/")
        if not endpoint_base.endswith("/get"):
            endpoint_base = endpoint_base + "/get"
        print(f"Using bulk endpoint: {endpoint_base}/{size_path}")
        print(f"Sequence size: {args.seq_length} bits (~{seq_bytes} bytes)")

    # Generate sequences one at a time
    for i in range(1, args.sequences + 1):
        try:
            if args.use == "qse":
                hex_data = fetch_bulk_hex(args.endpoint, size_path)
                bits = hex_to_bits(hex_data)
                if len(bits) < args.seq_length:
                    raise RuntimeError(
                        f"API returned {len(bits)} bits, need {args.seq_length}"
                    )
                bits = bits[: args.seq_length]
                summary = f"{len(bits)} bits via bulk entropy endpoint ({size_path})"
            else:
                bits = local_entropy_bits(args.seq_length)
                summary = f"{len(bits)} bits via local generator"

            raw_bytes = bits_to_bytes(bits)

            out_path = os.path.join(out_dir, f"seq_{i:04d}_{args.seq_length}bits.bin")
            with open(out_path, "wb") as f:
                f.write(raw_bytes)

            print(f"[{i}/{args.sequences}] Wrote {summary} -> {out_path} ({len(raw_bytes)} bytes)")

        except Exception as exc:
            print(f"[{i}/{args.sequences}] Failed: {exc}", file=sys.stderr)
            return 1

    print("\n✅ Done.")
    print(f"Output folder: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
