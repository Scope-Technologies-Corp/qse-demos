#!/usr/bin/env python3
"""
sts_api.py

Wrapper module for NIST STS pipeline functions to be used by web API.
Provides functions for generating entropy, running STS tests, and parsing results.
"""

import json
import os
import subprocess
import sys
import time
import secrets
import urllib.error
import urllib.request
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

# Try to import pexpect for interactive STS binary
try:
    import pexpect
    PEXPECT_AVAILABLE = True
except ImportError:
    PEXPECT_AVAILABLE = False
    print("Warning: pexpect not available. STS binary interaction may fail.", file=sys.stderr)

# Import functions from existing STS scripts
# We'll need to import parse_sts_report functions
sys.path.insert(0, os.path.dirname(__file__))

try:
    from parse_sts_report import parse_summary_block, build_report
    from compare_sts_results import load_json, score_test
    from generate_scorecard import headline_verdict
except ImportError as e:
    # Fallback if imports fail
    print(f"Warning: Could not import STS utilities: {e}", file=sys.stderr)
    parse_summary_block = None
    build_report = None
    load_json = None
    score_test = None
    headline_verdict = None

ENTROPY_ENDPOINT_ENV = "ENTROPY_ENDPOINT"
DEFAULT_STS_DIR = Path(__file__).parent
DEFAULT_ALPHA = 0.01


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


def bytes_to_size_path(hex_char_count: int) -> str:
    """
    Convert hex character count to API size path format.
    API format: "1k" = 1000 hex chars, "100k" = 100000 hex chars, etc.
      - divisible by 1000 -> Xk (e.g., 125000 -> 125k)
      - else -> X (e.g., 123456 -> 123456)
    """
    if hex_char_count % 1000 == 0:
        return f"{hex_char_count // 1000}k"
    return str(hex_char_count)


def fetch_bulk_hex(base_url: str, size_path: str) -> str:
    """
    GET entropy from API endpoint.
    Expected response: {"success": true, "response": "<hex>"}
    API format: endpoint/get/<size>
    where size can be like "125k" for 125000 bytes or "100000" for 100000 bytes
    
    Examples:
    - base_url="http://scopesvr.fractalarmor.com:8888/entropy", size="125k" 
      -> "http://scopesvr.fractalarmor.com:8888/entropy/get/125k"
    - base_url="http://api:8888/entropy/get", size="125k" 
      -> "http://api:8888/entropy/get/125k"
    """
    base_url = base_url.rstrip("/")
    size_path = size_path.strip().lstrip("/")
    
    # Remove trailing /get if present (we'll add it back)
    if base_url.endswith("/get"):
        base_url = base_url[:-4]
    
    # Construct URL: base_url/get/size_path
    url = f"{base_url}/get/{size_path}"
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


def generate_entropy_sequences(
    source: str,  # "qse" or "system"
    sequences: int,
    seq_length_bits: int,
    out_dir: Path,
    endpoint: Optional[str] = None,
    progress_callback=None,
) -> Tuple[Path, List[str]]:
    """
    Generate entropy sequences using the existing generate_entropy.py script.
    This calls the tested script instead of reimplementing.
    
    Returns:
        (output_directory, list_of_generated_files)
    """
    # Use the existing generate_entropy.py script
    script_path = Path(__file__).parent / "generate_entropy.py"
    if not script_path.exists():
        raise FileNotFoundError(f"generate_entropy.py not found at {script_path}")
    
    # generate_entropy.py creates the source folder (qse/system) inside out-dir
    # So we need to pass the parent directory if out_dir already includes the source folder
    # Otherwise pass out_dir as-is
    if out_dir.name in ["qse", "system"]:
        # out_dir is already the source-specific directory, use its parent
        base_out_dir = out_dir.parent
    else:
        # out_dir is the base directory, use it as-is
        base_out_dir = out_dir
    
    # Build command to call existing script
    cmd = [
        sys.executable,
        str(script_path),
        "--use", source if source == "qse" else "local",
        "--seq-length", str(seq_length_bits),
        "--sequences", str(sequences),
        "--out-dir", str(base_out_dir),
    ]
    
    if source == "qse":
        if not endpoint:
            raise ValueError("QSE endpoint required for QSE entropy generation")
        # Pass endpoint as-is, script handles /get suffix
        cmd.extend(["--endpoint", endpoint.rstrip("/")])
    
    if progress_callback:
        progress_callback({
            'step': 'generate',
            'source': source,
            'message': f'Running generate_entropy.py for {source} entropy ({sequences} sequences, {seq_length_bits} bits each)...'
        })
    
    try:
        # Run the script and capture output for progress messages
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Stream output for progress messages
        output_lines = []
        for line in process.stdout:
            line = line.strip()
            if line:
                output_lines.append(line)
                if progress_callback:
                    progress_callback({
                        'step': 'generate',
                        'source': source,
                        'message': line
                    })
        
        process.wait()
        
        if process.returncode != 0:
            raise RuntimeError(f"generate_entropy.py failed with exit code {process.returncode}")
        
        # Find generated files - generate_entropy.py creates source_folder inside base_out_dir
        source_folder = "qse" if source == "qse" else "system"
        actual_out_path = base_out_dir / source_folder
        
        if not actual_out_path.exists():
            raise RuntimeError(f"Output directory not created: {actual_out_path}")
        
        generated_files = sorted(list(actual_out_path.glob("*.bin")))
        if len(generated_files) != sequences:
            raise RuntimeError(
                f"Expected {sequences} files, but found {len(generated_files)} in {actual_out_path}"
            )
        
        if progress_callback:
            progress_callback({
                'step': 'generate',
                'source': source,
                'message': f'✓ Generated {len(generated_files)} sequences in {actual_out_path}'
            })
        
        return actual_out_path, [str(f) for f in generated_files]
        
    except Exception as exc:
        raise RuntimeError(f"Failed to generate entropy sequences: {exc}") from exc


def run_sts_for_source(
    source: str,
    input_dir: Path,
    output_dir: Path,
    seq_length_bits: int,
    alpha: float = DEFAULT_ALPHA,
    sts_dir: Path = DEFAULT_STS_DIR,
    progress_callback=None,
) -> Path:
    """
    Run NIST STS for a given entropy source.
    
    Returns:
        Path to finalAnalysisReport.txt
    """
    if progress_callback:
        progress_callback({
            'step': 'sts_run',
            'source': source,
            'message': f'Running NIST STS for {source} entropy...'
        })

    # Resolve STS directory - try multiple locations
    sts_dir = Path(sts_dir).resolve()
    if not sts_dir.exists():
        # Try relative to current working directory
        sts_dir = Path("sts-2.1.2").resolve()
        if not sts_dir.exists():
            raise FileNotFoundError(
                f"STS directory not found. Tried {Path(sts_dir).resolve()} and sts-2.1.2"
            )

    # Find STS binary - use absolute path
    assess_binary = sts_dir / "assess"
    if not assess_binary.exists():
        raise FileNotFoundError(
            f"STS assess binary not found at {assess_binary}. "
            "Run 'make' in sts-2.1.2 first."
        )
    
    # Resolve to absolute path
    assess_binary = assess_binary.resolve()
    
    # Check if binary is executable
    if not os.access(assess_binary, os.X_OK):
        raise PermissionError(f"STS binary {assess_binary} is not executable")
    
    if progress_callback:
        progress_callback({
            'step': 'sts_run',
            'source': source,
            'message': f'Found STS binary at: {assess_binary}'
        })

    data_dir = sts_dir / "data"
    experiments_dir = sts_dir / "experiments"

    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    # Clean STS data folder
    for f in data_dir.glob("*"):
        if f.is_file():
            f.unlink()

    # Follow README Step 2: Combine sequences into one file
    # STS expects one file containing multiple sequences back-to-back
    bin_files = sorted(list(input_dir.glob("*.bin")))
    if not bin_files:
        raise ValueError(f"No .bin files found in {input_dir}")

    num_sequences = len(bin_files)
    
    # Combine all .bin files into one file (as per README Step 2)
    combined_filename = f"{source}_all.bin"
    combined_file = data_dir / combined_filename
    
    if progress_callback:
        progress_callback({
            'step': 'combine',
            'source': source,
            'message': f'Combining {num_sequences} sequences into {combined_filename}...'
        })
    
    with open(combined_file, "wb") as outfile:
        for bin_file in bin_files:
            with open(bin_file, "rb") as infile:
                shutil.copyfileobj(infile, outfile)
    
    if progress_callback:
        file_size_mb = combined_file.stat().st_size / (1024 * 1024)
        progress_callback({
            'step': 'combine',
            'source': source,
            'message': f'✓ Combined file created: {combined_filename} ({file_size_mb:.2f} MB)'
        })

    # Clean previous experiments and create necessary directories
    # STS requires specific directory structure to exist before running
    # Per README troubleshooting: need to create directories and set permissions
    if experiments_dir.exists():
        shutil.rmtree(experiments_dir)
    
    # Create full directory structure that STS expects
    # STS creates files in experiments/AlgorithmTesting/{testName}/ for each test
    # Per utilities.c: STS tries to open files in these directories during openOutputStreams()
    experiments_dir.mkdir(parents=True, exist_ok=True)
    algorithm_testing_dir = experiments_dir / "AlgorithmTesting"
    algorithm_testing_dir.mkdir(parents=True, exist_ok=True)
    
    # Create subdirectories for all 15 NIST tests (from decls.h)
    # STS will fail if these don't exist when it tries to open files
    test_names = [
        "Frequency", "BlockFrequency", "CumulativeSums", "Runs", "LongestRun", "Rank",
        "FFT", "NonOverlappingTemplate", "OverlappingTemplate", "Universal", 
        "ApproximateEntropy", "RandomExcursions", "RandomExcursionsVariant", 
        "Serial", "LinearComplexity"
    ]
    
    for test_name in test_names:
        test_dir = algorithm_testing_dir / test_name
        test_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(test_dir, 0o777)
        except Exception:
            pass  # Ignore permission errors, try to continue
    
    # STS also needs results directory
    results_dir = sts_dir / "results"
    if results_dir.exists():
        shutil.rmtree(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    
    # Set permissions to ensure STS can write (as per README troubleshooting)
    try:
        os.chmod(experiments_dir, 0o777)
        os.chmod(algorithm_testing_dir, 0o777)
        os.chmod(results_dir, 0o777)
    except Exception as e:
        if progress_callback:
            progress_callback({
                'step': 'sts_run',
                'source': source,
                'message': f'⚠️  Warning: Could not set directory permissions: {e}'
            })
    
    # Verify directories are writable and test write access
    try:
        # Test write access to experiments directory
        test_file = algorithm_testing_dir / ".test_write"
        test_file.write_text("test")
        test_file.unlink()
        
        # Test write access to results directory
        test_file = results_dir / ".test_write"
        test_file.write_text("test")
        test_file.unlink()
        
        if progress_callback:
            progress_callback({
                'step': 'sts_run',
                'source': source,
                'message': f'✓ Verified STS directories are writable: {experiments_dir}, {results_dir}'
            })
    except Exception as e:
        raise PermissionError(
            f"Cannot write to STS directories. "
            f"Experiments: {experiments_dir} (exists: {experiments_dir.exists()}, writable: {os.access(experiments_dir, os.W_OK)}), "
            f"AlgorithmTesting: {algorithm_testing_dir} (exists: {algorithm_testing_dir.exists()}, writable: {os.access(algorithm_testing_dir, os.W_OK)}), "
            f"Results: {results_dir} (exists: {results_dir.exists()}, writable: {os.access(results_dir, os.W_OK)}). "
            f"Error: {e}"
        )

    # Verify combined file exists and is readable
    if not combined_file.exists():
        raise FileNotFoundError(f"Combined file not found: {combined_file}")
    
    file_size = combined_file.stat().st_size
    expected_size = num_sequences * (seq_length_bits // 8)
    if abs(file_size - expected_size) > expected_size * 0.1:  # Allow 10% tolerance
        if progress_callback:
            progress_callback({
                'step': 'sts_run',
                'source': source,
                'message': f'⚠️  Warning: Combined file size {file_size} bytes, expected ~{expected_size} bytes'
            })
    
    # Run STS binary using manual workflow from README Step 3
    # Following sts_test.py exact sequence:
    # 1. "Enter Choice:" -> "0" (Input File)
    # 2. "User Prescribed Input File:" -> "data/qse_all.bin"
    # 3. "Enter Choice:" -> "1" (Apply all tests)
    # 4. "Select Test (0 to continue):" -> "0" (skip parameter adjustments)
    # 5. "How many bitstreams?" -> num_sequences
    # 6. "Select input mode:" -> "1" (Binary)
    input_sequence = f"0\ndata/{combined_filename}\n1\n0\n{num_sequences}\n1\n"
    
    if progress_callback:
        progress_callback({
            'step': 'sts_run',
            'source': source,
            'message': f'Running NIST STS binary with {num_sequences} bitstreams (this may take several minutes)...'
        })
        progress_callback({
            'step': 'sts_run',
            'source': source,
            'message': f'Using combined file: {combined_file} ({file_size / (1024*1024):.2f} MB)'
        })
    
    try:
        # Try using pexpect if available for more reliable interaction
        # Otherwise fall back to subprocess with piped input
        if PEXPECT_AVAILABLE:
            if progress_callback:
                progress_callback({
                    'step': 'sts_run',
                    'source': source,
                    'message': 'Using pexpect for interactive STS prompts...'
                })
            
            # Use absolute path to assess binary
            child = pexpect.spawn(
                str(assess_binary),
                [str(seq_length_bits)],
                cwd=str(sts_dir),
                timeout=3600,
                encoding='utf-8',
            )
            
            # Follow exact sequence from sts_test.py with better error handling
            try:
                if progress_callback:
                    progress_callback({
                        'step': 'sts_run',
                        'source': source,
                        'message': 'Step 2/4: Starting STS binary interaction...'
                    })
                
                child.expect("Enter Choice:", timeout=120)
                child.sendline("0")
                
                child.expect("User Prescribed Input File:", timeout=120)
                child.sendline(f"data/{combined_filename}")
                
                child.expect("Enter Choice:", timeout=120)
                child.sendline("1")
                
                child.expect("Select Test \\(0 to continue\\):", timeout=120)
                child.sendline("0")
                
                child.expect("How many bitstreams\\?", timeout=120)
                child.sendline(str(num_sequences))
                
                child.expect("Select input mode:", timeout=120)
                child.sendline("1")  # Binary
                
                if progress_callback:
                    progress_callback({
                        'step': 'sts_run',
                        'source': source,
                        'message': f'Step 3/4: Running {num_sequences} bitstreams through 15 NIST statistical tests (this takes 10-30 minutes)...'
                    })
                
                # Wait for completion - this is the slow part
                child.expect(pexpect.EOF, timeout=3600)
                child.close()
                
                if progress_callback:
                    progress_callback({
                        'step': 'sts_run',
                        'source': source,
                        'message': 'Step 4/4: STS tests completed, processing results...'
                    })
                
                # STS uses exit code 1 for "success with warnings" - check if report was generated instead
                report_file = sts_dir / "finalAnalysisReport.txt"
                if not report_file.exists():
                    remaining = child.before if hasattr(child, 'before') else ""
                    error_msg = f"STS binary exited with code {child.exitstatus} but no report generated.\n"
                    error_msg += f"Output before exit: {remaining[-1000:]}\n"
                    error_msg += f"Experiments dir: {experiments_dir} (exists: {experiments_dir.exists()})\n"
                    error_msg += f"Results dir: {results_dir} (exists: {results_dir.exists()})\n"
                    raise RuntimeError(error_msg)
                
                if progress_callback:
                    progress_callback({
                        'step': 'sts_run',
                        'source': source,
                        'message': f'✓ STS completed (exit code {child.exitstatus}) - report generated successfully'
                    })
                    
            except pexpect.exceptions.TIMEOUT as e:
                error_msg = f"STS binary timed out waiting for prompt.\n"
                error_msg += f"Last output: {child.before[-500:] if hasattr(child, 'before') else 'N/A'}\n"
                raise RuntimeError(error_msg)
            except pexpect.exceptions.EOF as e:
                error_msg = f"STS binary exited unexpectedly (EOF).\n"
                error_msg += f"Exit status: {child.exitstatus}\n"
                error_msg += f"Output before exit: {child.before[-2000:] if hasattr(child, 'before') else 'N/A'}\n"
                error_msg += f"Experiments dir: {experiments_dir} (exists: {experiments_dir.exists()}, writable: {os.access(experiments_dir, os.W_OK)})\n"
                error_msg += f"Results dir: {results_dir} (exists: {results_dir.exists()}, writable: {os.access(results_dir, os.W_OK)})\n"
                error_msg += f"Combined file: {combined_file} (exists: {combined_file.exists()}, size: {file_size} bytes)\n"
                raise RuntimeError(error_msg)
        else:
            # Fallback to subprocess with piped input
            if progress_callback:
                progress_callback({
                    'step': 'sts_run',
                    'source': source,
                    'message': 'Using subprocess with piped input (pexpect not available)...'
                })
            
            # Use absolute path to assess binary
            process = subprocess.Popen(
                [str(assess_binary), str(seq_length_bits)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=str(sts_dir),
                text=True,
                bufsize=1,
            )
            
            stdout, _ = process.communicate(input=input_sequence, timeout=3600)
            
            # STS uses exit code 1 for "success with warnings" - check if report was generated instead
            report_file = sts_dir / "finalAnalysisReport.txt"
            if not report_file.exists():
                error_msg = f"STS binary exited with code {process.returncode} but no report generated.\n"
                error_msg += f"Combined file: {combined_file} (exists: {combined_file.exists()}, size: {file_size} bytes)\n"
                if stdout:
                    error_msg += f"Output (last 2000 chars):\n{stdout[-2000:]}\n"
                raise RuntimeError(error_msg)
            
            if progress_callback:
                progress_callback({
                    'step': 'sts_run',
                    'source': source,
                    'message': f'✓ STS completed (exit code {process.returncode}) - report generated successfully'
                })
        
        if progress_callback:
            progress_callback({
                'step': 'sts_run',
                'source': source,
                'message': f'✓ STS completed successfully'
            })
            
    except subprocess.TimeoutExpired:
        process.kill()
        raise RuntimeError("STS binary timed out after 1 hour")
    except Exception as e:
        raise RuntimeError(f"Failed to run STS binary: {e}")

    # Copy final report
    report_source = experiments_dir / "AlgorithmTesting" / "finalAnalysisReport.txt"
    if not report_source.exists():
        # List what's actually in experiments_dir for debugging
        experiments_contents = list(experiments_dir.rglob("*"))
        raise FileNotFoundError(
            f"STS report not found at {report_source}. "
            f"Experiments directory contents: {[str(p.relative_to(experiments_dir)) for p in experiments_contents[:10]]}"
        )

    report_dest = output_dir / "finalAnalysisReport.txt"
    shutil.copy2(report_source, report_dest)

    return report_dest


def parse_sts_report(report_path: Path) -> Dict[str, Any]:
    """Parse STS finalAnalysisReport.txt into JSON structure."""
    if not parse_summary_block or not build_report:
        # Fallback: try to read existing JSON if available
        json_path = report_path.parent / "report.json"
        if json_path.exists():
            with open(json_path, "r") as f:
                return json.load(f)
        raise RuntimeError("STS parsing utilities not available")

    with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    generator, results = parse_summary_block(text)
    return build_report(generator, results)


def compare_sts_results(qse_report: Dict[str, Any], system_report: Dict[str, Any]) -> Dict[str, Any]:
    """Compare QSE and System STS results."""
    if not score_test:
        raise RuntimeError("STS comparison utilities not available")

    qse_tests = {t["test_name"]: t for t in qse_report["tests"]}
    sys_tests = {t["test_name"]: t for t in system_report["tests"]}

    all_test_names = sorted(set(qse_tests.keys()) | set(sys_tests.keys()))

    comparisons = []
    win_counts = {"qse": 0, "system": 0, "tie": 0}

    for name in all_test_names:
        if name not in qse_tests or name not in sys_tests:
            continue
        row = score_test(qse_tests[name], sys_tests[name])
        comparisons.append(row)
        win_counts[row["winner"]] += 1

    overall_winner = "tie"
    if win_counts["qse"] > win_counts["system"]:
        overall_winner = "qse"
    elif win_counts["system"] > win_counts["qse"]:
        overall_winner = "system"

    return {
        "overall": {
            "qse_overall_pass": qse_report["summary"]["overall_pass"],
            "system_overall_pass": system_report["summary"]["overall_pass"],
            "winner": overall_winner,
            "win_counts": win_counts,
        },
        "comparisons": comparisons,
    }


def generate_scorecard(
    qse_report: Dict[str, Any],
    system_report: Dict[str, Any],
    comparison: Dict[str, Any],
) -> Dict[str, Any]:
    """Generate scorecard JSON from reports and comparison."""
    from datetime import datetime

    if not headline_verdict:
        verdict = "STS comparison completed"
    else:
        verdict = headline_verdict(qse_report, system_report, comparison)

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "config": {
            "alpha": DEFAULT_ALPHA,
            "sequences": qse_report["summary"]["total_tests"] // 15,  # Approximate
            "sequence_length_bits": 1_000_000,
            "input_mode": "binary",
        },
        "headline_verdict": verdict,
        "overall": comparison["overall"],
        "qse_summary": qse_report["summary"],
        "system_summary": system_report["summary"],
        "qse_weakest_test": qse_report["weakest_test"],
        "system_weakest_test": system_report["weakest_test"],
        "qse_lowest_uniformity_test": qse_report["lowest_uniformity_test"],
        "system_lowest_uniformity_test": system_report["lowest_uniformity_test"],
        "qse_borderline_tests": qse_report["borderline_tests"],
        "system_borderline_tests": system_report["borderline_tests"],
        "wins_by_test": comparison["overall"]["win_counts"],
        "comparisons": comparison["comparisons"],
    }


def load_scorecard(scorecard_path: Path) -> Optional[Dict[str, Any]]:
    """Load existing scorecard JSON."""
    if not scorecard_path.exists():
        return None
    
    with open(scorecard_path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_sts_results_base() -> Path:
    """Find the base directory for STS results."""
    # Try relative to current file
    base = DEFAULT_STS_DIR / "sts-results"
    if base.exists():
        return base
    
    # Try relative to project root
    base = Path("sts-2.1.2") / "sts-results"
    if base.exists():
        return base
    
    # Create if doesn't exist
    base = DEFAULT_STS_DIR / "sts-results"
    base.mkdir(parents=True, exist_ok=True)
    return base
