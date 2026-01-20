# Detailed File Explanations and Usage Guide

This project contains four demonstration scripts that illustrate the critical importance of entropy quality in cryptographic systems. Each script demonstrates different aspects of how weak entropy can compromise security.

---

## 1. `entropy_effectiveness_demo.py` - Comprehensive Entropy Comparison Demo

### What It Does

This is the most comprehensive demo script. It compares two encryption scenarios side-by-side:

1. **Weak Entropy Case**: Derives an AES-GCM encryption key from a low-entropy seed (UNIX timestamp in seconds). This demonstrates how an attacker can brute-force the seed within a small time window.

2. **QRNG Entropy Case**: Derives an AES-GCM encryption key from 256 bytes of Quantum Random Number Generator (QRNG) data. This demonstrates why brute-force attacks are infeasible with high-quality entropy.

### Key Features

- **Live Attack Demonstration**: Actually performs a brute-force attack on the weak seed case
- **Work Factor Calculation**: Computes the theoretical time required to brute-force both scenarios
- **Multiple Output Formats**: Supports human-readable output, CSV, and JSON formats
- **Safe Harness**: Uses a known prefix to prevent accidental decryption of arbitrary data

### How It Works

1. **Weak Case**:
   - Uses current UNIX timestamp (seconds) as seed
   - Derives 256-bit key using HKDF-SHA256
   - Encrypts a message with AES-GCM
   - Brute-forces seeds within a configurable time window (±window seconds)
   - Reports success/failure and timing statistics

2. **QRNG Case**:
   - Takes 256 bytes of QRNG data (base64 encoded)
   - Derives 256-bit key using HKDF-SHA256
   - Encrypts the same message with AES-GCM
   - Calculates theoretical brute-force time (doesn't actually attempt it)

### Usage Instructions

#### Basic Usage (with environment variable):

```bash
# Set QRNG data as environment variable
export QRNG_B64="<your_base64_encoded_256_bytes_of_qrng_data>"

# Run the demo
python3 entropy_effectiveness_demo.py
```

#### Using STDIN for QRNG data:

```bash
# Pipe QRNG data from a file or command
echo "b4836dc03758feda506877a85397fdeaa2fc3107d803e6580c62027c860097a2..." | \
  python3 entropy_effectiveness_demo.py --qrng-stdin
```

#### Customizing the Demo:

```bash
# Adjust the brute-force window (default: 120 seconds)
python3 entropy_effectiveness_demo.py --window 180

# Change the message to encrypt
python3 entropy_effectiveness_demo.py --message "Your custom message here"

# Generate CSV output for analysis
python3 entropy_effectiveness_demo.py --csv

# Generate JSON report
python3 entropy_effectiveness_demo.py --json

# Combine options
python3 entropy_effectiveness_demo.py \
  --qrng-stdin \
  --window 180 \
  --csv \
  --json
```

#### Command-Line Arguments:

- `--window <seconds>`: Time window for brute-force attack (default: 120 seconds)
- `--message <text>`: Message to encrypt (default: "Entropy matters: weak seed space collapses security.")
- `--qrng-stdin`: Read QRNG base64 from STDIN instead of environment variable
- `--qrng-env <name>`: Environment variable name for QRNG data (default: QRNG_B64)
- `--csv`: Print CSV summary line for data analysis
- `--json`: Print detailed JSON report

### Expected Output

The script outputs:
- Public artifacts (nonces, ciphertexts, AAD)
- Attack results (success/failure, timing, guesses per second)
- Side-by-side work factor comparison
- Human-readable time estimates for brute-force attempts

### Example Output Interpretation

- **Weak case**: Typically succeeds in seconds, showing how vulnerable low-entropy seeds are
- **QRNG case**: Shows astronomical time estimates (e.g., "2^256 operations"), demonstrating infeasibility

---

## 2. `qrng_seed_demo.py` - Simple QRNG Key Derivation Demo

### What It Does

This is a simpler, focused demo that shows how to derive a cryptographic key from QRNG data and use it for AES-GCM encryption. It demonstrates why brute-force attacks fail with high-quality entropy.

### Key Features

- **Simple Key Derivation**: Mixes QRNG bytes with OS randomness using SHA-256
- **AES-GCM Encryption**: Encrypts a message using the derived key
- **Educational Output**: Explains why brute-force fails with high entropy

### How It Works

1. Reads QRNG data from environment variable `SRNG_BASE64`
2. Decodes base64 QRNG data
3. Derives a 256-bit key by hashing: `SHA-256("qrng-demo-v1" || qrng_bytes || os_urandom(32))`
4. Encrypts a message using AES-GCM
5. Outputs nonce, ciphertext, and key fingerprint

### Usage Instructions

#### Basic Usage:

```bash
# Set QRNG data in environment variable
export SRNG_BASE64="<your_base64_encoded_qrng_data>"

# Run the demo
python3 qrng_seed_demo.py
```

#### Using .env file:

The script automatically loads a `.env` file from the same directory:

```bash
# Create .env file
echo "SRNG_BASE64=<your_base64_encoded_qrng_data>" > .env

# Run the demo
python3 qrng_seed_demo.py
```

### Expected Output

- Nonce (hexadecimal)
- Ciphertext preview (hexadecimal, truncated)
- Key fingerprint (SHA-256 hash of the key)
- Explanation of why brute-force fails

### Key Differences from Other Scripts

- **Simpler**: No brute-force attack, just demonstrates proper key derivation
- **Single Mode**: Only shows QRNG case (no weak entropy comparison)
- **Educational**: Focuses on explaining the security properties

---

## 3. `rsa_shared_prime_entropy_demo.py` - RSA Key Generation Entropy Demo

### What It Does

This demo illustrates how weak entropy in RSA key generation can lead to catastrophic security failures. It generates multiple RSA public keys using two different entropy sources and scans for shared prime factors.

### Key Features

- **RSA Key Generation**: Generates RSA public moduli (n = p × q) using weak vs. QRNG entropy
- **Shared Factor Detection**: Uses GCD (Greatest Common Divisor) to find keys that share prime factors
- **Vulnerability Analysis**: Counts how many keys are compromised due to prime reuse
- **Safe Demo**: Only generates public material (no private keys, no decryption)

### How It Works

1. **Weak Entropy Mode**:
   - Generates RSA keys where prime `p` is derived from a tiny seed space (e.g., 12 bits)
   - Prime `q` varies per key but still uses weak entropy
   - Many keys end up sharing the same prime `p`, making them vulnerable

2. **QRNG Entropy Mode**:
   - Generates RSA keys where both primes are derived from 256-byte QRNG data
   - Each key gets unique, high-entropy seed material via HKDF
   - Keys should have no shared factors

3. **Vulnerability Scan**:
   - Computes GCD(n₁, n₂) for all pairs of keys
   - If GCD > 1 and < min(n₁, n₂), both keys share a prime factor and are compromised
   - Reports vulnerable key counts and examples

### Usage Instructions

#### Basic Usage:

```bash
# Set QRNG data
export QRNG_B64="<your_base64_encoded_256_bytes_of_qrng_data>"

# Run the demo
python3 rsa_shared_prime_entropy_demo.py
```

#### Using STDIN:

```bash
echo "<qrng_base64_data>" | python3 rsa_shared_prime_entropy_demo.py --qrng-stdin
```

#### Customizing Parameters:

```bash
# Generate more keys (default: 200)
python3 rsa_shared_prime_entropy_demo.py --count 500

# Use larger RSA moduli (default: 512 bits - DEMO ONLY, not secure)
python3 rsa_shared_prime_entropy_demo.py --bits 1024

# Adjust weak seed space (default: 12 bits = 4096 possibilities)
python3 rsa_shared_prime_entropy_demo.py --seed-space-bits 10

# Show more example findings
python3 rsa_shared_prime_entropy_demo.py --max-findings 20

# Combine options
python3 rsa_shared_prime_entropy_demo.py \
  --qrng-stdin \
  --count 300 \
  --bits 512 \
  --seed-space-bits 14
```

#### Command-Line Arguments:

- `--count <number>`: Number of keys to generate per mode (default: 200)
- `--bits <number>`: RSA modulus size in bits (default: 512, must be even and ≥256)
- `--seed-space-bits <number>`: Weak seed space size in bits (default: 12)
- `--qrng-stdin`: Read QRNG base64 from STDIN
- `--qrng-env <name>`: Environment variable name (default: QRNG_B64)
- `--max-findings <number>`: Maximum example findings to print (default: 10)

### Expected Output

1. **Generation Phase**:
   - Time to generate weak keys
   - Time to generate QRNG keys

2. **Weak Keys Scan**:
   - Number of vulnerable keys (keys sharing prime factors)
   - Example shared-factor pairs
   - Prime fingerprint collisions (showing repeated primes)

3. **QRNG Keys Scan**:
   - Should show 0 vulnerable keys
   - Confirms no shared factors

4. **Summary**:
   - Explains the security implications

### Security Implications

If two RSA keys share a prime factor:
- Both private keys can be recovered from the public moduli
- This is a catastrophic failure that compromises both keys
- Weak entropy makes this likely in real-world scenarios (e.g., devices booted at similar times)

---

## 4. `weak_seed_bruteforce_demo.py` - Simple Weak Seed Brute-Force Demo

### What It Does

This is a simplified demonstration of how weak, guessable seeds can be brute-forced to recover encrypted data. It's similar to `entropy_effectiveness_demo.py` but simpler and more focused.

### Key Features

- **Timestamp-Based Seed**: Uses current UNIX timestamp as a weak seed
- **Brute-Force Attack**: Attempts to recover the seed within a time window
- **Simple KDF**: Uses SHA-256 for key derivation (simpler than HKDF)
- **Educational**: Shows the attack process step-by-step

### How It Works

1. **Encryption**:
   - Uses current timestamp as seed
   - Derives 256-bit key: `SHA-256("demo-v1" || seed_bytes)`
   - Encrypts a message with AES-GCM

2. **Attack**:
   - Assumes seed is a timestamp near current time
   - Tries all seeds in [now - window, now + window]
   - Attempts decryption with each candidate key
   - Reports success when plaintext is recovered

### Usage Instructions

#### Basic Usage:

```bash
# Run the demo (uses timestamp-based weak seed)
python3 weak_seed_bruteforce_demo.py
```

#### Using .env file:

The script can use a `.env` file (though the main demo uses timestamps):

```bash
# Create .env file if needed
echo "SRNG_BASE64=<qrng_data>" > .env

# Run the demo
python3 weak_seed_bruteforce_demo.py
```

### Code Configuration

The script has a `time_demo` flag that can be toggled:
- `time_demo = True`: Uses timestamp-based weak seed (default)
- `time_demo = False`: Attempts to use QRNG from environment (experimental)

### Expected Output

1. **Defender Output**:
   - Actual seed used (timestamp)
   - Nonce (hexadecimal)
   - Ciphertext preview (hexadecimal)

2. **Attacker Output**:
   - Recovered seed
   - Recovered plaintext
   - Time taken for brute-force

### Key Differences from `entropy_effectiveness_demo.py`

- **Simpler**: No QRNG comparison, just weak seed attack
- **Basic KDF**: Uses SHA-256 instead of HKDF
- **Single Mode**: Only demonstrates the weak case
- **Educational**: Good for understanding the basic attack concept

---

## Common Requirements

All scripts require:

1. **Python 3.10+** (for type hints and modern features)
2. **cryptography library**: Install with `pip install cryptography`
3. **python-dotenv** (for some scripts): Install with `pip install python-dotenv`

### Installation:

```bash
pip install cryptography python-dotenv
```

## QRNG Data Format

All scripts that use QRNG data expect:
- **Base64-encoded** binary data
- **At least 256 bytes** of raw QRNG data (2048 bits)
- Can be provided via:
  - Environment variable (default: `QRNG_B64` or `SRNG_BASE64`)
  - STDIN (with `--qrng-stdin` flag)

### Example QRNG Data:

```bash
# Generate test QRNG data (for testing only - not real QRNG!)
python3 -c "import base64, os; print(base64.b64encode(os.urandom(256)).decode())"
```

## Security Notes

⚠️ **Important**: These are demonstration scripts for educational purposes:

1. **Not Production Code**: These demos are simplified for clarity
2. **Demo RSA Sizes**: RSA keys use small sizes (512 bits) - NOT secure for real use
3. **Safe Harness**: Scripts include safety features to prevent misuse
4. **No Real Attacks**: The brute-force attacks are constrained and educational

## Recommended Workflow

1. **Start Simple**: Run `weak_seed_bruteforce_demo.py` to understand basic concepts
2. **Compare Entropy**: Run `entropy_effectiveness_demo.py` to see the difference
3. **Understand RSA**: Run `rsa_shared_prime_entropy_demo.py` for RSA-specific issues
4. **Practice QRNG**: Use `qrng_seed_demo.py` to understand proper key derivation

## Troubleshooting

### "No QRNG data provided"
- Set the appropriate environment variable (`QRNG_B64` or `SRNG_BASE64`)
- Or use `--qrng-stdin` to pipe data from STDIN

### "Bad QRNG base64"
- Ensure your QRNG data is valid base64
- Ensure it decodes to at least 256 bytes

### Attack fails unexpectedly
- Try increasing the `--window` parameter
- Check that system time is correct

### Import errors
- Install required packages: `pip install cryptography python-dotenv`

