# QSE Demos Dockerfile
# Multi-stage build for efficient image size

FROM ubuntu:22.04 AS builder

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    libgsl-dev \
    git \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Save our custom dieharder scripts before we remove and clone dieharder
RUN mkdir -p /tmp/dieharder_custom_scripts && \
    if [ -d "dieharder" ]; then \
        echo "Found dieharder directory, saving custom scripts..."; \
        cp dieharder/*.py /tmp/dieharder_custom_scripts/ 2>/dev/null || echo "No .py files found"; \
        cp dieharder/*.sh /tmp/dieharder_custom_scripts/ 2>/dev/null || echo "No .sh files found"; \
        cp dieharder/.gitignore /tmp/dieharder_custom_scripts/ 2>/dev/null || echo "No .gitignore found"; \
        echo "Saved $(ls /tmp/dieharder_custom_scripts/ 2>/dev/null | wc -l) custom script files:"; \
        ls -la /tmp/dieharder_custom_scripts/ 2>/dev/null || echo "No files saved"; \
    else \
        echo "WARNING: dieharder directory not found - scripts may not be in build context"; \
    fi

# Build NIST STS binary
# Remove any pre-built binary from host (may be macOS/Windows binary)
WORKDIR /app/sts-2.1.2
RUN rm -f assess && \
    make clean 2>/dev/null || true && \
    make && \
    chmod +x assess && \
    if [ ! -f "assess" ]; then \
        echo "ERROR: assess binary not found after make!"; \
        exit 1; \
    fi && \
    file assess && \
    ls -lh assess && \
    # Verify it's a Linux ELF binary (not macOS/Windows)
    if ! file assess | grep -q "ELF.*executable"; then \
        echo "ERROR: Built binary is not a Linux ELF executable!"; \
        echo "Binary type: $(file assess)"; \
        echo "This means the binary was not built correctly in Docker."; \
        exit 1; \
    fi && \
    echo "✅ STS assess binary built successfully (Linux ELF)"

# Build Dieharder binary
WORKDIR /app
RUN rm -rf dieharder && \
    git clone https://github.com/eddelbuettel/dieharder.git && \
    cd dieharder && \
    rm -rf .git && \
    test -d libdieharder && test -d include && \
    libtoolize --force --copy || true && \
    autoreconf -f -i && \
    ./configure --prefix=/usr/local && \
    make
# Copy our custom scripts into the cloned dieharder directory
WORKDIR /app/dieharder
RUN echo "Restoring custom scripts from /tmp/dieharder_custom_scripts/..." && \
    if [ -d "/tmp/dieharder_custom_scripts" ] && [ "$(ls -A /tmp/dieharder_custom_scripts 2>/dev/null)" ]; then \
        cp /tmp/dieharder_custom_scripts/*.py . 2>/dev/null && \
        cp /tmp/dieharder_custom_scripts/*.sh . 2>/dev/null && \
        cp /tmp/dieharder_custom_scripts/.gitignore . 2>/dev/null || true && \
        chmod +x *.sh 2>/dev/null && \
        echo "✅ Restored custom scripts. Files in dieharder:" && \
        ls -la *.py *.sh 2>/dev/null | head -10; \
    else \
        echo "ERROR: No custom scripts found in /tmp/dieharder_custom_scripts/"; \
        echo "This means scripts were not saved before cloning dieharder"; \
        exit 1; \
    fi
WORKDIR /app

# Runtime stage
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libgsl27 \
    libc6 \
    file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Reinstall Python packages in runtime stage (simpler and more reliable)
COPY --from=builder /app/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY --from=builder /app/web_demo_app.py .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
COPY --from=builder /app/*.py ./
COPY --from=builder /app/start_web_demo.sh .

# Copy built binaries with executable permissions preserved
COPY --from=builder --chmod=755 /app/sts-2.1.2/assess ./sts-2.1.2/assess
# Verify STS binary
RUN if [ ! -f "./sts-2.1.2/assess" ]; then \
        echo "ERROR: assess binary not found after copy!"; \
        exit 1; \
    fi && \
    # Ensure executable permissions
    chmod +x ./sts-2.1.2/assess && \
    # Verify file type
    echo "File type:" && \
    file ./sts-2.1.2/assess && \
    echo "File permissions:" && \
    ls -lh ./sts-2.1.2/assess && \
    # Verify it's a Linux ELF binary
    if ! file ./sts-2.1.2/assess | grep -q "ELF.*executable"; then \
        echo "ERROR: assess is not a valid Linux ELF executable!"; \
        file ./sts-2.1.2/assess; \
        exit 1; \
    fi && \
    # Check shared library dependencies
    echo "Checking shared library dependencies:" && \
    (ldd ./sts-2.1.2/assess 2>&1 || echo "Note: ldd check completed") && \
    echo "✅ STS assess binary verified and made executable"
# Copy dieharder binary and its shared library
COPY --from=builder /app/dieharder/dieharder/.libs/dieharder ./dieharder/dieharder/dieharder
COPY --from=builder /app/dieharder/libdieharder/.libs/libdieharder.so* ./dieharder/libdieharder/.libs/

# Copy STS and Dieharder scripts and directories
COPY --from=builder /app/sts-2.1.2/*.py ./sts-2.1.2/
COPY --from=builder /app/sts-2.1.2/*.sh ./sts-2.1.2/
COPY --from=builder /app/sts-2.1.2/templates ./sts-2.1.2/templates
# Copy experiments directory structure from local (needed for STS binary)
COPY --from=builder /app/sts-2.1.2/experiments ./sts-2.1.2/experiments
# Copy dieharder custom scripts from builder stage
# Create dieharder directory first
RUN mkdir -p dieharder
# Copy our custom scripts explicitly (will fail build if missing, which is good)
COPY --from=builder /app/dieharder/compare_dieharder_results.py ./dieharder/
COPY --from=builder /app/dieharder/generate_scorecard.py ./dieharder/
COPY --from=builder /app/dieharder/parse_dieharder_report.py ./dieharder/
COPY --from=builder /app/dieharder/render_scorecard_html.py ./dieharder/
COPY --from=builder /app/dieharder/run_pipeline_auto.sh ./dieharder/
# Make scripts executable and verify
RUN chmod +x dieharder/*.sh dieharder/*.py && \
    if [ ! -f "dieharder/run_pipeline_auto.sh" ]; then \
        echo "ERROR: run_pipeline_auto.sh not found after copy!"; \
        exit 1; \
    fi && \
    echo "✅ Dieharder custom scripts verified: $(ls dieharder/*.py dieharder/*.sh 2>/dev/null | wc -l) files"

# Create necessary directories
RUN mkdir -p \
    sts-2.1.2/entropy-streams \
    sts-2.1.2/data \
    sts-2.1.2/sts-results \
    sts-2.1.2/experiments/AlgorithmTesting \
    dieharder/entropy-streams \
    dieharder/data \
    dieharder/dieharder-results \
    dieharder/libdieharder/.libs && \
    # Ensure experiments directory has write permissions
    chmod -R 755 sts-2.1.2/experiments

# Expose port (default 5001, but app finds free port)
EXPOSE 5001

# Set Python to unbuffered mode
ENV PYTHONUNBUFFERED=1
# Set library path for dieharder
ENV LD_LIBRARY_PATH=/app/dieharder/libdieharder/.libs
ENV PORT=5001
ENV FLASK_ENV=production
# Run the application
CMD ["python3", "web_demo_app.py"]
