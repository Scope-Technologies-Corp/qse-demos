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

# Build NIST STS binary
WORKDIR /app/sts-2.1.2
RUN make

# Build Dieharder binary
WORKDIR /app
RUN if [ ! -d "dieharder" ]; then \
        git clone https://github.com/eddelbuettel/dieharder.git; \
    fi

WORKDIR /app/dieharder
RUN rm -rf .git && \
    ./autogen.sh && \
    ./configure --prefix=/usr/local && \
    make

# Runtime stage
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libgsl27 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python dependencies
# Try common paths for Python site-packages
COPY --from=builder /usr/local/lib/python3.10/dist-packages /usr/local/lib/python3.10/dist-packages
COPY --from=builder /usr/local/lib/python3/dist-packages /usr/local/lib/python3/dist-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Reinstall Python packages in runtime stage (simpler and more reliable)
COPY --from=builder /app/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY --from=builder /app/web_demo_app.py .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
COPY --from=builder /app/*.py ./
COPY --from=builder /app/start_web_demo.sh .

# Copy built binaries
COPY --from=builder /app/sts-2.1.2/assess ./sts-2.1.2/assess
COPY --from=builder /app/dieharder/dieharder/dieharder ./dieharder/dieharder/dieharder

# Copy STS and Dieharder scripts and directories
COPY --from=builder /app/sts-2.1.2/*.py ./sts-2.1.2/
COPY --from=builder /app/sts-2.1.2/*.sh ./sts-2.1.2/
COPY --from=builder /app/sts-2.1.2/templates ./sts-2.1.2/templates
COPY --from=builder /app/dieharder/*.py ./dieharder/
COPY --from=builder /app/dieharder/*.sh ./dieharder/

# Create necessary directories
RUN mkdir -p \
    sts-2.1.2/entropy-streams \
    sts-2.1.2/data \
    sts-2.1.2/sts-results \
    dieharder/entropy-streams \
    dieharder/data \
    dieharder/dieharder-results

# Expose port (default 5001, but app finds free port)
EXPOSE 5001

# Set Python to unbuffered mode
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python3", "web_demo_app.py"]
