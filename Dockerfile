# Multi-stage Dockerfile for GhidRift
# Stage 1: Base system with dependencies
FROM ubuntu:24.04 AS base

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    jq \
    openjdk-21-jdk \
    openjdk-21-jdk-headless \
    openjdk-21-source \
    python3 \
    python3-pip \
    python3-venv \
    git \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set Java environment with debugging
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH
ENV JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8"

# Stage 2: Install Rust toolchain
FROM base AS rust-installer

# Install rustup and set up Rust environment
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH=/opt/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path \
    && chmod -R a+w $RUSTUP_HOME $CARGO_HOME

# Stage 3: Install Ghidra
FROM rust-installer AS ghidra-installer

# Download and install Ghidra (with proper filename discovery)
ARG GHIDRA_VERSION=11.3.1
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Copy install script and try to copy releases directory
COPY docker/install-ghidra.sh /tmp/install-ghidra.sh
RUN chmod +x /tmp/install-ghidra.sh

# Copy the entire context for selective processing in install script
COPY . /tmp/build-context/

# Run Ghidra installation script
RUN /tmp/install-ghidra.sh ${GHIDRA_VERSION} ${GHIDRA_INSTALL_DIR}

# Ensure Ghidra scripts directory exists and has proper permissions
RUN mkdir -p $GHIDRA_INSTALL_DIR/Ghidra/Features/Base/ghidra_scripts && \
    chmod -R 755 $GHIDRA_INSTALL_DIR

# Stage 4: Final application stage
FROM ghidra-installer AS ghidrift

# Create non-root user for security
RUN useradd -m -s /bin/bash ghidrift && \
    usermod -aG sudo ghidrift

# Set up application directory
WORKDIR /app

# Copy application files
COPY . /app/

# Install Python dependencies (Ubuntu 24.04 requires --break-system-packages in containers)
RUN python3 -m pip install --break-system-packages --no-cache-dir -r requirements.txt && \
    python3 -m pip install --break-system-packages --no-cache-dir -e .

# Copy GhidRift scripts to Ghidra installation (exclude problematic TestScript)
RUN cp /app/ghidra_scripts/GhidRift_ExtractMetadata.java $GHIDRA_INSTALL_DIR/Ghidra/Features/Base/ghidra_scripts/ && \
    chmod 644 $GHIDRA_INSTALL_DIR/Ghidra/Features/Base/ghidra_scripts/GhidRift_*.java && \
    echo "Debug: Verifying script installation..." && \
    ls -la $GHIDRA_INSTALL_DIR/Ghidra/Features/Base/ghidra_scripts/GhidRift_*.java && \
    echo "Debug: Java version check..." && \
    java -version && javac -version

# Create working directory for container operations
RUN mkdir -p /workdir && \
    chown -R ghidrift:ghidrift /workdir && \
    chown -R ghidrift:ghidrift /app && \
    chown -R ghidrift:ghidrift $RUSTUP_HOME && \
    chown -R ghidrift:ghidrift $CARGO_HOME && \
    chown -R ghidrift:ghidrift $GHIDRA_INSTALL_DIR

# Create entrypoint script
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Switch to non-root user
USER ghidrift

# Set up environment variables
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH=/opt/cargo/bin:$PATH
ENV PYTHONPATH=/app:$PYTHONPATH

# Set working directory for user operations
WORKDIR /workdir

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command
CMD ["--help"]
