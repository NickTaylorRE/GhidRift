# GhidRift Docker Documentation

This document provides comprehensive instructions for using GhidRift in Docker containers, which isolates Rust toolchain installations and keeps your host Ghidra installation clean.

## Quick Start

### Build the Container
```bash
# Build with default Ghidra version (11.4)
docker build -t ghidrift/analyzer .

# Build with specific Ghidra version
docker build --build-arg GHIDRA_VERSION=11.3.1 -t ghidrift/analyzer .

# Or use docker-compose
docker-compose build

# Build specific version with docker-compose
docker-compose build --build-arg GHIDRA_VERSION=11.3.1
```

### Basic Usage
```bash
# Analyze a Rust binary (complete pipeline) - copies binary in, processes, copies results out (both FIDB and BSIM by default)
docker run -v $(pwd):/workdir ghidrift/analyzer full my_rust_binary

# Extract metadata only - copies binary in, extracts metadata, copies metadata out
docker run -v $(pwd):/workdir ghidrift/analyzer extract my_rust_binary

# Generate signatures from existing metadata - copies metadata in, processes, copies .fidb/.bsim out (both by default)
docker run -v $(pwd):/workdir ghidrift/analyzer analyze metadata.json
```

## Ghidra Version Management

### Supported Versions
The container supports any Ghidra version available on GitHub releases. The build process automatically discovers the correct download filename for the specified version.

**Common versions:**
- `11.4` (default) - Latest stable release
- `11.3.1` - Previous stable release  
- `11.2` - Older stable release
- `11.1.2` - LTS-compatible release

### Version Compatibility
```bash
# For maximum compatibility, use 11.3.1
docker build --build-arg GHIDRA_VERSION=11.3.1 -t ghidrift/analyzer .

# For latest features, use default (11.4)
docker build -t ghidrift/analyzer .

# Check what version is in your container
docker run ghidrift/analyzer shell
# Inside container: $GHIDRA_INSTALL_DIR/ghidraRun -version
```

## Container Workflow: Copy-In/Copy-Out

GhidRift uses a **copy-in/copy-out** approach for complete isolation:

1. **Copy-In**: Your binary/metadata files are copied INTO the container's isolated workspace (`/tmp/analysis/`)
2. **Process**: All analysis happens within the container using isolated Rust toolchains and Ghidra
3. **Copy-Out**: Results (.fidb, .bsim files) are copied back to your host directory

### Benefits of This Approach
- **Complete Isolation**: No shared state between container and host during processing
- **Clean Workspace**: Each analysis starts with a fresh container environment  
- **No Permission Issues**: Files are owned correctly after copy-out
- **Reproducible**: Same input always produces same output regardless of host state

### File Flow Example
```bash
# Input: /path/to/my_binary
docker run -v /path/to:/workdir ghidrift/analyzer full /workdir/my_binary --fid

# What happens inside:
# 1. Copy: /workdir/my_binary → /tmp/analysis/my_binary  
# 2. Process: Extract metadata, download Rust toolchains, generate signatures
# 3. Copy out: /tmp/analysis/FIDB/ → /workdir/FIDB/
# 4. Copy out: /tmp/analysis/my_binary.json → /workdir/my_binary.json
```

## Container Architecture

### Isolation Benefits
- **Rust Toolchains**: All `rustup` installations are contained within `/opt/rustup` and `/opt/cargo`
- **Ghidra Installation**: Self-contained in `/opt/ghidra` with GhidRift scripts pre-installed
- **User Data**: Your files remain in the mounted `/workdir` directory
- **No Host Pollution**: No scripts added to your host Ghidra installation

### Directory Structure
```
Container Layout:
├── /opt/ghidra/              # Isolated Ghidra installation
│   └── Ghidra/Features/Base/ghidra_scripts/  # GhidRift scripts pre-installed
├── /opt/rustup/              # Isolated rustup installation
├── /opt/cargo/               # Isolated cargo home
├── /app/                     # GhidRift application code
└── /workdir/                 # Mounted user directory (your files)
```

## Usage Patterns

### 1. Single Binary Analysis
```bash
# Complete analysis with both signatures (default behavior)
docker run -v $(pwd):/workdir ghidrift/analyzer full binary.exe

# Complete analysis with only FunctionID signatures
docker run -v $(pwd):/workdir ghidrift/analyzer full binary.exe --fid

# Complete analysis with only BSIM signatures
docker run -v $(pwd):/workdir ghidrift/analyzer full binary.exe --bsim

# With verbose logging (still generates both by default)
docker run -v $(pwd):/workdir ghidrift/analyzer full binary.exe --verbose
```

### 2. Two-Step Process
```bash
# Step 1: Extract metadata
docker run -v $(pwd):/workdir ghidrift/analyzer extract my_rust_app

# Step 2: Generate signatures (produces both .fidb and .bsim files by default)
docker run -v $(pwd):/workdir ghidrift/analyzer analyze my_rust_app.json
```

### 3. Interactive Development
```bash
# Start interactive shell
docker run -it -v $(pwd):/workdir ghidrift/analyzer shell

# Inside container:
ghidrift-cli metadata.json --fid --verbose
rustup toolchain list
ls /opt/ghidra
```

### 4. Batch Processing with Docker Compose
```bash
# Set up directories
mkdir -p input output

# Copy your binaries to input/
cp *.exe input/

# Start batch processing service
docker-compose up ghidrift-batch

# Process multiple files
docker-compose exec ghidrift-batch bash -c "
for binary in input/*.exe; do
  echo Processing \$binary...
  /usr/local/bin/entrypoint.sh full \$binary --fid
  mv *.json *.fidb output/ 2>/dev/null || true
done"
```

## Docker Compose Services

### Default Service (`ghidrift`)
```bash
# Interactive shell
docker-compose run ghidrift

# Run specific command
docker-compose run ghidrift full binary.exe --fid
```

### GUI Service (`ghidrift-gui`)
```bash
# Launch Ghidra GUI (requires X11 forwarding on Linux)
xhost +local:docker
docker-compose up ghidrift-gui
```

### Batch Service (`ghidrift-batch`)
```bash
# For processing multiple files
docker-compose up ghidrift-batch
```

## Advanced Configuration

### Persistent Data Volumes
The docker-compose setup includes persistent volumes for:
- `ghidrift-rustup`: Rust toolchain installations
- `ghidrift-cargo`: Cargo cache and registry
- `ghidrift-ghidra-user`: Ghidra user preferences

```bash
# View persistent volumes
docker volume ls | grep ghidrift

# Clean up volumes (removes all cached toolchains)
docker-compose down -v
```


### Direct CLI Access
```bash
# Use ghidrift-cli directly with any arguments
docker run -v $(pwd):/workdir ghidrift/analyzer \
  cli metadata.json --fid --output custom_dir/
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `GHIDRA_INSTALL_DIR` | `/opt/ghidra` | Ghidra installation path |
| `RUSTUP_HOME` | `/opt/rustup` | Rustup installation directory |
| `CARGO_HOME` | `/opt/cargo` | Cargo home directory |
| `DISPLAY` | `:0` | X11 display for GUI mode |

## Output Files

### Generated Files Structure
```
your_project/
├── my_rust_binary          # Original binary
├── my_rust_binary.json     # Extracted metadata
├── coff/                   # Extracted object files
│   ├── toolchain/          # Rust standard library objects
│   └── crates/             # Third-party crate objects
└── FIDB/                   # Generated signature databases  
    ├── rust_combined.fidb  # Combined FunctionID database
    └── rust_signatures.bsim # BSIM database (if --bsim used)
```

### Using Generated Signatures

#### FunctionID Signatures
```bash
# Copy to your host Ghidra installation (outside container)
cp FIDB/*.fidb $YOUR_GHIDRA_DIR/Ghidra/Features/FunctionID/data/

# Then in Ghidra CodeBrowser:
# 1. Open your Rust binary
# 2. Analysis -> One Shot -> Function ID  
# 3. Select rust_combined signature library
```

#### BSIM Database
```bash
# Use with GhidRift_ApplyBSIMSignatures.java script
# The script is already installed in the container's Ghidra
```

## Troubleshooting

### Common Issues

#### 1. Permission Errors
```bash
# Ensure proper ownership of output files
docker run -v $(pwd):/workdir ghidrift/analyzer shell
# Inside container: ls -la /workdir
```

#### 2. X11 Forwarding (GUI Mode)
```bash
# On Linux host:
xhost +local:docker
export DISPLAY=:0

# On macOS with XQuartz:
# Install XQuartz, then:
xhost +localhost
export DISPLAY=host.docker.internal:0
```

#### 3. Large Binary Analysis
```bash
# Increase memory
docker run -m 8g -v $(pwd):/workdir ghidrift/analyzer \
  full large_binary.exe --fid
```

#### 4. Network Issues (Rust Downloads)
```bash
# If behind corporate firewall, you may need:
docker run --network=host -v $(pwd):/workdir ghidrift/analyzer \
  full binary.exe --fid
```

### Debug Mode
```bash
# Enable debug logging and start shell
docker run -it -v $(pwd):/workdir -e GHIDRIFT_DEBUG=1 \
  ghidrift/analyzer shell

# Inside container:
python3 -c "import logging; logging.basicConfig(level=logging.DEBUG)"
ghidrift-cli metadata.json --fid --verbose
```

## Container Maintenance

### Updating the Container
```bash
# Rebuild with latest changes
docker-compose build --no-cache

# Pull latest base images
docker pull ubuntu:22.04
docker-compose build
```

### Cleaning Up
```bash
# Remove containers and images
docker-compose down
docker rmi ghidrift/analyzer

# Clean up volumes (removes cached toolchains)
docker-compose down -v

# Clean up all Docker resources
docker system prune -a
```

## Integration Examples

### CI/CD Pipeline
```yaml
# .github/workflows/rust-analysis.yml
name: Rust Binary Analysis
on: [push]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Analyze Rust Binary
        run: |
          docker run -v $(pwd):/workdir ghidrift/analyzer \
            full target/release/my_app --fid --bsim
      - name: Upload Signatures
        uses: actions/upload-artifact@v3
        with:
          name: signatures
          path: FIDB/
```

### Makefile Integration
```makefile
# Makefile
BINARY ?= target/release/my_app

.PHONY: analyze
analyze:
	docker run -v $(PWD):/workdir ghidrift/analyzer full $(BINARY) --fid

.PHONY: extract  
extract:
	docker run -v $(PWD):/workdir ghidrift/analyzer extract $(BINARY)

.PHONY: signatures
signatures: $(BINARY).json
	docker run -v $(PWD):/workdir ghidrift/analyzer analyze $< --fid --bsim
```

This Docker setup provides complete isolation while maintaining ease of use for Rust reverse engineering workflows.