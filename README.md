# GhidRift

A Ghidra-based tool for enhanced Rust malware analysis through pattern matching and function identification. GhidRift is a recreation of Microsoft's [RIFT (Rust Interactive Function Tool)](https://github.com/microsoft/RIFT) for Ghidra, with some design decisions made which match Ghidra's available tooling.

## Overview

GhidRift enhances Rust binary analysis by leveraging Ghidra's advanced features including FunctionID signatures and BSIM (Binary Similarity Database) for comprehensive function identification and matching. RIFT uses IDA Pro with FLIRT signatures and Diaphora diffing. GhidRift integrates natively with Ghidra's FunctionID signatures and BSIM similarity analysis systems.

## Key Features

- **Rust Metadata Extraction**: Automatically identifies Rust compiler version, target architecture, and crate dependencies
- **FunctionID Signature Generation**: Creates Ghidra-compatible signatures from Rust standard library and popular crates
- **BSIM Integration**: Leverages Ghidra's Binary Similarity Database for advanced function matching and similarity analysis
- **Automated Workflow**: Streamlined process from binary analysis to function identification and annotation

## Architecture Comparison with RIFT

| Component | RIFT (IDA Pro) | GhidRift (Ghidra) |
|-----------|----------------|-------------------|
| **Signature System** | FLIRT signatures (.sig) | FunctionID signatures |
| **Similarity Analysis** | Diaphora + SQLite | BSIM Database |
| **Primary Interface** | IDA Pro Plugin | Ghidra Script/Plugin |
| **Pattern Matching** | Byte-pattern + Fuzzy | FunctionID + BSIM similarity |
| **Performance** | FLIRT (fast) + Diaphora (slow) | FunctionID (fast) + BSIM (optimized) |
| **Integration** | External tools pipeline | Native Ghidra integration |

## Docker Usage (Recommended)

GhidRift provides a Docker container for easy deployment and usage. This is the recommended way to use GhidRift as it handles all dependencies and environment setup automatically.

### Quick Start

1. **Build the container**:
   ```bash
   # Build using docker compose (recommended)
   docker compose build ghidrift
   ```

2. **Prepare your workspace**:
   ```bash
   # Create working directory and copy your Rust binary
   mkdir ~/ghidrift-analysis
   cp /path/to/your/rust_binary ~/ghidrift-analysis/
   cd ~/ghidrift-analysis

   # Set directory permissions to allow container to write output files
   chmod 777 .
   ```

3. **Run analysis** (generates both FIDB and BSIM signatures by default):
   ```bash
   docker run -v $(pwd):/workdir ghidrift/analyzer extract rust_binary
   ```

**IMPORTANT**: The binary file must be in the directory you mount as `/workdir`. The container cannot access files outside the mounted directory.

### Available Commands

```bash
# Complete analysis: extract metadata + generate both signature types (default)
docker run -v $(pwd):/workdir ghidrift/analyzer extract <binary_name>

# Generate only FunctionID signatures
docker run -v $(pwd):/workdir ghidrift/analyzer extract <binary_name> --fid

# Generate only BSIM signatures
docker run -v $(pwd):/workdir ghidrift/analyzer extract <binary_name> --bsim

# Analyze existing metadata file
docker run -v $(pwd):/workdir ghidrift/analyzer analyze metadata.json

# Interactive shell for debugging
docker run -it -v $(pwd):/workdir ghidrift/analyzer shell
```

### Example: Analyzing a Rust Binary

```bash
# Prepare workspace
mkdir ~/rust-binary-analysis
cd ~/rust-binary-analysis

# Copy binary (REQUIRED - must be in mounted directory)
cp ~/path/to/rust_binary .

# Set directory permissions (REQUIRED - allows container to write files)
chmod 777 .

# Run complete analysis
docker run -v $(pwd):/workdir ghidrift/analyzer extract rust_binary

# Check results
ls -la
# Expected output:
# rust_binary                    (original binary)
# rust_binary_metadata.json     (extracted Rust metadata)
# *.fidb                         (FunctionID signature files)
# rust_signatures.bsim*          (BSIM database files)
# coff/                          (extracted Rust object files)
```

### Using Generated Signatures

#### FunctionID Signatures (.fidb files)
```bash
# Copy FIDB files to Ghidra
cp *.fidb $GHIDRA_INSTALL_DIR/Ghidra/Features/FunctionID/data/

# In Ghidra CodeBrowser:
# 1. Open your Rust binary
# 2. Run Analysis → One Shot → Function ID
# 3. Select the generated signature libraries
```

#### BSIM Database (.bsim files)
```bash
# Use GhidRift_ApplyBSIMSignatures.java script in Ghidra:
# 1. Open your Rust binary in Ghidra
# 2. Run the GhidRift_ApplyBSIMSignatures script
# 3. Browse to your rust_signatures.bsim file
# 4. Review and apply function matches
```

## Installation (Non-Docker)

For users who prefer not to use Docker or need to integrate GhidRift into existing workflows:

```bash
# Clone the repository
git clone https://github.com/yourusername/GhidRift.git
cd GhidRift

# Install Python dependencies
pip install -r requirements.txt

# Copy Ghidra script to your Ghidra scripts directory
cp ghidra_scripts/GhidRift_ExtractMetadata.java ~/ghidra_scripts/

# Set Ghidra installation directory
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Run the CLI tool
./ghidrift-cli /path/to/rust_binary --verbose
```

## Contributing

This project is currently in development. Contributions and feedback are welcome once the core functionality is implemented.

## License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

## Acknowledgments

- **Microsoft Research** for creating the original [RIFT project](https://github.com/microsoft/RIFT), which pioneered this approach to Rust binary analysis. GhidRift is a ground-up reimplementation of RIFT's concepts for the Ghidra platform.
- NSA for Ghidra and its powerful analysis capabilities
