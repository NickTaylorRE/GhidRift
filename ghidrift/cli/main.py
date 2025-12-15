#!/usr/bin/env python3
"""
GhidRift CLI - Main entry point for GhidRift Rust reverse engineering toolkit
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ghidrift.core.signature_generator import SignatureGenerator
from ghidrift.core.bsim_manager import BSIMManager
from ghidrift.core.rust_toolchain import RustToolchain


def setup_logging(verbose: bool = False, log_file: Path = None):
    """Setup logging configuration with console and file output"""
    level = logging.DEBUG if verbose else logging.INFO

    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Always capture DEBUG for file

    # Remove any existing handlers
    root_logger.handlers = []

    # Console handler (respects verbose flag)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(simple_formatter)
    root_logger.addHandler(console_handler)

    # File handler (always DEBUG level for troubleshooting)
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, mode='w')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(detailed_formatter)
            root_logger.addHandler(file_handler)
            root_logger.info(f"Debug logging to: {log_file}")
        except Exception as e:
            root_logger.warning(f"Could not create log file {log_file}: {e}")


def generate_signatures(metadata_file: Path, output_dir: Path = None, verbose: bool = False, fid: bool = False, bsim: bool = False, bsim_db: Path = None):
    """
    Generate FunctionID and/or BSIM signatures from metadata file

    Args:
        metadata_file: Path to GhidRift metadata JSON file
        output_dir: Output directory for FIDB files (default: same as metadata file)
        verbose: Enable verbose logging
        fid: Generate FunctionID signatures
        bsim: Generate BSIM signatures
        bsim_db: Path to existing BSIM database
    """
    # Default output directory is same as metadata file
    if output_dir is None:
        output_dir = metadata_file.parent

    output_dir.mkdir(parents=True, exist_ok=True)

    # Set up logging with debug file
    log_file = output_dir / "ghidrift_debug.log"
    setup_logging(verbose, log_file)
    logger = logging.getLogger(__name__)

    logger.info("="*80)
    logger.info("GhidRift Signature Generation Starting")
    logger.info("="*80)
    
    if not metadata_file.exists():
        logger.error(f"Metadata file not found: {metadata_file}")
        return False
    
    # If no specific operation is requested, default to both FID and BSIM
    if not fid and not bsim:
        fid = True
        bsim = True
        logger.info("No specific operation specified - generating both FunctionID and BSIM signatures by default")
    
    # Load metadata to show info
    try:
        with open(metadata_file) as f:
            metadata = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load metadata: {e}")
        return False
    
    # Extract rust version from toolchain directory if not in metadata
    rust_version = metadata.get("rustVersion", "unknown")
    coff_dir = metadata_file.parent / "coff"
    
    if rust_version == "unknown" and coff_dir.exists():
        toolchain_dir = coff_dir / "toolchain"
        if toolchain_dir.exists():
            for dir_name in toolchain_dir.iterdir():
                if dir_name.is_dir() and "-" in dir_name.name:
                    version_part = dir_name.name.split("-")[0]
                    if version_part.replace(".", "").isdigit():
                        rust_version = version_part
                        break
    
    logger.info(f"Processing metadata from: {metadata_file}")
    logger.info(f"Rust Version: {rust_version}")
    logger.info(f"Target Triple: {metadata.get('targetTriple', 'unknown')}")
    logger.info(f"Commit Hash: {metadata.get('commitHash', 'unknown')}")
    logger.info(f"Output Directory: {output_dir}")
    
    # Check if COFF files exist, if not extract them
    if not coff_dir.exists():
        logger.info("COFF directory not found, extracting from Rust toolchain...")
        try:
            # Initialize Rust toolchain manager
            rust_toolchain = RustToolchain(base_dir=output_dir)
            
            # Process metadata to extract COFF files
            toolchain_files, crate_files = rust_toolchain.process_metadata(metadata_file, output_alongside=True)
            
            if not toolchain_files and not crate_files:
                logger.error("Failed to extract COFF files from Rust toolchain")
                return False
                
            logger.info(f"Extracted {len(toolchain_files)} toolchain files and {len(crate_files)} crate files")
            
        except Exception as e:
            logger.error(f"Failed to extract COFF files: {e}")
            return False
    
    # Count COFF files
    coff_count = sum(1 for _ in coff_dir.rglob("*.o")) + sum(1 for _ in coff_dir.rglob("*.obj"))
    logger.info(f"Found {coff_count} COFF/object files to process")
    
    if coff_count == 0:
        logger.warning("No COFF files found - nothing to process")
        return True
    
    # Initialize signature generator with base directory as the metadata file's parent directory
    try:
        base_dir = metadata_file.parent
        sig_gen = SignatureGenerator(base_dir=base_dir)
    except RuntimeError as e:
        logger.error(f"Failed to initialize signature generator: {e}")
        logger.error("Please ensure GHIDRA_INSTALL_DIR is set correctly")
        return False
    
    # Generate Ghidra projects and optionally FunctionID databases
    # Both FID and BSIM need the projects, so we always create them
    if fid:
        logger.info("Processing Rust libraries and creating Ghidra projects for FunctionID...")
    else:
        logger.info("Processing Rust libraries and creating Ghidra projects for BSIM...")
    
    # Always keep projects if BSIM is requested, skip FID if not requested
    fidb_files = sig_gen.generate_from_metadata(metadata_file, output_dir, keep_projects=bsim, skip_fid=(not fid))
    
    # Handle FunctionID results (only report if --fid was used)
    if fid:
        if fidb_files:
            logger.info(f"Successfully generated combined FunctionID database:")
            total_size = 0
            for name, path in fidb_files.items():
                size = path.stat().st_size
                total_size += size
                logger.info(f"  {path.name} ({size:,} bytes)")
            
            logger.info(f"FIDB file saved to: {output_dir}/")
            
            logger.info("")
            logger.info("To use this signature database in Ghidra:")
            logger.info("1. Copy the .fidb file to your Ghidra FunctionID directory:")
            logger.info("   $GHIDRA_INSTALL_DIR/Ghidra/Features/FunctionID/data/")
            logger.info("2. Open your Rust binary in Ghidra CodeBrowser")
            logger.info("3. Run Analysis -> One Shot -> Function ID")
            logger.info("4. Select the rust_combined signature library")
        else:
            logger.error("Failed to generate FunctionID databases")
            return False
    
    # Generate BSIM signatures if requested
    if bsim:
        logger.info("")
        logger.info("Generating BSIM signatures...")
        
        try:
            bsim_mgr = BSIMManager(sig_gen.ghidra_dir, base_dir=base_dir)
            
            # Create or use existing database
            if bsim_db:
                bsim_db_path = bsim_db
                logger.info(f"Using existing BSIM database: {bsim_db_path}")
            else:
                # Use input filename (without extension) for BSIM database name
                db_name = metadata_file.stem
                bsim_db_path = bsim_mgr.create_database(db_name)
                logger.info(f"Created new BSIM database: {bsim_db_path}")
            
            # Use the project info from the signature generator
            if sig_gen.last_project_info:
                project_base = sig_gen.last_project_info['project_base']
                project_name = sig_gen.last_project_info['project_name']
                
                # Add to BSIM database
                sig_gen.generate_bsim_signatures(
                    project_base, project_name, bsim_mgr, bsim_db_path
                )
            else:
                logger.error("No project information available for BSIM processing")
                logger.error("Make sure the FunctionID generation completed successfully")
                return False
            
            logger.info(f"BSIM signatures added to database: {bsim_db_path}")
            logger.info("")
            logger.info("To use BSIM database:")
            logger.info("1. Use Ghidra's BSIM tools to query similar functions")
            logger.info(f"2. Database location: {bsim_db_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate BSIM signatures: {e}")
            return False
        
    
    # If we get here, all requested operations completed successfully
    return True


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="GhidRift - Rust reverse engineering toolkit for Ghidra",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate both FunctionID and BSIM signatures (default behavior)
  ghidrift /path/to/metadata.json
  
  # Generate only FunctionID signatures
  ghidrift /path/to/metadata.json --fid
  
  # Generate only BSIM signatures
  ghidrift /path/to/metadata.json --bsim
  
  # Generate both with custom output directory
  ghidrift /path/to/metadata.json --output /path/to/signatures/
  
  # Use existing BSIM database
  ghidrift /path/to/metadata.json --bsim --bsim-db /path/to/existing.bsim
  
  # Enable verbose logging
  ghidrift /path/to/metadata.json --verbose
        """
    )
    
    parser.add_argument(
        "metadata_file",
        type=Path,
        help="Path to GhidRift metadata JSON file"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output directory for FIDB files (default: same as metadata file)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    
    parser.add_argument(
        "--fid", "--functionid",
        action="store_true",
        dest="fid",
        help="Generate only FunctionID signatures (default: generate both FID and BSIM)"
    )
    
    parser.add_argument(
        "--bsim",
        action="store_true",
        help="Generate only BSIM signatures (default: generate both FID and BSIM)"
    )
    
    parser.add_argument(
        "--bsim-db",
        type=Path,
        help="Path to existing BSIM database (used with --bsim)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="GhidRift 1.0.0 (Phase 4)"
    )
    
    args = parser.parse_args()
    
    # Generate signatures
    success = generate_signatures(
        metadata_file=args.metadata_file,
        output_dir=args.output,
        verbose=args.verbose,
        fid=args.fid,
        bsim=args.bsim,
        bsim_db=args.bsim_db
    )
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()