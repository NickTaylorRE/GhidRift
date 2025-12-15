import argparse
import logging
import sys
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from ghidrift.core.bsim_manager import BSIMManager


def main():
    """Create BSIM database command"""
    parser = argparse.ArgumentParser(
        description="Create BSIM database for Rust function signatures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create new BSIM database in current directory
  python -m ghidrift.create_bsim_db --database rust_sigs
  
  # Create database in specific directory
  python -m ghidrift.create_bsim_db --database rust_sigs --output /path/to/project
  
  # Create database with specific template
  python -m ghidrift.create_bsim_db --database rust_sigs --template medium_32
  
  # Create database with verbose output
  python -m ghidrift.create_bsim_db --database rust_sigs -v
        """
    )
    
    parser.add_argument(
        "--database",
        required=True,
        help="Database name"
    )
    
    parser.add_argument(
        "--output",
        type=Path,
        default=Path.cwd(),
        help="Output directory for database (default: current directory)"
    )
    
    parser.add_argument(
        "--template",
        default="medium_64",
        choices=["medium_64", "medium_32", "medium_nosize"],
        help="BSIM database template (default: medium_64)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Create BSIM manager with output directory as base
        manager = BSIMManager(base_dir=args.output)
        
        # Create database
        db_path = manager.create_database(args.database, args.template)
        
        print(f"Successfully created BSIM database: {db_path}")
        print("")
        print("To use this database:")
        print(f"1. Add signatures: ./ghidrift-cli /path/to/metadata.json --bsim --bsim-db {db_path}")
        print("2. Query with Ghidra's BSIM tools")
        
    except Exception as e:
        logger.error(f"Failed to create BSIM database: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()