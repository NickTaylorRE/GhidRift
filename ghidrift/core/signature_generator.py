"""
FunctionID signature generation for GhidRift
Generates Ghidra FunctionID signatures from Rust object files
"""

import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class SignatureGenerator:
    """Generates FunctionID signatures from Rust object files"""
    
    def __init__(self, ghidra_dir: str = None, work_dir: str = None, base_dir: Path = None):
        """
        Initialize the signature generator
        
        Args:
            ghidra_dir: Path to Ghidra installation
            work_dir: Working directory for signature generation
            base_dir: Base directory for all GhidRift data (defaults to ~/.ghidrift)
        """
        self.ghidra_dir = self._find_ghidra_dir(ghidra_dir)
        if work_dir:
            self.work_dir = Path(work_dir)
        elif base_dir:
            self.work_dir = base_dir / ".ghidrift" / "signatures"
        else:
            self.work_dir = Path.home() / ".ghidrift" / "signatures"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.scripts_copied = False  # Track if scripts have been copied
        self.last_project_info = None  # Track last created project for BSIM
        
        # Paths for signature storage
        self.fid_dir = self.work_dir / "fid"
        self.xml_dir = self.work_dir / "xml"
        self.fidb_dir = self.work_dir / "fidb"
        
        for d in [self.fid_dir, self.xml_dir, self.fidb_dir]:
            d.mkdir(parents=True, exist_ok=True)
    
    def _find_ghidra_dir(self, ghidra_dir: Optional[str]) -> Path:
        """Find Ghidra installation directory"""
        if ghidra_dir:
            return Path(ghidra_dir)
            
        # Check environment variable
        if "GHIDRA_INSTALL_DIR" in os.environ:
            return Path(os.environ["GHIDRA_INSTALL_DIR"])
            
        # Common locations
        common_paths = [
            Path("/opt/ghidra"),
            Path("/usr/local/ghidra"),
            Path.home() / "ghidra",
            Path("/Applications/ghidra") if os.uname().sysname == "Darwin" else None,
        ]
        
        for path in common_paths:
            if path and path.exists() and (path / "Ghidra").exists():
                return path
                
        raise RuntimeError("Could not find Ghidra installation. Please set GHIDRA_INSTALL_DIR")
    
    
    def generate_fidb_from_objects(self, obj_files: List[Path], library_name: str,
                                  rust_version: str, library_version: str, 
                                  output_dir: Optional[Path] = None, keep_project: bool = False,
                                  skip_fid: bool = False) -> Optional[Path]:
        """
        Generate FunctionID database from object files using two-pass Ghidra approach
        
        Args:
            obj_files: List of object files to process
            library_name: Name of the library (e.g., "std", "core", "clap")
            rust_version: Rust compiler version (e.g., "1.85.0")
            library_version: Library version (e.g., "3.2.25")
            output_dir: Output directory for FIDB files
            
        Returns:
            Path to generated FIDB file if successful
        """
        if not obj_files:
            logger.warning("No object files to process")
            return None
            
        # Use provided output dir or default
        if output_dir is None:
            output_dir = self.fidb_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate FIDB filename
        fidb_filename = f"{library_name}_{rust_version}_{library_version}.fidb"
        fidb_path = output_dir / fidb_filename
        
        # Create persistent project for processing (not temporary)
        project_base = self.work_dir / "fid_projects"
        project_base.mkdir(parents=True, exist_ok=True)
        
        project_name = f"fid_{library_name}_{rust_version}_{library_version}"
        
        # Build analyzeHeadless command to import files
        analyze_headless = self.ghidra_dir / "support" / "analyzeHeadless"
        
        # Get script path and verify it exists
        script_path = Path(__file__).parent.parent.parent / "ghidra_scripts"
        if not script_path.exists():
            logger.error(f"Ghidra scripts directory not found: {script_path}")
            return None
            
        # Copy scripts to Ghidra's FunctionID script directory (only once per instance)
        if not self.scripts_copied:
            ghidra_script_dir = self.ghidra_dir / "Ghidra" / "Features" / "FunctionID" / "ghidra_scripts"
            if not ghidra_script_dir.exists():
                logger.error(f"Ghidra FunctionID scripts directory not found: {ghidra_script_dir}")
                return None
                
            # Required scripts to copy
            required_scripts = [
                "FunctionIDHeadlessPrescript.java",
                "FunctionIDHeadlessPostscript.java", 
                "GhidRift_CreateLibraryFidb.java"
            ]
            
            # Copy each required script
            for script in required_scripts:
                source_script = script_path / script
                target_script = ghidra_script_dir / script
                
                if not source_script.exists():
                    logger.error(f"Required script not found: {source_script}")
                    return None
                    
                # Copy script to Ghidra installation
                try:
                    import shutil
                    shutil.copy2(source_script, target_script)
                    logger.debug(f"Copied {script} to Ghidra installation")
                except Exception as e:
                    logger.error(f"Failed to copy {script} to Ghidra installation: {e}")
                    return None
            
            self.scripts_copied = True
        
        try:
            # Pass 1: Import all object files into project with proper FID analysis setup
            logger.info(f"Pass 1: Importing {len(obj_files)} object files for {library_name}")
            logger.debug(f"Project base: {project_base}")
            logger.debug(f"Project name: {project_name}")

            cmd1 = [
                str(analyze_headless),
                str(project_base),
                project_name,
                "-prescript", "FunctionIDHeadlessPrescript.java"  # Prepare for FID signature generation
            ]

            # Add all object files
            logger.debug(f"Object files to import ({len(obj_files)}):")
            for i, obj_file in enumerate(obj_files, 1):
                cmd1.extend(["-import", str(obj_file)])
                logger.debug(f"  [{i}/{len(obj_files)}] {obj_file}")

            # Add post-script to validate functions
            cmd1.extend([
                "-postScript", "FunctionIDHeadlessPostscript.java"
            ])

            logger.debug(f"Executing Pass 1 command:")
            logger.debug(f"  {' '.join(cmd1)}")

            result1 = subprocess.run(
                cmd1,
                capture_output=True,
                text=True,
                check=True
            )

            logger.debug("Pass 1 stdout:")
            for line in result1.stdout.splitlines():
                logger.debug(f"  {line}")
            if result1.stderr:
                logger.debug("Pass 1 stderr:")
                for line in result1.stderr.splitlines():
                    logger.debug(f"  {line}")
            
            if skip_fid:
                # Skip Pass 2 - just keep the project for BSIM
                logger.info(f"Skipping FunctionID generation, keeping project for BSIM: {project_name}")
                
                # Store project info for BSIM processing
                self.last_project_info = {
                    'project_base': project_base,
                    'project_name': project_name
                }
                
                # Return None since no FIDB was created
                return None
            else:
                # Pass 2: Create FIDB from all programs in the project
                logger.info(f"Pass 2: Creating FunctionID database for {library_name}")
                logger.debug(f"Expected FIDB output: {fidb_path}")

                cmd2 = [
                    str(analyze_headless),
                    str(project_base),
                    project_name,
                    "-process",  # Process existing project
                    "-noanalysis",  # Don't re-analyze
                    "-postScript", "GhidRift_CreateLibraryFidb.java",
                    str(fidb_path),
                    f"Rust_{rust_version}",  # Library family
                    f"{rust_version}_{library_version}",  # Version
                    library_name  # Variant
                ]

                logger.debug(f"Executing Pass 2 command:")
                logger.debug(f"  {' '.join(cmd2)}")

                result2 = subprocess.run(
                    cmd2,
                    capture_output=True,
                    text=True,
                    check=True
                )

                logger.debug("Pass 2 stdout:")
                for line in result2.stdout.splitlines():
                    logger.debug(f"  {line}")
                if result2.stderr:
                    logger.debug("Pass 2 stderr:")
                    for line in result2.stderr.splitlines():
                        logger.debug(f"  {line}")

                if fidb_path.exists():
                    file_size = fidb_path.stat().st_size
                    logger.info(f"Successfully created FIDB: {fidb_path} ({file_size:,} bytes)")
                    
                    # Clean up project directory (unless we need it for BSIM)
                    if not keep_project:
                        project_dir = project_base / f"{project_name}.rep"
                        if project_dir.exists():
                            import shutil
                            shutil.rmtree(project_dir)
                        
                        gpr_file = project_base / f"{project_name}.gpr"
                        if gpr_file.exists():
                            gpr_file.unlink()
                    else:
                        logger.debug(f"Keeping project {project_name} for BSIM processing")
                        # Store project info for BSIM processing
                        self.last_project_info = {
                            'project_base': project_base,
                            'project_name': project_name
                        }
                    
                    return fidb_path
                else:
                    logger.error("FIDB file was not created")
                    logger.error(f"Expected FIDB at: {fidb_path}")
                    logger.error(f"Pass 2 stdout: {result2.stdout}")
                    logger.error(f"Pass 2 stderr: {result2.stderr}")
                    return None
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Ghidra analysis failed with return code {e.returncode}")
            logger.error(f"Command: {' '.join(e.cmd)}")
            if e.stdout:
                logger.error("Standard output:")
                for line in e.stdout.splitlines():
                    logger.error(f"  {line}")
            if e.stderr:
                logger.error("Error output:")
                for line in e.stderr.splitlines():
                    logger.error(f"  {line}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during FIDB generation: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None
    
    
    def generate_from_metadata(self, metadata_file: Path, output_dir: Optional[Path] = None, 
                              keep_projects: bool = False, skip_fid: bool = False) -> Dict[str, Path]:
        """
        Generate FunctionID databases from GhidRift metadata file
        
        Args:
            metadata_file: Path to metadata JSON file
            output_dir: Optional output directory for FIDB files
            keep_projects: Keep Ghidra projects after processing
            skip_fid: Skip FunctionID generation (only create projects)
            
        Returns:
            Dictionary mapping library names to FIDB file paths
        """
        with open(metadata_file) as f:
            metadata = json.load(f)
        
        rust_version = metadata.get("rustVersion", "unknown")
        target = metadata.get("targetTriple", "unknown")
        
        # Try to extract rust version from toolchain directory names
        if rust_version == "unknown":
            coff_dir = metadata_file.parent / "coff"
            if coff_dir.exists():
                toolchain_dir = coff_dir / "toolchain"
                if toolchain_dir.exists():
                    for dir_name in toolchain_dir.iterdir():
                        if dir_name.is_dir() and "-" in dir_name.name:
                            # Extract version from name like "1.85.0-x86_64-pc-linux-gnu"
                            version_part = dir_name.name.split("-")[0]
                            if version_part.replace(".", "").isdigit():
                                rust_version = version_part
                                break
        
        # Look for extracted COFF files
        coff_dir = metadata_file.parent / "coff"
        if not coff_dir.exists():
            logger.error(f"COFF directory not found: {coff_dir}")
            return {}
        
        # Create FIDB output directory - use same directory as JSON file
        if output_dir is None:
            output_dir = metadata_file.parent
        fidb_output_dir = output_dir
        fidb_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Collect ALL object files from both toolchain and crates
        all_coff_files = []

        # Add toolchain objects
        toolchain_dir = coff_dir / "toolchain"
        if toolchain_dir.exists():
            logger.debug(f"Scanning toolchain directory: {toolchain_dir}")
            toolchain_objects = list(toolchain_dir.rglob("*.o")) + list(toolchain_dir.rglob("*.obj"))
            all_coff_files.extend(toolchain_objects)
            logger.info(f"Found {len(toolchain_objects)} toolchain object files")
            logger.debug(f"Toolchain object files:")
            for obj in toolchain_objects[:10]:  # Log first 10
                logger.debug(f"  {obj}")
            if len(toolchain_objects) > 10:
                logger.debug(f"  ... and {len(toolchain_objects) - 10} more")
        else:
            logger.warning(f"Toolchain directory not found: {toolchain_dir}")

        # Add crates objects
        crates_dir = coff_dir / "crates"
        if crates_dir.exists():
            logger.debug(f"Scanning crates directory: {crates_dir}")
            crates_objects = list(crates_dir.rglob("*.o")) + list(crates_dir.rglob("*.obj"))
            all_coff_files.extend(crates_objects)
            logger.info(f"Found {len(crates_objects)} crates object files")
            logger.debug(f"Crates object files:")
            for obj in crates_objects[:10]:  # Log first 10
                logger.debug(f"  {obj}")
            if len(crates_objects) > 10:
                logger.debug(f"  ... and {len(crates_objects) - 10} more")
        else:
            logger.warning(f"Crates directory not found: {crates_dir}")

        if not all_coff_files:
            logger.error("No object files found in toolchain or crates directories")
            logger.error(f"Checked toolchain dir: {toolchain_dir} (exists: {toolchain_dir.exists()})")
            logger.error(f"Checked crates dir: {crates_dir} (exists: {crates_dir.exists()})")
            return {}
        
        if skip_fid:
            logger.info(f"Creating Ghidra projects from {len(all_coff_files)} object files (skipping FunctionID generation)")
            
            # Use metadata filename (without .json extension) as the project name
            project_name = metadata_file.stem
            
            # Still need to create the project for BSIM, but without FIDB generation
            # We'll create a temporary FIDB path but won't actually generate it
            fidb_output_path = fidb_output_dir / f"{project_name}_temp.fidb"
            
            # Call generate_fidb_from_objects but it will only create the project
            # We need to modify this method to support skip_fid too
            result = self.generate_fidb_from_objects(
                all_coff_files, 
                project_name, 
                rust_version, 
                "all_libraries", 
                fidb_output_dir,
                keep_project=True,
                skip_fid=True
            )
            
            # Return empty dict since no FIDB was created
            return {}
        else:
            logger.info(f"Generating single combined FIDB from {len(all_coff_files)} total object files")
            
            # Use metadata filename (without .json extension) as the FIDB name
            fidb_name = metadata_file.stem
            
            # Create single FIDB from ALL objects
            combined_fidb = self.generate_fidb_from_objects(
                all_coff_files, 
                fidb_name, 
                rust_version, 
                "all_libraries", 
                fidb_output_dir,
                keep_project=keep_projects
            )
            
            if combined_fidb:
                return {fidb_name: combined_fidb}
            else:
                return {}
    
    def generate_bsim_signatures(self, project_base: Path, project_name: str, 
                               bsim_manager, db_path: Path):
        """Add existing project to BSIM database"""
        logger.info(f"Adding {project_name} to BSIM database")
        bsim_manager.add_project_to_database(project_base, project_name, db_path)