import subprocess
import logging
from pathlib import Path
from typing import Optional, List, Dict
import os
import json

logger = logging.getLogger(__name__)

class BSIMManager:
    """Manages BSIM database operations using Ghidra's bsim CLI"""
    
    def __init__(self, ghidra_dir: str = None, base_dir: Path = None):
        self.ghidra_dir = self._find_ghidra_dir(ghidra_dir)
        self.bsim_cmd = self.ghidra_dir / "support" / "bsim"
        # Store BSIM databases directly in base directory (same as FIDB files)
        self.work_dir = base_dir if base_dir else Path.cwd()
        # No need to create directory - it should already exist
        
    def _find_ghidra_dir(self, ghidra_dir: Optional[str]) -> Path:
        """Find Ghidra installation directory"""
        if ghidra_dir:
            path = Path(ghidra_dir)
            if path.is_dir():
                return path
            else:
                raise ValueError(f"Ghidra directory not found: {ghidra_dir}")
        
        # Check environment variable
        env_ghidra = os.environ.get('GHIDRA_INSTALL_DIR')
        if env_ghidra:
            path = Path(env_ghidra)
            if path.is_dir():
                return path
        
        # Try common locations
        common_locations = [
            Path.home() / "ghidra",
            Path("/opt/ghidra"),
            Path("/usr/local/ghidra"),
        ]
        
        for location in common_locations:
            if location.is_dir():
                # Check if it's a Ghidra installation
                if (location / "support" / "analyzeHeadless").exists():
                    return location
        
        raise RuntimeError("Could not find Ghidra installation. Please set GHIDRA_INSTALL_DIR environment variable.")
        
    def create_database(self, db_name: str, template: str = "medium_64") -> Path:
        """Create new H2 BSIM database"""
        db_path = self.work_dir / f"{db_name}.bsim"
        
        # Check if database already exists
        # H2 databases have .mv.db extension
        if (self.work_dir / f"{db_name}.bsim.mv.db").exists():
            logger.info(f"BSIM database already exists: {db_path}")
            return db_path
        
        cmd = [
            str(self.bsim_cmd),
            "createdatabase",
            f"file://{db_path}",
            template,
            "--name", db_name,
            "--owner", "GhidRift",
            "--description", "Rust function signatures"
        ]
        
        logger.info(f"Creating BSIM database: {db_path}")
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.debug(f"BSIM output: {result.stdout}")
            if result.stderr:
                logger.warning(f"BSIM stderr: {result.stderr}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create BSIM database: {e}")
            if e.stdout:
                logger.error(f"stdout: {e.stdout}")
            if e.stderr:
                logger.error(f"stderr: {e.stderr}")
            raise
            
        return db_path
        
    def add_project_to_database(self, project_path: Path, project_name: str, db_path: Path):
        """Generate signatures from existing Ghidra project and add to BSIM database"""
        cmd = [
            str(self.bsim_cmd),
            "generatesigs",
            f"ghidra://{project_path}/{project_name}",
            "--bsim", f"file://{db_path}"
        ]
        
        logger.info(f"Adding project {project_name} to BSIM database")
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.debug(f"BSIM output: {result.stdout}")
            if result.stderr:
                logger.warning(f"BSIM stderr: {result.stderr}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add project to BSIM database: {e}")
            if e.stdout:
                logger.error(f"stdout: {e.stdout}")
            if e.stderr:
                logger.error(f"stderr: {e.stderr}")
            raise
        
    def list_executables(self, db_path: Path) -> List[Dict]:
        """List all executables in database"""
        cmd = [
            str(self.bsim_cmd),
            "listexes",
            f"file://{db_path}"
        ]
        
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return self._parse_listexes_output(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to list executables: {e}")
            if e.stdout:
                logger.error(f"stdout: {e.stdout}")
            if e.stderr:
                logger.error(f"stderr: {e.stderr}")
            raise
        
    def _parse_listexes_output(self, output: str) -> List[Dict]:
        """Parse bsim listexes output format"""
        executables = []
        lines = output.strip().split('\n')
        
        # Skip header lines and parse executable entries
        for line in lines:
            if line and not line.startswith('---'):
                # Basic parsing - adjust based on actual output format
                parts = line.split()
                if len(parts) >= 2:
                    executables.append({
                        'name': parts[0],
                        'id': parts[1] if len(parts) > 1 else None,
                        'full_line': line
                    })
        
        return executables