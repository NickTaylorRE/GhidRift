"""
Rust toolchain integration for GhidRift
Handles Rust compiler installation, library extraction, and crate management
"""

import os
import json
import subprocess
import shutil
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import logging
import ar
import zipfile
import platform
import re
import requests
from datetime import datetime
from urllib.parse import quote

logger = logging.getLogger(__name__)


@dataclass
class RustVersion:
    """Container for Rust version information"""
    version: str
    commit_hash: str
    target_triple: str
    
    @property
    def toolchain_name(self) -> str:
        """Get the rustup toolchain name"""
        return f"{self.version}-{self.target_triple}"


class RustToolchain:
    """Manages Rust toolchain operations for GhidRift"""

    # Toolchain-internal crates that should never be rebuilt from source
    # These are provided as pre-compiled .rlib files in the Rust toolchain
    TOOLCHAIN_INTERNAL_CRATES = {
        # Core standard library components
        'core',
        'std',
        'alloc',

        # Compiler builtins (requires nightly features)
        'compiler_builtins',

        # Panic handlers
        'panic_abort',
        'panic_unwind',

        # Testing and procedural macros
        'test',
        'proc_macro',

        # Standard library detection and workspaces
        'std_detect',
        'rustc_std_workspace_core',
        'rustc_std_workspace_alloc',
        'rustc_std_workspace_std',

        # Additional toolchain libraries
        'unwind',
        'profiler_builtins',
        'sysroot',

        # Any crate starting with 'rustc_' prefix will be filtered by pattern matching
    }

    def __init__(self, work_dir: str = None, rustup_home: str = None, auto_update_db: bool = True, base_dir: Path = None):
        """
        Initialize the Rust toolchain manager
        
        Args:
            work_dir: Working directory for extracted files
            rustup_home: Path to rustup directory (auto-detected if None)
            auto_update_db: Whether to automatically update the commit hash database
            base_dir: Base directory for all GhidRift data (defaults to ~/.ghidrift)
        """
        if work_dir:
            self.work_dir = Path(work_dir)
        elif base_dir:
            self.work_dir = base_dir / ".ghidrift" / "work"
        else:
            self.work_dir = Path.home() / ".ghidrift" / "work"
        self.rustup_home = self._find_rustup_home(rustup_home)
        self.output_dir = None  # Can be overridden for custom output location
        
        # Create directory structure
        self._create_directories()
        
        # Update database if requested
        if auto_update_db:
            self._update_rust_versions_db()
            
        # Load rust versions
        self.rust_versions = self._load_rust_versions()
        
    def _find_rustup_home(self, rustup_home: Optional[str]) -> Path:
        """Find the rustup home directory"""
        if rustup_home:
            return Path(rustup_home)
            
        # Check environment variable
        if "RUSTUP_HOME" in os.environ:
            return Path(os.environ["RUSTUP_HOME"])
            
        # Default locations
        if platform.system() == "Windows":
            default = Path.home() / ".rustup"
        else:
            default = Path.home() / ".rustup"
            
        if default.exists():
            return default
            
        raise RuntimeError("Could not find rustup installation. Please install rustup or set RUSTUP_HOME")
    
    def _create_directories(self):
        """Create necessary directory structure"""
        dirs = [
            self.work_dir / "rlib" / "toolchain",
            self.work_dir / "rlib" / "crates",
            self.work_dir / "coff" / "toolchain",
            self.work_dir / "coff" / "crates",
            self.work_dir / "signatures",
            self.work_dir / "bsim",
            self.work_dir / "tmp",
            self.work_dir / "cache",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
    
    def _load_rust_versions(self) -> Dict[str, str]:
        """Load Rust version mappings from embedded data"""
        data_file = Path(__file__).parent.parent / "rust_hashes" / "rustc_hashes.json"
        
        if not data_file.exists():
            logger.warning(f"Rust version database not found: {data_file}")
            return {}
            
        try:
            with open(data_file) as f:
                data = json.load(f)
                
            # Convert to simple hash -> version mapping
            version_map = {}
            for entry in data.get("exact_hash_to_version", []):
                commit_hash = entry.get("commit_hash")
                rust_version = entry.get("rust_version")
                if commit_hash and rust_version:
                    version_map[commit_hash] = rust_version
                    
            logger.info(f"Loaded {len(version_map)} Rust version mappings")
            return version_map
            
        except Exception as e:
            logger.error(f"Failed to load Rust version database: {e}")
            return {}
    
    def _update_rust_versions_db(self):
        """Update the Rust versions database with latest releases"""
        data_file = Path(__file__).parent.parent / "rust_hashes" / "rustc_hashes.json"
        
        # Skip update if file was updated recently (within 24 hours)
        if data_file.exists():
            mtime = datetime.fromtimestamp(data_file.stat().st_mtime)
            age = datetime.now() - mtime
            if age.total_seconds() < 86400:  # 24 hours
                logger.debug("Rust version database is recent, skipping update")
                return
        
        logger.info("Updating Rust version database...")
        
        try:
            # Load existing data
            existing_data = {"exact_hash_to_version": []}
            if data_file.exists():
                with open(data_file) as f:
                    existing_data = json.load(f)
            
            existing_hashes = {entry['commit_hash'] for entry in existing_data['exact_hash_to_version']}
            
            # Fetch channel list from S3
            url = "https://static-rust-lang-org.s3.amazonaws.com/?list-type=2&prefix=dist/channel-rust"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Extract TOML files
            toml_pattern = re.compile(r'<Key>(dist/channel-rust-[^<]+\.toml)</Key>')
            timestamp_pattern = re.compile(r'<LastModified>([^<]+)</LastModified>')
            
            files = toml_pattern.findall(response.text)
            timestamps = timestamp_pattern.findall(response.text)
            
            new_entries = 0
            checked = 0
            
            # Process up to 10 new versions
            for filepath, timestamp in zip(files, timestamps):
                if checked >= 10:
                    break
                    
                filename = filepath.replace('dist/', '')
                version_match = re.match(r'channel-rust-(.+?)\.toml', filename)
                if not version_match:
                    continue
                    
                rust_version = version_match.group(1)
                
                # Skip if we already have this version
                if any(entry['rust_version'] == rust_version for entry in existing_data['exact_hash_to_version']):
                    continue
                
                checked += 1
                
                # Download TOML file header
                toml_url = f"https://static.rust-lang.org/dist/{filename}"
                toml_response = requests.get(toml_url, stream=True, timeout=10)
                toml_response.raise_for_status()
                
                # Read first 2KB
                content = b''
                for chunk in toml_response.iter_content(chunk_size=2048):
                    content += chunk
                    break
                
                content_str = content.decode('utf-8', errors='ignore')
                
                # Extract commit hash
                hash_match = re.search(r'git_commit_hash = "([a-f0-9]{40})"', content_str)
                if hash_match and hash_match.group(1) not in existing_hashes:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    formatted_ts = dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    existing_data['exact_hash_to_version'].append({
                        'timestamp': formatted_ts,
                        'name': filename,
                        'url': toml_url,
                        'commit_hash': hash_match.group(1),
                        'rust_version': rust_version
                    })
                    new_entries += 1
            
            if new_entries > 0:
                # Sort by version
                existing_data['exact_hash_to_version'].sort(
                    key=lambda x: self._version_sort_key(x['rust_version']),
                    reverse=True
                )
                
                # Save updated database
                data_file.parent.mkdir(parents=True, exist_ok=True)
                with open(data_file, 'w') as f:
                    json.dump(existing_data, f, indent=2)
                
                logger.info(f"Added {new_entries} new Rust versions to database")
            else:
                # Touch the file to update mtime even if no new entries
                if data_file.exists():
                    data_file.touch()
                    
        except Exception as e:
            logger.warning(f"Failed to update Rust version database: {e}")
    
    def _version_sort_key(self, version: str) -> tuple:
        """Convert version string to sortable tuple"""
        if 'nightly' in version:
            return (999, 0, 0)
        if 'beta' in version:
            return (998, 0, 0)
        parts = version.split('.')
        try:
            return tuple(int(p) if p.isdigit() else 0 for p in parts)
        except:
            return (0, 0, 0)
    
    def get_rust_version_from_hash(self, commit_hash: str) -> Optional[str]:
        """Get Rust version from commit hash"""
        # First check our mapping
        if commit_hash in self.rust_versions:
            logger.info(f"Found exact match for commit {commit_hash}: {self.rust_versions[commit_hash]}")
            return self.rust_versions[commit_hash]
            
        # Try to find it via rustup
        try:
            result = subprocess.run(
                ["rustup", "toolchain", "list", "-v"],
                capture_output=True,
                text=True,
                check=True
            )
            for line in result.stdout.splitlines():
                if commit_hash in line:
                    # Extract version from line
                    parts = line.split()
                    if parts:
                        version = parts[0].split('-')[0]
                        logger.info(f"Found version {version} for commit {commit_hash} in local rustup")
                        return version
        except subprocess.CalledProcessError:
            logger.warning("Failed to query rustup toolchains")
            
        # Fallback: use the most recent stable version
        if self.rust_versions:
            # Get all stable versions (exclude beta/nightly)
            stable_versions = [v for v in self.rust_versions.values() 
                             if not any(x in v for x in ['beta', 'nightly'])]
            
            if stable_versions:
                # Sort versions properly (handle 1.9.0 vs 1.10.0)
                def version_key(v):
                    parts = v.split('.')
                    return tuple(int(p) if p.isdigit() else 0 for p in parts)

                latest_version = sorted(stable_versions, key=version_key)[-1]
                logger.warning(f"Unknown commit hash {commit_hash}, using latest stable version: {latest_version}")
                return latest_version
        
        logger.error(f"Could not determine Rust version for commit {commit_hash}")
        return None
    
    def install_rust_toolchain(self, version: str, target: str) -> bool:
        """
        Install a specific Rust toolchain version and target
        
        Args:
            version: Rust version (e.g., "1.63.0")
            target: Target triple (e.g., "x86_64-pc-windows-msvc")
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # First check if toolchain exists
            result = subprocess.run(
                ["rustup", "toolchain", "list"],
                capture_output=True,
                text=True,
                check=True
            )
            
            toolchains = result.stdout.strip().split('\n')
            toolchain_exists = any(version in t for t in toolchains)
            
            if not toolchain_exists:
                # Install toolchain
                logger.info(f"Installing Rust toolchain: {version}")
                result = subprocess.run(
                    ["rustup", "toolchain", "install", version],
                    capture_output=True,
                    text=True,
                    check=True
                )
                logger.debug(f"Toolchain install output: {result.stdout}")
            else:
                logger.info(f"Rust toolchain {version} already installed")
            
            # Check if we need to add the target
            # First, check what targets are already installed for this toolchain
            result = subprocess.run(
                ["rustup", "target", "list", "--installed", "--toolchain", version],
                capture_output=True,
                text=True,
                check=True
            )
            
            installed_targets = result.stdout.strip().split('\n') if result.stdout.strip() else []
            
            if target not in installed_targets:
                # Check if target is valid for this toolchain
                # Some targets might be built-in or have different names
                host_triple = self._get_host_triple()
                
                # If the target is the same OS/arch as host, it might be built-in
                if self._is_compatible_target(target, host_triple):
                    logger.info(f"Target {target} appears compatible with host {host_triple}, may be built-in")
                    return True
                
                # Try to add the target
                logger.info(f"Adding target: {target} to toolchain {version}")
                try:
                    result = subprocess.run(
                        ["rustup", "target", "add", target, "--toolchain", version],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    logger.debug(f"Target add output: {result.stdout}")
                except subprocess.CalledProcessError as e:
                    # If it fails, check if it's because the target is already available
                    if "does not support target" in str(e.stderr):
                        logger.warning(f"Target {target} not supported by toolchain {version}, will use host target")
                        return True
                    raise
            else:
                logger.info(f"Target {target} already installed for toolchain {version}")
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install toolchain: {e}")
            if e.stderr:
                logger.error(f"Error output: {e.stderr}")
            elif hasattr(e, 'output') and e.output:
                logger.error(f"Error output: {e.output}")
            return False
    
    def get_toolchain_lib_path(self, version: str, target: str) -> Path:
        """Get path to toolchain libraries"""
        host_triple = self._get_host_triple()
        toolchain_dir = self.rustup_home / "toolchains" / f"{version}-{host_triple}"
        
        # First try the exact target
        lib_path = toolchain_dir / "lib" / "rustlib" / target / "lib"
        
        # If that doesn't exist and target is compatible, try host triple
        if not lib_path.exists() and self._is_compatible_target(target, host_triple):
            lib_path = toolchain_dir / "lib" / "rustlib" / host_triple / "lib"
            if lib_path.exists():
                logger.info(f"Using host libraries at {lib_path} for target {target}")
        
        return lib_path
    
    def _get_host_triple(self) -> str:
        """Get the host target triple"""
        result = subprocess.run(
            ["rustc", "-vV"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.splitlines():
            if line.startswith("host:"):
                return line.split(":")[1].strip()
        return "unknown"
    
    def _is_compatible_target(self, target: str, host: str) -> bool:
        """Check if target is compatible with host (same arch/os)"""
        # Extract components
        target_parts = target.split('-')
        host_parts = host.split('-')
        
        if len(target_parts) < 3 or len(host_parts) < 3:
            return False
            
        # Check if same architecture and OS
        target_arch = target_parts[0]
        target_os = target_parts[2]
        host_arch = host_parts[0]
        host_os = host_parts[2]
        
        # Same arch and OS means likely compatible
        return target_arch == host_arch and target_os == host_os
    
    def extract_rlib_files(self, version: str, target: str) -> List[Path]:
        """
        Extract .rlib files from a Rust toolchain
        
        Args:
            version: Rust version
            target: Target triple
            
        Returns:
            List of paths to extracted COFF/object files
        """
        lib_path = self.get_toolchain_lib_path(version, target)
        if not lib_path.exists():
            logger.error(f"Library path does not exist: {lib_path}")
            return []
            
        # Use custom output directory if set, otherwise use default
        if self.output_dir:
            output_dir = self.output_dir / "coff" / "toolchain" / f"{version}-{target}"
        else:
            output_dir = self.work_dir / "coff" / "toolchain" / f"{version}-{target}"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_files = []
        
        # Find all .rlib files
        for rlib_file in lib_path.glob("*.rlib"):
            logger.info(f"Extracting {rlib_file.name}")
            extracted = self._extract_rlib(rlib_file, output_dir / rlib_file.stem)
            extracted_files.extend(extracted)
            
        return extracted_files
    
    def _extract_rlib(self, rlib_path: Path, output_dir: Path) -> List[Path]:
        """Extract COFF/object files from an .rlib archive"""
        output_dir.mkdir(parents=True, exist_ok=True)
        extracted = []
        
        try:
            with open(rlib_path, 'rb') as f:
                archive = ar.Archive(f)
                
                for member in archive:
                    member_name = member.name
                    
                    # Handle byte strings
                    if isinstance(member_name, bytes):
                        try:
                            member_name = member_name.decode('utf-8')
                        except UnicodeDecodeError:
                            # Use a safe representation for non-UTF8 names
                            member_name = member_name.decode('latin-1')
                    
                    # Skip metadata files
                    if member_name.startswith('.') or member_name == '/':
                        continue
                        
                    # Extract COFF/object files
                    if member_name.endswith(('.o', '.obj', '.coff')):
                        # Flatten path - use just the filename to avoid Windows absolute path issues
                        # (e.g., "C:/a/rust/build/.../file.o" -> "file.o")
                        # Use string split instead of Path since we're on Linux parsing Windows paths
                        safe_name = member_name.replace('\\', '/').split('/')[-1]
                        output_path = output_dir / safe_name
                        with open(output_path, 'wb') as out:
                            # Use archive.open to read member content
                            with archive.open(member, 'rb') as member_file:
                                content = member_file.read()
                                out.write(content)
                        extracted.append(output_path)
                        
        except Exception as e:
            logger.error(f"Failed to extract {rlib_path}: {e}")
            
        return extracted
    
    def build_crate_project(self, crates: List[str], version: str, target: str, use_host_target: bool = False) -> Optional[Path]:
        """
        Build a Cargo project with specified crates
        
        Args:
            crates: List of crate specifications (e.g., ["clap-3.2.25", "tokio-1.32.0"])
            version: Rust version to use
            target: Target triple
            
        Returns:
            Path to the project directory if successful
        """
        # Create temporary project
        project_dir = self.work_dir / "tmp" / f"crates_{version}_{target}"
        project_dir.mkdir(parents=True, exist_ok=True)
        
        # Create Cargo.toml
        cargo_toml = self._generate_cargo_toml(crates)
        (project_dir / "Cargo.toml").write_text(cargo_toml)
        
        # Create rust-toolchain file
        (project_dir / "rust-toolchain").write_text(version)
        
        # Create .cargo/config.toml
        cargo_dir = project_dir / ".cargo"
        cargo_dir.mkdir(exist_ok=True)
        
        # Use host target if requested (for compatibility)
        build_target = self._get_host_triple() if use_host_target else target
        config_toml = f'[build]\ntarget = "{build_target}"\n'
        (cargo_dir / "config.toml").write_text(config_toml)
        
        # Create dummy main.rs
        src_dir = project_dir / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "main.rs").write_text("fn main() {}")
        
        # Build the project
        try:
            # First, check dependencies
            logger.info(f"Checking crate dependencies with target {build_target}...")
            subprocess.run(
                ["cargo", "check", "--release", "--target", build_target],
                cwd=project_dir,
                check=True,
                capture_output=True
            )
            
            # Then build
            logger.info(f"Building crates for target {build_target}...")
            subprocess.run(
                ["cargo", "build", "--release", "--target", build_target],
                cwd=project_dir,
                check=True,
                capture_output=True
            )
            
            return project_dir
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to build crates: {e}")
            if e.stderr:
                logger.error(f"Error output: {e.stderr.decode()}")
            return None
    
    def _generate_cargo_toml(self, crates: List[str]) -> str:
        """Generate Cargo.toml content for crate dependencies"""
        toml_lines = [
            '[package]',
            'name = "ghidrift_crates"',
            'version = "0.1.0"',
            'edition = "2021"',
            '',
            '[dependencies]'
        ]

        # Track seen crates to avoid duplicates
        seen_crates = {}
        filtered_count = 0

        for crate_spec in crates:
            # Clean up crate names - remove registry prefixes like "index.crates.io-*/"
            if '/' in crate_spec:
                crate_spec = crate_spec.split('/')[-1]

            # Parse crate specification (e.g., "clap-3.2.25")
            parts = crate_spec.rsplit('-', 1)
            if len(parts) == 2 and parts[1][0].isdigit():
                crate_name = parts[0]
                version = parts[1]

                # Skip if we've already seen this crate
                if crate_name in seen_crates:
                    logger.debug(f"Skipping duplicate crate: {crate_name} (keeping version {seen_crates[crate_name]})")
                    continue

                # Filter out toolchain-internal crates
                if crate_name in self.TOOLCHAIN_INTERNAL_CRATES or crate_name.startswith('rustc_'):
                    logger.debug(f"Filtering toolchain-internal crate: {crate_name} {version} (already in toolchain)")
                    filtered_count += 1
                    continue

                seen_crates[crate_name] = version
                toml_lines.append(f'{crate_name} = "{version}"')
            else:
                # No version specified or couldn't parse
                # Skip invalid entries
                logger.warning(f"Could not parse crate specification: {crate_spec}")

        logger.info(f"Generated Cargo.toml with {len(seen_crates)} user crates ({filtered_count} toolchain crates filtered)")
        return '\n'.join(toml_lines)
    
    def extract_crate_rlibs(self, project_dir: Path, target: str, use_host_target: bool = False) -> List[Path]:
        """Extract .rlib files from a built crate project"""
        # Use host target if requested
        build_target = self._get_host_triple() if use_host_target else target
        deps_dir = project_dir / "target" / build_target / "release" / "deps"
        if not deps_dir.exists():
            logger.error(f"Dependencies directory not found: {deps_dir}")
            return []
            
        # Use custom output directory if set, otherwise use default
        if self.output_dir:
            output_dir = self.output_dir / "coff" / "crates"
        else:
            output_dir = self.work_dir / "coff" / "crates"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_files = []
        
        # Extract all .rlib files from deps
        for rlib_file in deps_dir.glob("*.rlib"):
            logger.info(f"Extracting crate {rlib_file.name}")
            extracted = self._extract_rlib(rlib_file, output_dir / rlib_file.stem)
            extracted_files.extend(extracted)
            
        return extracted_files
    
    def process_metadata(self, metadata_file: Path, output_alongside: bool = True) -> Tuple[List[Path], List[Path]]:
        """
        Process metadata JSON and extract all necessary libraries
        
        Args:
            metadata_file: Path to metadata JSON from GhidRift_ExtractMetadata.java
            output_alongside: If True, extract files alongside metadata.json
            
        Returns:
            Tuple of (toolchain_files, crate_files)
        """
        metadata_file = Path(metadata_file)
        
        # Set output directory to be alongside metadata.json if requested
        if output_alongside:
            self.output_dir = metadata_file.parent
            logger.info(f"Output directory set to: {self.output_dir}")
        
        with open(metadata_file) as f:
            metadata = json.load(f)
            
        commit_hash = metadata.get("commitHash")
        target_triple = metadata.get("targetTriple", "unknown")
        crates = metadata.get("crates", [])
        
        # Get Rust version from commit hash
        version = self.get_rust_version_from_hash(commit_hash)
        if not version:
            logger.error(f"Could not determine Rust version for commit {commit_hash}")
            return [], []
        
        # Ensure version has full format (e.g., "1.85" -> "1.85.0")
        if version.count('.') == 1 and not any(x in version for x in ['beta', 'nightly']):
            version = f"{version}.0"
            
        logger.info(f"Processing Rust {version} for target {target_triple}")
        
        # Install toolchain if needed
        if not self.install_rust_toolchain(version, target_triple):
            return [], []
            
        # Extract toolchain libraries
        toolchain_files = self.extract_rlib_files(version, target_triple)
        
        # Build and extract crate libraries
        crate_files = []
        if crates:
            # Check if target is compatible with host
            host_triple = self._get_host_triple()
            use_host = self._is_compatible_target(target_triple, host_triple)
            
            if use_host:
                logger.info(f"Target {target_triple} is compatible with host {host_triple}, using host for crate building")
            
            project_dir = self.build_crate_project(crates, version, target_triple, use_host_target=use_host)
            if project_dir:
                crate_files = self.extract_crate_rlibs(project_dir, target_triple, use_host_target=use_host)
                
        return toolchain_files, crate_files