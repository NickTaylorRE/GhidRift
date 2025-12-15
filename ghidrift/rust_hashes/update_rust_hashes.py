#!/usr/bin/env python3
"""
Update the Rust commit hash database by fetching data from Rust's distribution.
This script combines the AWS S3 listing and TOML processing into one step.
"""

import argparse
import re
import requests
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import sys
from urllib.parse import quote

# Add parent directory to path if running as script
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

logger = logging.getLogger(__name__)

# Regex patterns
RE_TOML_FILE_PATTERN = r'<Key>(dist/channel-rust-[^<]+\.toml)</Key>'
RE_TIMESTAMP_PATTERN = r'<LastModified>([^<]+)</LastModified>'
RE_COMMIT_HASH = r'git_commit_hash = "([a-f0-9]{40})"'
RE_RUST_VERSION = r'channel-rust-(.+?)\.toml'

# URLs
RUST_DIST_URL = "https://static.rust-lang.org/dist/"
S3_LISTING_URL = "https://static-rust-lang-org.s3.amazonaws.com/?list-type=2&prefix=dist/channel-rust"


class RustHashUpdater:
    """Updates the Rust commit hash database"""
    
    def __init__(self, output_file: Optional[Path] = None):
        """
        Initialize the updater
        
        Args:
            output_file: Path to output JSON file (defaults to package data directory)
        """
        if output_file:
            self.output_file = Path(output_file)
        else:
            self.output_file = Path(__file__).parent / "rustc_hashes.json"
            
        self.existing_data = self._load_existing_data()
        
    def _load_existing_data(self) -> Dict:
        """Load existing database if it exists"""
        if self.output_file.exists():
            try:
                with open(self.output_file) as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load existing data: {e}")
        
        return {"exact_hash_to_version": []}
    
    def fetch_channel_list(self) -> List[Dict[str, str]]:
        """Fetch the list of channel TOML files from S3"""
        logger.info("Fetching channel list from S3...")
        
        channels = []
        continuation_token = None
        
        while True:
            # Build URL with continuation token if needed
            url = S3_LISTING_URL
            if continuation_token:
                url += f"&continuation-token={quote(continuation_token)}"
                
            try:
                response = requests.get(url)
                response.raise_for_status()
                content = response.text
                
                # Extract TOML files and timestamps
                file_matches = re.finditer(RE_TOML_FILE_PATTERN, content)
                timestamp_matches = re.finditer(RE_TIMESTAMP_PATTERN, content)
                
                # Pair files with timestamps
                for file_match, ts_match in zip(file_matches, timestamp_matches):
                    filepath = file_match.group(1)
                    filename = filepath.replace('dist/', '')  # Remove dist/ prefix
                    timestamp = ts_match.group(1)
                    
                    # Parse timestamp to readable format
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    formatted_ts = dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    channels.append({
                        'name': filename,
                        'timestamp': formatted_ts,
                        'url': RUST_DIST_URL + filename
                    })
                
                # Check if there are more results
                if '<IsTruncated>true</IsTruncated>' in content:
                    # Extract continuation token
                    token_match = re.search(r'<NextContinuationToken>([^<]+)</NextContinuationToken>', content)
                    if token_match:
                        continuation_token = token_match.group(1)
                    else:
                        break
                else:
                    break
                    
            except Exception as e:
                logger.error(f"Failed to fetch channel list: {e}")
                break
                
        logger.info(f"Found {len(channels)} channel files")
        return channels
    
    def process_channel(self, channel_info: Dict[str, str]) -> Optional[Dict]:
        """Process a single channel TOML file"""
        filename = channel_info['name']
        
        # Extract Rust version from filename
        version_match = re.match(RE_RUST_VERSION, filename)
        if not version_match:
            return None
            
        rust_version = version_match.group(1)
        
        # Skip if we already have this version
        existing_versions = {entry['rust_version'] for entry in self.existing_data['exact_hash_to_version']}
        if rust_version in existing_versions:
            return None
            
        logger.debug(f"Processing {filename} (version {rust_version})")
        
        try:
            # Download TOML file (only need first part)
            response = requests.get(channel_info['url'], stream=True)
            response.raise_for_status()
            
            # Read first 2KB (commit hash is near the top)
            content = b''
            for chunk in response.iter_content(chunk_size=2048):
                content += chunk
                break
                
            content_str = content.decode('utf-8', errors='ignore')
            
            # Check if git_commit_hash exists (only since Rust 1.50.0)
            if 'git_commit_hash' not in content_str:
                return None
                
            # Extract commit hash
            hash_match = re.search(RE_COMMIT_HASH, content_str)
            if hash_match:
                commit_hash = hash_match.group(1)
                
                return {
                    'timestamp': channel_info['timestamp'],
                    'name': filename,
                    'url': channel_info['url'],
                    'commit_hash': commit_hash,
                    'rust_version': rust_version
                }
                
        except Exception as e:
            logger.warning(f"Failed to process {filename}: {e}")
            
        return None
    
    def update_database(self, limit: Optional[int] = None):
        """Update the commit hash database"""
        # Get channel list
        channels = self.fetch_channel_list()
        
        if not channels:
            logger.error("No channels found")
            return
            
        # Process channels
        new_entries = []
        processed = 0
        
        for channel_info in channels:
            if limit and processed >= limit:
                break
                
            entry = self.process_channel(channel_info)
            if entry:
                new_entries.append(entry)
                processed += 1
                
        logger.info(f"Found {len(new_entries)} new entries")
        
        if new_entries:
            # Merge with existing data
            existing_hashes = {entry['commit_hash'] for entry in self.existing_data['exact_hash_to_version']}
            
            for entry in new_entries:
                if entry['commit_hash'] not in existing_hashes:
                    self.existing_data['exact_hash_to_version'].append(entry)
                    
            # Sort by version (newest first)
            self.existing_data['exact_hash_to_version'].sort(
                key=lambda x: self._version_key(x['rust_version']),
                reverse=True
            )
            
            # Save updated database
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_file, 'w') as f:
                json.dump(self.existing_data, f, indent=2)
                
            logger.info(f"Updated database saved to {self.output_file}")
            logger.info(f"Total entries: {len(self.existing_data['exact_hash_to_version'])}")
    
    def _version_key(self, version: str) -> tuple:
        """Convert version string to sortable tuple"""
        # Handle special versions
        if 'nightly' in version:
            return (999, 0, 0)
        if 'beta' in version:
            return (998, 0, 0)
            
        # Parse regular versions
        parts = version.split('.')
        try:
            return tuple(int(p) if p.isdigit() else 0 for p in parts)
        except:
            return (0, 0, 0)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Update Rust commit hash database from official distributions"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file path",
        type=Path
    )
    parser.add_argument(
        "-l", "--limit",
        help="Limit number of new versions to process",
        type=int
    )
    parser.add_argument(
        "-v", "--verbose",
        help="Enable verbose logging",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run updater
    updater = RustHashUpdater(args.output)
    updater.update_database(args.limit)


if __name__ == "__main__":
    main()