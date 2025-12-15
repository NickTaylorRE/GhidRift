#!/bin/bash
set -e

GHIDRA_VERSION=$1
GHIDRA_INSTALL_DIR=$2

echo "Installing Ghidra version: $GHIDRA_VERSION"
echo "Installation directory: $GHIDRA_INSTALL_DIR"

# Create working directory
mkdir -p /tmp/ghidra
cd /tmp/ghidra

# Check if we have a local copy first
LOCAL_GHIDRA_FILE=""
if [ -d "/tmp/build-context/ghidra_releases" ]; then
    echo "Checking local ghidra_releases directory for version $GHIDRA_VERSION..."
    LOCAL_GHIDRA_FILE=$(find /tmp/build-context/ghidra_releases -name "*ghidra_${GHIDRA_VERSION}*_PUBLIC*.zip" 2>/dev/null | head -1)
fi

if [ -n "$LOCAL_GHIDRA_FILE" ] && [ -f "$LOCAL_GHIDRA_FILE" ]; then
    echo "Found local Ghidra release: $LOCAL_GHIDRA_FILE"
    cp "$LOCAL_GHIDRA_FILE" ghidra.zip
else
    echo "No local Ghidra $GHIDRA_VERSION found, downloading from GitHub..."
    
    # Debug: Show available releases
    curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases | jq -r '.[].tag_name' | head -5
    
    # Get the correct download URL for the specified version
    GHIDRA_URL=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases | \
                 jq -r ".[] | select(.tag_name == \"Ghidra_${GHIDRA_VERSION}_build\") | .assets[] | select(.name | contains(\"ghidra_\") and contains(\"_PUBLIC\") and endswith(\".zip\") and (contains(\".src.zip\") | not)) | .browser_download_url" | head -1)
    
    if [ -z "$GHIDRA_URL" ]; then
        echo "Error: Could not find Ghidra version $GHIDRA_VERSION"
        echo "Available versions:"
        curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases | jq -r '.[].tag_name' | head -10
        exit 1
    fi
    
    echo "Downloading Ghidra $GHIDRA_VERSION from: $GHIDRA_URL"
    wget -O ghidra.zip "$GHIDRA_URL"
fi

# Extract and install
echo "Extracting Ghidra..."
unzip ghidra.zip
mv ghidra_*_PUBLIC "$GHIDRA_INSTALL_DIR"

# Cleanup
rm -rf /tmp/ghidra
rm -rf /tmp/build-context

echo "Ghidra installation completed: $GHIDRA_INSTALL_DIR"