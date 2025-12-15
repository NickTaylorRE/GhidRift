#!/usr/bin/env python3
"""
Setup script for GhidRift - Rust Reverse Engineering Toolkit for Ghidra
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read requirements from requirements.txt
def read_requirements():
    requirements_path = Path(__file__).parent / "requirements.txt"
    if requirements_path.exists():
        with open(requirements_path, 'r') as f:
            # Filter out comments and empty lines
            requirements = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    requirements.append(line)
            return requirements
    return []

# Read README for long description
def read_readme():
    readme_path = Path(__file__).parent / "README.md"
    if readme_path.exists():
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return ""

setup(
    name="ghidrift",
    version="1.0.0",
    description="Rust Reverse Engineering Toolkit for Ghidra",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="GhidRift Development Team",
    author_email="noreply@example.com",
    url="https://github.com/GhidRift/GhidRift",
    
    # Package configuration
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    
    # Dependencies
    install_requires=read_requirements(),
    
    # Entry points for command line tools
    entry_points={
        'console_scripts': [
            'ghidrift-cli=ghidrift.cli.main:main',
        ],
    },
    
    # Package data
    package_data={
        'ghidrift.rust_hashes': ['*.json'],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
        "Topic :: Software Development :: Reverse Engineering",
    ],
    
    # Keywords
    keywords="rust ghidra reverse-engineering malware-analysis function-identification",
    
    # Project URLs
    project_urls={
        "Bug Reports": "https://github.com/GhidRift/GhidRift/issues",
        "Source": "https://github.com/GhidRift/GhidRift",
        "Documentation": "https://github.com/GhidRift/GhidRift/blob/main/README.md",
    },
)