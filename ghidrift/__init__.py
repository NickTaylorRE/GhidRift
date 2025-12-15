"""
GhidRift - Ghidra-based Rust malware analysis tool

A comprehensive tool for analyzing Rust binaries using Ghidra's advanced
capabilities including FunctionID signatures and BSIM database integration.
"""

__version__ = "0.1.0"
__author__ = "GhidRift Development Team"

from .core.rust_toolchain import RustToolchain

__all__ = [
    "RustToolchain",
]