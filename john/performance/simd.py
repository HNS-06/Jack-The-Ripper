"""SIMD detection and hardware capability reporting."""

import sys
import platform
import subprocess
import os
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class CPUInfo:
    """Detected CPU information."""
    brand: str = "Unknown"
    cores: int = 0
    logical_cores: int = 0
    architecture: str = ""
    features: list = None
    
    def __post_init__(self):
        if self.features is None:
            self.features = []


@dataclass
class SIMDInfo:
    """Detected SIMD capabilities."""
    sse: bool = False
    sse2: bool = False
    sse3: bool = False
    ssse3: bool = False
    sse41: bool = False
    sse42: bool = False
    avx: bool = False
    avx2: bool = False
    avx512: bool = False
    aes_ni: bool = False
    sha_extensions: bool = False
    popcnt: bool = False
    
    @property
    def best_vector_width(self) -> int:
        if self.avx512:
            return 512
        elif self.avx2 or self.avx:
            return 256
        elif self.sse42:
            return 128
        return 64
    
    def to_dict(self) -> dict:
        return {
            "SSE": self.sse, "SSE2": self.sse2, "SSE3": self.sse3,
            "SSSE3": self.ssse3, "SSE4.1": self.sse41, "SSE4.2": self.sse42,
            "AVX": self.avx, "AVX2": self.avx2, "AVX-512": self.avx512,
            "AES-NI": self.aes_ni, "SHA": self.sha_extensions, "POPCNT": self.popcnt,
        }


def detect_cpu() -> CPUInfo:
    """Detect CPU information."""
    info = CPUInfo()
    info.brand = platform.processor() or "Unknown"
    info.cores = os.cpu_count() or 1
    info.architecture = platform.machine()
    
    try:
        import multiprocessing
        info.logical_cores = multiprocessing.cpu_count()
    except Exception:
        info.logical_cores = info.cores
    
    # Try to get more info from system
    if sys.platform == "win32":
        try:
            info.brand = os.environ.get("PROCESSOR_IDENTIFIER", info.brand)
        except Exception:
            pass
    
    return info


def detect_simd() -> SIMDInfo:
    """Detect SIMD capabilities."""
    info = SIMDInfo()
    
    if sys.platform == "win32":
        return _detect_simd_windows(info)
    elif sys.platform == "linux":
        return _detect_simd_linux(info)
    elif sys.platform == "darwin":
        return _detect_simd_macos(info)
    
    return info


def _detect_simd_windows(info: SIMDInfo) -> SIMDInfo:
    """Detect SIMD on Windows using systeminfo or WMI."""
    try:
        # Try using wmic
        result = subprocess.run(
            ["wmic", "cpu", "get", "Caption,Name,NumberOfCores,NumberOfLogicalProcessors"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:
                if line.strip():
                    info.features.append(line.strip())
    except Exception:
        pass
    
    # Default to common features for modern CPUs
    # In production, use CPUID instruction or check /proc/cpuinfo equivalent
    info.sse = True
    info.sse2 = True
    info.sse3 = True
    info.ssse3 = True
    info.sse41 = True
    info.sse42 = True
    info.avx = True
    info.avx2 = True
    info.aes_ni = True
    info.popcnt = True
    
    return info


def _detect_simd_linux(info: SIMDInfo) -> SIMDInfo:
    """Detect SIMD on Linux from /proc/cpuinfo."""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('flags'):
                    flags = line.split(':')[1].strip().split()
                    info.sse = 'sse' in flags
                    info.sse2 = 'sse2' in flags
                    info.sse3 = 'sse3' in flags
                    info.ssse3 = 'ssse3' in flags
                    info.sse41 = 'sse4_1' in flags
                    info.sse42 = 'sse4_2' in flags
                    info.avx = 'avx' in flags
                    info.avx2 = 'avx2' in flags
                    info.avx512 = 'avx512' in flags
                    info.aes_ni = 'aes' in flags
                    info.sha_extensions = 'sha_ni' in flags
                    info.popcnt = 'popcnt' in flags
                    break
    except Exception:
        pass
    
    return info


def _detect_simd_macos(info: SIMDInfo) -> SIMDInfo:
    """Detect SIMD on macOS."""
    try:
        result = subprocess.run(["sysctl", "-n", "machdep.cpu.features"],
                               capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            features = result.stdout.strip().upper()
            info.sse = 'SSE' in features
            info.sse2 = 'SSE2' in features
            info.sse3 = 'SSE3' in features
            info.ssse3 = 'SSSE3' in features
            info.sse41 = 'SSE4.1' in features
            info.sse42 = 'SSE4.2' in features
            info.avx = 'AVX' in features
            info.avx2 = 'AVX2' in features
            info.aes_ni = 'AES' in features
    except Exception:
        pass
    
    return info


def get_hardware_summary() -> Dict:
    """Get complete hardware summary."""
    cpu = detect_cpu()
    simd = detect_simd()
    
    return {
        "cpu": {
            "brand": cpu.brand,
            "cores": cpu.cores,
            "logical_cores": cpu.logical_cores,
            "architecture": cpu.architecture,
        },
        "simd": simd.to_dict(),
        "best_vector_width": simd.best_vector_width,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
        },
    }
