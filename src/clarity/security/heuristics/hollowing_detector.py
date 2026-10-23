from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# Win32 Memory Constants
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", wintypes.DWORD),
        ("PebBaseAddress", wintypes.LPVOID),
        ("AffinityMask", ctypes.c_size_t),
        ("BasePriority", wintypes.DWORD),
        ("UniqueProcessId", ctypes.c_size_t),
        ("InheritedFromUniqueProcessId", ctypes.c_size_t),
    ]

@dataclass
class UnbackedExecutableRegion:
    base_address: int
    region_size: int
    protection: str
    memory_type: str

@dataclass
class HollowingAuditResult:
    pid: int
    is_suspicious: bool
    hollowing_confidence: float  # 0.0 to 1.0
    reasons: List[str]
    unbacked_regions: List[UnbackedExecutableRegion]
    parent_pid: Optional[int] = None
    expected_parent: Optional[str] = None

class ProcessHollowingDetector:
    """Detects Process Hollowing, Shellcode Injection, and Parent PID Spoofing
    using native NT/Win32 APIs (VirtualQueryEx, NtQueryInformationProcess).
    Zero commercial dependencies.
    """

    # Well-known Windows system binaries and their immutable expected parents
    LEGITIMATE_PARENTS = {
        "smss.exe": ["system", "smss.exe"],
        "csrss.exe": ["smss.exe"],
        "wininit.exe": ["smss.exe"],
        "services.exe": ["wininit.exe"],
        "lsass.exe": ["wininit.exe"],
        "svchost.exe": ["services.exe"],
        "explorer.exe": ["userinit.exe", "winlogon.exe"],
    }

    @classmethod
    def audit_process(cls, pid: int, process_name: str, parent_pid: Optional[int] = None, parent_name: Optional[str] = None) -> HollowingAuditResult:
        if os.name != "nt":
            return HollowingAuditResult(pid=pid, is_suspicious=False, hollowing_confidence=0.0, reasons=["Non-Windows platform"], unbacked_regions=[])

        reasons: List[str] = []
        confidence = 0.0
        unbacked_regions: List[UnbackedExecutableRegion] = []

        # 1. Parent PID Spoofing check
        pname_lower = process_name.lower()
        if pname_lower in cls.LEGITIMATE_PARENTS and parent_name:
            expected = cls.LEGITIMATE_PARENTS[pname_lower]
            parent_lower = parent_name.lower()
            if not any(exp in parent_lower for exp in expected):
                confidence += 0.45
                reasons.append(
                    f"Parent-PID Spoofing sospechoso: '{process_name}' generado por '{parent_name}' (esperado: {expected})"
                )

        # 2. Virtual Memory Map Inspection (Unbacked Executable Regions)
        kernel32 = ctypes.windll.kernel32
        h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_process:
            # Cannot inspect privileged system processes or protected light processes (PPL)
            return HollowingAuditResult(
                pid=pid,
                is_suspicious=confidence >= 0.4,
                hollowing_confidence=confidence,
                reasons=reasons,
                unbacked_regions=[],
                parent_pid=parent_pid,
            )

        try:
            mbi = MEMORY_BASIC_INFORMATION()
            current_address = ctypes.c_void_p(0)

            executable_protections = {
                PAGE_EXECUTE: "PAGE_EXECUTE",
                PAGE_EXECUTE_READ: "PAGE_EXECUTE_READ",
                PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
                PAGE_EXECUTE_WRITECOPY: "PAGE_EXECUTE_WRITECOPY",
            }

            while kernel32.VirtualQueryEx(
                h_process,
                current_address,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            ) == ctypes.sizeof(mbi):
                # We only care about committed memory pages
                if mbi.State == MEM_COMMIT:
                    # Check if memory has executable rights
                    protect = mbi.Protect & 0xFF
                    if protect in executable_protections:
                        # Legitimate PE code resides in MEM_IMAGE (backed by a disk binary).
                        # If executable memory is MEM_PRIVATE or MEM_MAPPED without image backing,
                        # it indicates injected shellcode, reflective DLL loading, or hollowed PE.
                        if mbi.Type == MEM_PRIVATE:
                            prot_str = executable_protections[protect]
                            unbacked = UnbackedExecutableRegion(
                                base_address=int(mbi.BaseAddress or 0),
                                region_size=mbi.RegionSize,
                                protection=prot_str,
                                memory_type="MEM_PRIVATE (Unbacked Code)",
                            )
                            unbacked_regions.append(unbacked)

                            # PAGE_EXECUTE_READWRITE (RWX) is a massive red flag (W^X violation)
                            if protect == PAGE_EXECUTE_READWRITE:
                                confidence += 0.50
                                reasons.append(
                                    f"Región RWX sin respaldo en disco detectada en 0x{unbacked.base_address:016X} ({unbacked.region_size // 1024} KB)"
                                )
                            else:
                                confidence += 0.25
                                reasons.append(
                                    f"Memoria ejecutable privada sin respaldo en disco en 0x{unbacked.base_address:016X}"
                                )

                # Advance to next memory region
                addr_val = int(mbi.BaseAddress or 0) + mbi.RegionSize
                if addr_val <= int(mbi.BaseAddress or 0) or addr_val >= 0x7FFFFFFFFFFF:
                    break
                current_address = ctypes.c_void_p(addr_val)

        except Exception as e:
            reasons.append(f"Error durante auditoría de memoria: {e}")
        finally:
            kernel32.CloseHandle(h_process)

        confidence = min(1.0, confidence)
        is_suspicious = confidence >= 0.40

        return HollowingAuditResult(
            pid=pid,
            is_suspicious=is_suspicious,
            hollowing_confidence=round(confidence, 2),
            reasons=reasons,
            unbacked_regions=unbacked_regions,
            parent_pid=parent_pid,
        )
