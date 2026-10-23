from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path
from typing import Any, Dict, Optional

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8)
    ]

# WINTRUST_ACTION_GENERIC_VERIFY_V2
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p)
    ]

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0
WTD_SAFER_FLAG = 0x00000100

_SIG_CACHE: Dict[str, Dict[str, Any]] = {}

class AuthenticodeVerifier:
    """High-performance Windows Authenticode Digital Signature Verifier.
    Uses WinTrust API directly via ctypes with zero subprocess overhead.
    """

    @classmethod
    def verify_file(cls, file_path: str | Path) -> Dict[str, Any]:
        p = Path(file_path).resolve()
        p_str = str(p)

        if not p.exists() or not p.is_file():
            return {
                "path": p_str,
                "is_signed": False,
                "status": "FILE_NOT_FOUND",
                "is_trusted": False
            }

        try:
            mtime = p.stat().st_mtime
            if p_str in _SIG_CACHE and _SIG_CACHE[p_str].get("mtime") == mtime:
                return _SIG_CACHE[p_str]
        except Exception:
            mtime = 0

        if os.name != "nt":
            return {
                "path": p_str,
                "is_signed": False,
                "status": "NON_WINDOWS",
                "is_trusted": False,
                "mtime": mtime
            }

        try:
            file_info = WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            file_info.pcwszFilePath = p_str
            file_info.hFile = None
            file_info.pgKnownSubject = None

            trust_data = WINTRUST_DATA()
            trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            trust_data.pPolicyCallbackData = None
            trust_data.pSIPClientData = None
            trust_data.dwUIChoice = WTD_UI_NONE
            trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
            trust_data.dwUnionChoice = WTD_CHOICE_FILE
            trust_data.pFile = ctypes.pointer(file_info)
            trust_data.dwStateAction = WTD_STATEACTION_IGNORE
            trust_data.hWVTStateData = None
            trust_data.pwszURLReference = None
            trust_data.dwProvFlags = WTD_SAFER_FLAG
            trust_data.dwUIContext = 0
            trust_data.pSignatureSettings = None

            wintrust = ctypes.windll.wintrust
            status_code = wintrust.WinVerifyTrust(
                None,
                ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(trust_data)
            )

            # 0 = ERROR_SUCCESS (Valid signature from trusted root)
            # TRUST_E_NOSIGNATURE = 0x800B0100
            # TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
            # CERT_E_UNTRUSTEDROOT = 0x800B0109
            is_trusted = (status_code == 0)
            if is_trusted:
                status_str = "VALID_TRUSTED"
            elif status_code == -2146762496 or status_code == 0x800B0100:
                status_str = "NOT_SIGNED"
            else:
                status_str = f"UNTRUSTED_OR_REVOKED (0x{status_code & 0xFFFFFFFF:08X})"

            res = {
                "path": p_str,
                "is_signed": is_trusted,
                "is_trusted": is_trusted,
                "status": status_str,
                "mtime": mtime
            }
            _SIG_CACHE[p_str] = res
            return res
        except Exception as e:
            return {
                "path": p_str,
                "is_signed": False,
                "is_trusted": False,
                "status": f"ERROR: {e}",
                "mtime": mtime
            }

    @classmethod
    def audit_process_list(cls, processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Audits a list of process dicts (containing 'Path' or 'path') and appends signature status."""
        annotated = []
        for p in processes:
            path = p.get("Path") or p.get("path")
            if path and os.path.exists(path):
                sig = cls.verify_file(path)
                p_copy = dict(p)
                p_copy["signature_status"] = sig["status"]
                p_copy["is_signed"] = sig["is_signed"]
                annotated.append(p_copy)
            else:
                annotated.append(dict(p))
        return annotated
