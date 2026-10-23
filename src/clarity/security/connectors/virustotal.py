from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

@dataclass
class CloudReputationReport:
    file_path: str
    sha256: str
    is_queried: bool
    is_malicious: bool
    malicious_count: int
    suspicious_count: int
    total_scanners: int
    web_report_url: str
    reputation_score: int  # -100 (malicious) to +100 (benign)
    threat_classification: Optional[str]
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class VirusTotalCloudConnector:
    """Async Cloud Reputation Connector for VirusTotal v3 API.
    Computes local SHA-256 hashes and verifies community reputation
    before taking destructive quarantine actions.
    """

    CACHE_FILE = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "ClarityPC" / "virustotal_cache.json"

    @classmethod
    def compute_sha256(cls, file_path: str | Path) -> str:
        """Computes SHA-256 in memory-efficient 64KB chunks."""
        p = Path(file_path).resolve()
        hasher = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest().lower()

    @classmethod
    def _read_cache(cls) -> Dict[str, Any]:
        if cls.CACHE_FILE.exists():
            try:
                with open(cls.CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    @classmethod
    def _write_cache(cls, cache: Dict[str, Any]) -> None:
        try:
            cls.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(cls.CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
        except Exception:
            pass

    @classmethod
    def check_file_reputation(cls, file_path: str | Path, api_key: Optional[str] = None) -> CloudReputationReport:
        p = Path(file_path).resolve()
        if not p.exists() or not p.is_file():
            return CloudReputationReport(
                file_path=str(p),
                sha256="",
                is_queried=False,
                is_malicious=False,
                malicious_count=0,
                suspicious_count=0,
                total_scanners=0,
                web_report_url="",
                reputation_score=0,
                threat_classification=None,
                message="El archivo objetivo no existe."
            )

        sha256 = cls.compute_sha256(p)
        web_url = f"https://www.virustotal.com/gui/file/{sha256}"

        # 1. Check local persistent cache
        cache = cls._read_cache()
        if sha256 in cache:
            cached = cache[sha256]
            return CloudReputationReport(
                file_path=str(p),
                sha256=sha256,
                is_queried=True,
                is_malicious=cached.get("is_malicious", False),
                malicious_count=cached.get("malicious_count", 0),
                suspicious_count=cached.get("suspicious_count", 0),
                total_scanners=cached.get("total_scanners", 0),
                web_report_url=web_url,
                reputation_score=cached.get("reputation_score", 0),
                threat_classification=cached.get("threat_classification"),
                message="Resultado obtenido desde caché local de reputación."
            )

        # 2. Check if API key is provided
        active_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        if not active_key:
            # Without API key, return the computed hash and direct web GUI URL
            return CloudReputationReport(
                file_path=str(p),
                sha256=sha256,
                is_queried=False,
                is_malicious=False,
                malicious_count=0,
                suspicious_count=0,
                total_scanners=0,
                web_report_url=web_url,
                reputation_score=0,
                threat_classification=None,
                message=f"Hash SHA-256 calculado ({sha256[:12]}...). Consulta disponible en: {web_url}"
            )

        # 3. Query VirusTotal v3 REST API
        endpoint = f"https://www.virustotal.com/api/v3/files/{sha256}"
        req = urllib.request.Request(
            endpoint,
            headers={
                "x-apikey": active_key,
                "User-Agent": "ClarityPC-OpenSource-Security/1.0"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=8) as response:
                payload = json.loads(response.read().decode("utf-8"))
                attrs = payload.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                popular_threat = attrs.get("popular_threat_classification", {})

                mal = int(stats.get("malicious", 0))
                susp = int(stats.get("suspicious", 0))
                undet = int(stats.get("undetected", 0))
                harm = int(stats.get("harmless", 0))
                total = mal + susp + undet + harm

                is_mal = mal >= 3
                rep_score = attrs.get("reputation", 0)
                threat_name = popular_threat.get("suggested_threat_label")

                report = CloudReputationReport(
                    file_path=str(p),
                    sha256=sha256,
                    is_queried=True,
                    is_malicious=is_mal,
                    malicious_count=mal,
                    suspicious_count=susp,
                    total_scanners=total,
                    web_report_url=web_url,
                    reputation_score=rep_score,
                    threat_classification=threat_name,
                    message=f"Detección en la nube: {mal}/{total} motores marcaron el archivo como malicioso."
                )

                # Save to cache
                cache[sha256] = {
                    "is_malicious": is_mal,
                    "malicious_count": mal,
                    "suspicious_count": susp,
                    "total_scanners": total,
                    "reputation_score": rep_score,
                    "threat_classification": threat_name
                }
                cls._write_cache(cache)

                return report

        except urllib.error.HTTPError as e:
            if e.code == 404:
                # File unknown to VirusTotal (never submitted before)
                return CloudReputationReport(
                    file_path=str(p),
                    sha256=sha256,
                    is_queried=True,
                    is_malicious=False,
                    malicious_count=0,
                    suspicious_count=0,
                    total_scanners=0,
                    web_report_url=web_url,
                    reputation_score=0,
                    threat_classification="UNKNOWN_FILE",
                    message="El archivo es completamente nuevo en la red (0 muestras en VirusTotal)."
                )
            return CloudReputationReport(
                file_path=str(p),
                sha256=sha256,
                is_queried=False,
                is_malicious=False,
                malicious_count=0,
                suspicious_count=0,
                total_scanners=0,
                web_report_url=web_url,
                reputation_score=0,
                threat_classification=None,
                message=f"Error HTTP consultando VirusTotal: {e.code}"
            )
        except Exception as e:
            return CloudReputationReport(
                file_path=str(p),
                sha256=sha256,
                is_queried=False,
                is_malicious=False,
                malicious_count=0,
                suspicious_count=0,
                total_scanners=0,
                web_report_url=web_url,
                reputation_score=0,
                threat_classification=None,
                message=f"Error de red consultando VirusTotal: {e}"
            )
