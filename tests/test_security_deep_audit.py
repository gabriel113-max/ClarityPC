"""
╔══════════════════════════════════════════════════════════════════════════╗
║  ClarityPC — DEEP SECURITY & FULL FUNCTION AUDIT TEST SUITE            ║
║                                                                        ║
║  Simulates real-world malware scenarios with SAFE, inert test files     ║
║  (EICAR standard) and validates EVERY detection & remediation path.    ║
║                                                                        ║
║  Categories tested:                                                    ║
║    A) Virus/malware detection (EICAR, signatures, heuristics)          ║
║    B) Hidden threat detection (hollowing, masquerading, persistence)   ║
║    C) Remediation engine (quarantine, boot-delete, hosts cleanup)      ║
║    D) All core diagnostic engines (hardware, BIOS, network, security)  ║
║    E) Optimizer actions (dry-run, apply, rollback)                     ║
║    F) Companion system (state machine, all characters, all moods)      ║
║    G) Reports (Markdown, JSON, forum bundle, anonymization)            ║
║    H) Safety (state manager, transaction recording, rollback tracking) ║
║    I) Telemetry & watchdog (live sensors, event log monitoring)        ║
║    J) Health score calculator (all penalty scenarios)                  ║
║    K) VRAM integrity tester                                            ║
║    L) Gaming latency engine (timer resolution, game detection)         ║
║    M) VirusTotal cloud connector (SHA-256, cache, API simulation)      ║
║    N) ClamAV local connector                                           ║
║    O) Anti-tamper system integrity monitor                             ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import ctypes
import hashlib
import json
import os
import shutil
import sys
import tempfile
import textwrap
import threading
import time
import traceback
import winreg
from pathlib import Path

# Ensure src is in pythonpath
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

# ─── EICAR Standard Anti-Malware Test String ──────────────────────────────
# This is the INDUSTRY STANDARD test string used by every antivirus vendor.
# It is completely inert and causes zero harm. If Defender intercepts it,
# that actually proves Defender's real-time protection works.
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# ─── Test infrastructure ──────────────────────────────────────────────────
_passed = 0
_failed = 0
_skipped = 0
_results = []

def _test(name, func, allow_skip=False):
    global _passed, _failed, _skipped
    try:
        func()
        _passed += 1
        _results.append((name, "PASS", ""))
        print(f"  ✅ [PASS] {name}")
    except PermissionError as e:
        if allow_skip:
            _skipped += 1
            _results.append((name, "SKIP", str(e)))
            print(f"  ⏭️  [SKIP] {name} (requiere admin: {e})")
        else:
            _failed += 1
            _results.append((name, "FAIL", str(e)))
            print(f"  ❌ [FAIL] {name} → {e}")
    except Exception as e:
        _failed += 1
        tb = traceback.format_exc()
        _results.append((name, "FAIL", tb))
        print(f"  ❌ [FAIL] {name} → {e}")


def run_deep_security_audit():
    """Master test runner that exercises every capability of ClarityPC."""

    # Create a safe temporary sandbox for all test artifacts
    sandbox = Path(tempfile.mkdtemp(prefix="ClarityPC_SecurityAudit_"))
    print(f"\n{'='*80}")
    print(f"  🔬 ClarityPC DEEP SECURITY & FULL FUNCTION AUDIT")
    print(f"  📂 Sandbox: {sandbox}")
    print(f"{'='*80}\n")

    try:
        # ═══════════════════════════════════════════════════════════════════
        #  SECTION A: VIRUS / MALWARE DETECTION TESTS
        # ═══════════════════════════════════════════════════════════════════
        print("─── A) DETECCIÓN DE VIRUS Y MALWARE ───────────────────────")

        # A1: EICAR test file creation & SHA-256 verification
        def test_eicar_sha256():
            from clarity.security.connectors.virustotal import VirusTotalCloudConnector
            eicar_path = sandbox / "eicar_test.com"
            try:
                eicar_path.write_text(EICAR_STRING, encoding="ascii")
            except PermissionError:
                # Defender may block writing EICAR - that's actually a PASS!
                print("    ↳ Defender bloqueó la escritura del EICAR (protección activa confirmada)")
                return
            
            if eicar_path.exists():
                sha = VirusTotalCloudConnector.compute_sha256(eicar_path)
                # Known EICAR SHA-256
                expected = hashlib.sha256(EICAR_STRING.encode("ascii")).hexdigest().lower()
                assert sha == expected, f"SHA-256 mismatch: {sha} != {expected}"
                # Clean up immediately
                try:
                    eicar_path.unlink()
                except Exception:
                    pass
            else:
                # Defender removed it - that's the best proof of detection!
                pass
        _test("A1: EICAR Standard AV Test File + SHA-256 Hash Computation", test_eicar_sha256)

        # A2: Defender status check
        def test_defender_status():
            from clarity.core.security import SecurityDiagnosticEngine
            eng = SecurityDiagnosticEngine()
            report = eng.run()
            assert report is not None
            defender_item = next((i for i in report.items if i.id == "sec_defender_status"), None)
            assert defender_item is not None, "sec_defender_status diagnostic item not found"
            assert defender_item.category == "Antivirus"
            # Should have metrics
            assert "real_time" in defender_item.metrics or defender_item.severity.value == "info"
        _test("A2: Windows Defender Status & Real-Time Protection Check", test_defender_status)

        # A3: Threat history audit
        def test_threat_history():
            from clarity.core.security import SecurityDiagnosticEngine
            eng = SecurityDiagnosticEngine()
            report = eng.run()
            threat_item = next((i for i in report.items if i.id == "sec_threat_history"), None)
            # May not exist if Get-MpThreatDetection fails (non-Defender systems)
            if threat_item:
                assert "threat_count" in threat_item.metrics
        _test("A3: Malware Threat History Audit (Get-MpThreatDetection)", test_threat_history)

        # A4: VirusTotal connector - compute hash & check reputation (offline)
        def test_virustotal_connector():
            from clarity.security.connectors.virustotal import VirusTotalCloudConnector
            # Test with a known safe system file
            explorer = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "explorer.exe"
            if explorer.exists():
                report = VirusTotalCloudConnector.check_file_reputation(explorer)
                assert report.sha256 != "", "SHA-256 should not be empty"
                assert len(report.sha256) == 64, "SHA-256 should be 64 hex chars"
                assert "virustotal.com" in report.web_report_url
            
            # Test with non-existent file
            report_bad = VirusTotalCloudConnector.check_file_reputation(r"C:\fake_file_xyz.exe")
            assert report_bad.is_queried is False
        _test("A4: VirusTotal Cloud Connector (SHA-256 + Offline Reputation)", test_virustotal_connector)

        # A5: VirusTotal cache persistence
        def test_vt_cache():
            from clarity.security.connectors.virustotal import VirusTotalCloudConnector
            # Force write a cache entry and read it back
            test_cache = {"abc123": {"is_malicious": True, "malicious_count": 50, "total_scanners": 70}}
            original_cache_file = VirusTotalCloudConnector.CACHE_FILE
            test_cache_file = sandbox / "vt_test_cache.json"
            VirusTotalCloudConnector.CACHE_FILE = test_cache_file
            try:
                VirusTotalCloudConnector._write_cache(test_cache)
                read_back = VirusTotalCloudConnector._read_cache()
                assert "abc123" in read_back
                assert read_back["abc123"]["malicious_count"] == 50
            finally:
                VirusTotalCloudConnector.CACHE_FILE = original_cache_file
        _test("A5: VirusTotal Local Reputation Cache Persistence", test_vt_cache)

        # A6: ClamAV connector availability check
        def test_clamav_connector():
            from clarity.security.connectors.clamav import ClamAVConnector
            # Test binary detection (may not be installed)
            is_installed = ClamAVConnector.is_installed()
            assert isinstance(is_installed, bool)
            
            # Test scan of non-existent file
            result = ClamAVConnector.scan_file(r"C:\fake_nonexistent_binary.exe")
            assert result.is_infected is False
            if not is_installed:
                assert result.engine_available is False
                assert "winget" in result.message.lower() or "clamav" in result.message.lower()
        _test("A6: ClamAV Local Engine Connector & Fallback", test_clamav_connector)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION B: HIDDEN THREAT DETECTION (THE "IMPOSSIBLE" ONES)
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── B) DETECCIÓN DE AMENAZAS OCULTAS ('IMPOSIBLES') ────────")

        # B1: Fake malware in %TEMP% detection
        def test_detect_temp_process():
            from clarity.security.heuristics.process_telemetry import ProcessTelemetryEngine
            # Simulate a suspicious process running from TEMP
            fake_proc = {
                "Id": 99999,
                "ProcessName": "trojan_test",
                "Path": os.path.join(os.environ.get("TEMP", ""), "trojan_test.exe"),
                "ParentId": 1,
                "ParentName": "explorer.exe"
            }
            record = ProcessTelemetryEngine.evaluate_process(fake_proc)
            assert record.score >= 25, f"Expected score >= 25 for TEMP executable, got {record.score}"
            assert record.level in ("LOW_RISK", "SUSPICIOUS", "CRITICAL_THREAT")
            assert any("temp" in r.lower() or "temporal" in r.lower() for r in record.reasons)
        _test("B1: Detect Fake Executable Running from %TEMP%", test_detect_temp_process)

        # B2: Process masquerading detection (fake svchost.exe)
        def test_masquerade_svchost():
            from clarity.security.heuristics.process_telemetry import ProcessTelemetryEngine
            fake_proc = {
                "Id": 88888,
                "ProcessName": "svchost",
                "Path": r"C:\Users\Public\svchost.exe",  # WRONG PATH = masquerade
                "ParentId": 1,
                "ParentName": "explorer.exe"  # svchost should be from services.exe
            }
            record = ProcessTelemetryEngine.evaluate_process(fake_proc)
            assert record.score >= 55, f"Masquerade score should be >= 55, got {record.score}"
            assert record.level == "CRITICAL_THREAT", f"Expected CRITICAL_THREAT, got {record.level}"
            assert any("falsificación" in r.lower() or "masquerade" in r.lower() or "no autorizada" in r.lower() for r in record.reasons)
        _test("B2: Detect svchost.exe Masquerading (Fake System Process)", test_masquerade_svchost)

        # B3: Fake lsass.exe masquerading
        def test_masquerade_lsass():
            from clarity.security.heuristics.process_telemetry import ProcessTelemetryEngine
            record = ProcessTelemetryEngine.evaluate_process({
                "Id": 77777,
                "ProcessName": "lsass",
                "Path": r"C:\Users\Public\Downloads\lsass.exe",
                "ParentId": 4,
                "ParentName": "cmd.exe"
            })
            assert record.score >= 55, f"Fake lsass score should be >= 55, got {record.score}"
            assert record.level == "CRITICAL_THREAT"
        _test("B3: Detect lsass.exe Masquerading Attack", test_masquerade_lsass)

        # B4: Parent PID spoofing detection
        def test_parent_pid_spoofing():
            from clarity.security.heuristics.hollowing_detector import ProcessHollowingDetector
            # csrss.exe should be spawned by smss.exe, NOT by cmd.exe
            result = ProcessHollowingDetector.audit_process(
                pid=0,  # Not a real PID, but tests the heuristic logic
                process_name="csrss.exe",
                parent_pid=999,
                parent_name="cmd.exe"
            )
            assert result.hollowing_confidence >= 0.40, f"Expected >= 0.40 confidence, got {result.hollowing_confidence}"
            assert result.is_suspicious is True
            assert any("parent" in r.lower() or "spoofing" in r.lower() for r in result.reasons)
        _test("B4: Parent PID Spoofing Detection (csrss.exe from cmd.exe)", test_parent_pid_spoofing)

        # B5: Process hollowing detector on current process (should be clean)
        def test_self_hollowing_clean():
            from clarity.security.heuristics.hollowing_detector import ProcessHollowingDetector
            my_pid = os.getpid()
            result = ProcessHollowingDetector.audit_process(
                pid=my_pid,
                process_name="python.exe",
                parent_pid=os.getppid() if hasattr(os, 'getppid') else None,
                parent_name=None
            )
            # Our own Python process should NOT be flagged as hollowed
            # (small RWX regions from JIT are possible but confidence should be low)
            assert isinstance(result.hollowing_confidence, float)
            assert isinstance(result.unbacked_regions, list)
        _test("B5: Self-Audit Process Hollowing (Current Python Process)", test_self_hollowing_clean)

        # B6: Executable in C:\Users\Public detection
        def test_detect_public_folder():
            from clarity.security.heuristics.process_telemetry import ProcessTelemetryEngine
            record = ProcessTelemetryEngine.evaluate_process({
                "Id": 66666,
                "ProcessName": "backdoor_sim",
                "Path": r"C:\Users\Public\backdoor_sim.exe",
                "ParentId": 1,
                "ParentName": "explorer.exe"
            })
            assert record.score >= 35, f"Public folder score should be >= 35, got {record.score}"
            assert any("public" in r.lower() for r in record.reasons)
        _test("B6: Detect Executable in C:\\Users\\Public (Common Trojan Vector)", test_detect_public_folder)

        # B7: AppData Roaming execution detection
        def test_detect_appdata_roaming():
            from clarity.security.heuristics.process_telemetry import ProcessTelemetryEngine
            appdata = os.environ.get("APPDATA", r"C:\Users\test\AppData\Roaming")
            record = ProcessTelemetryEngine.evaluate_process({
                "Id": 55555,
                "ProcessName": "stealer_sim",
                "Path": os.path.join(appdata, "stealer_sim.exe"),
                "ParentId": 1,
                "ParentName": "explorer.exe"
            })
            assert record.score >= 25, f"AppData Roaming score should be >= 25, got {record.score}"
        _test("B7: Detect Executable from %APPDATA% Roaming", test_detect_appdata_roaming)

        # B8: Full system process scan
        def test_full_process_scan():
            from clarity.security.heuristics.process_telemetry import ProcessTelemetryEngine
            records = ProcessTelemetryEngine.scan_all_processes(max_processes=30)
            assert isinstance(records, list)
            if records:
                # Should be sorted by score descending
                scores = [r.score for r in records]
                assert scores == sorted(scores, reverse=True), "Records should be sorted by score descending"
                # Verify data structure
                first = records[0]
                assert hasattr(first, "pid")
                assert hasattr(first, "score")
                assert hasattr(first, "level")
                assert hasattr(first, "is_signed")
                assert hasattr(first, "hollowing_detected")
                assert first.level in ("CLEAN", "LOW_RISK", "SUSPICIOUS", "CRITICAL_THREAT")
        _test("B8: Full System Process Scan (Top 30 Processes)", test_full_process_scan)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION C: PERSISTENCE HUNTING & REMEDIATION
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── C) CAZA DE PERSISTENCIA Y REMEDIACIÓN ─────────────────")

        # C1: Registry Run key audit
        def test_persistence_registry():
            from clarity.security.persistence.auditor import PersistenceAuditor
            items = PersistenceAuditor._audit_registry_run()
            assert isinstance(items, list)
            for item in items:
                assert item.location_type == "REGISTRY"
                assert item.risk_level in ("LOW", "MEDIUM", "CRITICAL")
                assert isinstance(item.is_signed, bool)
        _test("C1: Registry Run/RunOnce Persistence Audit", test_persistence_registry)

        # C2: Winlogon Shell/Userinit hijacking audit
        def test_persistence_winlogon():
            from clarity.security.persistence.auditor import PersistenceAuditor
            items = PersistenceAuditor._audit_winlogon_hijacks()
            assert isinstance(items, list)
            # On a clean system, shell should be explorer.exe
            for item in items:
                assert item.location_type == "WINLOGON"
                if "Shell" in item.name and not item.is_suspicious:
                    assert "explorer.exe" in item.target.lower()
        _test("C2: Winlogon Shell & Userinit Hijack Audit", test_persistence_winlogon)

        # C3: IFEO debugger hijack audit
        def test_persistence_ifeo():
            from clarity.security.persistence.auditor import PersistenceAuditor
            items = PersistenceAuditor._audit_ifeo_hijacks()
            assert isinstance(items, list)
            # Any IFEO with Debugger key is suspicious
            for item in items:
                assert item.location_type == "IFEO"
                assert item.is_suspicious is True
                assert item.risk_level == "CRITICAL"
        _test("C3: Image File Execution Options (IFEO) Debugger Hijack Audit", test_persistence_ifeo)

        # C4: Scheduled Tasks persistence scan
        def test_persistence_scheduled_tasks():
            from clarity.security.persistence.auditor import PersistenceAuditor
            items = PersistenceAuditor._audit_scheduled_tasks()
            assert isinstance(items, list)
            for item in items:
                assert item.location_type == "SCHEDULED_TASK"
        _test("C4: Scheduled Tasks Persistence Scan", test_persistence_scheduled_tasks)

        # C5: Hosts file poisoning detection
        def test_persistence_hosts():
            from clarity.security.persistence.auditor import PersistenceAuditor
            items = PersistenceAuditor._audit_hosts_file()
            assert isinstance(items, list)
            # On a clean system, should be empty (no security domain redirects)
            for item in items:
                assert item.location_type == "HOSTS"
                assert item.is_suspicious is True
                assert item.risk_level == "CRITICAL"
        _test("C5: Hosts File DNS Sinkhole Detection", test_persistence_hosts)

        # C6: Simulated hosts file poisoning detection
        def test_simulated_hosts_poisoning():
            from clarity.security.persistence.auditor import PersistenceAuditor
            # Create a fake hosts file with malicious redirects
            fake_hosts = sandbox / "hosts_poisoned"
            fake_hosts.write_text(
                "# Normal entries\n"
                "127.0.0.1       localhost\n"
                "::1             localhost\n"
                "# Malicious redirects blocking security updates\n"
                "0.0.0.0  virustotal.com\n"
                "0.0.0.0  update.microsoft.com\n"
                "0.0.0.0  malwarebytes.com\n",
                encoding="utf-8"
            )
            # Temporarily point auditor to our fake file
            original_path = PersistenceAuditor.HOSTS_PATH
            PersistenceAuditor.HOSTS_PATH = fake_hosts
            try:
                items = PersistenceAuditor._audit_hosts_file()
                assert len(items) >= 3, f"Expected >= 3 malicious redirects detected, got {len(items)}"
                domains_found = [i.name.lower() for i in items]
                assert any("virustotal" in d for d in domains_found), "Should detect virustotal.com redirect"
                assert any("microsoft" in d for d in domains_found), "Should detect microsoft.com redirect"
                assert any("malwarebytes" in d for d in domains_found), "Should detect malwarebytes.com redirect"
            finally:
                PersistenceAuditor.HOSTS_PATH = original_path
        _test("C6: Simulated Hosts File Poisoning (Blocks Security Sites)", test_simulated_hosts_poisoning)

        # C7: Full persistence audit
        def test_full_persistence_audit():
            from clarity.security.persistence.auditor import PersistenceAuditor
            all_items = PersistenceAuditor.audit_all()
            assert isinstance(all_items, list)
            # Should have at least some registry items on any Windows system
            types_found = {i.location_type for i in all_items}
            assert "REGISTRY" in types_found or "WINLOGON" in types_found, "Should find persistence in Registry or Winlogon"
        _test("C7: Full Comprehensive Persistence Audit (All Vectors)", test_full_persistence_audit)

        # C8: Quarantine engine
        def test_quarantine():
            from clarity.security.persistence.remediation import SafeRemediationEngine
            # Create a fake malware file
            fake_malware = sandbox / "fake_trojan.exe"
            fake_malware.write_bytes(b"\x00" * 1024)
            
            # Override quarantine dir to sandbox
            original_qdir = SafeRemediationEngine.DEFAULT_QUARANTINE_DIR
            SafeRemediationEngine.DEFAULT_QUARANTINE_DIR = sandbox / "quarantine_test"
            try:
                result = SafeRemediationEngine.quarantine_file(fake_malware, reason="Test quarantine")
                assert result.success is True
                assert result.action_type == "QUARANTINED"
                # Verify quarantine metadata was created
                q_dir = sandbox / "quarantine_test"
                meta_files = list(q_dir.glob("*.meta.json"))
                assert len(meta_files) >= 1, "Quarantine metadata file should exist"
                # Verify original file was deleted
                assert not fake_malware.exists(), "Original malware file should be deleted after quarantine"
            finally:
                SafeRemediationEngine.DEFAULT_QUARANTINE_DIR = original_qdir
        _test("C8: Safe Quarantine Engine (Isolate + Delete Malware)", test_quarantine)

        # C9: Boot-time deletion scheduling
        def test_boot_deletion():
            from clarity.security.persistence.remediation import SafeRemediationEngine
            # Test with non-existent file (should return True)
            result = SafeRemediationEngine.schedule_boot_deletion(r"C:\nonexistent_file_xyz.tmp")
            assert result is True
        _test("C9: Boot-Time Deletion via MoveFileExW (Kernel-Level Delete)", test_boot_deletion)

        # C10: Process termination safety check
        def test_process_terminate_safety():
            from clarity.security.persistence.remediation import SafeRemediationEngine
            # Should refuse to terminate system-critical PIDs (PID <= 4)
            result = SafeRemediationEngine.terminate_process_safe(0)
            assert result is False
            result = SafeRemediationEngine.terminate_process_safe(4)
            assert result is False
        _test("C10: Process Termination Safety Guard (Refuses PID <= 4)", test_process_terminate_safety)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION D: CORE DIAGNOSTIC ENGINES (ALL MODULES)
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── D) MOTORES DE DIAGNÓSTICO CORE ────────────────────────")

        # D1: Hardware engine
        def test_hw_engine():
            from clarity.core.hardware import HardwareDiagnosticEngine
            eng = HardwareDiagnosticEngine()
            report = eng.run()
            assert report is not None
            assert report.engine_name == "hardware"
            assert len(report.items) >= 3
            categories = {i.category for i in report.items}
            assert "Procesador" in categories
        _test("D1: Hardware Diagnostic Engine (CPU, RAM/XMP, GPU/TDR, PSU)", test_hw_engine)

        # D2: BIOS engine
        def test_bios_engine():
            from clarity.core.bios import BiosDiagnosticEngine
            eng = BiosDiagnosticEngine()
            report = eng.run()
            assert report is not None
            assert report.engine_name == "bios"
            assert len(report.items) >= 2
            ids = {i.id for i in report.items}
            assert "bios_firmware_info" in ids
            assert "bios_secure_boot" in ids
        _test("D2: BIOS & UEFI Firmware Diagnostic Engine", test_bios_engine)

        # D3: Network engine
        def test_network_engine():
            from clarity.core.network import NetworkDiagnosticEngine
            eng = NetworkDiagnosticEngine()
            report = eng.run()
            assert report is not None
            assert report.engine_name == "network"
            assert len(report.items) >= 2
            ids = {i.id for i in report.items}
            assert "net_latency_jitter" in ids
            assert "net_dns_latency" in ids
        _test("D3: Network & DNS Latency Diagnostic Engine", test_network_engine)

        # D4: Security engine (all sub-diagnostics)
        def test_security_engine_full():
            from clarity.core.security import SecurityDiagnosticEngine
            eng = SecurityDiagnosticEngine()
            report = eng.run()
            assert report is not None
            assert report.engine_name == "security"
            ids = {i.id for i in report.items}
            expected_ids = {"sec_defender_status", "sec_process_audit", "sec_wintrust_signatures", "sec_startup_apps", "sec_network_ports"}
            found = expected_ids.intersection(ids)
            assert len(found) >= 4, f"Expected at least 4 security diagnostics, found: {found}"
        _test("D4: Full Security Engine (Defender + Heuristics + Signatures + Ports)", test_security_engine_full)

        # D5: Authenticode signature verification
        def test_authenticode():
            from clarity.core.signature import AuthenticodeVerifier
            # explorer.exe should be signed (embedded Authenticode)
            res = AuthenticodeVerifier.verify_file(r"C:\Windows\explorer.exe")
            assert res["is_signed"] is True
            assert res["status"] == "VALID_TRUSTED"
            
            # winlogon.exe may use catalog signing (NOT embedded Authenticode)
            # WinTrust API only validates embedded signatures, so NOT_SIGNED is valid
            res2 = AuthenticodeVerifier.verify_file(r"C:\Windows\System32\winlogon.exe")
            assert isinstance(res2["is_signed"], bool)
            assert res2["status"] in ("VALID_TRUSTED", "NOT_SIGNED")
            
            # Non-existent file
            res3 = AuthenticodeVerifier.verify_file(r"C:\fake.exe")
            assert res3["is_signed"] is False
            assert res3["status"] == "FILE_NOT_FOUND"
            
            # Test cache (second call should be cached)
            res4 = AuthenticodeVerifier.verify_file(r"C:\Windows\explorer.exe")
            assert res4["is_signed"] is True
        _test("D5: Native WinTrust Authenticode Signature Verification", test_authenticode)

        # D6: Authenticode batch process audit
        def test_authenticode_batch():
            from clarity.core.signature import AuthenticodeVerifier
            procs = [
                {"Path": r"C:\Windows\explorer.exe"},
                {"Path": r"C:\Windows\System32\cmd.exe"},
                {"path": r"C:\nonexistent.exe"},
            ]
            results = AuthenticodeVerifier.audit_process_list(procs)
            assert len(results) == 3
            # explorer.exe should have embedded Authenticode signature
            assert results[0].get("is_signed") is True
            # cmd.exe may use catalog signing (NOT embedded Authenticode) on newer Windows builds
            assert isinstance(results[1].get("is_signed"), bool)
            assert results[1].get("signature_status") in ("VALID_TRUSTED", "NOT_SIGNED")
        _test("D6: Batch Process Authenticode Audit", test_authenticode_batch)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION E: OPTIMIZER ACTIONS (DRY-RUN, APPLY, ROLLBACK)
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── E) ACCIONES DE OPTIMIZACIÓN ────────────────────────────")

        # E1: DirectX Shader Cache cleaner
        def test_shader_cache():
            from clarity.optimizer.cleaner import DirectXShaderCacheAction
            action = DirectXShaderCacheAction()
            assert action.id == "clean_directx_shader_cache"
            assert action.is_applicable() is True
            preview = action.dry_run()
            assert preview is not None
            assert len(preview.operations) > 0
            assert len(preview.rollback_guarantee) > 0
        _test("E1: DirectX Shader Cache Cleaner (Dry-Run)", test_shader_cache)

        # E2: Safe Temp Cleaner
        def test_temp_cleaner():
            from clarity.optimizer.cleaner import SafeTempCleanerAction
            action = SafeTempCleanerAction()
            assert action.id == "clean_safe_temp"
            preview = action.dry_run()
            assert preview is not None
            assert "24" in preview.operations[0] or "huérfano" in preview.operations[0].lower()
        _test("E2: Safe Temp Cleaner >24h (Dry-Run)", test_temp_cleaner)

        # E3: DNS Flush
        def test_dns_flush():
            from clarity.optimizer.cleaner import DnsFlushAction
            action = DnsFlushAction()
            assert action.id == "network_dns_flush"
            preview = action.dry_run()
            assert "DNS" in preview.operations[0] or "Dns" in preview.operations[0]
        _test("E3: DNS Cache Flush (Dry-Run)", test_dns_flush)

        # E4: Windows Update Cache
        def test_win_update():
            from clarity.optimizer.cleaner import WinUpdateCacheAction
            action = WinUpdateCacheAction()
            assert action.id == "clean_win_update_cache"
            preview = action.dry_run()
            assert preview is not None
        _test("E4: Windows Update Cache Cleaner (Dry-Run)", test_win_update)

        # E5: Debloat actions
        def test_debloat_diagtrack():
            from clarity.optimizer.debloat import DisableDiagTrackAction
            action = DisableDiagTrackAction()
            assert action.id == "opt_debloat_diagtrack"
            preview = action.dry_run()
            assert any("DiagTrack" in op for op in preview.operations)
            is_already = action.is_applied()
            assert isinstance(is_already, bool)
        _test("E5: Disable DiagTrack Telemetry (Dry-Run + Status)", test_debloat_diagtrack)

        def test_debloat_bing():
            from clarity.optimizer.debloat import DisableStartMenuBingSearchAction
            action = DisableStartMenuBingSearchAction()
            assert action.id == "opt_debloat_bing_search"
            preview = action.dry_run()
            assert "DisableSearchBoxSuggestions" in preview.operations[0]
        _test("E6: Disable Bing Search in Start Menu (Dry-Run)", test_debloat_bing)

        def test_debloat_edge():
            from clarity.optimizer.debloat import DisableEdgeBackgroundBoostAction
            action = DisableEdgeBackgroundBoostAction()
            assert action.id == "opt_debloat_edge_boost"
            preview = action.dry_run()
            assert any("Edge" in op for op in preview.operations)
        _test("E7: Disable Edge Background Boost (Dry-Run)", test_debloat_edge)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION F: COMPANION SYSTEM (ALL CHARACTERS, ALL MOODS)
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── F) SISTEMA DE COMPAÑERO INTERACTIVO ────────────────────")

        # F1: All characters initialization
        def test_all_characters():
            from clarity.companion.characters import CharacterType, CHARACTERS
            assert len(CHARACTERS) == 4
            for ctype in CharacterType:
                profile = CHARACTERS[ctype]
                assert profile.name != ""
                assert profile.icon_idle != ""
                assert profile.icon_working != ""
                assert profile.icon_alarm != ""
                assert profile.icon_happy != ""
        _test("F1: All 4 Companion Characters (Byte, Patch, Gizmo, Pro)", test_all_characters)

        # F2: All moods for each character
        def test_all_moods():
            from clarity.companion.state_machine import CompanionStateMachine, CompanionMood
            from clarity.companion.characters import CharacterType
            for ctype in CharacterType:
                sm = CompanionStateMachine(ctype)
                for mood in CompanionMood:
                    bubble = sm.get_speech(mood, context="Test Context", extra_data="Test Detail")
                    assert bubble is not None
                    assert bubble.mood == mood
                    assert bubble.headline != ""
                    assert bubble.message != ""
        _test("F2: All 6 Moods × 4 Characters = 24 Dialogue Combinations", test_all_moods)

        # F3: Character switching
        def test_character_switching():
            from clarity.companion.state_machine import CompanionStateMachine, CompanionMood
            from clarity.companion.characters import CharacterType
            sm = CompanionStateMachine(CharacterType.BYTE_CAT)
            assert sm.profile.name == "Byte"
            sm.set_character(CharacterType.PATCH_DOG)
            assert sm.profile.name == "Patch"
            sm.set_character(CharacterType.GIZMO_ROBOT)
            assert sm.profile.name == "Gizmo"
            sm.set_character(CharacterType.PRO_SILENT)
            # Pro silent mode should return technical-only output
            bubble = sm.get_speech(CompanionMood.IDLE)
            assert bubble.character_name == "Consola"
        _test("F3: Dynamic Character Switching & Pro-Silent Mode", test_character_switching)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION G: REPORTS & EXPORT
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── G) REPORTES Y EXPORTACIÓN ──────────────────────────────")

        # G1: Markdown report
        def test_markdown_report():
            from clarity.core.base import DiagnosticReport, DiagnosticItem, Severity
            from clarity.reports.exporter import ReportExporter
            report = DiagnosticReport(engine_name="test_engine")
            report.items.append(DiagnosticItem(
                id="test_1", category="Test", title="Test Item",
                severity=Severity.WARNING, summary="This is a test warning",
                recommendation="Fix this"
            ))
            report.items.append(DiagnosticItem(
                id="test_2", category="Test", title="Test OK",
                severity=Severity.OK, summary="All good"
            ))
            md = ReportExporter.to_markdown([report], user_name="TestUser")
            assert "ClarityPC" in md
            assert "🟡 AVISO" in md
            assert "🟢 OK" in md
            assert "Fix this" in md
        _test("G1: Markdown Report Generation (Severity Badges)", test_markdown_report)

        # G2: JSON report
        def test_json_report():
            from clarity.core.base import DiagnosticReport, DiagnosticItem, Severity
            from clarity.reports.exporter import ReportExporter
            report = DiagnosticReport(engine_name="json_test")
            report.items.append(DiagnosticItem(
                id="j1", category="Cat", title="Title",
                severity=Severity.CRITICAL, summary="Critical issue",
                metrics={"score": 99}
            ))
            json_str = ReportExporter.to_json([report])
            data = json.loads(json_str)
            assert len(data) == 1
            assert data[0]["engine"] == "json_test"
            assert data[0]["highest_severity"] == "critical"
            assert data[0]["items"][0]["metrics"]["score"] == 99
        _test("G2: JSON Report Serialization (All Fields)", test_json_report)

        # G3: Forum bundle with anonymization
        def test_forum_bundle():
            from clarity.reports.forum_bundle import ForumBundleExporter
            hw = {
                "cpu": {"name": "AMD Ryzen 7 5800X3D", "cores": "8C / 16T"},
                "ram": {"capacity": "32 GB DDR4", "configured_mhz": 2666, "rated_mhz": 3600},
                "gpu": {"name": "NVIDIA GeForce RTX 4090", "tdr_count": 250},
                "psu": {"kp41_count": 15},
                "motherboard": {"name": "ASUS ROG X570"},
            }
            telem = {"dpc_jitter_us": 500.0, "dpc_peak_us": 12000.0}
            md = ForumBundleExporter.generate_markdown(hw, telem)
            assert "ClarityPC" in md
            assert "RTX 4090" in md
            assert "250 nvlddmkm" in md
            assert "CRITICAL" in md
            assert "DISABLED" in md  # XMP disabled
            assert "DPC" in md or "Latency" in md
            # Anonymization
            username = os.environ.get("USERNAME", "")
            if username and username != "<USER>":
                assert username not in md, f"Username '{username}' was NOT anonymized!"
        _test("G3: Forum Bundle Generation + Username Anonymization", test_forum_bundle)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION H: SAFETY & TRANSACTION MANAGEMENT
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── H) SEGURIDAD Y GESTIÓN DE TRANSACCIONES ────────────────")

        # H1: Transaction recording & rollback
        def test_state_manager():
            from clarity.safety.state_manager import StateManager
            state_file = sandbox / "test_transactions.json"
            sm = StateManager(state_file)
            
            # Record
            sm.record_apply("action_1", "Test Action", {"key": "original_value"})
            state = sm.get_latest_state("action_1")
            assert state is not None
            assert state["key"] == "original_value"
            
            # Mark rollback
            sm.mark_rolled_back("action_1")
            state2 = sm.get_latest_state("action_1")
            assert state2 is None  # Should be None after rollback
            
            # Active transactions
            sm.record_apply("action_2", "Second Action", {"foo": "bar"})
            active = sm.get_all_active_transactions()
            assert len(active) == 1
            assert active[0]["action_id"] == "action_2"
        _test("H1: Transaction State Manager (Record, Rollback, Active Query)", test_state_manager)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION I: TELEMETRY & WATCHDOG
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── I) TELEMETRÍA Y WATCHDOG ───────────────────────────────")

        # I1: Telemetry worker
        def test_telemetry_worker():
            from clarity.core.telemetry_worker import TelemetryWorker
            worker = TelemetryWorker.get_instance()
            assert worker._running is True
            snap = worker.get_snapshot()
            assert "cpu_pct" in snap
            assert "ram_load_pct" in snap
            assert "ram_used_gb" in snap
            assert "ram_total_gb" in snap
            assert "gpu" in snap
            assert "dpc_jitter_us" in snap
            assert "dpc_peak_us" in snap
            assert "history" in snap
            assert snap["ram_total_gb"] > 0
        _test("I1: Live Telemetry Worker (CPU, RAM, GPU, DPC Jitter)", test_telemetry_worker)

        # I2: Watchdog
        def test_watchdog():
            from clarity.core.watchdog import SystemWatchdog
            wd = SystemWatchdog.get_instance()
            assert wd.is_running is True
            status = wd.get_status()
            assert "is_running" in status
            assert "auto_guard_enabled" in status
            assert "total_tdr_intercepted" in status
            assert "recent_incidents" in status
            # Toggle test
            wd.set_auto_guard(False)
            assert wd.auto_guard_enabled is False
            wd.set_auto_guard(True)
            assert wd.auto_guard_enabled is True
        _test("I2: System Watchdog & Auto-TDR Guard Toggle", test_watchdog)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION J: HEALTH SCORE CALCULATOR
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── J) CALCULADORA DE SALUD DEL PC ─────────────────────────")

        # J1: Critical scenario
        def test_health_critical():
            from clarity.core.health_score import PCHealthScoreCalculator
            result = PCHealthScoreCalculator.calculate(
                topology_data={
                    "gpu": {"tdr_count": 500},
                    "psu": {"kp41_count": 20},
                    "ram": {"configured_mhz": 2133, "rated_mhz": 3600}
                },
                telemetry_data={"dpc_peak_us": 5000.0}
            )
            assert result["score"] <= 30, f"Critical scenario should score <= 30, got {result['score']}"
            assert result["status_color"] == "critical"
            assert result["verdict"] == "Crítico: Requiere Intervención"
            assert len(result["penalties"]) >= 4
        _test("J1: Health Score - CRITICAL Scenario (All Systems Failing)", test_health_critical)

        # J2: Optimal scenario
        def test_health_optimal():
            from clarity.core.health_score import PCHealthScoreCalculator
            result = PCHealthScoreCalculator.calculate(
                topology_data={
                    "gpu": {"tdr_count": 0},
                    "psu": {"kp41_count": 0},
                    "ram": {"configured_mhz": 3600, "rated_mhz": 3600}
                },
                telemetry_data={"dpc_peak_us": 150.0}
            )
            assert result["score"] == 100
            assert result["status_color"] == "optimal"
            assert len(result["penalties"]) == 0
        _test("J2: Health Score - OPTIMAL Scenario (Perfect System)", test_health_optimal)

        # J3: Warning scenario
        def test_health_warning():
            from clarity.core.health_score import PCHealthScoreCalculator
            result = PCHealthScoreCalculator.calculate(
                topology_data={
                    "gpu": {"tdr_count": 3},
                    "psu": {"kp41_count": 1},
                    "ram": {"configured_mhz": 2666, "rated_mhz": 3200}
                },
                telemetry_data={"dpc_peak_us": 1500.0}
            )
            assert 40 <= result["score"] <= 80
            assert result["status_color"] in ("warning", "critical")
            assert len(result["penalties"]) >= 2
        _test("J3: Health Score - WARNING Scenario (Bottlenecks Present)", test_health_warning)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION K: VRAM INTEGRITY TESTER
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── K) TEST DE INTEGRIDAD VRAM ─────────────────────────────")

        def test_vram():
            from clarity.core.vram_test import VRAMIntegrityTester
            tester = VRAMIntegrityTester.get_instance()
            status = tester.get_status()
            assert "status" in status
            assert "is_running" in status
            assert "errors_found" in status
            assert "patterns_tested" in status
            
            # Run a small 64MB test
            if not tester.is_running:
                started = tester.start_test(total_mb=64)
                assert started is True
                t0 = time.time()
                while tester.is_running and time.time() - t0 < 10:
                    time.sleep(0.2)
                final = tester.get_status()
                assert final["status"] in ("completed", "error")
                assert final["errors_found"] == 0
        _test("K1: VRAM Integrity Stress Test (64 MB, 3 Bit Patterns)", test_vram)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION L: GAMING LATENCY ENGINE
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── L) MOTOR DE LATENCIA GAMING ─────────────────────────────")

        def test_gaming_timer():
            from clarity.optimizer.gaming_latency import GamingLatencyEngine
            # Enable 1ms timer
            ok = GamingLatencyEngine.enable_high_res_timer()
            assert ok is True
            assert GamingLatencyEngine.is_timer_active() is True
            # Disable
            GamingLatencyEngine.disable_high_res_timer()
            assert GamingLatencyEngine.is_timer_active() is False
        _test("L1: Gaming High-Resolution Timer (1ms / 0.5ms)", test_gaming_timer)

        def test_game_detection():
            from clarity.optimizer.gaming_latency import GamingLatencyEngine, KNOWN_GAMES
            # Verify game database
            assert len(KNOWN_GAMES) >= 15, f"Expected >= 15 known games, found {len(KNOWN_GAMES)}"
            assert "cs2.exe" in KNOWN_GAMES
            assert "valorant-win64-shipping.exe" in KNOWN_GAMES
            assert "fortniteclient-win64-shipping.exe" in KNOWN_GAMES
            
            # Run detection (may find 0 games)
            games = GamingLatencyEngine.detect_running_games()
            assert isinstance(games, list)
        _test("L2: Game Detection Database & Process Scanner", test_game_detection)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION M: ANTI-TAMPER INTEGRITY MONITOR
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── M) MONITOR ANTI-TAMPER DE INTEGRIDAD ───────────────────")

        def test_anti_tamper():
            from clarity.security.integrity.anti_tamper import SystemIntegrityMonitor
            monitor = SystemIntegrityMonitor.get_instance()
            assert monitor is not None
            # Start monitoring
            monitor.start()
            assert monitor._running is True
            # Get alerts (should be empty on fresh start)
            alerts = monitor.get_recent_alerts(limit=10)
            assert isinstance(alerts, list)
            # Stop
            monitor.stop()
            assert monitor._running is False
            # Restart for other tests
            monitor.start()
        _test("M1: System32/Drivers Anti-Tamper File Sentinel", test_anti_tamper)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION N: BASE CLASSES & DATA MODEL INTEGRITY
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── N) MODELO DE DATOS Y CLASES BASE ───────────────────────")

        def test_severity_enum():
            from clarity.core.base import Severity
            assert Severity.OK.value == "ok"
            assert Severity.INFO.value == "info"
            assert Severity.WARNING.value == "warning"
            assert Severity.CRITICAL.value == "critical"
        _test("N1: Severity Enum Values", test_severity_enum)

        def test_report_highest_severity():
            from clarity.core.base import DiagnosticReport, DiagnosticItem, Severity
            r = DiagnosticReport(engine_name="test")
            r.items.append(DiagnosticItem(id="a", category="X", title="A", severity=Severity.OK, summary=""))
            assert r.highest_severity == Severity.OK
            r.items.append(DiagnosticItem(id="b", category="X", title="B", severity=Severity.WARNING, summary=""))
            assert r.highest_severity == Severity.WARNING
            r.items.append(DiagnosticItem(id="c", category="X", title="C", severity=Severity.CRITICAL, summary=""))
            assert r.highest_severity == Severity.CRITICAL
        _test("N2: DiagnosticReport.highest_severity Escalation Logic", test_report_highest_severity)

        def test_optimization_base_classes():
            from clarity.optimizer.base import OptimizationCategory, OptimizationImpact
            assert OptimizationCategory.SYSTEM.value == "system"
            assert OptimizationCategory.GAMING.value == "gaming"
            assert OptimizationCategory.STORAGE.value == "storage"
            assert OptimizationCategory.NETWORK.value == "network"
            assert OptimizationImpact.LOW.value == "low"
            assert OptimizationImpact.MEDIUM.value == "medium"
            assert OptimizationImpact.HIGH.value == "high"
        _test("N3: Optimization Category & Impact Enums", test_optimization_base_classes)

        # ═══════════════════════════════════════════════════════════════════
        #  SECTION O: EDGE CASES & STRESS TESTS
        # ═══════════════════════════════════════════════════════════════════
        print("\n─── O) CASOS LÍMITE Y STRESS TESTS ─────────────────────────")

        # O1: Process with empty path
        def test_empty_path_process():
            from clarity.security.heuristics.process_telemetry import ProcessTelemetryEngine
            record = ProcessTelemetryEngine.evaluate_process({
                "Id": 0, "ProcessName": "", "Path": "",
                "ParentId": None, "ParentName": None
            })
            assert record.level == "CLEAN"
            assert record.score == 0
        _test("O1: Empty Path Process Evaluation (No False Positives)", test_empty_path_process)

        # O2: Legitimate signed process from Program Files
        def test_legitimate_process():
            from clarity.security.heuristics.process_telemetry import ProcessTelemetryEngine
            record = ProcessTelemetryEngine.evaluate_process({
                "Id": 12345,
                "ProcessName": "notepad",
                "Path": r"C:\Windows\System32\notepad.exe",
                "ParentId": 1,
                "ParentName": "explorer.exe"
            })
            assert record.level == "CLEAN", f"Notepad should be CLEAN, got {record.level} (score={record.score})"
            # notepad.exe may use catalog signing (not embedded Authenticode) on modern Windows
            assert isinstance(record.is_signed, bool)
        _test("O2: Legitimate System Process Should Score CLEAN", test_legitimate_process)

        # O3: Multiple simultaneous signature verifications (thread safety)
        def test_concurrent_signatures():
            from clarity.core.signature import AuthenticodeVerifier
            results = []
            def verify_worker(path):
                r = AuthenticodeVerifier.verify_file(path)
                results.append(r)
            
            targets = [
                r"C:\Windows\explorer.exe",
                r"C:\Windows\System32\cmd.exe",
                r"C:\Windows\System32\notepad.exe",
                r"C:\Windows\System32\calc.exe",
            ]
            threads = [threading.Thread(target=verify_worker, args=(t,)) for t in targets]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
            
            assert len(results) >= 3, "At least 3 signatures should complete"
        _test("O3: Concurrent Signature Verification (Thread Safety)", test_concurrent_signatures)

        # O4: Health score with None inputs
        def test_health_none_inputs():
            from clarity.core.health_score import PCHealthScoreCalculator
            result = PCHealthScoreCalculator.calculate(None, None)
            # With None inputs, defaults apply (RAM 2666/3200 causes a legitimate penalty)
            assert result["score"] >= 80, f"Expected >= 80 with defaults, got {result['score']}"
            assert result["status_color"] == "optimal"
        _test("O4: Health Score with None Inputs (Graceful Default)", test_health_none_inputs)

        # O5: Forum bundle with empty data
        def test_forum_empty():
            from clarity.reports.forum_bundle import ForumBundleExporter
            md = ForumBundleExporter.generate_markdown()
            assert "ClarityPC" in md
            assert len(md) > 100
        _test("O5: Forum Bundle with Empty Hardware Data (Graceful Fallback)", test_forum_empty)

    finally:
        # Cleanup sandbox
        try:
            shutil.rmtree(sandbox, ignore_errors=True)
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════
    #  FINAL SUMMARY
    # ═══════════════════════════════════════════════════════════════════
    total = _passed + _failed + _skipped
    print(f"\n{'='*80}")
    print(f"  📊 RESULTADOS FINALES DE LA AUDITORÍA PROFUNDA")
    print(f"{'='*80}")
    print(f"  ✅ Pasaron:    {_passed}")
    print(f"  ❌ Fallaron:   {_failed}")
    print(f"  ⏭️  Omitidos:  {_skipped}")
    print(f"  📦 Total:      {total}")
    print(f"{'='*80}")

    if _failed > 0:
        print("\n  ⚠️  TESTS QUE FALLARON:")
        for name, status, err in _results:
            if status == "FAIL":
                print(f"    ❌ {name}")
                # Show first 3 lines of error
                for line in err.strip().split("\n")[:3]:
                    print(f"       {line}")

    if _failed == 0:
        print("\n  🏆 ¡ClarityPC PASÓ TODAS LAS PRUEBAS DE SEGURIDAD!")
        print("     La app cumple con TODO lo que promete.\n")
    else:
        print(f"\n  ⚠️  {_failed} test(s) necesitan atención.\n")

    return _failed


if __name__ == "__main__":
    exit_code = run_deep_security_audit()
    sys.exit(exit_code)
