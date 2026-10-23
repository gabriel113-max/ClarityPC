import os
import sys
import unittest
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from clarity.security.heuristics.process_telemetry import ProcessTelemetryEngine, ProcessSuspicionRecord
from clarity.security.heuristics.hollowing_detector import ProcessHollowingDetector
from clarity.security.persistence.auditor import PersistenceAuditor
from clarity.security.persistence.remediation import SafeRemediationEngine
from clarity.security.connectors.clamav import ClamAVConnector
from clarity.security.connectors.virustotal import VirusTotalCloudConnector
from clarity.security.integrity.anti_tamper import SystemIntegrityMonitor

class TestEnterpriseSecurity(unittest.TestCase):
    def test_process_telemetry_evaluation(self):
        # Clean process
        clean_proc = {
            "Id": 1000,
            "ProcessName": "explorer.exe",
            "Path": r"C:\Windows\explorer.exe",
            "ParentId": 4,
            "ParentName": "System"
        }
        res_clean = ProcessTelemetryEngine.evaluate_process(clean_proc)
        self.assertLessEqual(res_clean.score, 30)

        # Suspicious fake process in temp
        susp_proc = {
            "Id": 9999,
            "ProcessName": "svchost.exe",
            "Path": r"C:\Users\Public\svchost.exe",
            "ParentId": 8888,
            "ParentName": "cmd.exe"
        }
        res_susp = ProcessTelemetryEngine.evaluate_process(susp_proc)
        self.assertGreaterEqual(res_susp.score, 50)
        self.assertIn("CRITICAL", res_susp.level)
        print(f"✓ Process Telemetry Evaluation: Suspicious Score={res_susp.score} ({res_susp.level})")

    def test_hollowing_detector_safe(self):
        current_pid = os.getpid()
        audit = ProcessHollowingDetector.audit_process(pid=current_pid, process_name="python.exe")
        self.assertIsInstance(audit.is_suspicious, bool)
        print(f"✓ Process Hollowing Audit on PID {current_pid}: Suspicious={audit.is_suspicious}")

    def test_persistence_auditor(self):
        items = PersistenceAuditor.audit_all()
        self.assertIsInstance(items, list)
        self.assertGreater(len(items), 0)
        types = {i.location_type for i in items}
        self.assertTrue(any(t in types for t in ["REGISTRY", "WINLOGON", "HOSTS"]))
        print(f"✓ Persistence Auditor: Found {len(items)} inspected targets (Types: {types})")

    def test_virustotal_sha256_computation(self):
        test_file = Path(__file__).resolve()
        sha = VirusTotalCloudConnector.compute_sha256(test_file)
        self.assertEqual(len(sha), 64)
        rep = VirusTotalCloudConnector.check_file_reputation(test_file)
        self.assertIn("virustotal.com", rep.web_report_url)
        print(f"✓ VirusTotal Connector: SHA-256={sha[:12]}... Web={rep.web_report_url}")

    def test_clamav_connector_status(self):
        is_inst = ClamAVConnector.is_installed()
        self.assertIsInstance(is_inst, bool)
        print(f"✓ ClamAV Connector: Installed={is_inst}")

    def test_anti_tamper_sentry(self):
        sentry = SystemIntegrityMonitor.get_instance()
        sentry.start()
        alerts = sentry.get_recent_alerts()
        self.assertIsInstance(alerts, list)
        sentry.stop()
        print("✓ System Integrity Anti-Tamper Sentry verified")

if __name__ == "__main__":
    unittest.main()
