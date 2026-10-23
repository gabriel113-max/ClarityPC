import sys
import os
import json
import urllib.request
import threading
import time
import traceback

# Ensure src is in pythonpath
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

def run_tests():
    passed = 0
    failed = 0
    results = []

    def test(name, func):
        nonlocal passed, failed
        try:
            func()
            passed += 1
            results.append((name, True, "OK"))
            print(f"[PASS] {name}")
        except Exception as e:
            failed += 1
            err = f"{e}\n{traceback.format_exc()}"
            results.append((name, False, err))
            print(f"[FAIL] {name} -> {e}")

    print("==================================================")
    print("      CLARITYPC FULL VERIFICATION SUITE (ALL 5 NEW FEATURES)")
    print("==================================================")

    # Start In-Process Server for API testing if needed
    from clarity.ui.gui.server import start_server
    server = start_server(port=57321)
    actual_port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)
    base_url = f"http://127.0.0.1:{actual_port}"

    # 1. Hardware Engine
    def test_hardware():
        from clarity.core.hardware import HardwareDiagnosticEngine
        eng = HardwareDiagnosticEngine()
        rep = eng.run()
        assert rep is not None
        assert len(rep.items) >= 4
        categories = {item.category.lower() for item in rep.items}
        assert any("ram" in c or "procesador" in c or "gráfica" in c for c in categories)
    test("Core: Hardware Diagnostic Engine Execution", test_hardware)

    # 2. BIOS Engine
    def test_bios():
        from clarity.core.bios import BiosDiagnosticEngine
        eng = BiosDiagnosticEngine()
        rep = eng.run()
        assert rep is not None
        assert len(rep.items) >= 2
    test("Core: BIOS & UEFI Diagnostic Engine", test_bios)

    # 3. Network Engine
    def test_network():
        from clarity.core.network import NetworkDiagnosticEngine
        eng = NetworkDiagnosticEngine()
        rep = eng.run()
        assert rep is not None
        assert len(rep.items) >= 2
    test("Core: Network & DNS Benchmark Engine", test_network)

    # 4. Security & Heuristics Engine
    def test_security():
        from clarity.core.security import SecurityDiagnosticEngine
        eng = SecurityDiagnosticEngine()
        rep = eng.run()
        assert rep is not None
        categories = {item.category for item in rep.items}
        assert "Antivirus" in categories
        assert "Heurística" in categories
        assert "Autoarranque" in categories
        assert "Red" in categories
        assert "Firmas Digitales" in categories
    test("Core: Security & Process Heuristics Engine", test_security)

    # 4b. Authenticode WinTrust Verifier
    def test_authenticode():
        from clarity.core.signature import AuthenticodeVerifier
        res = AuthenticodeVerifier.verify_file(r"C:\Windows\explorer.exe")
        assert res["is_signed"] is True
        assert res["status"] == "VALID_TRUSTED"
        fake_res = AuthenticodeVerifier.verify_file(r"C:\non_existent_file_xyz.exe")
        assert fake_res["is_signed"] is False
    test("Pillar 1: Native Authenticode WinTrust Signature Verification", test_authenticode)

    # 5. Cleaners & Optimizers (11 Actions with Dry Run & Rollback)
    def test_actions_dry_run():
        from clarity.ui.gui.server import ClarityApiHandler
        handler = ClarityApiHandler.__new__(ClarityApiHandler)
        actions = handler._get_actions()
        assert len(actions) >= 11, f"Expected >= 11 actions, found {len(actions)}"
        
        found_shaders = False
        found_temp = False
        found_winupdate = False
        found_diagtrack = False
        found_bing = False
        found_edge = False
        
        for a in actions:
            preview = a.dry_run()
            assert preview is not None
            assert len(preview.operations) > 0
            assert len(preview.rollback_guarantee) > 0
            if a.id == "clean_directx_shader_cache":
                found_shaders = True
            elif a.id == "clean_safe_temp":
                found_temp = True
            elif a.id == "clean_win_update_cache":
                found_winupdate = True
            elif a.id == "opt_debloat_diagtrack":
                found_diagtrack = True
            elif a.id == "opt_debloat_bing_search":
                found_bing = True
            elif a.id == "opt_debloat_edge_boost":
                found_edge = True

        assert found_shaders, "clean_directx_shader_cache not registered"
        assert found_temp, "clean_safe_temp not registered"
        assert found_winupdate, "clean_win_update_cache not registered"
        assert found_diagtrack, "Feature 5: opt_debloat_diagtrack not registered"
        assert found_bing, "Feature 5: opt_debloat_bing_search not registered"
        assert found_edge, "Feature 5: opt_debloat_edge_boost not registered"
    test("Feature 5 / Pillar 4: Deep Hygiene & 11 Safe Debloat Actions", test_actions_dry_run)

    # 6. Telemetry Worker
    def test_telemetry():
        from clarity.core.telemetry_worker import TelemetryWorker
        worker = TelemetryWorker.get_instance()
        assert worker._thread is not None and worker._thread.is_alive()
        snap = worker.get_snapshot()
        assert "cpu_pct" in snap
        assert "ram_load_pct" in snap
        assert "gpu" in snap
        assert "dpc_jitter_us" in snap
        assert "history" in snap
        assert len(snap["history"]["cpu"]) > 0
        assert len(snap["history"]["ram"]) > 0
        assert len(snap["history"]["gpu_power"]) > 0
        assert len(snap["history"]["dpc"]) > 0
    test("Pillar 2/3: Native Hardware Telemetry Daemon & Rolling Buffer", test_telemetry)

    # 7. FEATURE 1: System Watchdog & Auto-TDR Guard
    def test_watchdog():
        from clarity.core.watchdog import SystemWatchdog
        sentry = SystemWatchdog.get_instance()
        assert sentry.is_running
        status = sentry.get_status()
        assert "is_running" in status
        assert "auto_guard_enabled" in status
        assert "total_tdr_intercepted" in status
        assert status["auto_guard_enabled"] is True
        
        # Test toggling
        sentry.set_auto_guard(False)
        assert sentry.auto_guard_enabled is False
        sentry.set_auto_guard(True)
        assert sentry.auto_guard_enabled is True
    test("Feature 1: System Watchdog & Auto-TDR Guard Sentry", test_watchdog)

    # 8. FEATURE 2: Safe VRAM & Memory Integrity Tester
    def test_vram_tester():
        from clarity.core.vram_test import VRAMIntegrityTester
        tester = VRAMIntegrityTester.get_instance()
        status_before = tester.get_status()
        assert "status" in status_before
        
        # Run test with 128 MB for quick verification
        started = tester.start_test(total_mb=128)
        assert started is True
        
        # Wait up to 5s for completion
        t0 = time.time()
        while tester.is_running and time.time() - t0 < 5:
            time.sleep(0.1)
            
        status_after = tester.get_status()
        assert status_after["status"] in ["completed", "running"]
        assert status_after["errors_found"] == 0
        assert len(status_after["patterns_tested"]) > 0
    test("Feature 2: Safe VRAM Memory Integrity Stress Test (Bit Parity)", test_vram_tester)

    # 9. FEATURE 3: Game Latency & Process Affinity Engine
    def test_gaming_engine():
        from clarity.optimizer.gaming_latency import GamingLatencyEngine
        # Test 1ms timer resolution
        assert GamingLatencyEngine.enable_high_res_timer() is True
        assert GamingLatencyEngine.is_timer_active() is True
        GamingLatencyEngine.disable_high_res_timer()
        
        # Test process detection
        games = GamingLatencyEngine.detect_running_games()
        assert isinstance(games, list)
    test("Feature 3: Game Latency Engine & 0.5ms Timer Resolution", test_gaming_engine)

    # 10. FEATURE 4: Anonymized Forum Forensic Bundle
    def test_forum_bundle():
        from clarity.reports.forum_bundle import ForumBundleExporter
        hw_sample = {
            "cpu": {"name": "Intel Core i7-10700KF", "cores": "8C / 16T"},
            "ram": {"capacity": "16 GB DDR4", "configured_mhz": 2666, "rated_mhz": 3200},
            "gpu": {"name": "NVIDIA GeForce RTX 3060 12GB", "tdr_count": 448},
            "motherboard": {"name": "Gigabyte Z490 AORUS ULTRA (BIOS F22)"},
            "storage": {"name": "Samsung 980 PRO", "health": "100% SMART OK"},
            "psu": {"kp41_count": 18}
        }
        telem_sample = {"dpc_jitter_us": 220.5, "dpc_peak_us": 8842.1}
        md = ForumBundleExporter.generate_markdown(hw_sample, telem_sample)
        
        assert "ClarityPC Hardware & Stability Forensic Report" in md
        assert "Intel Core i7-10700KF" in md
        assert "XMP Status: DISABLED" in md
        assert "448 nvlddmkm driver timeout resets" in md
        assert "18 Kernel-Power Event 41 abrupt reboots" in md
        # Verify strict anonymization
        username = os.environ.get("USERNAME", "")
        if username:
            assert username not in md or username == "<USER>"
    test("Feature 4: Anonymized Forum Forensic Bundle Generator", test_forum_bundle)

    # 11. Live HTTP API Endpoints (Exercising All 5 Features via REST)
    def test_live_apis():
        # Standard endpoints
        for endpoint in ["/api/status", "/api/topology", "/api/dpc-pulse", "/api/telemetry/live", "/api/security/scan"]:
            with urllib.request.urlopen(f"{base_url}{endpoint}", timeout=10) as r:
                assert r.status == 200
        
        # Optimizations (verifying 11 items returned)
        with urllib.request.urlopen(f"{base_url}/api/optimizations", timeout=5) as r:
            opts = json.loads(r.read().decode())
            assert len(opts) >= 11
            
        # Feature 1: Watchdog status & toggle
        with urllib.request.urlopen(f"{base_url}/api/watchdog/status", timeout=5) as r:
            w_stat = json.loads(r.read().decode())
            assert "auto_guard_enabled" in w_stat
            
        req = urllib.request.Request(
            f"{base_url}/api/watchdog/toggle",
            data=json.dumps({"enable": True}).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            res = json.loads(r.read().decode())
            assert res.get("success") is True
            
        # Feature 2: VRAM test status
        with urllib.request.urlopen(f"{base_url}/api/vram-test/status", timeout=5) as r:
            v_stat = json.loads(r.read().decode())
            assert "status" in v_stat
            
        # Feature 3: Games running
        with urllib.request.urlopen(f"{base_url}/api/games/running", timeout=5) as r:
            g_list = json.loads(r.read().decode())
            assert isinstance(g_list, list)
            
        # Feature 4: Forum bundle
        with urllib.request.urlopen(f"{base_url}/api/export-forum-bundle", timeout=5) as r:
            f_bundle = json.loads(r.read().decode())
            assert f_bundle.get("success") is True
            assert "markdown" in f_bundle
            assert "ClarityPC" in f_bundle["markdown"]

        # Feature 6: Health Score API
        with urllib.request.urlopen(f"{base_url}/api/health-score", timeout=5) as r:
            h_data = json.loads(r.read().decode())
            assert "score" in h_data
            assert "potential_score" in h_data
            assert "penalties" in h_data
            assert isinstance(h_data["penalties"], list)

        # Feature 7: Settings API (GET and POST)
        with urllib.request.urlopen(f"{base_url}/api/settings", timeout=5) as r:
            s_data = json.loads(r.read().decode())
            assert "language" in s_data
            assert "theme" in s_data
            assert "gpu_safe_wattage" in s_data

        req_set = urllib.request.Request(
            f"{base_url}/api/settings",
            data=json.dumps({"theme": "dark", "gpu_safe_wattage": 100}).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_set, timeout=5) as r:
            set_res = json.loads(r.read().decode())
            assert set_res.get("success") is True

        # Enterprise Security: Process Telemetry & Suspicion API
        with urllib.request.urlopen(f"{base_url}/api/security/processes", timeout=12) as r:
            p_data = json.loads(r.read().decode())
            assert isinstance(p_data, list)
            if p_data:
                assert "score" in p_data[0]
                assert "level" in p_data[0]

        # Enterprise Security: Persistence Hunter API
        with urllib.request.urlopen(f"{base_url}/api/security/persistence", timeout=12) as r:
            pers_data = json.loads(r.read().decode())
            assert isinstance(pers_data, list)

        # Enterprise Security: Anti-Tamper Alerts API
        with urllib.request.urlopen(f"{base_url}/api/security/tamper-alerts", timeout=5) as r:
            t_data = json.loads(r.read().decode())
            assert isinstance(t_data, list)
    test("Live API: All Core & Extended REST Endpoints", test_live_apis)

    # 11b. PC Health Score Engine Unit Test
    def test_health_score_engine():
        from clarity.core.health_score import PCHealthScoreCalculator
        topo = {
            "gpu": {"tdr_count": 448},
            "psu": {"kp41_count": 18},
            "ram": {"configured_mhz": 2666, "rated_mhz": 3200}
        }
        res = PCHealthScoreCalculator.calculate(topology_data=topo, telemetry_data={"dpc_peak_us": 120.0})
        assert res["score"] <= 50, f"Expected critical score <= 50, got {res['score']}"
        assert res["potential_score"] >= 90, f"Expected potential >= 90, got {res['potential_score']}"
        assert res["status_color"] == "critical"
        assert len(res["penalties"]) >= 3
    test("Feature 6: PC Health Score Engine & Penalty Breakdown", test_health_score_engine)

    # 11c. Settings & HKCU Auto-start Sync
    def test_settings_sync():
        from clarity.config import ClaritySettings
        settings = ClaritySettings.load()
        assert settings.language in ("es", "en")
        assert settings.gpu_safe_wattage > 0
        sync_ok = settings.sync_autostart_registry()
        assert isinstance(sync_ok, bool)
    test("Feature 7: ClaritySettings Data Model & Registry Sync", test_settings_sync)

    # 12. Web UI HTML & Assets Integrity
    def test_web_ui_integrity():
        web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "clarity", "ui", "gui", "web"))
        html_path = os.path.join(web_dir, "index.html")
        assert os.path.exists(html_path)
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Verify Core Elements
        assert 'id="btnLang"' in content
        assert 'id="folderTheater"' in content
        assert 'id="roamingCat"' in content
        assert 'id="btnScan"' in content
        assert 'id="btnGpuCap"' in content
        assert 'executeRebootUefi()' in content
        assert 'id="dpcCanvas"' in content
        assert 'data-i18n=' in content
        
        # Verify Extended Features in UI
        assert 'id="watchdogChip"' in content, "Missing Watchdog Status Chip in Header"
        assert 'id="healthScoreChip"' in content, "Missing Health Score Chip in Header"
        assert 'id="btnSettings"' in content, "Missing Settings Header Button"
        assert 'id="healthModal"' in content, "Missing Health Score Modal"
        assert 'id="settingsModal"' in content, "Missing Settings Modal"
        assert 'id="btnVramTest"' in content, "Missing VRAM Test Action Button"
        assert 'id="vramModal"' in content, "Missing VRAM Test Modal Dialog"
        assert 'id="btnGameBoost"' in content, "Missing Game Latency Boost Button"
        assert 'id="gameModal"' in content, "Missing Game Latency Modal Dialog"
        assert 'id="btnForumReport"' in content, "Missing Forum Forensic Report Button"
        assert 'id="toastContainer"' in content, "Missing Toast Container"
        assert 'openHealthModal()' in content, "Missing openHealthModal JS"
        assert 'openSettingsModal()' in content, "Missing openSettingsModal JS"
        assert 'saveSettings()' in content, "Missing saveSettings JS"
        assert 'copyForumReport()' in content, "Missing copyForumReport JavaScript Handler"
        assert 'runVramTest()' in content, "Missing runVramTest JavaScript Handler"
        assert 'loadRunningGames()' in content, "Missing loadRunningGames JavaScript Handler"
    test("Pillar 7 & UI: Bilingual UI, All Extended Features & Modals", test_web_ui_integrity)

    # 13. Standalone Binary & Desktop Launchers
    def test_executables():
        exe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dist", "ClarityPC", "ClarityPC.exe"))
        assert os.path.exists(exe_path), f"ClarityPC.exe does not exist at {exe_path}"
        assert os.path.getsize(exe_path) > 1_000_000, "Executable is too small"
        
        desktop = os.path.join(os.environ.get("USERPROFILE", ""), "OneDrive", "Desktop")
        if not os.path.exists(desktop):
            desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
        
        shortcut_lnk = os.path.join(desktop, "ClarityPC.lnk")
        shortcut_bat = os.path.join(desktop, "ClarityPC.bat")
        assert os.path.exists(shortcut_lnk) or os.path.exists(shortcut_bat), "Desktop launcher shortcut missing"
    test("Pillar 5/6: Standalone Binary, Manifest & Desktop Launchers", test_executables)

    print("\n==================================================")
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED (Total: {passed + failed})")
    print("==================================================")

    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
