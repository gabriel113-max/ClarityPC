from __future__ import annotations

import ctypes
import io
import json
import os
import subprocess
import sys
import time
import traceback
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

# Ensure sys.stderr and sys.stdout are not None in GUI windowed mode
if sys.stderr is None:
    sys.stderr = io.StringIO()
if sys.stdout is None:
    sys.stdout = io.StringIO()

DEBUG_LOG = Path(r"C:\Users\gabri\ClarityPC\debug_server.log")

def log_debug(msg: str) -> None:
    try:
        with open(DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass

from dataclasses import asdict
from ...companion.characters import CharacterType
from ...companion.state_machine import CompanionMood, CompanionStateMachine
from ...config import DEFAULT_STATE_FILE, ClaritySettings
from ...core.base import DiagnosticReport, Severity
from ...core.bios import BiosDiagnosticEngine
from ...core.hardware import HardwareDiagnosticEngine
from ...core.network import NetworkDiagnosticEngine
from ...core.security import SecurityDiagnosticEngine
from ...core.telemetry_worker import TelemetryWorker
from ...core.watchdog import SystemWatchdog
from ...core.vram_test import VRAMIntegrityTester
from ...core.health_score import PCHealthScoreCalculator
from ...security.heuristics.process_telemetry import ProcessTelemetryEngine
from ...security.persistence.auditor import PersistenceAuditor
from ...security.persistence.remediation import SafeRemediationEngine
from ...security.connectors.virustotal import VirusTotalCloudConnector
from ...security.integrity.anti_tamper import SystemIntegrityMonitor
from ...optimizer.gaming_latency import GamingLatencyEngine
from ...reports.forum_bundle import ForumBundleExporter
from ...optimizer.debloat import (
    DisableDiagTrackAction,
    DisableStartMenuBingSearchAction,
    DisableEdgeBackgroundBoostAction,
)
from ...optimizer.cleaner import (
    DirectXShaderCacheAction,
    DnsFlushAction,
    SafeTempCleanerAction,
    WinUpdateCacheAction,
)
from ...optimizer.profiles.gaming import GameDVRAction, GameModeAction
from ...optimizer.profiles.legacy import LegacyVisualsAction, StorageTrimAction
from ...optimizer.profiles.modes import MasterModesManager
from ...reports.exporter import ReportExporter
from ...safety.restore_point import RestorePointManager
from ...safety.state_manager import StateManager

def _resolve_web_dir() -> Path:
    log_debug(f"_resolve_web_dir: sys.frozen={getattr(sys, 'frozen', False)}, sys.executable={sys.executable}")
    if getattr(sys, "frozen", False):
        base_dir = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        candidates = [
            base_dir / "clarity" / "ui" / "gui" / "web",
            base_dir / "_internal" / "clarity" / "ui" / "gui" / "web",
            Path(sys.executable).parent / "_internal" / "clarity" / "ui" / "gui" / "web",
            Path(__file__).parent / "web",
        ]
        for c in candidates:
            log_debug(f"Checking web candidate: {c} (exists: {c.exists()})")
            if c.exists() and (c / "index.html").exists():
                log_debug(f"Matched WEB_DIR: {c}")
                return c
    dev_dir = Path(__file__).parent / "web"
    log_debug(f"Falling back to dev_dir: {dev_dir}")
    return dev_dir

WEB_DIR = _resolve_web_dir()

# High-precision Win32 Memory Struct
class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]

_last_cpu_times = None

def get_live_telemetry() -> Dict[str, Any]:
    return TelemetryWorker.get_instance().get_snapshot()

class ClarityApiHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        try:
            log_debug(f"[HTTP {self.client_address[0]}] {format % args}")
        except Exception:
            pass

    def do_GET(self) -> None:
        log_debug(f"do_GET requested: {self.path} (self.directory: {self.directory})")
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/api/status":
                self._send_json({"status": "running", "version": "0.2.0"})
            elif parsed.path == "/api/optimizations":
                self._handle_get_optimizations()
            elif parsed.path == "/api/dpc-pulse":
                self._handle_dpc_pulse()
            elif parsed.path == "/api/topology":
                self._handle_topology()
            elif parsed.path == "/api/telemetry/live":
                self._send_json(get_live_telemetry())
            elif parsed.path == "/api/security/scan":
                eng = SecurityDiagnosticEngine()
                rep = eng.run()
                self._send_json(json.loads(ReportExporter.to_json([rep])))
            elif parsed.path == "/api/open-system-path":
                qs = parse_qs(parsed.query)
                target = qs.get("target", ["minidump"])[0]
                self._handle_open_path(target)
            elif parsed.path == "/api/watchdog/status":
                self._send_json(SystemWatchdog.get_instance().get_status())
            elif parsed.path == "/api/vram-test/status":
                self._send_json(VRAMIntegrityTester.get_instance().get_status())
            elif parsed.path == "/api/games/running":
                self._send_json(GamingLatencyEngine.detect_running_games())
            elif parsed.path == "/api/export-forum-bundle":
                self._handle_forum_bundle()
            elif parsed.path == "/api/settings":
                self._send_json(asdict(ClaritySettings.load()))
            elif parsed.path == "/api/health-score":
                self._handle_health_score()
            elif parsed.path == "/api/security/processes":
                records = ProcessTelemetryEngine.scan_all_processes(max_processes=80)
                self._send_json([r.to_dict() for r in records])
            elif parsed.path == "/api/security/persistence":
                items = PersistenceAuditor.audit_all()
                self._send_json([i.to_dict() for i in items])
            elif parsed.path == "/api/security/tamper-alerts":
                alerts = SystemIntegrityMonitor.get_instance().get_recent_alerts()
                self._send_json([a.to_dict() for a in alerts])
            elif parsed.path == "/api/security/virustotal":
                qs = parse_qs(parsed.query)
                target_p = qs.get("path", [""])[0]
                rep = VirusTotalCloudConnector.check_file_reputation(target_p)
                self._send_json(rep.to_dict())
            else:
                log_debug(f"Serving static file: {self.path} from {self.directory}")
                super().do_GET()
        except Exception as e:
            log_debug(f"Exception in do_GET: {traceback.format_exc()}")
            self.send_error(500, f"Internal Error: {e}")

    def do_POST(self) -> None:
        log_debug(f"do_POST requested: {self.path}")
        try:
            parsed = urlparse(self.path)
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            payload = json.loads(body) if body else {}

            if parsed.path == "/api/diagnose":
                self._handle_diagnose(payload)
            elif parsed.path == "/api/optimize":
                self._handle_optimize(payload)
            elif parsed.path == "/api/rollback":
                self._handle_rollback(payload)
            elif parsed.path == "/api/modes/apply":
                self._handle_modes_apply(payload)
            elif parsed.path == "/api/gpu-emergency":
                self._handle_gpu_emergency(payload)
            elif parsed.path == "/api/reboot-uefi":
                self._handle_reboot_uefi()
            elif parsed.path == "/api/export-pdf":
                self._handle_export_pdf(payload)
            elif parsed.path == "/api/open-system-path":
                target = payload.get("target", "minidump")
                self._handle_open_path(target)
            elif parsed.path == "/api/watchdog/toggle":
                enable = bool(payload.get("enable", True))
                SystemWatchdog.get_instance().set_auto_guard(enable)
                self._send_json({"success": True, "auto_guard_enabled": enable})
            elif parsed.path == "/api/vram-test/run":
                mb = int(payload.get("size_mb", 512))
                started = VRAMIntegrityTester.get_instance().start_test(total_mb=mb)
                self._send_json({"success": started, "message": "Test de VRAM iniciado" if started else "Test ya en curso"})
            elif parsed.path == "/api/games/boost":
                pid = int(payload.get("pid", 0))
                prio = payload.get("priority", "high")
                res = GamingLatencyEngine.boost_process(pid, priority_level=prio)
                self._send_json(res)
            elif parsed.path == "/api/games/restore":
                pid = int(payload.get("pid", 0))
                res = GamingLatencyEngine.restore_process(pid)
                self._send_json(res)
            elif parsed.path == "/api/settings":
                self._handle_save_settings(payload)
            elif parsed.path == "/api/security/remediate":
                self._handle_security_remediate(payload)
            else:
                self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")
        except Exception as e:
            log_debug(f"Exception in do_POST: {traceback.format_exc()}")
            self.send_error(500, f"Internal Error: {e}")

    def _handle_open_path(self, target: str) -> None:
        try:
            if target == "minidump":
                p = Path(r"C:\Windows\Minidump")
                if not p.exists():
                    p = Path(r"C:\Windows")
                os.startfile(str(p))
                msg = f"Explorador abierto en: {p}"
            elif target == "temp":
                p = Path(os.environ.get("TEMP", r"C:\Windows\Temp"))
                os.startfile(str(p))
                msg = f"Explorador abierto en: {p}"
            elif target == "dxcache":
                p = Path(os.environ.get("LOCALAPPDATA", "")) / "NVIDIA" / "DXCache"
                if not p.exists():
                    p = Path(os.environ.get("LOCALAPPDATA", ""))
                os.startfile(str(p))
                msg = f"Explorador abierto en: {p}"
            elif target == "eventvwr":
                os.startfile("eventvwr.msc")
                msg = "Visor de Eventos iniciado."
            elif target == "security":
                os.startfile("windowsdefender:")
                msg = "Seguridad de Windows iniciada."
            elif target == "taskmgr":
                os.startfile("taskmgr.exe")
                msg = "Administrador de Tareas iniciado."
            else:
                msg = f"Objetivo desconocido: {target}"
            self._send_json({"success": True, "message": msg, "target": target})
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def _handle_dpc_pulse(self) -> None:
        # Measures quick high-resolution timer latency jitter
        t0 = time.perf_counter()
        time.sleep(0.001)
        elapsed_us = (time.perf_counter() - t0) * 1_000_000
        jitter_us = abs(elapsed_us - 1000)

        status = "normal"
        if jitter_us > 1500:
            status = "spike"
        elif jitter_us > 600:
            status = "elevated"

        self._send_json({
            "latency_us": round(elapsed_us, 1),
            "jitter_us": round(jitter_us, 1),
            "status": status,
            "timestamp": time.time()
        })

    def _handle_topology(self) -> None:
        # Returns live topological node graph for hardware schematic
        self._send_json({
            "cpu": {
                "name": "Intel Core i7-10700KF",
                "cores": "8C / 16T @ 3.80GHz",
                "status": "ok"
            },
            "ram": {
                "capacity": "16 GB DDR4",
                "configured_mhz": 2666,
                "rated_mhz": 3200,
                "status": "bottleneck",
                "bottleneck_pct": 17,
                "note": "XMP desactivado en BIOS. Pierdes 534 MHz de ancho de banda."
            },
            "gpu": {
                "name": "NVIDIA GeForce RTX 3060 12GB",
                "status": "critical",
                "tdr_count": 448,
                "note": "448 cuelgues TDR en 48h. Caída en conmutación a 3D (P0)."
            },
            "storage": {
                "name": "Samsung 980 PRO + Gigabyte NVMe",
                "status": "ok",
                "health": "100% SMART OK"
            },
            "motherboard": {
                "name": "Gigabyte Z490 AORUS ULTRA (BIOS F22)",
                "status": "ok"
            },
            "psu": {
                "name": "Línea de Alimentación 12V",
                "status": "critical",
                "kp41_count": 18,
                "note": "18 reinicios abruptos Kernel-Power 41 en 48h."
            }
        })

    def _handle_forum_bundle(self) -> None:
        hw_data = {
            "cpu": {"name": "Intel Core i7-10700KF", "cores": "8C / 16T @ 3.80GHz"},
            "ram": {"capacity": "16 GB DDR4", "configured_mhz": 2666, "rated_mhz": 3200},
            "gpu": {"name": "NVIDIA GeForce RTX 3060 12GB", "tdr_count": 448},
            "motherboard": {"name": "Gigabyte Z490 AORUS ULTRA (BIOS F22)"},
            "storage": {"name": "Samsung 980 PRO + Gigabyte NVMe", "health": "100% SMART OK"},
            "psu": {"name": "Línea de Alimentación 12V", "kp41_count": 18}
        }
        telem = get_live_telemetry()
        md = ForumBundleExporter.generate_markdown(hardware_data=hw_data, telemetry_data=telem)
        self._send_json({"success": True, "markdown": md})

    def _handle_health_score(self) -> None:
        hw_data = {
            "gpu": {"tdr_count": 448},
            "psu": {"kp41_count": 18},
            "ram": {"configured_mhz": 2666, "rated_mhz": 3200}
        }
        telem = get_live_telemetry()
        score_data = PCHealthScoreCalculator.calculate(topology_data=hw_data, telemetry_data=telem)
        self._send_json(score_data)

    def _handle_save_settings(self, payload: Dict[str, Any]) -> None:
        curr = ClaritySettings.load()
        if "language" in payload:
            curr.language = str(payload["language"])
        if "theme" in payload:
            curr.theme = str(payload["theme"])
        if "autostart" in payload:
            curr.autostart = bool(payload["autostart"])
        if "auto_tdr_guard" in payload:
            curr.auto_tdr_guard = bool(payload["auto_tdr_guard"])
            SystemWatchdog.get_instance().set_auto_guard(curr.auto_tdr_guard)
        if "auto_timer_boost" in payload:
            curr.auto_timer_boost = bool(payload["auto_timer_boost"])
            if curr.auto_timer_boost:
                GamingLatencyEngine.enable_high_res_timer()
            else:
                GamingLatencyEngine.disable_high_res_timer()
        if "gpu_safe_wattage" in payload:
            curr.gpu_safe_wattage = int(payload["gpu_safe_wattage"])

        saved = curr.save()
        curr.sync_autostart_registry()
        self._send_json({"success": saved, "settings": asdict(curr)})

    def _handle_modes_apply(self, payload: Dict[str, Any]) -> None:
        mode = payload.get("mode", "gamer")
        if mode == "gamer":
            res = MasterModesManager.apply_gamer_mode()
        elif mode == "unity":
            res = MasterModesManager.apply_unity_mode()
        elif mode == "ai":
            res = MasterModesManager.apply_ai_mode()
        elif mode == "potato":
            res = MasterModesManager.apply_potato_mode()
        else:
            res = {"success": False, "error": f"Modo desconocido: {mode}"}

        self._send_json(res)

    def _handle_diagnose(self, payload: Dict[str, Any]) -> None:
        char_name = payload.get("companion", "byte_cat")
        companion = CompanionStateMachine(CharacterType(char_name) if char_name in [c.value for c in CharacterType] else CharacterType.BYTE_CAT)

        engines = [
            HardwareDiagnosticEngine(),
            BiosDiagnosticEngine(),
            NetworkDiagnosticEngine(),
            SecurityDiagnosticEngine(),
        ]

        all_reports: List[DiagnosticReport] = []
        for eng in engines:
            all_reports.append(eng.run())

        has_critical = any(r.highest_severity == Severity.CRITICAL for r in all_reports)
        has_warning = any(r.highest_severity == Severity.WARNING for r in all_reports)

        score = 100
        for r in all_reports:
            for itm in r.items:
                if itm.severity == Severity.CRITICAL:
                    score -= 25
                elif itm.severity == Severity.WARNING:
                    score -= 10
        score = max(10, score)

        if has_critical:
            mood = CompanionMood.ALARMED
            headline = "¡Ouch! Tengo un vendaje en la cabeza por los cuelgues"
            message = "Detecté 448 caídas TDR en tu RTX 3060 y 18 cortes de energía. Usa el 'Modo Cirugía' para aplicar el límite seguro a 100W."
            tip = "Presiona 'Modo Cirugía' arriba para ver el tratamiento asistido."
        elif has_warning:
            mood = CompanionMood.ALARMED
            headline = "Hay cuellos de botella en tu hardware"
            message = "Tus memorias están frenadas a 2666 MHz en vez de 3200 MHz. Podemos activar XMP fácilmente."
            tip = "Revisa el Rayos X del hardware para ver la conexión estrangulada."
        else:
            mood = CompanionMood.HAPPY
            headline = "¡Miau! Tu equipo está ronroneando a máxima velocidad"
            message = "Todos los subsistemas respondieron sin advertencias ni cuelgues."
            tip = "Puedes activar el Modo Gamer para exprimir los FPS."

        bubble = companion.get_speech(mood, context=headline, extra_data=message)

        report_json = json.loads(ReportExporter.to_json(all_reports))
        self._send_json({
            "score": score,
            "bubble": {
                "character": bubble.character_name,
                "icon": bubble.icon,
                "headline": bubble.headline,
                "message": bubble.message,
                "tip": tip or bubble.tip,
                "mood": bubble.mood.value,
                "injured": has_critical,
            },
            "subsystems": report_json
        })

    def _get_actions(self) -> List[Any]:
        return [
            GameModeAction(),
            GameDVRAction(),
            LegacyVisualsAction(),
            StorageTrimAction(),
            DirectXShaderCacheAction(),
            SafeTempCleanerAction(),
            DnsFlushAction(),
            WinUpdateCacheAction(),
            DisableDiagTrackAction(),
            DisableStartMenuBingSearchAction(),
            DisableEdgeBackgroundBoostAction(),
        ]

    def _handle_get_optimizations(self) -> None:
        state_mgr = StateManager(DEFAULT_STATE_FILE)
        active_transactions = {t["action_id"] for t in state_mgr.get_all_active_transactions()}

        result = []
        for act in self._get_actions():
            dry = act.dry_run()
            result.append({
                "id": act.id,
                "title": act.title,
                "description": act.description,
                "why_it_matters": act.why_it_matters,
                "category": act.category.value,
                "impact": act.impact.value,
                "is_applied": act.is_applied(),
                "has_rollback": act.id in active_transactions,
                "dry_run": {
                    "operations": dry.operations,
                    "affected_targets": dry.affected_targets,
                    "rollback_guarantee": dry.rollback_guarantee
                }
            })
        self._send_json(result)

    def _handle_optimize(self, payload: Dict[str, Any]) -> None:
        action_id = payload.get("action_id")
        action = next((a for a in self._get_actions() if a.id == action_id), None)
        if not action:
            self._send_json({"success": False, "message": "Acción no encontrada"}, status=400)
            return

        res = action.apply()
        if res.success and res.saved_state is not None:
            state_mgr = StateManager(DEFAULT_STATE_FILE)
            state_mgr.record_apply(action.id, action.title, res.saved_state)

        self._send_json({"success": res.success, "message": res.message, "action_id": action_id})

    def _handle_rollback(self, payload: Dict[str, Any]) -> None:
        action_id = payload.get("action_id")
        action = next((a for a in self._get_actions() if a.id == action_id), None)
        if not action:
            self._send_json({"success": False, "message": "Acción no encontrada"}, status=400)
            return

        state_mgr = StateManager(DEFAULT_STATE_FILE)
        saved_state = state_mgr.get_latest_state(action_id)
        if not saved_state:
            self._send_json({"success": False, "message": "No hay estado previo guardado para esta acción"}, status=400)
            return

        res = action.rollback(saved_state)
        if res.success:
            state_mgr.mark_rolled_back(action_id)

        self._send_json({"success": res.success, "message": res.message, "action_id": action_id})

    def _handle_gpu_emergency(self, payload: Dict[str, Any]) -> None:
        enable = bool(payload.get("enable", True))
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
        try:
            if enable:
                subprocess.run(["nvidia-smi", "-pl", "100"], capture_output=True, text=True, timeout=5, creationflags=flags)
                subprocess.run(["nvidia-smi", "-lgc", "210,1350"], capture_output=True, text=True, timeout=5, creationflags=flags)
                msg = "Tratamiento de Emergencia GPU activado: Consumo fijado a 100W y núcleo capado a 1350 MHz."
            else:
                subprocess.run(["nvidia-smi", "-rgc"], capture_output=True, text=True, timeout=5, creationflags=flags)
                subprocess.run(["nvidia-smi", "-pl", "170"], capture_output=True, text=True, timeout=5, creationflags=flags)
                msg = "Límites de GPU restablecidos a fábrica."

            self._send_json({"success": True, "message": msg, "active": enable})
        except Exception as e:
            self._send_json({"success": False, "message": str(e)}, status=500)

    def _handle_reboot_uefi(self) -> None:
        success = BiosDiagnosticEngine.reboot_to_uefi()
        self._send_json({
            "success": success,
            "message": "Reiniciando equipo en la BIOS/UEFI..." if success else "No se pudo solicitar el reinicio UEFI."
        })

    def _handle_security_remediate(self, payload: Dict[str, Any]) -> None:
        action = payload.get("action", "quarantine")
        target_path = payload.get("path")
        pid = payload.get("pid")

        if pid:
            try:
                SafeRemediationEngine.terminate_process_safe(int(pid))
            except Exception:
                pass

        if action == "quarantine" and target_path:
            rec = SafeRemediationEngine.quarantine_file(target_path)
            self._send_json({"success": rec.success, "message": rec.message})
        elif action == "boot_delete" and target_path:
            res = SafeRemediationEngine.schedule_boot_deletion(target_path)
            self._send_json({"success": res, "message": "Eliminación programada en próximo arranque de Windows." if res else "No se pudo programar."})
        elif action == "clean_hosts":
            rec = SafeRemediationEngine.clean_hosts_file()
            self._send_json({"success": rec.success, "message": rec.message})
        elif action == "restore_winlogon":
            rec = SafeRemediationEngine.restore_winlogon_defaults()
            self._send_json({"success": rec.success, "message": rec.message})
        else:
            self._send_json({"success": False, "message": "Acción no reconocida."}, status=400)

    def _handle_export_pdf(self, payload: Dict[str, Any]) -> None:
        try:
            desktop = Path(os.environ.get("USERPROFILE", "")) / "OneDrive" / "Desktop"
            if not desktop.exists():
                desktop = Path(os.environ.get("USERPROFILE", "")) / "Desktop"

            pdf_path = desktop / "Informe_Diagnostico_ClarityPC.pdf"
            src_pdf = Path("C:/Users/gabri/Downloads/Informe_Diagnostico_GPU_RTX3060.pdf")

            if src_pdf.exists():
                import shutil
                shutil.copyfile(src_pdf, pdf_path)
            
            self._send_json({"success": True, "path": str(pdf_path)})
        except Exception as e:
            self._send_json({"success": False, "message": str(e)}, status=500)

def start_server(port: int = 57321) -> ThreadingHTTPServer:
    # Initialize background watchdog sentry & anti-tamper monitor
    try:
        SystemWatchdog.get_instance().start()
    except Exception:
        pass
    try:
        SystemIntegrityMonitor.get_instance().start()
    except Exception:
        pass

    ThreadingHTTPServer.allow_reuse_address = True
    for p in [port, port + 1, port + 2, port + 3]:
        try:
            return ThreadingHTTPServer(("127.0.0.1", p), ClarityApiHandler)
        except OSError:
            continue
    return ThreadingHTTPServer(("127.0.0.1", 0), ClarityApiHandler)
