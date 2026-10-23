from __future__ import annotations

import os
import subprocess
import threading
import time
import webbrowser
from pathlib import Path
try:
    from clarity.ui.gui.server import log_debug, start_server
except ImportError:
    from .server import log_debug, start_server

PORT = 57321

def launch_gui() -> None:
    log_debug("=== launch_gui() START ===")
    try:
        server = start_server(port=PORT)
        actual_port = server.server_port
        log_debug(f"Server bound successfully on port {actual_port}")

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        log_debug("Server background thread started")

        # Give server thread 200ms to be ready for incoming connections
        time.sleep(0.2)

        url = f"http://127.0.0.1:{actual_port}/index.html"
        log_debug(f"Target UI URL: {url}")

        # Attempt to launch true native Windows desktop window using pywebview (Microsoft Edge WebView2)
        use_native_window = False
        try:
            import webview
            log_debug("pywebview imported successfully, creating native window...")
            window = webview.create_window(
                "ClarityPC — Diagnóstico y Optimización Forense",
                url,
                width=1280,
                height=860,
                min_size=(1050, 700),
                background_color="#121214"
            )
            use_native_window = True
            log_debug("Native pywebview window created, starting event loop...")
            webview.start()
            log_debug("Native pywebview window closed by user, terminating app cleanly.")
            return
        except Exception as e:
            log_debug(f"pywebview native window unavailable or failed: {e}. Falling back to browser app mode.")
            use_native_window = False

        # Fallback: Candidate standalone browser apps
        app_candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]

        browser_bin = next((p for p in app_candidates if Path(p).exists()), None)
        log_debug(f"Target browser binary: {browser_bin}")

        launched = False
        if browser_bin:
            try:
                # App mode: clean, frameless, dedicated standalone window
                subprocess.Popen([
                    browser_bin,
                    "--new-window",
                    f"--app={url}",
                    "--window-size=1240,880"
                ])
                launched = True
                log_debug(f"App mode spawned successfully via {browser_bin}")
            except Exception as e:
                log_debug(f"Error launching browser app mode: {e}")

        # Always trigger Windows ShellExecute (os.startfile) if app mode failed
        if not launched:
            try:
                os.startfile(url)
                log_debug("Default browser opened via os.startfile")
            except Exception:
                webbrowser.open(url)
                log_debug("Default browser opened via webbrowser module")

        while True:
            time.sleep(1)
    except Exception as e:
        import traceback
        log_debug(f"CRITICAL ERROR in launch_gui: {traceback.format_exc()}")
    finally:
        log_debug("=== launch_gui() EXIT ===")

if __name__ == "__main__":
    launch_gui()
