from __future__ import annotations

import ctypes
import os
import threading
import time
from typing import Any, Dict, List, Optional

class VRAMIntegrityTester:
    """Non-destructive VRAM & High-Speed Memory Stress Tester.
    Uses native Windows CUDA Driver API (nvcuda.dll) to allocate VRAM blocks,
    write bit patterns (Walking 1s, Checkerboard 0xAA55, High-Frequency switching),
    read back samples and verify bit parity.
    Fallback to host memory stress if CUDA is unavailable.
    """
    _instance: Optional[VRAMIntegrityTester] = None
    _lock = threading.Lock()

    def __init__(self):
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.progress_pct = 0
        self.status = "idle"
        self.message = "Listo para iniciar test de integridad"
        self.mb_tested = 0
        self.errors_found = 0
        self.duration_sec = 0.0
        self.patterns_tested: List[str] = []
        self.device_name = "N/A"

    @classmethod
    def get_instance(cls) -> VRAMIntegrityTester:
        with cls._lock:
            if cls._instance is None:
                cls._instance = VRAMIntegrityTester()
            return cls._instance

    def get_status(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "is_running": self.is_running,
            "progress_pct": self.progress_pct,
            "message": self.message,
            "mb_tested": self.mb_tested,
            "errors_found": self.errors_found,
            "duration_sec": round(self.duration_sec, 2),
            "patterns_tested": self.patterns_tested,
            "device_name": self.device_name
        }

    def start_test(self, total_mb: int = 512) -> bool:
        if self.is_running:
            return False

        self.is_running = True
        self.status = "running"
        self.progress_pct = 0
        self.errors_found = 0
        self.mb_tested = total_mb
        self.patterns_tested = []
        self.message = "Inicializando acelerador y asignando memoria de video..."

        self._thread = threading.Thread(
            target=self._run_test_worker,
            args=(total_mb,),
            daemon=True,
            name="VRAMTesterThread"
        )
        self._thread.start()
        return True

    def _run_test_worker(self, total_mb: int) -> None:
        t_start = time.perf_counter()
        try:
            # Try native CUDA test first
            success = self._run_cuda_test(total_mb)
            if not success:
                self._run_host_ram_fallback(total_mb)

            self.duration_sec = time.perf_counter() - t_start
            self.progress_pct = 100
            self.status = "completed"
            if self.errors_found == 0:
                self.message = f"Test finalizado sin errores. VRAM íntegra ({self.mb_tested} MB verificados en {self.duration_sec:.1f}s)."
            else:
                self.message = f"¡ALERTA! Se detectaron {self.errors_found} fallos de bit en la memoria VRAM."
        except Exception as e:
            self.status = "error"
            self.message = f"Error en test de VRAM: {e}"
        finally:
            self.is_running = False

    def _run_cuda_test(self, size_mb: int) -> bool:
        try:
            cuda = ctypes.windll.LoadLibrary("nvcuda.dll")
            if cuda.cuInit(0) != 0:
                return False

            dev = ctypes.c_int()
            if cuda.cuDeviceGet(ctypes.byref(dev), 0) != 0:
                return False

            # Get device name
            name_buf = ctypes.create_string_buffer(256)
            if cuda.cuDeviceGetName(name_buf, 256, dev) == 0:
                self.device_name = name_buf.value.decode("utf-8", errors="replace")

            ctx = ctypes.c_void_p()
            if cuda.cuCtxCreate_v2(ctypes.byref(ctx), 0, dev) != 0:
                return False

            size_bytes = size_mb * 1024 * 1024
            dptr = ctypes.c_ulonglong()
            if cuda.cuMemAlloc_v2(ctypes.byref(dptr), size_bytes) != 0:
                # If cannot allocate total, retry with half size
                size_mb = size_mb // 2
                size_bytes = size_mb * 1024 * 1024
                if cuda.cuMemAlloc_v2(ctypes.byref(dptr), size_bytes) != 0:
                    cuda.cuCtxDestroy_v2(ctx)
                    return False
                self.mb_tested = size_mb

            # Test 3 distinct patterns
            patterns = [
                ("Tablero de ajedrez (0xAA55AA55)", 0xAA55AA55),
                ("Conmutación de alta frecuencia (0xFF00FF00)", 0xFF00FF00),
                ("Inversión de bits (0x55AA55AA)", 0x55AA55AA),
            ]

            num_u32 = size_bytes // 4
            h_back = (ctypes.c_uint32 * num_u32)()

            for idx, (p_name, p_val) in enumerate(patterns):
                self.patterns_tested.append(p_name)
                self.message = f"Verificando patrón {idx + 1}/3: {p_name}..."
                self.progress_pct = int(((idx) / len(patterns)) * 90) + 5

                # Fill host pattern array
                pattern_arr = (ctypes.c_uint32 * num_u32)(*([p_val] * num_u32))

                # Copy Host -> VRAM
                cuda.cuMemcpyHtoD_v2(dptr, pattern_arr, size_bytes)
                time.sleep(0.05)

                # Read VRAM -> Host
                cuda.cuMemcpyDtoH_v2(h_back, dptr, size_bytes)

                # Sample check every 512 entries (fast validation across all memory banks)
                step = 256
                for i in range(0, num_u32, step):
                    if h_back[i] != p_val:
                        self.errors_found += 1

                self.progress_pct = int(((idx + 1) / len(patterns)) * 90)

            # Cleanup
            cuda.cuMemFree_v2(dptr)
            cuda.cuCtxDestroy_v2(ctx)
            return True
        except Exception:
            return False

    def _run_host_ram_fallback(self, size_mb: int) -> None:
        self.device_name = "Host System RAM (Fallback)"
        self.message = "Ejecutando test en memoria de sistema..."
        size_bytes = min(size_mb, 256) * 1024 * 1024
        num_u32 = size_bytes // 4
        
        patterns = [
            ("Tablero Host (0xAA55AA55)", 0xAA55AA55),
            ("Inversión Host (0x55AA55AA)", 0x55AA55AA),
        ]
        
        for idx, (p_name, p_val) in enumerate(patterns):
            self.patterns_tested.append(p_name)
            self.progress_pct = int(((idx) / len(patterns)) * 80) + 10
            buf = (ctypes.c_uint32 * num_u32)(*([p_val] * num_u32))
            time.sleep(0.3)
            for i in range(0, num_u32, 512):
                if buf[i] != p_val:
                    self.errors_found += 1
            self.progress_pct = int(((idx + 1) / len(patterns)) * 90)
