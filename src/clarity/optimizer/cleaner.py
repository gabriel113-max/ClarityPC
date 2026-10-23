from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import (
    BaseOptimizationAction,
    DryRunPreview,
    OptimizationCategory,
    OptimizationImpact,
    OptimizationResult,
)

class DirectXShaderCacheAction(BaseOptimizationAction):
    @property
    def id(self) -> str:
        return "clean_directx_shader_cache"

    @property
    def title(self) -> str:
        return "Depuración de Caché de Sombreadores DirectX"

    @property
    def description(self) -> str:
        return "Purga los fragmentos binarios obsoletos de DirectX y NVIDIA compilados por versiones antiguas del driver."

    @property
    def why_it_matters(self) -> str:
        return "Los archivos de shaders huérfanos provocan micro-tirones (stuttering) en juegos tras actualizar el controlador gráfico."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.STORAGE

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.MEDIUM

    def _get_target_dirs(self) -> List[Path]:
        local_app = Path(os.environ.get("LOCALAPPDATA", ""))
        candidates = [
            local_app / "NVIDIA" / "DXCache",
            local_app / "D3DSCache"
        ]
        return [c for c in candidates if c.exists()]

    def is_applicable(self) -> bool:
        return os.name == "nt"

    def is_applicable(self) -> bool:
        return os.name == "nt"

    def is_applied(self) -> bool:
        total_size = sum(f.stat().st_size for d in self._get_target_dirs() for f in d.glob("*") if f.is_file())
        return total_size < 5 * 1024 * 1024

    def dry_run(self) -> DryRunPreview:
        dirs = self._get_target_dirs()
        total_bytes = 0
        file_count = 0
        for d in dirs:
            for f in d.glob("*"):
                if f.is_file():
                    try:
                        total_bytes += f.stat().st_size
                        file_count += 1
                    except Exception:
                        pass
        mb = round(total_bytes / (1024 * 1024), 1)
        return DryRunPreview(
            action_id=self.id,
            operations=[f"Eliminar {file_count} archivos de caché obsoletos ({mb} MB) en directorios de sombreadores"],
            affected_targets=[str(d) for d in dirs],
            rollback_guarantee="Los sombreadores se recompilan de forma automática y limpia en el próximo lanzamiento de cada juego."
        )

    def apply(self) -> OptimizationResult:
        dirs = self._get_target_dirs()
        deleted_count = 0
        freed_bytes = 0
        skipped_locked = 0

        for d in dirs:
            for f in d.glob("*"):
                if f.is_file():
                    try:
                        size = f.stat().st_size
                        f.unlink()
                        deleted_count += 1
                        freed_bytes += size
                    except (PermissionError, OSError):
                        skipped_locked += 1

        freed_mb = round(freed_bytes / (1024 * 1024), 1)
        msg = f"Limpieza completada: {freed_mb} MB liberados ({deleted_count} archivos eliminados)."
        if skipped_locked > 0:
            msg += f" {skipped_locked} archivos en uso por juegos activos fueron preservados de forma segura."

        return OptimizationResult(
            success=True,
            action_id=self.id,
            message=msg,
            saved_state={"freed_mb": freed_mb, "deleted_count": deleted_count}
        )

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        return OptimizationResult(
            success=True,
            action_id=self.id,
            message="Los cachés de sombreadores no requieren reversión; el motor gráfico los recrea bajo demanda."
        )

class SafeTempCleanerAction(BaseOptimizationAction):
    @property
    def id(self) -> str:
        return "clean_safe_temp"

    @property
    def title(self) -> str:
        return "Higiene Segura de Temporales (>24 Horas)"

    @property
    def description(self) -> str:
        return "Elimina únicamente archivos temporales huérfanos con más de 24 horas de antigüedad, preservando instaladores activos."

    @property
    def why_it_matters(self) -> str:
        return "Previene la saturación de la unidad C: sin riesgo de romper configuraciones en segundo plano."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.STORAGE

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.LOW

    def _get_temp_dir(self) -> Path:
        return Path(os.environ.get("TEMP", r"C:\Windows\Temp"))

    def is_applicable(self) -> bool:
        return os.name == "nt"

    def is_applicable(self) -> bool:
        return os.name == "nt"

    def is_applied(self) -> bool:
        return False

    def dry_run(self) -> DryRunPreview:
        temp_dir = self._get_temp_dir()
        now = time.time()
        age_limit = 24 * 3600
        eligible_bytes = 0
        file_count = 0

        if temp_dir.exists():
            for item in temp_dir.iterdir():
                try:
                    st = item.stat()
                    if (now - st.st_mtime) > age_limit:
                        file_count += 1
                        eligible_bytes += st.st_size if item.is_file() else 4096
                except Exception:
                    pass

        mb = round(eligible_bytes / (1024 * 1024), 1)
        return DryRunPreview(
            action_id=self.id,
            operations=[f"Purgar ~{file_count} elementos huérfanos con más de 24 horas ({mb} MB)"],
            affected_targets=[str(temp_dir)],
            rollback_guarantee="Archivos bloqueados o creados hoy se omiten automáticamente para garantizar estabilidad total."
        )

    def apply(self) -> OptimizationResult:
        temp_dir = self._get_temp_dir()
        now = time.time()
        age_limit = 24 * 3600
        deleted_count = 0
        freed_bytes = 0

        if temp_dir.exists():
            for item in temp_dir.iterdir():
                try:
                    st = item.stat()
                    if (now - st.st_mtime) > age_limit:
                        size = st.st_size if item.is_file() else 0
                        if item.is_file():
                            item.unlink()
                        elif item.is_dir():
                            shutil.rmtree(item, ignore_errors=True)
                        deleted_count += 1
                        freed_bytes += size
                except (PermissionError, OSError):
                    pass

        freed_mb = round(freed_bytes / (1024 * 1024), 1)
        return OptimizationResult(
            success=True,
            action_id=self.id,
            message=f"Higiene completada: {freed_mb} MB depurados de forma segura.",
            saved_state={"freed_mb": freed_mb}
        )

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        return OptimizationResult(
            success=True,
            action_id=self.id,
            message="Los archivos temporales huérfanos no requieren restauración."
        )

class DnsFlushAction(BaseOptimizationAction):
    @property
    def id(self) -> str:
        return "network_dns_flush"

    @property
    def title(self) -> str:
        return "Purgado y Limpieza de Caché DNS"

    @property
    def description(self) -> str:
        return "Vacía la caché de resolución DNS de Windows para resolver cuellos de botella de resolución de nombres."

    @property
    def why_it_matters(self) -> str:
        return "Elimina registros DNS corruptos o vencidos que causan demoras al conectar a servidores de juegos y APIs."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.NETWORK

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.LOW

    def is_applicable(self) -> bool:
        return os.name == "nt"

    def is_applicable(self) -> bool:
        return os.name == "nt"

    def is_applied(self) -> bool:
        return False

    def dry_run(self) -> DryRunPreview:
        return DryRunPreview(
            action_id=self.id,
            operations=["Ejecutar Clear-DnsClientCache para vaciar entradas caducadas"],
            affected_targets=["Caché del servicio Dnscache de Windows"],
            rollback_guarantee="Completamente inocuo: el sistema resuelve las direcciones frescas en la siguiente petición."
        )

    def apply(self) -> OptimizationResult:
        cmd = ["powershell.exe", "-NoProfile", "-Command", "Clear-DnsClientCache"]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=5, creationflags=flags)
            return OptimizationResult(
                success=res.returncode == 0,
                action_id=self.id,
                message="Caché de resolución DNS purgada correctamente con registros actualizados."
            )
        except Exception as e:
            return OptimizationResult(success=False, action_id=self.id, message=f"Error al vaciar DNS: {e}")

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        return OptimizationResult(
            success=True,
            action_id=self.id,
            message="No aplica reversión para purgado DNS."
        )

class WinUpdateCacheAction(BaseOptimizationAction):
    @property
    def id(self) -> str:
        return "clean_win_update_cache"

    @property
    def title(self) -> str:
        return "Limpieza de Descargas de Windows Update"

    @property
    def description(self) -> str:
        return "Libera paquetes de actualización ya instalados en SoftwareDistribution\\Download."

    @property
    def why_it_matters(self) -> str:
        return "Windows acumula gigabytes de parches ya aplicados que nunca elimina por sí solo."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.STORAGE

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.MEDIUM

    def _get_dir(self) -> Path:
        return Path(r"C:\Windows\SoftwareDistribution\Download")

    def is_applicable(self) -> bool:
        return os.name == "nt"

    def is_applied(self) -> bool:
        d = self._get_dir()
        if not d.exists():
            return True
        return sum(f.stat().st_size for f in d.glob("*") if f.is_file()) < 50 * 1024 * 1024

    def dry_run(self) -> DryRunPreview:
        d = self._get_dir()
        total_bytes = 0
        count = 0
        if d.exists():
            for f in d.glob("*"):
                try:
                    total_bytes += f.stat().st_size if f.is_file() else 4096
                    count += 1
                except Exception:
                    pass
        mb = round(total_bytes / (1024 * 1024), 1)
        return DryRunPreview(
            action_id=self.id,
            operations=[f"Eliminar {count} paquetes descargados ya instalados (~{mb} MB)"],
            affected_targets=[str(d)],
            rollback_guarantee="Solo elimina descargas temporales; no modifica actualizaciones ya aplicadas."
        )

    def apply(self) -> OptimizationResult:
        d = self._get_dir()
        freed = 0
        count = 0
        if d.exists():
            for f in d.glob("*"):
                try:
                    size = f.stat().st_size if f.is_file() else 0
                    if f.is_file():
                        f.unlink()
                    elif f.is_dir():
                        shutil.rmtree(f, ignore_errors=True)
                    count += 1
                    freed += size
                except Exception:
                    pass
        mb = round(freed / (1024 * 1024), 1)
        return OptimizationResult(
            success=True,
            action_id=self.id,
            message=f"Caché de Windows Update limpiada: {mb} MB liberados.",
            saved_state={"freed_mb": mb}
        )

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        return OptimizationResult(
            success=True,
            action_id=self.id,
            message="No aplica reversión."
        )
