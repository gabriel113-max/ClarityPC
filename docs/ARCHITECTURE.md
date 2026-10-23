# Arquitectura de Software — ClarityPC

## 1. Filosofía de Diseño ("Anti-Slop")
ClarityPC se rige por cuatro principios inviolables:
1. **Transparencia y Determinismo:** Ninguna optimización es una caja negra. Cada acción declara explícitamente sus claves de registro, servicios o archivos afectados.
2. **Reversibilidad Obligatoria:** Cada acción que implementa `apply()` debe implementar obligatoriamente su contraparte `rollback()` con estado previo persistido en JSON.
3. **Cero Dependencias Infladas:** Uso preferente de APIs nativas de Windows (CIM/WMI, Win32, PowerShell core) sin telemetría ni rastreo.
4. **Desacoplamiento Estricto:** La lógica de diagnóstico y optimización (`core`, `optimizer`) es completamente agnóstica de la interfaz de usuario (`cli`, `gui`).

---

## 2. Mapa de Capas

```
ClarityPC
│
├── core/                  # Capa de Inspección Forense (Solo Lectura)
│   ├── base.py            # Interfaces BaseDiagnosticEngine, DiagnosticItem, Severity
│   ├── hardware.py        # CPU, RAM (detección XMP), GPU (detección TDR), Motherboard
│   ├── bios.py            # SMBIOS, Secure Boot, reinicio directo a firmware UEFI
│   ├── network.py         # Latencia ICMP, jitter, pérdida de paquetes
│   └── security.py        # Windows Defender API, firmas, persistencia en inicio
│
├── optimizer/             # Capa de Acciones Atómicas
│   ├── base.py            # Contrato BaseOptimizationAction (apply, rollback, dry_run)
│   └── profiles/
│       ├── gaming.py      # GameMode, GameDVR buffer
│       └── legacy.py      # Atenuación visual para PCs lentas, TRIM en SSDs
│
├── safety/                # Capa de Garantía y Recuperación
│   ├── restore_point.py   # Creación de Puntos de Restauración vía VSS
│   └── state_manager.py   # Registro transaccional JSON para reversión
│
├── companion/             # Motor del Asistente Virtual / Mascota
│   ├── characters.py      # Perfiles (Byte el Gato, Patch el Perro, Gizmo el Robot, Modo Pro)
│   └── state_machine.py   # Máquina de estados (IDLE, INVESTIGATING, WORKING, ALARMED, HAPPY)
│
├── reports/               # Capa de Exportación Pericial
│   └── exporter.py        # Exportadores a Markdown, JSON y HTML/PDF
│
└── ui/                    # Capa de Presentación
    ├── cli.py             # Interfaz de línea de comandos interactiva
    └── gui/               # Interfaz gráfica moderna desacoplada
```

---

## 3. Contratos de Datos Clave

### A. Diagnóstico (`DiagnosticItem`)
* `id: str`: Identificador único del componente evaluado.
* `category: str`: Categoría lógica (Procesador, RAM, GPU, Red, Seguridad).
* `severity: Severity`: Nivel de gravedad (`OK`, `INFO`, `WARNING`, `CRITICAL`).
* `summary: str`: Frase concisa para la interfaz.
* `details: str`: Información forense técnica profunda para el reporte.
* `metrics: dict`: Valores numéricos en crudo (temperatura, MHz, % pérdida).
* `recommendation: Optional[str]`: Guía accionable de solución para el usuario.

### B. Optimización (`BaseOptimizationAction`)
* `is_applicable() -> bool`: Verifica si el sistema operativo y hardware soportan la acción.
* `is_applied() -> bool`: Comprueba el estado actual en el registro o servicios.
* `dry_run() -> DryRunPreview`: Genera el listado exacto de cambios antes de tocar nada.
* `apply() -> OptimizationResult`: Aplica el cambio y retorna el estado previo para backup.
* `rollback(saved_state) -> OptimizationResult`: Restaura el valor exacto anterior.
