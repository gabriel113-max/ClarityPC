# ⚡ ClarityPC

> **Suite Open-Source de Diagnóstico Forense de Hardware, Ciberseguridad Avanzada (Técnicas 2026) y Optimización de Baja Latencia para Windows.**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20x64-0078D6.svg)](https://microsoft.com)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Security Tests: 61/61 Passed](https://img.shields.io/badge/Security%20Tests-61%2F61%20Passed-success.svg)](#)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-100%25%20Zero%20%2F%20Private-purple.svg)](#)

---

## 💡 ¿Por qué ClarityPC?

Las suites tradicionales de seguridad y optimización para Windows suelen ser opacas, consumen recursos excesivos en segundo plano e inundan el sistema con telemetría comercial invasiva. 

**ClarityPC** fue concebida como una alternativa empresarial, disruptiva y 100% de código abierto: **ultra-ligera, transparente, respetuosa de la privacidad y centrada en el rendimiento máximo**.

---

## 🛡️ Pilares y Capacidades Principales

### 1. Módulo de Ciberseguridad Avanzada (2026)
- **Motor de Telemetría de Procesos y Suspicion Score (0–100):** Supervisión en tiempo real con ponderación por rutas no confiables (`AppData\Local`, `Temp`, `ProgramData`), certificados ausentes o autofirmados y comportamiento anómalo.
- **Detección de Process Hollowing e Inyección de Memoria:** Análisis de regiones de memoria virtual (`VirtualQueryEx`) identificando páginas ejecutables sin respaldo en disco (`MEM_PRIVATE` con `PAGE_EXECUTE_READWRITE` / violación W^X).
- **Detección de Suplantación de Procesos (PPID Spoofing):** Detección de árboles de procesos anómalos (ej. `svchost.exe`, `lsass.exe`, `csrss.exe` lanzados desde shells no autorizadas).
- **Verificación Nativa Authenticode (WinTrust):** Integración Win32 con `wintrust.dll` y `WinVerifyTrust` para validar la cadena de confianza digital de binarios en ejecución.
- **Auditoría Forense de Persistencia & Desinfección Profunda:** Escaneo y saneamiento de claves `Run/RunOnce`, secuestros en `Winlogon` (`Shell`/`Userinit`), trampas de depuración IFEO, tareas programadas huérfanas y desvíos maliciosos en el archivo `hosts`.
- **Remediación Segura ("Fuerza Bruta"):** Terminación selectiva de hilos, aislamiento en bóveda de cuarentena (`.clarity_quarantine`) y borrado garantizado a nivel de kernel en el próximo arranque (`MoveFileExW` con `MOVEFILE_DELAY_UNTIL_REBOOT`).
- **Conectores Open-Source & Threat Intelligence:** Integración con motor local **ClamAV** (`clamscan`) y consultas asíncronas seguras a la API v3 de **VirusTotal** mediante hash SHA-256 por bloques de 64 KB sin exponer archivos locales.
- **Centinela Anti-Tamper de Integridad:** Monitoreo en segundo plano con `ReadDirectoryChangesW` sobre `System32` y controladores de drivers.

---

### 2. Osciloscopio DPC y Latencia en Tiempo Real (60 FPS)
- **Visualizador Gráfico de Jitter:** Osciloscopio en tiempo real con curvas Bézier, rejilla de calibración (`0 µs`, `500 µs`, `1000 µs`, `2000 µs`) y gradientes de resplandor dinámicos reactivos a picos de latencia de controladores.
- **Temporizador de Alta Precisión:** Fija la resolución del planificador del kernel a **0.5 ms / 1.0 ms** (`timeBeginPeriod`) para erradicar micro-stuttering en partidas competitivas y producción de audio ASIO.

---

### 3. Diagnóstico de Hardware & Auto-TDR Guard
- **Topología de Componentes:** Monitor de carga por hilo en CPU, detección de perfiles XMP desactivados en memoria RAM, telemetría de GPU (temperatura, potencia en Watts, reloj y VRAM) y salud S.M.A.R.T. de unidades NVMe/SSD.
- **Auto-TDR Guard Watchdog:** Centinela en segundo plano que vigila caídas por *Kernel-Power 41* y *TDR 153* para mitigar colapsos gráficos antes de un pantallazo azul (BSOD).
- **Test de Estrés de Integridad de VRAM:** Diagnóstico de memoria de video con patrones alternados de paridad de bits (*Bit Parity*) no destructivos.
- **Acceso Directo a UEFI:** Botón de reinicio directo hacia el firmware de la placa base sin secuencias de teclas.

---

### 4. Higiene Forense y Debloat Seguro (11 Acciones)
- Purgado de caché DirectX corrupta (`DXCache`).
- Depuración de temporales huérfanos con más de 24 horas de antigüedad (`%TEMP%`).
- Vaciado de descargas obsoletas de Windows Update (`SoftwareDistribution\Download`).
- Purgado y flush de caché de resolución DNS.
- Optimización TRIM en unidades SSD y NVMe.
- Supresión de telemetría invasiva DiagTrack.
- Desactivación de búsquedas remotas de Bing en el Menú Inicio.
- Suspensión de procesos en segundo plano de Microsoft Edge.

---

## 📐 Estructura del Proyecto

```text
ClarityPC/
├── package/                  # Recursos de compilación, manifiestos e iconos nativos
│   ├── clarity.ico           # Icono oficial multirresolución (256x256 a 16x16)
│   └── clarity.exe.manifest  # Manifiesto DPI-Aware & elevación UAC
├── src/clarity/
│   ├── core/                 # Motores de Hardware, BIOS, Red, Watchdog y VRAM
│   ├── optimizer/            # Debloat seguro, perfiles de rendimiento y latencia
│   ├── safety/               # Gestión transaccional y puntos de restauración
│   ├── security/             # Heurísticas, hollowing, persistencia, VirusTotal, ClamAV
│   ├── companion/            # Copiloto técnico interactivo (Byte)
│   ├── reports/              # Exportación forense a PDF, JSON y bundles anónimos
│   └── ui/                   # Interfaz WebView2 bilingüe y CLI nativa
├── tests/                    # Suites completas de pruebas unitarias y E2E
│   ├── test_security_deep_audit.py   # 61/61 pruebas de ciberseguridad
│   ├── test_enterprise_security.py   # Pruebas de integración de seguridad
│   └── test_e2e_full_suite.py        # 16/16 pruebas E2E de diagnóstico y UI
├── ClarityPC.spec            # Especificación de empaquetado PyInstaller
├── pyproject.toml            # Configuración de paquete Python estándar
├── requirements.txt          # Dependencias directas
└── README.md
```

---

## 🚀 Instalación y Uso

### Opción 1: Ejecución desde Código Fuente

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/TU_USUARIO/ClarityPC.git
   cd ClarityPC
   ```

2. **Crear y activar entorno virtual:**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Lanzar la aplicación:**
   ```bash
   python entrypoint.py
   ```

---

### Opción 2: Compilación de Binario Standalone (.exe)

Para generar el ejecutable nativo para Windows:

```bash
pyinstaller --noconfirm ClarityPC.spec
```

El binario autocontenido se generará en `dist/ClarityPC/ClarityPC.exe`.

---

## 🧪 Verificación de Pruebas

Para validar el 100% de los subsistemas y algoritmos forenses:

```bash
# Auditoría profunda de seguridad (61 pruebas):
python tests/test_security_deep_audit.py

# Verificación de integración E2E (16 pruebas):
python tests/test_e2e_full_suite.py
```

---

## 🔒 Privacidad & Compromiso Ético
- **Cero Telemetría:** ClarityPC no recopila, envía ni almacena ningún dato de telemetría de sus usuarios en servidores externos.
- **Transparencia Transaccional:** Cada acción de limpieza y optimización registra un estado previo con posibilidad de reversión (*Rollback*).
- **APIs Nativas:** Sin controladores opacos de terceros en modo kernel que comprometan la estabilidad del sistema operativo.

---

## 📜 Licencia
Este proyecto está licenciado bajo la **GNU General Public License v3.0 (GPL-3.0)**. Consulta el archivo [LICENSE](LICENSE) para más detalles.
