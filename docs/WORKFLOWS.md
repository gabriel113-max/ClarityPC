# Flujos Operativos y Comportamiento de ClarityPC

Este documento define la interacción entre el usuario, el motor de diagnóstico, las optimizaciones seguras y la máquina de estados de la mascota interactiva.

---

## 1. Flujo de Diagnóstico Completo (Read-Only)

```mermaid
sequenceDiagram
    autonumber
    actor Usuario
    participant UI as Interfaz (CLI / GUI)
    participant Mascot as Compañero (Byte / Patch / Gizmo)
    participant Engine as Diagnostic Engine
    participant OS as Windows Kernel / WMI / APIs

    Usuario->>UI: Solicitar Diagnóstico ("Escanear")
    UI->>Mascot: Cambiar estado a INVESTIGATING
    Mascot-->>UI: Renderizar icono de detective y bocadillo
    
    loop Cada subsistema (Hardware, BIOS, Red, Seguridad)
        UI->>Engine: run()
        Engine->>OS: Consultar CIM/WMI, registros y red
        OS-->>Engine: Métricas en crudo
        Engine-->>UI: DiagnosticReport
    end

    alt Hay ítems CRITICAL o WARNING
        UI->>Mascot: Cambiar estado a ALARMED
        Mascot-->>UI: Expresión de alerta + Recomendación directa
    else Todo OK
        UI->>Mascot: Cambiar estado a HAPPY
        Mascot-->>UI: Expresión de éxito y felicitación
    end

    UI->>Usuario: Mostrar resultados categorizados con código de colores
```

---

## 2. Flujo de Optimización Segura (Con Rollback Garantizado)

```mermaid
sequenceDiagram
    autonumber
    actor Usuario
    participant UI as Interfaz (CLI / GUI)
    participant Safety as Capa de Seguridad (Restore Point)
    participant State as StateManager (JSON Audit)
    participant Action as BaseOptimizationAction
    participant Win as Registro / Servicios de Windows

    Usuario->>UI: Marcar casilla de optimización (ej. Modo Juego)
    UI->>Action: dry_run()
    Action-->>UI: DryRunPreview (Ver cambios exactos)
    
    Usuario->>UI: Confirmar "Aplicar Optimización"
    
    opt Primera ejecución
        UI->>Safety: create_restore_point()
        Safety->>Win: Checkpoint-Computer (VSS)
    end

    UI->>Action: apply()
    Action->>Win: Leer valor previo y aplicar nuevo valor
    Win-->>Action: Confirmación
    Action->>State: record_apply(action_id, saved_state)
    State-->>UI: Transacción guardada en transactions.json
    UI->>Usuario: Notificación de éxito con botón "Revertir"

    opt Si el usuario presiona "Revertir"
        Usuario->>UI: Solicitar Rollback
        UI->>State: get_latest_state(action_id)
        State-->>UI: saved_state previo
        UI->>Action: rollback(saved_state)
        Action->>Win: Restaurar valores anteriores
        UI->>State: mark_rolled_back(action_id)
        UI->>Usuario: Sistema restaurado al estado original
    end
```

---

## 3. Máquina de Estados del Compañero (Avatar)

La mascota no es solo un adorno gráfico; es un **intérprete semántico** del estado del PC:

| Estado (`CompanionMood`) | Disparador | Expresión Visual | Propósito |
| :--- | :--- | :---: | :--- |
| `IDLE` | Al iniciar la app sin acciones en curso. | 🐱 Durmiendo / Ronroneando | Transmitir tranquilidad y disponibilidad. |
| `INVESTIGATING` | Durante la ejecución de diagnósticos. | 🔍 Lupa / Detective | Indicar progreso de escaneo sin congelar la app. |
| `WORKING` | Aplicando TRIM, planes de energía o ajustes. | 🛠️ Casco / Llave inglesa | Notificar que se está modificando un ajuste de forma segura. |
| `ALARMED` | Al detectar TDR en GPU, XMP inactivo o virus. | 😿 Alerta / Cartel de advertencia | Explicar el fallo técnico en lenguaje humano sin asustar. |
| `HAPPY` | Tras optimizar o si el PC tiene salud 100%. | 😸 Alegre / Pulgar arriba | Reforzar que el sistema está en su mejor estado. |
| `EXPLAINING` | Al pasar el cursor sobre cualquier casilla. | 💡 Bombilla / Bocadillo | Educar al usuario sobre qué hace cada interruptor. |
