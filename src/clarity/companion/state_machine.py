from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional
from .characters import CharacterType, CHARACTERS, CompanionProfile

class CompanionMood(str, Enum):
    IDLE = "idle"
    INVESTIGATING = "investigating"
    WORKING = "working"
    ALARMED = "alarmed"
    HAPPY = "happy"
    EXPLAINING = "explaining"

@dataclass(slots=True)
class DialogueBubble:
    mood: CompanionMood
    character_name: str
    icon: str
    headline: str
    message: str
    tip: Optional[str] = None

class CompanionStateMachine:
    def __init__(self, character_type: CharacterType = CharacterType.BYTE_CAT):
        self.profile: CompanionProfile = CHARACTERS.get(character_type, CHARACTERS[CharacterType.BYTE_CAT])
        self.current_mood: CompanionMood = CompanionMood.IDLE

    def set_character(self, character_type: CharacterType) -> None:
        self.profile = CHARACTERS.get(character_type, CHARACTERS[CharacterType.BYTE_CAT])

    def get_speech(self, mood: CompanionMood, context: str = "", extra_data: Optional[str] = None) -> DialogueBubble:
        self.current_mood = mood
        
        if self.profile.id == CharacterType.PRO_SILENT:
            return DialogueBubble(
                mood=mood,
                character_name="Consola",
                icon="📊",
                headline=context or "Estado del Sistema",
                message=extra_data or "",
                tip=None
            )

        if mood == CompanionMood.IDLE:
            return DialogueBubble(
                mood=mood,
                character_name=self.profile.name,
                icon=self.profile.icon_idle,
                headline=f"{self.profile.name} está vigilando el equipo",
                message="Tu PC está descansando. ¿Quieres que hagamos un chequeo de salud?",
                tip="Presiona 'Iniciar Diagnóstico' para revisar componentes."
            )

        if mood == CompanionMood.INVESTIGATING:
            return DialogueBubble(
                mood=mood,
                character_name=self.profile.name,
                icon="🔍",
                headline=f"Revisando: {context}",
                message=f"Estoy analizando {context}. Revisando registros, hardware y posibles amenazas...",
                tip="Esto toma solo unos segundos."
            )

        if mood == CompanionMood.WORKING:
            return DialogueBubble(
                mood=mood,
                character_name=self.profile.name,
                icon=self.profile.icon_working,
                headline=f"Aplicando optimización: {context}",
                message=f"Ajustando {context} de forma segura. Guardando punto de restauración...",
                tip="Siempre puedes revertir este cambio con un clic."
            )

        if mood == CompanionMood.ALARMED:
            return DialogueBubble(
                mood=mood,
                character_name=self.profile.name,
                icon=self.profile.icon_alarm,
                headline="¡Atención! Encontré un problema",
                message=context or "Detecté una anomalía que afecta la estabilidad de tu PC.",
                tip=extra_data or "Revisa el informe detallado abajo para ver la solución."
            )

        if mood == CompanionMood.HAPPY:
            return DialogueBubble(
                mood=mood,
                character_name=self.profile.name,
                icon=self.profile.icon_happy,
                headline="¡Todo listo y optimizado!",
                message=context or "Tu sistema está afinado y limpio. El hardware responde con fluidez.",
                tip="Puedes generar un informe en PDF para guardar el diagnóstico."
            )

        # EXPLAINING
        return DialogueBubble(
            mood=mood,
            character_name=self.profile.name,
            icon="💡",
            headline=f"¿Qué hace '{context}'?",
            message=extra_data or "Esta opción ajusta parámetros para mejorar el rendimiento sin riesgos.",
            tip="Recuerda que tienes control total sobre este ajuste."
        )
