from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

class CharacterType(str, Enum):
    BYTE_CAT = "byte_cat"
    PATCH_DOG = "patch_dog"
    GIZMO_ROBOT = "gizmo_robot"
    PRO_SILENT = "pro_silent"

@dataclass(slots=True)
class CompanionProfile:
    id: CharacterType
    name: str
    species: str
    tone: str
    icon_idle: str
    icon_working: str
    icon_alarm: str
    icon_happy: str

CHARACTERS = {
    CharacterType.BYTE_CAT: CompanionProfile(
        id=CharacterType.BYTE_CAT,
        name="Byte",
        species="Gato",
        tone="Curioso, ágil y protector del hardware",
        icon_idle="🐱",
        icon_working="🛠️",
        icon_alarm="😿",
        icon_happy="😸",
    ),
    CharacterType.PATCH_DOG: CompanionProfile(
        id=CharacterType.PATCH_DOG,
        name="Patch",
        species="Perro Guardián",
        tone="Leal, alerta ante amenazas y vigilante de seguridad",
        icon_idle="🐶",
        icon_working="⚙️",
        icon_alarm="🐕‍🦺",
        icon_happy="🦴",
    ),
    CharacterType.GIZMO_ROBOT: CompanionProfile(
        id=CharacterType.GIZMO_ROBOT,
        name="Gizmo",
        species="Androide",
        tone="Preciso, analítico y amante de las métricas exactas",
        icon_idle="🤖",
        icon_working="⚡",
        icon_alarm="🚨",
        icon_happy="🚀",
    ),
    CharacterType.PRO_SILENT: CompanionProfile(
        id=CharacterType.PRO_SILENT,
        name="Modo Técnico",
        species="Ninguno",
        tone="Silencioso y puramente técnico",
        icon_idle="📊",
        icon_working="⏳",
        icon_alarm="⚠️",
        icon_happy="✅",
    ),
}
