"""Cryptanalytic goals, distinct from produced representations."""

from enum import Enum


class AttackTarget(str, Enum):
    """The semantic goal pursued by an attack or analysis problem."""

    KEY_RECOVERY = "key_recovery"
    PLAINTEXT_RECOVERY = "plaintext_recovery"
    COLLISION = "collision"
    PREIMAGE = "preimage"
    DISTINGUISHER = "distinguisher"
