"""Cryptanalytic goals, distinct from produced representations."""

from enum import Enum


class AttackTarget(str, Enum):
    """The semantic goal pursued by an attack or analysis problem.

    EXAMPLES::

        >>> tuple(member.value for member in AttackTarget)
        ('key_recovery', 'plaintext_recovery', 'collision', 'preimage', 'distinguisher')
    """

    KEY_RECOVERY = "key_recovery"
    PLAINTEXT_RECOVERY = "plaintext_recovery"
    COLLISION = "collision"
    PREIMAGE = "preimage"
    DISTINGUISHER = "distinguisher"
