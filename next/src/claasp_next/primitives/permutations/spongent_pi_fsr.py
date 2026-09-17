"""Spongent-pi feedback-register realization."""

from claasp_next.primitives.permutations.spongent_pi import SpongentPi


class SpongentPiFSR(SpongentPi):
    """Spongent-pi with its counter register represented by equivalent wiring."""

__all__ = ["SpongentPiFSR"]
