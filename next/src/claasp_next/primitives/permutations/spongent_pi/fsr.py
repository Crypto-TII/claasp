"""Feedback-register realization of Spongent-pi."""

from .primitive import SpongentPi


class SpongentPiFSR(SpongentPi):
    """Spongent-pi with its counter register represented by equivalent wiring."""

__all__ = ["SpongentPiFSR"]
