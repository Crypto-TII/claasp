"""Information attached to primitive graph inputs, components, and outputs."""

from claasp.annotations.base import AnnotationEntry, AnnotationRole, GraphAnnotation
from claasp.annotations.traces import ExecutionTrace, LeakageSample, SideChannelTrace

__all__ = [
    "AnnotationEntry",
    "AnnotationRole",
    "ExecutionTrace",
    "GraphAnnotation",
    "LeakageSample",
    "SideChannelTrace",
]
