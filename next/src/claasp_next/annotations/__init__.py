"""Information attached to cipher graph inputs, components, and outputs."""

from claasp_next.annotations.base import AnnotationEntry, AnnotationRole, GraphAnnotation
from claasp_next.annotations.traces import ExecutionTrace, LeakageSample, SideChannelTrace

__all__ = [
    "AnnotationEntry", "AnnotationRole", "ExecutionTrace", "GraphAnnotation",
    "LeakageSample", "SideChannelTrace",
]
