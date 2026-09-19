"""Safe file and execution drivers for generated source artifacts."""

import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp_next.graph import Primitive
from claasp_next.provenance import DriverIdentity, DriverKind, ResultProvenance
from claasp_next.representations.source import SourceArtifact, SourceLanguage


class SourceExecutionStatus(str, Enum):
    """Outcome of an explicitly requested generated-source run.

    EXAMPLES::

        >>> tuple(member.value for member in SourceExecutionStatus)
        ('success', 'failed', 'timeout', 'unavailable')
    """

    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class SourceExecutionResult:
    """Bounded subprocess outcome and semantic projection.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (SourceExecutionResult.__dataclass_params__.frozen, tuple(field.name for field in fields(SourceExecutionResult)))
        (True, ('status', 'output', 'values', 'command', 'runtime_seconds', 'stdout', 'stderr', 'return_code', 'source_digest', 'provenance'))
    """

    status: SourceExecutionStatus
    output: tuple[int, ...] | None
    values: tuple[tuple[str, tuple[int, ...]], ...]
    command: tuple[str, ...]
    runtime_seconds: float
    stdout: str
    stderr: str
    return_code: int | None
    source_digest: str
    provenance: ResultProvenance


PYTHON_SOURCE_DRIVER = DriverIdentity(
    "python_generated_source",
    DriverKind.EXECUTION_ENGINE,
    f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
)


def write_source(
    artifact: SourceArtifact, path: str | os.PathLike, *, overwrite: bool = False
) -> Path:
    """Write one source artifact to an explicit matching file path.

    EXAMPLES::

        >>> try:
        ...     write_source()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    if not isinstance(artifact, SourceArtifact):
        raise TypeError("write_source requires a SourceArtifact")
    destination = Path(path)
    if (
        not destination.name
        or destination.name in {".", ".."}
        or any(character in destination.name for character in ("\0", "\n", "\r"))
    ):
        raise ValueError("source output requires a safe explicit filename")
    suffix = ".py" if artifact.language is SourceLanguage.PYTHON else ".c"
    if destination.suffix != suffix:
        raise ValueError(f"{artifact.language.value} source path must end in {suffix}")
    if not destination.parent.exists() or not destination.parent.is_dir():
        raise ValueError("source output parent directory must already exist")
    mode = "w" if overwrite else "x"
    with destination.open(mode, encoding="utf-8", newline="\n") as stream:
        stream.write(artifact.source)
    return destination


def run_python_source(
    artifact: SourceArtifact,
    primitive: Primitive,
    inputs: Mapping[str, int | Sequence[int]],
    *,
    timeout_seconds: float = 10.0,
) -> SourceExecutionResult:
    """Run a generated Python artifact in an isolated temporary directory.

    EXAMPLES::

        >>> try:
        ...     run_python_source()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    if not isinstance(artifact, SourceArtifact) or artifact.language is not SourceLanguage.PYTHON:
        raise TypeError("run_python_source requires a Python SourceArtifact")
    if artifact.primitive_digest != _primitive_digest(primitive):
        raise ValueError("source artifact belongs to a different primitive graph")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 0 < timeout_seconds <= 60
    ):
        raise ValueError("timeout_seconds must be in (0, 60]")
    payload = _json_inputs(primitive, inputs)
    runtime_root = str(Path(__file__).resolve().parents[2])
    launcher = (
        "import runpy,sys;"
        f"sys.path.insert(0,{runtime_root!r});"
        "runpy.run_path(sys.argv[1],run_name='__main__')"
    )
    with TemporaryDirectory(prefix="claasp-source-") as directory:
        source_path = Path(directory) / artifact.filename
        write_source(artifact, source_path)
        command = (sys.executable, "-I", "-c", launcher, str(source_path))
        started = monotonic()
        try:
            completed = subprocess.run(
                command,
                input=json.dumps(payload, separators=(",", ":"), sort_keys=True),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                cwd=directory,
                env={"LANG": "C", "LC_ALL": "C", "PYTHONHASHSEED": "0"},
            )
        except subprocess.TimeoutExpired as error:
            runtime = monotonic() - started
            return SourceExecutionResult(
                SourceExecutionStatus.TIMEOUT,
                None,
                (),
                command,
                runtime,
                error.stdout or "",
                error.stderr or "",
                None,
                artifact.source_digest,
                ResultProvenance.for_primitive(primitive, PYTHON_SOURCE_DRIVER),
            )
        runtime = monotonic() - started
        if completed.returncode:
            return SourceExecutionResult(
                SourceExecutionStatus.FAILED,
                None,
                (),
                command,
                runtime,
                completed.stdout,
                completed.stderr,
                completed.returncode,
                artifact.source_digest,
                ResultProvenance.for_primitive(primitive, PYTHON_SOURCE_DRIVER),
            )
        try:
            decoded = json.loads(completed.stdout)
            output = None if decoded["output"] is None else tuple(decoded["output"])
            values = tuple((item["source"], tuple(item["value"])) for item in decoded["values"])
            _validate_generated_values(primitive, output, values)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            return SourceExecutionResult(
                SourceExecutionStatus.FAILED,
                None,
                (),
                command,
                runtime,
                completed.stdout,
                f"invalid generated output: {error}",
                completed.returncode,
                artifact.source_digest,
                ResultProvenance.for_primitive(primitive, PYTHON_SOURCE_DRIVER),
            )
        return SourceExecutionResult(
            SourceExecutionStatus.SUCCESS,
            output,
            values,
            command,
            runtime,
            completed.stdout,
            completed.stderr,
            completed.returncode,
            artifact.source_digest,
            ResultProvenance.for_primitive(primitive, PYTHON_SOURCE_DRIVER),
        )


def _json_inputs(primitive, inputs):
    if not isinstance(inputs, Mapping) or set(inputs) != set(primitive.input_ports):
        raise ValueError("generated-source inputs must match primitive input names exactly")
    payload = {}
    for name, value in inputs.items():
        if isinstance(value, int) and not isinstance(value, bool):
            payload[name] = value
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            frozen = list(value)
            if any(not isinstance(item, int) or isinstance(item, bool) for item in frozen):
                raise TypeError("generated-source input sequences must contain integers")
            payload[name] = frozen
        else:
            raise TypeError("generated-source inputs must be integers or integer sequences")
    return payload


def _primitive_digest(primitive):
    from claasp_next.serialization import primitive_digest

    return primitive_digest(primitive)


def _validate_generated_values(primitive, output, values):
    expected_order = (
        tuple(primitive.input_ports)
        + tuple(item.component_id for item in primitive.components)
        + tuple(item.binding_id for item in primitive.bindings)
    )
    if tuple(name for name, _ in values) != expected_order:
        raise ValueError("generated values do not follow semantic graph order")
    mapping = {}
    for source_id, value in values:
        value_type = primitive.port(source_id).value_type
        if len(value) != value_type.unit_count or any(
            not isinstance(item, int)
            or isinstance(item, bool)
            or not value_type.domain.contains(item)
            for item in value
        ):
            raise ValueError(f"generated value for {source_id!r} violates its type")
        mapping[source_id] = value
    expected_output = (
        None
        if primitive.output is None
        else primitive.resolve_selection(
            primitive.output,
            mapping,
        )
    )
    if output != expected_output:
        raise ValueError("generated output does not match its graph values")


__all__ = [
    "PYTHON_SOURCE_DRIVER",
    "SourceExecutionResult",
    "SourceExecutionStatus",
    "run_python_source",
    "write_source",
]
