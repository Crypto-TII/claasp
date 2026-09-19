"""Optional bounded compiler and execution drivers for generated C."""

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp_next.graph import Primitive
from claasp_next.provenance import DriverIdentity, DriverKind, ResultProvenance
from claasp_next.representations.source import SourceArtifact, SourceLanguage


class NativeCompilationStatus(str, Enum):
    """Outcome of optional native compilation.

    EXAMPLES::

        >>> tuple(member.value for member in NativeCompilationStatus)
        ('success', 'failed', 'timeout', 'unavailable')
    """

    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class NativeArtifact:
    """Compiled bytes plus exact tool and source provenance.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (NativeArtifact.__dataclass_params__.frozen, tuple(field.name for field in fields(NativeArtifact)))
        (True, ('binary', 'binary_digest', 'source_digest', 'primitive_digest', 'realization_identity', 'compiler', 'compiler_version', 'command', 'options'))
    """

    binary: bytes
    binary_digest: str
    source_digest: str
    primitive_digest: str
    realization_identity: str
    compiler: str
    compiler_version: str
    command: tuple[str, ...]
    options: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.binary, bytes) or not self.binary:
            raise ValueError("native artifact binary must be non-empty bytes")
        if sha256(self.binary).hexdigest() != self.binary_digest:
            raise ValueError("native binary digest does not match its bytes")
        for label, digest in (("source", self.source_digest), ("primitive", self.primitive_digest)):
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ValueError(f"native {label} digest must be lowercase SHA-256")
        if not self.realization_identity or not self.compiler or not self.compiler_version:
            raise ValueError("native artifact provenance fields must be non-empty")
        if not isinstance(self.command, tuple) or not self.command:
            raise ValueError("native compiler command must be a non-empty argument vector")
        if not isinstance(self.options, tuple):
            raise TypeError("native compiler options must be a tuple")


@dataclass(frozen=True, slots=True)
class NativeCompilationResult:
    """Compiler status, diagnostics, timings, and optional artifact.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (NativeCompilationResult.__dataclass_params__.frozen, tuple(field.name for field in fields(NativeCompilationResult)))
        (True, ('status', 'artifact', 'command', 'compiler_version', 'runtime_seconds', 'stdout', 'stderr', 'return_code', 'source_digest'))
    """

    status: NativeCompilationStatus
    artifact: NativeArtifact | None
    command: tuple[str, ...]
    compiler_version: str | None
    runtime_seconds: float
    stdout: str
    stderr: str
    return_code: int | None
    source_digest: str


class NativeExecutionStatus(str, Enum):
    """Outcome of running a compiled artifact.

    EXAMPLES::

        >>> tuple(member.value for member in NativeExecutionStatus)
        ('success', 'failed', 'timeout')
    """

    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True)
class NativeExecutionResult:
    """Bounded native execution outcome and typed primitive output.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (NativeExecutionResult.__dataclass_params__.frozen, tuple(field.name for field in fields(NativeExecutionResult)))
        (True, ('status', 'output', 'command', 'runtime_seconds', 'stdout', 'stderr', 'return_code', 'source_digest', 'compiler', 'compiler_version', 'compiler_command', 'compiler_options', 'provenance'))
    """

    status: NativeExecutionStatus
    output: tuple[int, ...] | None
    command: tuple[str, ...]
    runtime_seconds: float
    stdout: str
    stderr: str
    return_code: int | None
    source_digest: str
    compiler: str
    compiler_version: str
    compiler_command: tuple[str, ...]
    compiler_options: tuple[str, ...]
    provenance: ResultProvenance


NATIVE_EXECUTION_DRIVER = DriverIdentity("native_generated_c", DriverKind.EXECUTION_ENGINE, "1")
_ALLOWED_OPTIONS = frozenset(("-O0", "-O1", "-O2", "-O3", "-Wall", "-Wextra", "-pedantic"))


def compile_native(
    artifact: SourceArtifact,
    *,
    compiler: str = "cc",
    options: Sequence[str] = ("-O2",),
    timeout_seconds: float = 20.0,
) -> NativeCompilationResult:
    """Compile one generated C artifact without executing it.

    EXAMPLES::

        >>> try:
        ...     compile_native()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    if not isinstance(artifact, SourceArtifact) or artifact.language is not SourceLanguage.C:
        raise TypeError("compile_native requires a C SourceArtifact")
    if not isinstance(compiler, str) or not compiler or Path(compiler).name != compiler:
        raise ValueError("compiler must be one executable basename")
    options = tuple(options)
    if any(option not in _ALLOWED_OPTIONS for option in options):
        raise ValueError(f"compiler options must be selected from {sorted(_ALLOWED_OPTIONS)}")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 0 < timeout_seconds <= 60
    ):
        raise ValueError("timeout_seconds must be in (0, 60]")
    executable = shutil.which(compiler)
    if executable is None:
        return NativeCompilationResult(
            NativeCompilationStatus.UNAVAILABLE,
            None,
            (),
            None,
            0.0,
            "",
            f"compiler {compiler!r} is unavailable",
            None,
            artifact.source_digest,
        )
    version = _compiler_version(executable)
    with TemporaryDirectory(prefix="claasp-native-") as directory:
        source = Path(directory) / artifact.filename
        binary = Path(directory) / "primitive_evaluator"
        source.write_text(artifact.source, encoding="utf-8", newline="\n")
        command = (executable, "-std=c11", *options, str(source), "-o", str(binary))
        started = monotonic()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                cwd=directory,
                env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
            )
        except subprocess.TimeoutExpired as error:
            return NativeCompilationResult(
                NativeCompilationStatus.TIMEOUT,
                None,
                command,
                version,
                monotonic() - started,
                error.stdout or "",
                error.stderr or "",
                None,
                artifact.source_digest,
            )
        runtime = monotonic() - started
        if completed.returncode != 0 or not binary.is_file():
            return NativeCompilationResult(
                NativeCompilationStatus.FAILED,
                None,
                command,
                version,
                runtime,
                completed.stdout,
                completed.stderr,
                completed.returncode,
                artifact.source_digest,
            )
        payload = binary.read_bytes()
        native = NativeArtifact(
            payload,
            sha256(payload).hexdigest(),
            artifact.source_digest,
            artifact.primitive_digest,
            artifact.realization_identity,
            executable,
            version,
            command,
            options,
        )
        return NativeCompilationResult(
            NativeCompilationStatus.SUCCESS,
            native,
            command,
            version,
            runtime,
            completed.stdout,
            completed.stderr,
            completed.returncode,
            artifact.source_digest,
        )


def run_compiled(
    artifact: NativeArtifact,
    primitive: Primitive,
    inputs: Mapping[str, int | Sequence[int]],
    *,
    timeout_seconds: float = 10.0,
) -> NativeExecutionResult:
    """Execute a compiled artifact in a fresh isolated temporary directory.

    EXAMPLES::

        >>> try:
        ...     run_compiled()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    if not isinstance(artifact, NativeArtifact):
        raise TypeError("run_compiled requires a NativeArtifact")
    from claasp_next.serialization import primitive_digest

    if artifact.primitive_digest != primitive_digest(primitive):
        raise ValueError("compiled artifact belongs to a different primitive graph")
    if sha256(artifact.binary).hexdigest() != artifact.binary_digest:
        raise ValueError("compiled artifact binary digest is invalid")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 0 < timeout_seconds <= 60
    ):
        raise ValueError("timeout_seconds must be in (0, 60]")
    arguments = _hex_arguments(primitive, inputs)
    with TemporaryDirectory(prefix="claasp-run-") as directory:
        executable = Path(directory) / "primitive_evaluator"
        executable.write_bytes(artifact.binary)
        executable.chmod(0o700)
        command = (str(executable), *arguments)
        started = monotonic()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                cwd=directory,
                env={"LANG": "C", "LC_ALL": "C"},
            )
        except subprocess.TimeoutExpired as error:
            return _native_result(
                NativeExecutionStatus.TIMEOUT,
                None,
                command,
                monotonic() - started,
                error.stdout or "",
                error.stderr or "",
                None,
                artifact,
                primitive,
            )
        runtime = monotonic() - started
        if completed.returncode:
            return _native_result(
                NativeExecutionStatus.FAILED,
                None,
                command,
                runtime,
                completed.stdout,
                completed.stderr,
                completed.returncode,
                artifact,
                primitive,
            )
        try:
            packed = int(completed.stdout.strip(), 16)
            output = primitive._decode_boundary(packed, primitive.output.value_type)
        except (TypeError, ValueError) as error:
            return _native_result(
                NativeExecutionStatus.FAILED,
                None,
                command,
                runtime,
                completed.stdout,
                f"invalid native output: {error}",
                completed.returncode,
                artifact,
                primitive,
            )
        return _native_result(
            NativeExecutionStatus.SUCCESS,
            output,
            command,
            runtime,
            completed.stdout,
            completed.stderr,
            completed.returncode,
            artifact,
            primitive,
        )


def _native_result(
    status, output, command, runtime, stdout, stderr, return_code, artifact, primitive
):
    return NativeExecutionResult(
        status,
        output,
        command,
        runtime,
        stdout,
        stderr,
        return_code,
        artifact.source_digest,
        artifact.compiler,
        artifact.compiler_version,
        artifact.command,
        artifact.options,
        ResultProvenance.for_primitive(primitive, NATIVE_EXECUTION_DRIVER),
    )


def _compiler_version(executable):
    completed = subprocess.run(
        (executable, "--version"),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
    )
    line = (completed.stdout or completed.stderr).splitlines()
    return line[0].strip() if line else "unknown"


def _hex_arguments(primitive, inputs):
    if not isinstance(inputs, Mapping) or set(inputs) != set(primitive.input_ports):
        raise ValueError("native inputs must match primitive input names exactly")
    arguments = []
    for name, descriptor in primitive.input_descriptors.items():
        value = inputs[name]
        if isinstance(value, int) and not isinstance(value, bool):
            packed = value
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            packed = primitive._encode_boundary(tuple(value), descriptor.value_type)
            if not isinstance(packed, int):
                raise TypeError("native source requires canonically encoded fixed-width inputs")
        else:
            raise TypeError("native inputs must be integers or integer sequences")
        if packed < 0 or packed.bit_length() > descriptor.value_type.encoded_bit_size:
            raise ValueError(f"native input {name!r} is outside its encoded width")
        arguments.append(f"0x{packed:x}")
    return tuple(arguments)


__all__ = [
    "NATIVE_EXECUTION_DRIVER",
    "NativeArtifact",
    "NativeCompilationResult",
    "NativeCompilationStatus",
    "NativeExecutionResult",
    "NativeExecutionStatus",
    "compile_native",
    "run_compiled",
]
