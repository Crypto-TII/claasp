"""Public workflows for migrated truncated, impossible, and boomerang models."""

from dataclasses import dataclass

from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.semantics import PROBABILISTIC_TRUNCATED_XOR
from claasp.semantics.cryptanalysis import (
    BoomerangConnectivity,
    ImpossiblePropagationBoundary,
    ProbabilisticTruncatedTrail,
    PropagationProblem,
    TruncatedXorDifference,
    propagate_two_word_simon_round,
    propagate_two_word_speck_round,
)


@dataclass(frozen=True, slots=True)
class TruncatedPropagationResult:
    """Independently checked deterministic-truncated round boundaries.

    EXAMPLES::

        >>> callable(TruncatedPropagationResult)
        True
    """

    boundaries: tuple[TruncatedXorDifference, ...]
    primitive: str
    backend: str = "dependency_free"
    independently_valid: bool = True


@dataclass(frozen=True, slots=True)
class CPCharacteristicResult:
    """A decoded and independently validated CP characteristic.

    EXAMPLES::

        >>> callable(CPCharacteristicResult)
        True
    """

    characteristic: object
    runtime_seconds: float
    solver: str
    provenance: tuple[str, ...]
    independently_valid: bool = True


def propagate_truncated_xor_difference(primitive, input_pattern):
    """Propagate a three-valued XOR difference over supported round graphs.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> result = propagate_truncated_xor_difference(Simon(number_of_rounds=1), "0" * 31 + "1")
        >>> len(result.boundaries)
        2
    """

    pattern = _pattern(input_pattern)
    boundaries = [pattern]
    if primitive.family_name == "speck":
        operation = lambda value: propagate_two_word_speck_round(primitive, value)
    elif primitive.family_name == "simon":
        operation = propagate_two_word_simon_round
    else:
        raise NotImplementedError(
            f"primitive {primitive.family_name!r}, analysis 'deterministic_truncated_xor', "
            "backend 'dependency_free': first unsupported component/domain has no "
            "sound three-valued propagation rule"
        )
    for _ in primitive.graph.rounds:
        boundaries.append(operation(boundaries[-1]))
    return TruncatedPropagationResult(tuple(boundaries), primitive.family_name)


def find_probabilistic_truncated_xor_differential(
    primitive, input_pattern, output_pattern, *, solver=None
):
    """Optimize the migrated counter-based Speck truncated model.

    EXAMPLES::

        >>> callable(find_probabilistic_truncated_xor_differential)
        True
    """

    from claasp.representations.constraints.cp import SpeckProbabilisticTruncatedCPModel

    problem = PropagationProblem(
        primitive,
        PROBABILISTIC_TRUNCATED_XOR,
        provenance=("public probabilistic-truncated XOR search",),
    )
    try:
        model = SpeckProbabilisticTruncatedCPModel(
            problem, _pattern(input_pattern), _pattern(output_pattern)
        )
    except NotImplementedError as error:
        raise NotImplementedError(
            f"primitive {primitive.family_name!r}, analysis "
            "'probabilistic_truncated_xor', backend 'cp': " + str(error)
        ) from error
    cp_model = model.cp_model()
    solved = _solver(solver).solve(cp_model)
    if solved.status is not CPStatus.SATISFIED or solved.assignment is None:
        raise RuntimeError(f"probabilistic-truncated CP search returned {solved.status.value}")
    trail = model.decode_trail(solved.assignment)
    if not isinstance(trail, ProbabilisticTruncatedTrail):
        raise TypeError("CP model decoded an unexpected characteristic type")
    return CPCharacteristicResult(trail, solved.runtime_seconds, solved.solver, cp_model.provenance)


def find_impossible_xor_differential(
    primitive,
    middle_round,
    *,
    input_pattern=None,
    output_pattern=None,
    solver=None,
):
    """Find or prove a migrated deterministic-truncated middle contradiction.

    EXAMPLES::

        >>> callable(find_impossible_xor_differential)
        True
    """

    from claasp.representations.constraints.cp import (
        SimonImpossibleCPModel,
        SpeckImpossibleCPModel,
    )

    if primitive.family_name == "speck":
        if input_pattern is not None or output_pattern is not None:
            raise ValueError("the Speck automatic search chooses both external patterns")
        model = SpeckImpossibleCPModel(primitive, middle_round)
    elif primitive.family_name == "simon":
        if input_pattern is None or output_pattern is None:
            raise ValueError("Simon impossible search requires input_pattern and output_pattern")
        model = SimonImpossibleCPModel(
            primitive, _pattern(input_pattern), _pattern(output_pattern), middle_round
        )
    else:
        raise NotImplementedError(
            f"primitive {primitive.family_name!r}, analysis 'impossible_xor_differential', "
            "backend 'cp': first unsupported component/domain has no inverse "
            "deterministic-truncated rule"
        )
    cp_model = model.cp_model()
    solved = _solver(solver).solve(cp_model)
    if solved.status is not CPStatus.SATISFIED or solved.assignment is None:
        raise RuntimeError(f"impossible-differential CP search returned {solved.status.value}")
    boundary = model.decode_boundary(solved.assignment)
    if not isinstance(boundary, ImpossiblePropagationBoundary) or not boundary.is_impossible:
        raise ValueError("decoded middle boundary is not independently contradictory")
    return CPCharacteristicResult(
        boundary, solved.runtime_seconds, solved.solver, cp_model.provenance
    )


def find_sbox_boomerang_transition(
    primitive,
    component,
    *,
    input_difference=None,
    output_difference=None,
    solver=None,
):
    """Maximize or check an exact BCT entry for a graph S-box.

    EXAMPLES::

        >>> callable(find_sbox_boomerang_transition)
        True
    """

    from claasp.components import BitVectorSBox
    from claasp.representations.constraints.cp import SBoxBoomerangCPModel

    selected = _component(primitive, component)
    if not isinstance(selected, BitVectorSBox):
        raise NotImplementedError(
            f"primitive {primitive.family_name!r}, analysis 'sbox_boomerang', backend 'cp': "
            f"component {selected.component_id!r} ({type(selected).__name__}) is not a "
            "bijective bit-vector S-box"
        )
    model = SBoxBoomerangCPModel(selected, input_difference, output_difference)
    cp_model = model.cp_model()
    solved = _solver(solver).solve(cp_model)
    if solved.status is not CPStatus.SATISFIED or solved.assignment is None:
        raise RuntimeError(f"S-box boomerang CP search returned {solved.status.value}")
    entry = model.decode(solved.assignment)
    if not isinstance(entry, BoomerangConnectivity) or not entry.is_possible:
        raise ValueError("decoded BCT transition failed independent validation")
    return CPCharacteristicResult(entry, solved.runtime_seconds, solved.solver, cp_model.provenance)


def _pattern(value):
    if isinstance(value, TruncatedXorDifference):
        return value
    if isinstance(value, str):
        return TruncatedXorDifference.parse(value)
    raise TypeError("truncated patterns must be strings or TruncatedXorDifference values")


def _solver(solver):
    selected = MiniZincSolver() if solver is None else solver
    if not hasattr(selected, "solve"):
        raise TypeError("solver must provide solve(model)")
    return selected


def _component(primitive, component):
    if not isinstance(component, str):
        if any(item is component for item in primitive.graph.components):
            return component
        raise ValueError("component does not belong to this primitive")
    try:
        return next(item for item in primitive.graph.components if item.component_id == component)
    except StopIteration as error:
        raise KeyError(f"primitive component {component!r} does not exist") from error
