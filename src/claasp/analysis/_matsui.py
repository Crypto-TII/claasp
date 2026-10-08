"""Exact probability-domain branch-and-bound primitives for trail search."""

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Generic, TypeVar

State = TypeVar("State")
Payload = TypeVar("Payload")


@dataclass(frozen=True, slots=True)
class MatsuiEdge(Generic[State, Payload]):
    """One exact round transition supplied to the search engine."""

    state: State
    probability: Fraction
    payload: Payload

    def __post_init__(self) -> None:
        if not 0 < self.probability <= 1:
            raise ValueError("a Matsui edge probability must be in (0, 1]")


@dataclass(frozen=True, slots=True)
class MatsuiSearchStatistics:
    """Deterministic counters describing one branch-and-bound proof."""

    visited_nodes: int
    generated_edges: int
    pruned_nodes: int
    incumbent_updates: int


@dataclass(frozen=True, slots=True)
class MatsuiSearchOutcome(Generic[Payload]):
    """The retained exact incumbent and proof counters."""

    probability: Fraction
    payload: tuple[Payload, ...]
    statistics: MatsuiSearchStatistics


def matsui_branch_and_bound(
    *,
    rounds: int,
    initial_state: State,
    incumbent_probability: Fraction,
    incumbent_payload: Sequence[Payload],
    suffix_probability_bounds: Sequence[Fraction],
    successors: Callable[[int, State, Fraction], Iterable[MatsuiEdge[State, Payload]]],
) -> MatsuiSearchOutcome[Payload]:
    """Maximize a trail probability with Matsui's inductive bound.

    ``suffix_probability_bounds[k]`` must upper-bound every compatible
    ``k``-round suffix. ``successors`` receives the strict minimum local
    probability that could still improve the retained incumbent and must
    enumerate every edge above it. Equality is pruned because a complete,
    independently checkable incumbent is supplied by the caller.
    """

    if not isinstance(rounds, int) or isinstance(rounds, bool) or rounds <= 0:
        raise ValueError("rounds must be a positive integer")
    if len(suffix_probability_bounds) != rounds + 1:
        raise ValueError("suffix bounds must contain entries for zero through all rounds")
    if suffix_probability_bounds[0] != 1:
        raise ValueError("the zero-round suffix probability bound must be one")
    if any(not 0 < bound <= 1 for bound in suffix_probability_bounds):
        raise ValueError("suffix probability bounds must be in (0, 1]")
    if not 0 < incumbent_probability <= 1:
        raise ValueError("the incumbent probability must be in (0, 1]")
    if len(incumbent_payload) != rounds:
        raise ValueError("the incumbent payload must contain one entry per round")

    incumbent = incumbent_probability
    best_payload = tuple(incumbent_payload)
    visited_nodes = generated_edges = pruned_nodes = incumbent_updates = 0

    def visit(
        round_index: int,
        state: State,
        prefix_probability: Fraction,
        payload: tuple[Payload, ...],
    ) -> None:
        nonlocal incumbent, best_payload
        nonlocal visited_nodes, generated_edges, pruned_nodes, incumbent_updates
        visited_nodes += 1
        remaining = rounds - round_index
        if prefix_probability * suffix_probability_bounds[remaining] <= incumbent:
            pruned_nodes += 1
            return
        if round_index == rounds:
            incumbent = prefix_probability
            best_payload = payload
            incumbent_updates += 1
            return

        suffix_bound = suffix_probability_bounds[remaining - 1]
        strict_minimum = incumbent / (prefix_probability * suffix_bound)
        for edge in successors(round_index, state, strict_minimum):
            generated_edges += 1
            if edge.probability <= strict_minimum:
                raise ValueError("successors returned an edge that cannot improve the incumbent")
            visit(
                round_index + 1,
                edge.state,
                prefix_probability * edge.probability,
                payload + (edge.payload,),
            )

    # The root must be visited even when its bound equals the incumbent: its
    # successors are what prove that no strictly better trail exists.
    visited_nodes += 1
    strict_minimum = incumbent / suffix_probability_bounds[rounds - 1]
    for edge in successors(0, initial_state, strict_minimum):
        generated_edges += 1
        if edge.probability <= strict_minimum:
            raise ValueError("successors returned an edge that cannot improve the incumbent")
        visit(1, edge.state, edge.probability, (edge.payload,))

    return MatsuiSearchOutcome(
        incumbent,
        best_payload,
        MatsuiSearchStatistics(
            visited_nodes,
            generated_edges,
            pruned_nodes,
            incumbent_updates,
        ),
    )


@dataclass(frozen=True, slots=True)
class ModularAddDifference:
    """An exact modular-addition XOR-differential candidate."""

    left: int
    right: int
    output: int
    probability: Fraction


def modular_add_differences_above(
    width: int,
    minimum_probability: Fraction,
    *,
    left: int | None = None,
    right: int | None = None,
) -> tuple[ModularAddDifference, ...]:
    """Enumerate every xdp+ transition strictly above ``minimum_probability``.

    The recursion assigns difference bits from least to most significant. At
    every prefix it evaluates the exact paired-carry probability and prunes
    when that monotone upper bound cannot exceed the requested threshold.
    Fixed operands restrict later-round searches; free operands implement the
    nested first-round bit recursion without materializing a full DDT.
    """

    if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
        raise ValueError("width must be a positive integer")
    if not 0 <= minimum_probability < 1:
        raise ValueError("minimum_probability must be in [0, 1)")
    limit = 1 << width
    for name, value in (("left", left), ("right", right)):
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < limit
        ):
            raise ValueError(f"{name} difference must fit the word width")

    result: list[ModularAddDifference] = []

    def visit(
        bit: int,
        left_difference: int,
        right_difference: int,
        output_difference: int,
        carries: dict[tuple[int, int], int],
    ) -> None:
        partial_probability = Fraction(sum(carries.values()), 1 << (2 * bit))
        if partial_probability <= minimum_probability:
            return
        if bit == width:
            result.append(
                ModularAddDifference(
                    left_difference,
                    right_difference,
                    output_difference,
                    partial_probability,
                )
            )
            return

        left_bits = ((left >> bit) & 1,) if left is not None else (0, 1)
        right_bits = ((right >> bit) & 1,) if right is not None else (0, 1)
        for left_bit in left_bits:
            for right_bit in right_bits:
                for output_bit in (0, 1):
                    next_carries: dict[tuple[int, int], int] = {}
                    for (carry, paired_carry), count in carries.items():
                        for left_value in (0, 1):
                            for right_value in (0, 1):
                                total = left_value + right_value + carry
                                paired_total = (
                                    (left_value ^ left_bit)
                                    + (right_value ^ right_bit)
                                    + paired_carry
                                )
                                if ((total ^ paired_total) & 1) != output_bit:
                                    continue
                                pair = (total >> 1, paired_total >> 1)
                                next_carries[pair] = next_carries.get(pair, 0) + count
                    visit(
                        bit + 1,
                        left_difference | (left_bit << bit),
                        right_difference | (right_bit << bit),
                        output_difference | (output_bit << bit),
                        next_carries,
                    )

    visit(0, 0, 0, 0, {(0, 0): 1})
    return tuple(
        sorted(
            result,
            key=lambda item: (-item.probability, item.left, item.right, item.output),
        )
    )
