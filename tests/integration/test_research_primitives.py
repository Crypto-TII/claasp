"""Published vectors and independent-circuit checks for the research catalogue.

NOEKEON: designers' Noekeon_ref.zip/NoekeonTestVectors.txt.
PRIDE: Appendix J vectors, also reproduced in obfusk/pypride's examples.
uLBC: https://doi.org/10.62056/a63zzoja5, Appendix A (all six vectors).
"""

from random import Random

import pytest

from claasp.catalogue import catalogue
from claasp.primitives import ULBC, Noekeon, Pride, ULBCTweakable
from claasp.representations.execution import ScalarExecutionDriver, TransposedBatchExecutionDriver


@pytest.mark.parametrize("factory", [Noekeon, Pride, ULBC, ULBCTweakable])
def test_native_catalogue_and_transposed_batch_execution(factory):
    primitive = factory(number_of_rounds=2)
    assert catalogue.primitive(factory.__name__).name == factory.__name__
    assert len(primitive.graph.rounds) == 2
    rng = Random(2411)
    samples = {
        name: tuple(
            tuple(
                rng.randrange(1 << value.array_type.unit_type.encoded_bit_size)
                for _ in range(value.array_type.unit_count)
            )
            for _ in range(3)
        )
        for name, value in primitive.graph.input_arrays.items()
    }
    batch = TransposedBatchExecutionDriver().evaluate(primitive, samples)
    scalar = ScalarExecutionDriver()
    assert batch.outputs == tuple(
        scalar.evaluate(primitive, {name: values[i] for name, values in samples.items()}).output
        for i in range(3)
    )


@pytest.mark.parametrize(
    "factory,kwargs",
    [
        (Noekeon, {"number_of_rounds": True}),
        (Noekeon, {"number_of_rounds": 17}),
        (Noekeon, {"key_mode": "other"}),
        (Pride, {"number_of_rounds": 21}),
        (Pride, {"number_of_rounds": False}),
        (ULBC, {"key_bit_size": 192}),
        (ULBC, {"number_of_rounds": 0}),
        (ULBC, {"number_of_rounds": 19}),
        (ULBCTweakable, {"key_bit_size": 127}),
        (ULBCTweakable, {"key_bit_size": 385}),
        (ULBCTweakable, {"number_of_rounds": 31}),
        (ULBCTweakable, {"number_of_rounds": False}),
    ],
)
def test_invalid_parameters(factory, kwargs):
    with pytest.raises(ValueError):
        factory(**kwargs)


def test_specification_instances_are_separate_from_round_reductions():
    assert {r.values["key_bit_size"] for r in ULBC(number_of_rounds=2).instances} == {128, 256}
    assert {r.values["number_of_rounds"] for r in Pride(number_of_rounds=2).instances} == {20}
    assert {r.values["key_mode"] for r in Noekeon(number_of_rounds=2).instances} == {
        "direct",
        "indirect",
    }
