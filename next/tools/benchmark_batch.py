"""Compare dependency-free batch backends on the bundled Poseidon graph."""

from argparse import ArgumentParser
from timeit import repeat

from claasp_next.evaluators import BatchEvaluator, TransposedBatchEvaluator

from claasp_next.parameters import poseidon_bn254_width3


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--number", type=int, default=3)
    args = parser.parse_args()
    if args.batch_size <= 0 or args.number <= 0:
        parser.error("batch-size and number must be positive")
    parameters = poseidon_bn254_width3()
    cipher = parameters.permutation()
    states = tuple(
        tuple((lane + position) % parameters.modulus for position in range(parameters.width))
        for lane in range(args.batch_size)
    )
    inputs = {"state": states}
    evaluators = (BatchEvaluator(), TransposedBatchEvaluator())
    reference = evaluators[0].evaluate(cipher, inputs).outputs
    for evaluator in evaluators:
        assert evaluator.evaluate(cipher, inputs).outputs == reference
        elapsed = (
            min(
                repeat(
                    lambda evaluator=evaluator: evaluator.evaluate(cipher, inputs),
                    repeat=3,
                    number=args.number,
                )
            )
            / args.number
        )
        print(f"{type(evaluator).__name__}: {elapsed:.6f} seconds/evaluation")


if __name__ == "__main__":
    main()
