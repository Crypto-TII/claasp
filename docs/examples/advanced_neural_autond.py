"""Reproducible advanced neural experiment."""

from claasp.primitives import Speck


def run_example():
    primitive = Speck(number_of_rounds=3)
    return primitive.analysis.autond(
        samples=3000,
        epochs=15,
        batch_size=64,
        validation_fraction=0.1,
        seed=9,
        optimizer_population=8,
        optimizer_generations=2,
        optimizer_samples=64,
        active_inputs=("plaintext",),
    )


if __name__ == "__main__":
    print(run_example())
