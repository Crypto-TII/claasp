from claasp.analysis.statistical import run_statistical_campaign
from claasp.analysis.statistical_results import (
    DieharderReport,
    StatisticalTestRun,
)
from claasp.primitives import Speck


class RecordingDriver:
    def __init__(self):
        self.datasets = []
        self.options = []

    def run(self, dataset, **options):
        self.datasets.append(dataset)
        self.options.append(options)
        return StatisticalTestRun(
            "recording",
            "1",
            dataset.digest(),
            ("recording",),
            0.0,
            DieharderReport(()),
            "",
            "",
        )


def test_public_campaign_restores_every_dataset_family_and_round_range():
    primitive = Speck(number_of_rounds=2)
    for kind in (
        "avalanche",
        "correlation",
        "cbc",
        "random",
        "low_density",
        "high_density",
    ):
        driver = RecordingDriver()
        result = primitive.analysis.run_statistical_tests(
            driver,
            kind,
            "plaintext",
            number_of_samples=1,
            blocks_per_sample=2,
            ratio=0,
            fixed_inputs={"key": 0},
            round_start=1,
            round_end=2,
            driver_options={"test": 0},
        )

        assert result.kind == kind
        assert tuple(item.round_number for item in result.rounds) == (1, 2)
        assert all(item.dataset.kind == kind for item in result.rounds)
        assert all(item.run.dataset_sha256 == item.dataset.digest() for item in result.rounds)
        assert driver.options == [{"test": 0}, {"test": 0}]


def test_campaign_validates_kind_sizes_rounds_and_driver():
    primitive = Speck(number_of_rounds=2)
    driver = RecordingDriver()

    for call, message in (
        (
            lambda: run_statistical_campaign(
                primitive,
                driver,
                "random",
                "plaintext",
                number_of_samples=1,
            ),
            "blocks_per_sample",
        ),
        (
            lambda: run_statistical_campaign(
                primitive,
                driver,
                "unknown",
                "plaintext",
                number_of_samples=1,
            ),
            "unsupported statistical dataset kind",
        ),
        (
            lambda: run_statistical_campaign(
                primitive,
                driver,
                "avalanche",
                "plaintext",
                number_of_samples=1,
                round_start=0,
            ),
            "round range",
        ),
    ):
        try:
            call()
        except ValueError as error:
            assert message in str(error)
        else:
            raise AssertionError("expected ValueError")
