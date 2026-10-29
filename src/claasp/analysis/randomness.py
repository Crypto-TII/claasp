"""Dataset-independent tests from NIST SP 800-22 Rev. 1a."""

from dataclasses import dataclass
from math import erfc, isfinite, sqrt

from claasp.analysis.statistical_datasets import SuppliedStatisticalDataset


@dataclass(frozen=True, slots=True)
class FrequencyTestResult:
    """Monobit p-value with its sample size, level and applicability.

    ``passed`` is unavailable below the recommended 100 bits. Statistical
    tests cannot certify cryptographic security.

    EXAMPLES::

        >>> result = frequency_test([0, 1] * 50)
        >>> result.p_value, result.passed
        (1.0, True)
    """

    bit_count: int
    ones: int
    p_value: float
    alpha: float
    applicable: bool

    @property
    def passed(self) -> bool | None:
        """Return the decision, or None when the sequence is too short."""
        return self.p_value >= self.alpha if self.applicable else None


def frequency_test(bits, *, alpha: float = 0.01) -> FrequencyTestResult:
    """Test a flat bit iterable or supplied dataset using NIST section 2.1.

    EXAMPLES::

        >>> frequency_test([1] * 100).passed
        False
    """
    if not isfinite(alpha) or not 0 < alpha < 1:
        raise ValueError("alpha must lie strictly between zero and one")
    dataset = (
        bits
        if isinstance(bits, SuppliedStatisticalDataset)
        else SuppliedStatisticalDataset.from_bits(bits)
    )
    ones = sum(byte.bit_count() for byte in dataset.data)
    n = dataset.bit_count
    p_value = erfc(abs(2 * ones - n) / sqrt(2 * n))
    return FrequencyTestResult(n, ones, p_value, alpha, n >= 100)
