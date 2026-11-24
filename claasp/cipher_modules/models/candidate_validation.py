"""Measure external events selected by CLAASP trail-search models.

This module keeps solver weights separate from empirical measurements. It
reuses the existing vectorized checkers where their input restrictions hold,
and uses scalar evaluation for small, non-byte-aligned ciphers.
"""

import math
import random

from claasp.cipher_modules.models import utils
from claasp.name_mappings import CIPHER_OUTPUT, INPUT_KEY, INPUT_PLAINTEXT

_CHECKERS = {
    name: getattr(utils, name)
    for name in (
        "boomerang_checker_for_block_cipher_single_key",
        "differential_checker_permutation",
        "differential_linear_checker_for_block_cipher_single_key",
        "differential_truncated_checker_permutation",
        "differential_truncated_checker_single_key",
        "differential_truncated_checker_permutation_input_and_output_truncated",
        "linear_checker_for_block_cipher_single_key",
        "linear_checker_permutation",
        "shared_difference_paired_input_differential_checker_permutation",
        "shared_difference_paired_input_differential_linear_checker_permutation",
        "truncated_differential_linear_checker_permutation",
    )
}


def _data_input(cipher):
    if INPUT_PLAINTEXT in cipher.inputs:
        return INPUT_PLAINTEXT
    candidates = [name for name in cipher.inputs if name != INPUT_KEY]
    if len(candidates) != 1:
        raise ValueError("Select a cipher with one data input")
    return candidates[0]


def _endpoints(cipher, candidate, checker, overrides):
    components = candidate.get("components_values") or {}
    data = _data_input(cipher)
    output = next(
        (
            component.id
            for component in reversed(cipher.all_components())
            if component.type == CIPHER_OUTPUT
        ),
        None,
    )
    if output is None:
        raise ValueError("Cipher has no cipher output component")
    boomerang = checker.startswith("boomerang_")
    linear = "linear" in checker and not checker.startswith("boomerang_")
    input_names = (
        [f"upper_{data}"]
        if boomerang
        else [f"{data}_o", data]
        if checker.startswith("linear_checker_")
        else [data, f"{data}_o"]
    )
    output_names = (
        [f"lower_{output}"]
        if boomerang
        else [f"{output}_o", output]
        if linear
        else [output, f"{output}_o"]
    )

    def value(names, label):
        if label in overrides:
            return overrides[label]
        for name in names:
            if name in components:
                return components[name]["value"]
        raise ValueError(f"Candidate has no {label}; supply it explicitly")

    input_label = (
        "input_trunc_diff"
        if "input_and_output_truncated" in checker or checker.startswith("truncated_")
        else "input_difference"
    )
    if checker.startswith("linear_checker_"):
        input_label = "input_mask"
    output_label = "output_mask" if linear else "output_difference"
    if "truncated_checker" in checker:
        output_label = (
            "output_trunc_diff"
            if "input_and_output_truncated" in checker
            else "output_difference"
        )
    return (
        input_label,
        value(input_names, input_label),
        output_label,
        value(output_names, output_label),
    )


def _normalized_value(value, label, width):
    if "mask" in label and label != "input_trunc_diff":
        return (
            value
            if isinstance(value, str)
            and set(value) <= {"0", "1"}
            and len(value) == width
            else format(
                int(value, 0) if isinstance(value, str) else int(value), f"0{width}b"
            )
        )
    if (
        "trunc" in label
        or isinstance(value, str)
        and set(value) <= {"0", "1", "?", "2"}
        and len(value) == width
    ):
        return value
    return int(value, 0) if isinstance(value, str) else int(value)


def _default_checker(cipher, model_type):
    keyed = INPUT_KEY in cipher.inputs
    if model_type == "boomerang":
        return (
            "boomerang_checker_for_block_cipher_single_key"
            if keyed
            else "boomerang_scalar"
        )
    if model_type == "xor_differential":
        return (
            "differential_truncated_checker_single_key"
            if keyed
            else "differential_checker_permutation"
        )
    if model_type == "xor_linear":
        return (
            "linear_checker_for_block_cipher_single_key"
            if keyed
            else "linear_checker_permutation"
        )
    if "differential_linear" in model_type:
        if keyed:
            return "differential_linear_checker_for_block_cipher_single_key"
        return "differential_linear_scalar"
    raise ValueError(
        "Select one of the available checkers explicitly for this model type"
    )


def _scalar_event(
    cipher, checker, first, second, trials, fixed_key, seed, exclude_returning_quartets
):
    data = _data_input(cipher)
    width = cipher.inputs_bit_size[cipher.inputs.index(data)]
    size = 1 << width
    exhaustive = trials == "exhaustive"
    if exhaustive and size > 1 << 16:
        raise ValueError("Exhaustive validation is limited to 16-bit data inputs")
    if not exhaustive and (not isinstance(trials, int) or trials <= 0):
        raise ValueError("trials must be a positive integer or 'exhaustive'")
    if INPUT_KEY in cipher.inputs and fixed_key is None:
        raise ValueError("Supply fixed_key for a keyed cipher")
    if any(name not in (data, INPUT_KEY) for name in cipher.inputs):
        raise NotImplementedError(
            "Supply a cipher with only data and optional key inputs"
        )
    inverse = cipher.cipher_inverse() if checker == "boomerang_scalar" else None

    def evaluate(target, value):
        arguments = [
            fixed_key if name == INPUT_KEY else value for name in target.inputs
        ]
        return int(target.evaluate(arguments))

    rng = random.Random(seed)
    inputs = range(size) if exhaustive else (rng.randrange(size) for _ in range(trials))
    successes = 0
    for x in inputs:
        y0 = evaluate(cipher, x)
        if checker == "linear_scalar":
            successes += ((x & first).bit_count() ^ (y0 & second).bit_count()) & 1 == 0
            continue
        y1 = evaluate(cipher, x ^ first)
        if checker == "differential_linear_scalar":
            successes += ((y0 ^ y1) & second).bit_count() % 2 == 0
            continue
        if checker == "differential_scalar":
            successes += y0 ^ y1 == second
            continue
        x2 = evaluate(inverse, y0 ^ second)
        x3 = evaluate(inverse, y1 ^ second)
        successes += x2 ^ x3 == first and (
            not exclude_returning_quartets or x2 not in (x, x ^ first)
        )
    total = size if exhaustive else trials
    return successes, total


def _confidence_interval(successes, trials, correlation):
    """Wilson two-sided 95% interval for a binomial event or correlation."""
    fraction = successes / trials
    z = 1.959963984540054
    denominator = 1 + z * z / trials
    center = (fraction + z * z / (2 * trials)) / denominator
    radius = (
        z
        * math.sqrt(fraction * (1 - fraction) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    lower, upper = center - radius, center + radius
    return (2 * lower - 1, 2 * upper - 1) if correlation else (lower, upper)


def validate_candidate(
    cipher,
    candidate,
    trials,
    fixed_key=None,
    seed=None,
    num_workers=1,
    checker=None,
    baseline="random_permutation",
    exclude_returning_quartets=False,
    **endpoints,
):
    """Measure a candidate's external event with an existing CLAASP checker.

    INPUT:

    - ``cipher`` -- original cipher object, before a search model removes its
      key schedule or splits it into upper and lower copies.
    - ``candidate`` -- SATISFIABLE trail dictionary returned by a CLAASP model.
    - ``trials`` -- positive number of random plaintexts, or ``'exhaustive'``
      for data inputs of at most 16 bits.
    - ``fixed_key`` -- actual key value for a keyed cipher.
    - ``seed`` -- reproducible random seed for sampled validation.
    - ``checker`` -- optional name of any experimental checker in
      ``claasp.cipher_modules.models.utils``. Ordinary XOR differential,
      XOR linear, differential-linear, and boomerang trails select one
      automatically; specialized events can pass endpoint overrides.
    - ``baseline`` -- ``'random_permutation'`` (default) or ``None``.
    - ``exclude_returning_quartets`` -- omit two-point boomerang returns.

    OUTPUT: event counts, measured probability or correlation, a matched
    baseline when available, and a 95% interval for sampled measurements.
    A zero sampled count is ``INCONCLUSIVE`` and includes a one-sided upper
    bound. An exhaustive count is exact for the selected cipher and key.
    Neither the candidate weight nor a selected witness is treated as an
    external probability.
    """
    if not isinstance(candidate, dict) or not candidate.get("components_values"):
        raise ValueError("candidate must contain a solved trail with components_values")
    if candidate.get("status", "SATISFIABLE") != "SATISFIABLE":
        raise ValueError("candidate must have SATISFIABLE status")
    model_type = candidate.get("model_type", "")
    checker = checker or _default_checker(cipher, model_type)
    if checker not in _CHECKERS and checker not in {
        "boomerang_scalar",
        "differential_scalar",
        "linear_scalar",
        "differential_linear_scalar",
    }:
        raise ValueError(f"Unknown candidate checker: {checker}")
    keyed = INPUT_KEY in cipher.inputs
    if checker in _CHECKERS and ("single_key" in checker) != keyed:
        raise ValueError("Checker and cipher key model do not match")
    if baseline not in (None, "random_permutation"):
        raise ValueError("baseline must be None or 'random_permutation'")
    data = _data_input(cipher)
    width = cipher.inputs_bit_size[cipher.inputs.index(data)]
    key_size = (
        cipher.inputs_bit_size[cipher.inputs.index(INPUT_KEY)]
        if INPUT_KEY in cipher.inputs
        else None
    )
    input_label, first, output_label, second = _endpoints(
        cipher, candidate, checker, endpoints
    )
    first = _normalized_value(first, input_label, width)
    second = _normalized_value(second, output_label, cipher.output_bit_size)
    if (
        checker
        in (
            "boomerang_scalar",
            "differential_scalar",
            "linear_scalar",
            "differential_linear_scalar",
        )
        or trials == "exhaustive"
        or width % 8
        or (key_size is not None and key_size % 8)
        or (key_size is not None and cipher.inputs.index(data) != 0)
    ):
        if checker in (
            "boomerang_scalar",
            "differential_scalar",
            "linear_scalar",
            "differential_linear_scalar",
        ):
            scalar = checker
        elif checker.startswith("boomerang_"):
            scalar = "boomerang_scalar"
        elif checker.startswith("linear_checker_"):
            scalar = "linear_scalar"
        elif checker.startswith("differential_linear_checker_"):
            scalar = "differential_linear_scalar"
        elif checker in (
            "differential_checker_permutation",
            "differential_truncated_checker_single_key",
        ):
            scalar = "differential_scalar"
        else:
            raise NotImplementedError(
                "This checker requires byte-aligned vectorized evaluation"
            )
        scalar_first = int(first, 2) if isinstance(first, str) else first
        scalar_second = int(second, 2) if isinstance(second, str) else second
        successes, total = _scalar_event(
            cipher,
            scalar,
            scalar_first,
            scalar_second,
            trials,
            fixed_key,
            seed,
            exclude_returning_quartets,
        )
        measure = (
            2 * successes / total - 1
            if scalar in ("linear_scalar", "differential_linear_scalar")
            else successes / total
        )
        checker_used = scalar
    else:
        if not isinstance(trials, int) or trials <= 0:
            raise ValueError("trials must be a positive integer or 'exhaustive'")
        parameters = {
            input_label: first,
            output_label: second,
            "number_of_samples": trials,
            "seed": seed,
            "num_workers": num_workers,
        }
        if INPUT_KEY in cipher.inputs:
            if fixed_key is None:
                raise ValueError("Supply fixed_key for a keyed cipher")
            parameters.update(fixed_key=fixed_key, key_size=key_size)
            parameters[
                "state_size" if "truncated_checker" in checker else "block_size"
            ] = width
        else:
            parameters["state_size"] = width
        if checker == "differential_truncated_checker_single_key" and isinstance(
            second, int
        ):
            parameters[output_label] = format(second, f"0{width}b")
        if checker == "boomerang_checker_for_block_cipher_single_key":
            parameters["exclude_returning_quartets"] = exclude_returning_quartets
            parameters["return_counts"] = True
        measured = _CHECKERS[checker](cipher, **parameters)
        if (
            checker.startswith("linear_checker_")
            or "differential_linear_checker" in checker
        ):
            measure = measured
            successes = round((measured + 1) * trials / 2)
        elif checker.startswith("boomerang_"):
            successes, total = measured
            measure = successes / total
        else:
            measure = 0.0 if measured == float("-inf") else 2**measured
            successes = round(measure * trials)
        total = trials
        checker_used = checker
    correlation = (
        checker_used in ("linear_scalar", "differential_linear_scalar")
        or checker_used.startswith("linear_checker_")
        or "differential_linear_checker" in checker_used
    )
    result = {
        "checker": checker_used,
        input_label: first,
        output_label: second,
        "successes": successes,
        "trials": total,
        "observed_correlation" if correlation else "observed_probability": measure,
        "status": "EXACT"
        if trials == "exhaustive"
        else "MEASURED"
        if successes
        else "INCONCLUSIVE",
        "sampling": "exhaustive" if trials == "exhaustive" else "random_plaintexts",
        "confidence_interval_95": None
        if trials == "exhaustive"
        else _confidence_interval(successes, total, correlation),
    }
    if baseline == "random_permutation":
        size = 1 << width
        if correlation:
            trivial_linear = (
                checker_used
                in (
                    "linear_scalar",
                    "linear_checker_permutation",
                    "linear_checker_for_block_cipher_single_key",
                )
                and not int(first, 2)
                and not int(second, 2)
            )
            trivial_differential_linear = "differential_linear" in checker_used and (
                first == 0 or not int(second, 2)
            )
            result["baseline_correlation"] = float(
                trivial_linear or trivial_differential_linear
            )
        elif checker_used.startswith("boomerang_"):
            if not first or not second:
                result["baseline_probability"] = float(not exclude_returning_quartets)
            elif size > 3:
                result["baseline_probability"] = (size - 2) / (
                    (size - 1) * (size - 3)
                ) + (0 if exclude_returning_quartets else 1 / (size - 1))
        elif checker_used in (
            "differential_scalar",
            "differential_checker_permutation",
            "differential_truncated_checker_single_key",
        ):
            result["baseline_probability"] = (
                1.0
                if first == second == 0
                else 0.0
                if not first or not second
                else 1 / (size - 1)
            )
    baseline_value = result.get(
        "baseline_correlation", result.get("baseline_probability")
    )
    if baseline_value is not None:
        result["advantage"] = measure - baseline_value
    if trials != "exhaustive" and successes == 0:
        bound = -math.expm1(math.log(0.05) / total)
        result["one_sided_upper_bound_95"] = 2 * bound - 1 if correlation else bound
    return result


class CandidateValidationMixin:
    """Expose the same candidate-validation method on every model backend."""

    def validate_candidate(self, candidate, trials, **options):
        """Measure a solved candidate's event on the original cipher.

        For a small permutation, ``model.validate_candidate(candidate,
        trials='exhaustive')`` returns an exact external count. See
        :func:`validate_candidate` for sampling, keys, checkers, and fields.
        """
        cipher = getattr(self, "original_cipher", self._validation_cipher)
        return validate_candidate(cipher, candidate, trials, **options)
