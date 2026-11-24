"""Measure external events selected by CLAASP trail-search models.

This module keeps solver weights separate from empirical measurements. It
reuses the existing vectorized checkers where their input restrictions hold,
and uses scalar evaluation for small, non-byte-aligned ciphers.
"""

import math

import numpy as np

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


def _candidate_value(components, overrides, names, label):
    if label in overrides:
        return overrides[label]
    for name in names:
        if name in components:
            return components[name]["value"]
    raise ValueError(f"Candidate has no {label}; supply it explicitly")


def _endpoint_names(data, output, checker):
    if checker.startswith("boomerang_"):
        return [f"upper_{data}"], [f"lower_{output}"]
    if checker.startswith("linear_checker_"):
        input_names = [f"{data}_o", data]
    else:
        input_names = [data, f"{data}_o"]
    if "linear" in checker:
        output_names = [f"{output}_o", output]
    else:
        output_names = [output, f"{output}_o"]
    return input_names, output_names


def _endpoint_labels(checker):
    input_label = "input_difference"
    if "input_and_output_truncated" in checker or checker.startswith("truncated_"):
        input_label = "input_trunc_diff"
    if checker.startswith("linear_checker_"):
        input_label = "input_mask"
    output_label = "output_difference"
    if "linear" in checker and not checker.startswith("boomerang_"):
        output_label = "output_mask"
    if "input_and_output_truncated" in checker:
        output_label = "output_trunc_diff"
    return input_label, output_label


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
    input_names, output_names = _endpoint_names(data, output, checker)
    input_label, output_label = _endpoint_labels(checker)
    return (
        input_label,
        _candidate_value(components, overrides, input_names, input_label),
        output_label,
        _candidate_value(components, overrides, output_names, output_label),
    )


def _normalized_value(value, label, width):
    if "mask" in label and label != "input_trunc_diff":
        if isinstance(value, str) and set(value) <= {"0", "1"} and len(value) == width:
            return value
        return format(_as_int(value), f"0{width}b")
    if (
        "trunc" in label
        or isinstance(value, str)
        and set(value) <= {"0", "1", "?", "2"}
        and len(value) == width
    ):
        return value
    return _as_int(value)


def _as_int(value):
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


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
    if INPUT_KEY in cipher.inputs and fixed_key is None:
        raise ValueError("Supply fixed_key for a keyed cipher")
    if any(name not in (data, INPUT_KEY) for name in cipher.inputs):
        raise NotImplementedError(
            "Supply a cipher with only data and optional key inputs"
        )
    inverse = cipher.cipher_inverse() if checker == "boomerang_scalar" else None
    inputs, total = _scalar_inputs(size, trials, seed)
    successes = sum(
        _scalar_match(
            cipher, inverse, checker, x, first, second, fixed_key,
            exclude_returning_quartets,
        )
        for x in inputs
    )
    return successes, total


def _scalar_inputs(size, trials, seed):
    if trials == "exhaustive":
        if size > 1 << 16:
            raise ValueError("Exhaustive validation is limited to 16-bit data inputs")
        return range(size), size
    if not isinstance(trials, int) or trials <= 0:
        raise ValueError("trials must be a positive integer or 'exhaustive'")
    rng = np.random.default_rng(seed)
    return (int(rng.integers(size)) for _ in range(trials)), trials


def _fixed_key_evaluate(cipher, value, fixed_key):
    arguments = [fixed_key if name == INPUT_KEY else value for name in cipher.inputs]
    return int(cipher.evaluate(arguments))


def _scalar_match(
    cipher, inverse, checker, x, first, second, fixed_key,
    exclude_returning_quartets,
):
    y0 = _fixed_key_evaluate(cipher, x, fixed_key)
    if checker == "linear_scalar":
        return ((x & first).bit_count() ^ (y0 & second).bit_count()) & 1 == 0
    y1 = _fixed_key_evaluate(cipher, x ^ first, fixed_key)
    if checker == "differential_linear_scalar":
        return ((y0 ^ y1) & second).bit_count() % 2 == 0
    if checker == "differential_scalar":
        return y0 ^ y1 == second
    x2 = _fixed_key_evaluate(inverse, y0 ^ second, fixed_key)
    x3 = _fixed_key_evaluate(inverse, y1 ^ second, fixed_key)
    if exclude_returning_quartets and x2 in (x, x ^ first):
        return False
    return x2 ^ x3 == first


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


_SCALAR_CHECKERS = {
    "boomerang_scalar",
    "differential_scalar",
    "linear_scalar",
    "differential_linear_scalar",
}


def _validate_request(cipher, candidate, checker, baseline):
    if not isinstance(candidate, dict) or not candidate.get("components_values"):
        raise ValueError("candidate must contain a solved trail with components_values")
    if candidate.get("status", "SATISFIABLE") != "SATISFIABLE":
        raise ValueError("candidate must have SATISFIABLE status")
    if checker not in _CHECKERS and checker not in _SCALAR_CHECKERS:
        raise ValueError(f"Unknown candidate checker: {checker}")
    if checker in _CHECKERS and ("single_key" in checker) != (INPUT_KEY in cipher.inputs):
        raise ValueError("Checker and cipher key model do not match")
    if baseline not in (None, "random_permutation"):
        raise ValueError("baseline must be None or 'random_permutation'")


def _cipher_sizes(cipher):
    data = _data_input(cipher)
    width = cipher.inputs_bit_size[cipher.inputs.index(data)]
    key_size = None
    if INPUT_KEY in cipher.inputs:
        key_size = cipher.inputs_bit_size[cipher.inputs.index(INPUT_KEY)]
    return data, width, key_size


def _uses_scalar(cipher, checker, trials, data, width, key_size):
    if checker in _SCALAR_CHECKERS or trials == "exhaustive" or width % 8:
        return True
    if key_size is None:
        return False
    return bool(key_size % 8 or cipher.inputs.index(data) != 0)


def _scalar_checker(checker):
    if checker in _SCALAR_CHECKERS:
        return checker
    if checker.startswith("boomerang_"):
        return "boomerang_scalar"
    if checker.startswith("linear_checker_"):
        return "linear_scalar"
    if checker.startswith("differential_linear_checker_"):
        return "differential_linear_scalar"
    if checker in ("differential_checker_permutation", "differential_truncated_checker_single_key"):
        return "differential_scalar"
    raise NotImplementedError("This checker requires byte-aligned vectorized evaluation")


def _scalar_measure(cipher, checker, first, second, trials, fixed_key, seed, exclude):
    scalar = _scalar_checker(checker)
    scalar_first = int(first, 2) if isinstance(first, str) else first
    scalar_second = int(second, 2) if isinstance(second, str) else second
    successes, total = _scalar_event(
        cipher, scalar, scalar_first, scalar_second, trials, fixed_key, seed, exclude
    )
    measure = successes / total
    if scalar in ("linear_scalar", "differential_linear_scalar"):
        measure = 2 * measure - 1
    return scalar, successes, total, measure


def _checker_parameters(
    cipher, checker, labels, values, trials, fixed_key, seed, num_workers,
    width, key_size, exclude,
):
    input_label, output_label = labels
    first, second = values
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
        size_label = "block_size"
        if "truncated_checker" in checker:
            size_label = "state_size"
        parameters[size_label] = width
    else:
        parameters["state_size"] = width
    if checker == "differential_truncated_checker_single_key" and isinstance(second, int):
        parameters[output_label] = format(second, f"0{width}b")
    if checker == "boomerang_checker_for_block_cipher_single_key":
        parameters["exclude_returning_quartets"] = exclude
        parameters["return_counts"] = True
    return parameters


def _is_correlation(checker):
    return (
        checker in ("linear_scalar", "differential_linear_scalar")
        or checker.startswith("linear_checker_")
        or "differential_linear_checker" in checker
    )


def _vectorized_measure(cipher, checker, parameters, trials):
    measured = _CHECKERS[checker](cipher, **parameters)
    if _is_correlation(checker):
        return checker, round((measured + 1) * trials / 2), trials, measured
    if checker.startswith("boomerang_"):
        successes, total = measured
        return checker, successes, total, successes / total
    measure = 0.0
    if measured != float("-inf"):
        measure = 2**measured
    return checker, round(measure * trials), trials, measure


def _measurement_status(exhaustive, successes):
    if exhaustive:
        return "EXACT"
    if successes:
        return "MEASURED"
    return "INCONCLUSIVE"


def _measurement_result(checker, labels, values, successes, total, measure, exhaustive):
    input_label, output_label = labels
    first, second = values
    correlation = _is_correlation(checker)
    result = {
        "checker": checker,
        input_label: first,
        output_label: second,
        "successes": successes,
        "trials": total,
        "status": _measurement_status(exhaustive, successes),
        "sampling": "exhaustive" if exhaustive else "random_plaintexts",
        "confidence_interval_95": None,
    }
    result["observed_correlation" if correlation else "observed_probability"] = measure
    if not exhaustive:
        result["confidence_interval_95"] = _confidence_interval(successes, total, correlation)
    return result


def _correlation_baseline(checker, first, second):
    simple_linear = checker in (
        "linear_scalar", "linear_checker_permutation",
        "linear_checker_for_block_cipher_single_key",
    )
    trivial_linear = simple_linear and not int(first, 2) and not int(second, 2)
    trivial_pair = "differential_linear" in checker and (
        first == 0 or not int(second, 2)
    )
    return "baseline_correlation", float(trivial_linear or trivial_pair)


def _boomerang_baseline(first, second, size, exclude):
    if not first or not second:
        return "baseline_probability", float(not exclude)
    if size <= 3:
        return None
    value = (size - 2) / ((size - 1) * (size - 3))
    if not exclude:
        value += 1 / (size - 1)
    return "baseline_probability", value


def _differential_baseline(first, second, size):
    if first == second == 0:
        return "baseline_probability", 1.0
    if not first or not second:
        return "baseline_probability", 0.0
    return "baseline_probability", 1 / (size - 1)


def _random_baseline(checker, first, second, width, exclude):
    size = 1 << width
    if _is_correlation(checker):
        return _correlation_baseline(checker, first, second)
    if checker.startswith("boomerang_"):
        return _boomerang_baseline(first, second, size, exclude)
    if checker in (
        "differential_scalar", "differential_checker_permutation",
        "differential_truncated_checker_single_key",
    ):
        return _differential_baseline(first, second, size)
    return None


def _add_baseline_and_bound(result, baseline, width, exclude):
    checker = result["checker"]
    first = result.get("input_mask", result.get("input_difference"))
    second = result.get("output_mask", result.get("output_difference"))
    measure = result.get("observed_correlation", result.get("observed_probability"))
    if baseline == "random_permutation":
        reference = _random_baseline(checker, first, second, width, exclude)
        if reference is not None:
            label, value = reference
            result[label] = value
            result["advantage"] = measure - value
    if result["status"] == "INCONCLUSIVE":
        bound = -math.expm1(math.log(0.05) / result["trials"])
        if _is_correlation(checker):
            bound = 2 * bound - 1
        result["one_sided_upper_bound_95"] = bound
    return result


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
    """Measure a solved trail's external event independently of its solver weight.

    Pass a SATISFIABLE candidate from any CLAASP model and a positive sample
    count, or ``trials='exhaustive'`` for data inputs of at most 16 bits.
    Keyed ciphers require ``fixed_key``. A ``seed`` makes sampling repeatable.
    Ordinary differential, linear, differential-linear, and boomerang trails
    select an existing checker automatically. Select a specialized checker by
    name and provide endpoint overrides when its event needs them.

    The result contains successes, trials, a measured probability or
    correlation, and a random-permutation baseline where applicable.
    Sampled zero counts are marked ``INCONCLUSIVE`` with a one-sided bound.
    Set ``exclude_returning_quartets=True`` to omit two-point boomerang
    returns. Set ``baseline=None`` to omit the comparison.
    """
    if not isinstance(candidate, dict):
        raise TypeError("candidate must be a solved trail dictionary")
    checker = checker or _default_checker(cipher, candidate.get("model_type", ""))
    _validate_request(cipher, candidate, checker, baseline)
    data, width, key_size = _cipher_sizes(cipher)
    input_label, first, output_label, second = _endpoints(
        cipher, candidate, checker, endpoints
    )
    first = _normalized_value(first, input_label, width)
    second = _normalized_value(second, output_label, cipher.output_bit_size)
    labels = input_label, output_label
    values = first, second
    if _uses_scalar(cipher, checker, trials, data, width, key_size):
        measured = _scalar_measure(
            cipher, checker, first, second, trials, fixed_key, seed,
            exclude_returning_quartets,
        )
    else:
        if not isinstance(trials, int) or trials <= 0:
            raise ValueError("trials must be a positive integer or 'exhaustive'")
        parameters = _checker_parameters(
            cipher, checker, labels, values, trials, fixed_key, seed,
            num_workers, width, key_size, exclude_returning_quartets,
        )
        measured = _vectorized_measure(cipher, checker, parameters, trials)
    checker_used, successes, total, measure = measured
    result = _measurement_result(
        checker_used, labels, values, successes, total, measure,
        trials == "exhaustive",
    )
    return _add_baseline_and_bound(
        result, baseline, width, exclude_returning_quartets
    )


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
