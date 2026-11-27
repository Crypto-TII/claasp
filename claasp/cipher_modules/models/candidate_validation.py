"""Measure external events selected by CLAASP trail-search models.

This module keeps solver weights separate from empirical measurements. It
reuses the existing vectorized checkers where their input restrictions hold,
and uses scalar evaluation for small, non-byte-aligned ciphers.
"""

import math
import random
from itertools import islice
from operator import index
from types import ModuleType

import numpy as np

from claasp.cipher_modules import code_generator
from claasp.cipher_modules.models import utils
from claasp.name_mappings import CIPHER_OUTPUT, INPUT_KEY, INPUT_PLAINTEXT

_CHECKERS = {
    name: getattr(utils, name)
    for name in (
        "boomerang_checker_for_block_cipher_single_key",
        "boomerang_checker_for_permutation",
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
            else "boomerang_checker_for_permutation"
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
    cipher, checker, first, second, trials, fixed_key, seed, exclude_returning_quartets,
    inverse_cipher,
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
    inverse = inverse_cipher
    if checker == "boomerang_scalar" and inverse is None:
        inverse = cipher.cipher_inverse()
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


def _boomerang_inputs(width, trials, seed, fixed_input_bits, alpha):
    """Sample the free data bits, or enumerate a small restricted input space."""
    if fixed_input_bits is None:
        if width <= 63:
            return _scalar_inputs(1 << width, trials, seed), None
        mask = value = 0
        scope = "initial_pair"
    else:
        if set(fixed_input_bits) != {"mask", "value", "scope"}:
            raise ValueError("fixed_input_bits needs mask, value, and scope")
        mask = _as_int(fixed_input_bits["mask"])
        value = _as_int(fixed_input_bits["value"])
        scope = fixed_input_bits["scope"]
        if scope not in ("initial_pair", "quartet"):
            raise ValueError("scope must be 'initial_pair' or 'quartet'")
        if not 0 <= mask < 1 << width or not 0 <= value < 1 << width or value & ~mask:
            raise ValueError("fixed input mask or value does not fit the data input")
        if alpha & mask:
            raise ValueError("input_pair_difference changes fixed input bits")
    free_positions = [i for i in range(width) if not (mask >> i) & 1]
    free_size = 1 << len(free_positions)
    if trials == "exhaustive":
        if len(free_positions) > 16:
            raise ValueError("Exhaustive validation is limited to 16 free input bits")
        choices, total = range(free_size), free_size
    else:
        if not isinstance(trials, int) or trials <= 0:
            raise ValueError("trials must be a positive integer or 'exhaustive'")
        rng = random.Random(int(seed) if seed is not None else None)
        choices, total = (rng.getrandbits(len(free_positions)) for _ in range(trials)), trials
    def expand(choice):
        return value | sum(((choice >> j) & 1) << i for j, i in enumerate(free_positions))
    return (map(expand, choices), total), (mask, value, scope)


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
    return _boomerang_endpoint_matches(
        x, x ^ first, x2, x3, first, exclude_returning_quartets,
    )


def _boomerang_endpoint_matches(x1, x2, x3, x4, alpha, exclude_returns):
    """Apply one endpoint predicate in both scalar validation paths."""
    return (not exclude_returns or x3 not in (x1, x2)) and x3 ^ x4 == alpha


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


def _scalar_measure(cipher, checker, first, second, trials, fixed_key, seed, exclude, inverse_cipher):
    scalar = _scalar_checker(checker)
    scalar_first = int(first, 2) if isinstance(first, str) else first
    scalar_second = int(second, 2) if isinstance(second, str) else second
    successes, total = _scalar_event(
        cipher, scalar, scalar_first, scalar_second, trials, fixed_key, seed,
        exclude, inverse_cipher,
    )
    measure = successes / total
    if scalar in ("linear_scalar", "differential_linear_scalar"):
        measure = 2 * measure - 1
    return scalar, successes, total, measure


def _checker_parameters(
    cipher, checker, labels, values, trials, fixed_key, seed, num_workers,
    width, key_size, exclude, inverse_cipher,
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
    if checker in (
        "boomerang_checker_for_block_cipher_single_key",
        "boomerang_checker_for_permutation",
    ):
        parameters["exclude_returning_quartets"] = exclude
        parameters["return_counts"] = True
    if checker == "boomerang_checker_for_permutation" and inverse_cipher is not None:
        parameters["inverse_cipher"] = inverse_cipher
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


def _candidate_score_kind(candidate):
    model_type = candidate.get("model_type", "")
    weight_type = candidate.get("weight_type")
    if weight_type == "outer_characteristic_weight":
        return None
    if model_type == "boomerang":
        if weight_type == "local_characteristic_weight_estimate":
            return "probability"
        return None
    if model_type == "xor_differential":
        return "probability"
    if model_type == "xor_linear" or "differential_linear" in model_type:
        return "absolute_correlation"
    return None


def _add_candidate_comparison(result, candidate):
    raw_weight = candidate.get("total_weight")
    if raw_weight is None:
        return result
    try:
        weight = float(raw_weight)
    except (TypeError, ValueError):
        return result
    comparison = {
        "reported_weight_bits": weight,
        "weight_type": candidate.get("weight_type", "unspecified"),
    }
    result["candidate_comparison"] = comparison
    if not math.isfinite(weight) or weight < 0:
        comparison["reason"] = "reported weight is not finite and nonnegative"
        return result
    kind = _candidate_score_kind(candidate)
    if kind is None:
        comparison["reason"] = "the score does not estimate the complete event"
        return result
    comparison["quantity"] = kind
    comparison["scope"] = "single-trail score versus full external event"
    comparison["implied_trail_value"] = 2 ** -weight if weight <= 1074 else None
    if result["status"] == "INCONCLUSIVE":
        comparison["reason"] = "zero sampled successes do not determine the event probability"
        return result
    observed = result.get("observed_probability")
    if kind == "absolute_correlation":
        observed = abs(result["observed_correlation"])
    comparison["observed_external_value"] = observed
    if comparison["implied_trail_value"] is None:
        comparison["reason"] = "implied trail value below float range; compare bit weights"
    else:
        comparison["observed_minus_implied_value"] = observed - comparison["implied_trail_value"]
    if observed > 0:
        observed_weight = -math.log2(observed)
        comparison["observed_external_weight_bits"] = observed_weight
        comparison["observed_minus_reported_weight_bits"] = observed_weight - weight
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
    inverse_cipher=None,
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
    When the candidate has a meaningful trail weight, the result also
    reports the numerical gap between its implied trail value and the
    measured full external event. This is a diagnostic, not a full-event
    probability estimate from the solver score.
    Sampled zero counts are marked ``INCONCLUSIVE`` with a one-sided bound.
    Set ``exclude_returning_quartets=True`` to omit two-point boomerang
    returns. Set ``baseline=None`` to omit the comparison.
    Set ``inverse_cipher`` when the keyless permutation's inverse must be
    supplied explicitly.
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
            exclude_returning_quartets, inverse_cipher,
        )
    else:
        if not isinstance(trials, int) or trials <= 0:
            raise ValueError("trials must be a positive integer or 'exhaustive'")
        parameters = _checker_parameters(
            cipher, checker, labels, values, trials, fixed_key, seed,
            num_workers, width, key_size, exclude_returning_quartets,
            inverse_cipher,
        )
        measured = _vectorized_measure(cipher, checker, parameters, trials)
    checker_used, successes, total, measure = measured
    result = _measurement_result(
        checker_used, labels, values, successes, total, measure,
        trials == "exhaustive",
    )
    result = _add_baseline_and_bound(
        result, baseline, width, exclude_returning_quartets
    )
    return _add_candidate_comparison(result, candidate)


def _compiled_component_evaluator(cipher):
    """Compile one evaluator and retain every physical component output."""
    module = ModuleType("boomerang_characteristic_evaluator")
    exec(code_generator.generate_python_code_string(cipher), module.__dict__)

    def evaluate(inputs):
        output, _, component_io = module.evaluate(inputs)
        trace = dict(zip(cipher.inputs, inputs))
        trace.update((name, values[1]) for name, values in component_io.items())
        return int(output), trace

    return evaluate


def _compiled_vectorized_component_evaluator(cipher, constraints):
    """Compile a batch evaluator returning only retained component values."""
    names = sorted({physical for _, physical, _ in constraints})
    code = code_generator.generate_byte_based_vectorized_python_code_string(cipher)
    lines = code.splitlines()
    terminal = lines.pop()
    if not terminal.startswith("  return "):
        raise ValueError("Unexpected vectorized evaluator output")
    values = ", ".join(f"{name!r}: {name}" for name in names)
    lines.append(f"  return {terminal[len('  return '):]}, {{{values}}}")
    module = ModuleType("boomerang_vectorized_trail_evaluator")
    exec("\n".join(lines), module.__dict__)

    def evaluate(inputs):
        return module.evaluate(inputs, False)

    return evaluate


def _vectorized_trail_matches(cipher, evaluator, constraints, states, key_bytes):
    """Check retained differences on a batch of four-path executions."""
    size = states[0].shape[1]
    combined = np.concatenate(states, axis=1)
    key = None if key_bytes is None else np.repeat(key_bytes[:, None], 4 * size, axis=1)
    arguments = [key if name == INPUT_KEY else combined for name in cipher.inputs]
    _, traces = evaluator(arguments)
    matched = np.ones(size, dtype=bool)
    for side, physical, expected in constraints:
        values = traces[physical]
        if values.shape[1] == 1:
            values = np.broadcast_to(values, (values.shape[0], 4 * size))
        first, second, third, fourth = np.split(values, 4, axis=1)
        target = np.frombuffer(expected.to_bytes(values.shape[0], "big"), dtype=np.uint8)[:, None]
        pairs = ((first, second), (third, fourth)) if side == "upper" else (
            (first, third), (second, fourth))
        for left, right in pairs:
            matched &= np.all((left ^ right) == target, axis=0)
        if not np.any(matched):
            break
    return int(np.count_nonzero(matched))


def _boomerang_characteristic_constraints(cipher, candidate):
    """Parse retained physical differences without dropping unknown fields."""
    widths = dict(zip(cipher.inputs, cipher.inputs_bit_size))
    widths.update((component.id, component.output_bit_size)
                  for component in cipher.all_components())
    components = candidate.get("components_values") or {}
    if not components:
        raise ValueError("candidate must contain component differences")
    constraints = []
    for name, item in components.items():
        if name.startswith("upper_"):
            side, physical = "upper", name[len("upper_"):]
        elif name.startswith("lower_"):
            side, physical = "lower", name[len("lower_"):]
        else:
            raise ValueError(f"Not an upper/lower physical difference: {name}")
        if physical not in widths:
            raise ValueError(f"Unknown physical component: {physical}")
        value = _as_int(item["value"])
        if not 0 <= value < 1 << widths[physical]:
            raise ValueError(f"Difference does not fit {physical}")
        constraints.append((side, physical, value))
    return constraints


def _matches_boomerang_characteristic(traces, constraints):
    """Require each retained difference on both copies of its path."""
    for side, physical, expected in constraints:
        pairs = ((0, 1), (2, 3)) if side == "upper" else ((0, 2), (1, 3))
        if any(traces[a][physical] ^ traces[b][physical] != expected
               for a, b in pairs):
            return False
    return True


def _boomerang_measurement(count, trials, exhaustive):
    result = {"successes": count, "probability": count / trials,
              "status": _measurement_status(exhaustive, count),
              "confidence_interval_95": None}
    if not exhaustive:
        result["confidence_interval_95"] = _confidence_interval(count, trials, False)
        if count == 0:
            result["one_sided_upper_bound_95"] = -math.expm1(math.log(0.05) / trials)
    return result


def _enforce_fixed_return_bits(matches, returned_first, returned_second, fixed_bits):
    """Keep quartet successes whose returned inputs satisfy fixed data bits."""
    if fixed_bits is None or fixed_bits[2] != "quartet":
        return matches
    mask, value, _ = fixed_bits
    for j in np.flatnonzero(matches):
        x3 = int.from_bytes(returned_first[j].tobytes(), "big")
        x4 = int.from_bytes(returned_second[j].tobytes(), "big")
        if x3 & mask != value or x4 & mask != value:
            matches[j] = False
    return matches


def _vectorized_boomerang_counts(
    cipher, inverse, inputs, width, total, alpha, beta, fixed_key,
    fixed_bits, exclude_returns, constraints,
):
    """Batch endpoint tests and trace only successful quartets."""
    byte_width = width // 8
    alpha_bytes = np.frombuffer(alpha.to_bytes(byte_width, "big"), dtype=np.uint8)
    beta_bytes = np.frombuffer(beta.to_bytes(byte_width, "big"), dtype=np.uint8)
    key_bytes = None
    if fixed_key is not None:
        key_width = cipher.inputs_bit_size[cipher.inputs.index(INPUT_KEY)] // 8
        key_bytes = np.frombuffer(fixed_key.to_bytes(key_width, "big"), dtype=np.uint8)
    trail_evaluate = (_compiled_vectorized_component_evaluator(cipher, constraints)
                      if constraints is not None else None)
    differential_count = trail_count = 0
    batch_size = max(1, min(4096, 65536 // byte_width))
    for _ in range(0, total, batch_size):
        batch = list(islice(inputs, batch_size))
        if not batch:
            break
        size = len(batch)
        state = np.frombuffer(
            b"".join(x.to_bytes(byte_width, "big") for x in batch),
            dtype=np.uint8,
        ).reshape(size, byte_width).T
        state_pair = state ^ alpha_bytes[:, None]
        key = None if key_bytes is None else np.repeat(key_bytes[:, None], size, axis=1)
        first_args = [key if name == INPUT_KEY else state for name in cipher.inputs]
        second_args = [key if name == INPUT_KEY else state_pair for name in cipher.inputs]
        first_output = cipher.evaluate_vectorized(first_args)[0]
        second_output = cipher.evaluate_vectorized(second_args)[0]
        first_cross = (first_output ^ beta_bytes).T
        second_cross = (second_output ^ beta_bytes).T
        first_inverse_args = [key if name == INPUT_KEY else first_cross for name in inverse.inputs]
        second_inverse_args = [key if name == INPUT_KEY else second_cross for name in inverse.inputs]
        returned_first = inverse.evaluate_vectorized(first_inverse_args)[0]
        returned_second = inverse.evaluate_vectorized(second_inverse_args)[0]
        matches = np.all((returned_first ^ returned_second) == alpha_bytes, axis=1)
        if exclude_returns:
            matches &= np.any(returned_first != state.T, axis=1)
            matches &= np.any(returned_first != state_pair.T, axis=1)
        matches = _enforce_fixed_return_bits(
            matches, returned_first, returned_second, fixed_bits,
        )
        successful = np.flatnonzero(matches)
        differential_count += len(successful)
        if constraints is None:
            continue
        if len(successful):
            states = (state[:, successful], state_pair[:, successful],
                      returned_first[successful].T, returned_second[successful].T)
            trail_count += _vectorized_trail_matches(
                cipher, trail_evaluate, constraints, states, key_bytes,
            )
    return differential_count, trail_count


def _scalar_boomerang_counts(
    cipher, inverse, inputs, alpha, beta, fixed_key, fixed_bits,
    exclude_returns, constraints,
):
    """Count endpoint and retained-trail events for exact or odd-width runs."""
    forward_evaluate = _compiled_component_evaluator(cipher)
    inverse_evaluate = _compiled_component_evaluator(inverse)
    differential_count = trail_count = 0
    for x in inputs:
        quartet, traces = _boomerang_quartet(
            cipher, inverse, forward_evaluate, inverse_evaluate,
            x, alpha, beta, fixed_key,
        )
        _, x2, x3, x4 = quartet
        if fixed_bits is not None and fixed_bits[2] == "quartet":
            mask, value, _ = fixed_bits
            if x3 & mask != value or x4 & mask != value:
                continue
        if not _boomerang_endpoint_matches(
            x, x2, x3, x4, alpha, exclude_returns,
        ):
            continue
        differential_count += 1
        if constraints is not None and _matches_boomerang_characteristic(traces, constraints):
            trail_count += 1
    return differential_count, trail_count


def _evaluation_arguments(cipher, value, fixed_key):
    """Use the graph's declared input order for data and fixed key."""
    return [fixed_key if name == INPUT_KEY else value for name in cipher.inputs]


def _boomerang_quartet(
    cipher, inverse, forward_evaluate, inverse_evaluate, x, alpha, beta, fixed_key,
):
    """Return four plaintexts and component traces, checking the inverse."""
    x2 = x ^ alpha
    y1, trace1 = forward_evaluate(_evaluation_arguments(cipher, x, fixed_key))
    y2, trace2 = forward_evaluate(_evaluation_arguments(cipher, x2, fixed_key))
    y3, y4 = y1 ^ beta, y2 ^ beta
    x3 = inverse_evaluate(_evaluation_arguments(inverse, y3, fixed_key))[0]
    x4 = inverse_evaluate(_evaluation_arguments(inverse, y4, fixed_key))[0]
    check3, trace3 = forward_evaluate(_evaluation_arguments(cipher, x3, fixed_key))
    check4, trace4 = forward_evaluate(_evaluation_arguments(cipher, x4, fixed_key))
    if (check3, check4) != (y3, y4):
        raise ValueError("Inverse does not match the forward cipher")
    return (x, x2, x3, x4), (trace1, trace2, trace3, trace4)


def _prepare_characteristic_request(cipher, candidate, trials, fixed_key, seed):
    """Validate the supported oracle and normalize Sage integer arguments."""
    if not isinstance(candidate, dict) or candidate.get("model_type") != "boomerang":
        raise ValueError("Expected a boomerang candidate")
    if candidate.get("status", "SATISFIABLE") != "SATISFIABLE":
        raise ValueError("Candidate must have SATISFIABLE status")
    if trials != "exhaustive":
        trials = index(trials)
    if seed is not None:
        seed = index(seed)
    if fixed_key is not None:
        fixed_key = _as_int(fixed_key)
    data, width, _ = _cipher_sizes(cipher)
    if any(name not in (data, INPUT_KEY) for name in cipher.inputs):
        raise NotImplementedError("Only a data input and optional key are supported")
    if INPUT_KEY in cipher.inputs and fixed_key is None:
        raise ValueError("Supply fixed_key for a keyed cipher")
    if fixed_key is not None and INPUT_KEY not in cipher.inputs:
        raise ValueError("This cipher has no key input")
    if fixed_key is not None:
        key_width = cipher.inputs_bit_size[cipher.inputs.index(INPUT_KEY)]
        if not 0 <= fixed_key < 1 << key_width:
            raise ValueError("fixed_key does not fit the key width")
    return width, trials, fixed_key, seed


def _add_local_model_estimate(result, candidate):
    """Label a local model value as an estimate, separate from measurement."""
    weight = candidate.get("total_weight")
    if candidate.get("weight_type") == "local_characteristic_weight_estimate" and weight is not None:
        weight = float(weight)
        if math.isfinite(weight) and weight >= 0:
            result["local_model_weight_bits"] = weight
            result["local_model_probability_estimate"] = 2 ** -weight
    return result


def validate_boomerang_trail(
    cipher, trail, trials, fixed_key=None, seed=None,
    exclude_returning_quartets=False, inverse_cipher=None, fixed_input_bits=None,
    include_trail=True,
):
    """Measure a boomerang differential and one retained trail.

    For fixed non-data inputs, choose a plaintext ``x`` and form
    ``x2=x xor alpha``, ``x3=E^-1(E(x) xor beta)``, and
    ``x4=E^-1(E(x2) xor beta)``. The external event is
    ``x3 xor x4=alpha``. A trail occurrence additionally requires
    every listed ``upper_`` component difference on both upper pairs and
    every listed ``lower_`` difference on both cross pairs. This is an
    exact four-execution event; it does not multiply local probabilities.

    INPUT:

    - ``cipher`` -- CLAASP permutation or fixed-key block cipher with one
      data input and, optionally, a key input.
    - ``trail`` -- solved boomerang dictionary with ``components_values``
      containing physical upper/lower component differences and endpoints.
    - ``trials`` -- positive sample count with replacement, or
      ``'exhaustive'`` for at most 16 data bits.
    - ``fixed_key`` -- required key value for keyed ciphers.
    - ``seed`` -- optional random seed for reproducible sampling.
    - ``exclude_returning_quartets`` -- omit two-point returns when True.
    - ``inverse_cipher`` -- optional compatible inverse when CLAASP cannot
      construct one automatically.
    - ``fixed_input_bits`` -- optional dictionary with integer ``mask`` and
      ``value`` and ``scope`` set to ``'initial_pair'`` or ``'quartet'``.
      Fixed bits are excluded from the sampled input space; quartet scope
      additionally requires both returned plaintexts to retain them.
    - ``include_trail`` -- check internal trail conditions when True; endpoint
      only when False. The model's endpoint methods set this automatically.

    OUTPUT: dictionary with differential and retained-trail counts,
    exact when exhaustive, or sample rates and two-sided Wilson 95%
    intervals. A zero sample count also has a one-sided 95% upper bound.
    The random-permutation baseline is reported for the external event.
    Results refer to the fixed key and specified differences; they are not
    all-key guarantees. Fix the trail before drawing the random sample;
    reusing data that selected it invalidates the nominal interval coverage.
    The local weight is included only as a separate
    estimate. Dependence between the four paths can make it inaccurate;
    see Kidmose and Tiessen, *A Formal Analysis
    of Boomerang Probabilities*, ToSC 2022, DOI 10.46586/tosc.v2022.i1.88-109.

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: from claasp.cipher_modules.models.candidate_validation import validate_boomerang_trail
        sage: toy = Cipher('tiny', 'permutation', ['plaintext'], [4], 4)
        sage: toy.add_round()
        sage: _ = toy.add_cipher_output_component(['plaintext'], [list(range(4))], 4)
        sage: trail = {'model_type': 'boomerang', 'components_values': {
        ....:     'upper_plaintext': {'value': '0x1'},
        ....:     'lower_cipher_output_0_0': {'value': '0x1'}}}
        sage: result = validate_boomerang_trail(toy, trail, 'exhaustive')
        sage: (result['differential']['successes'], result['trail']['successes'])
        (16, 16)
    """
    width, trials, fixed_key, seed = _prepare_characteristic_request(
        cipher, trail, trials, fixed_key, seed
    )
    _, alpha_raw, _, beta_raw = _endpoints(cipher, trail, "boomerang_scalar", {})
    alpha, beta = _as_int(alpha_raw), _as_int(beta_raw)
    if not 0 <= alpha < 1 << width or not 0 <= beta < 1 << cipher.output_bit_size:
        raise ValueError("External differences do not fit the cipher widths")
    constraints = _boomerang_characteristic_constraints(cipher, trail) if include_trail else None
    inverse = inverse_cipher if inverse_cipher is not None else cipher.cipher_inverse()
    (inputs, total), fixed_bits = _boomerang_inputs(
        width, trials, seed, fixed_input_bits, alpha,
    )
    key_width = (cipher.inputs_bit_size[cipher.inputs.index(INPUT_KEY)]
                 if INPUT_KEY in cipher.inputs else 0)
    if trials != "exhaustive" and width % 8 == 0 and key_width % 8 == 0:
        differential_count, trail_count = _vectorized_boomerang_counts(
            cipher, inverse, inputs, width, total, alpha, beta, fixed_key,
            fixed_bits, exclude_returning_quartets, constraints,
        )
    else:
        differential_count, trail_count = _scalar_boomerang_counts(
            cipher, inverse, inputs, alpha, beta, fixed_key, fixed_bits,
            exclude_returning_quartets, constraints,
        )
    exhaustive = trials == "exhaustive"
    result = {
        "input_difference": alpha, "output_difference": beta,
        "trials": total, "sampling": "exhaustive" if exhaustive else "random_plaintexts",
        "fixed_key": fixed_key, "seed": seed,
        "fixed_input_bits": fixed_input_bits,
        "exclude_returning_quartets": exclude_returning_quartets,
        "differential": _boomerang_measurement(differential_count, total, exhaustive),
    }
    if include_trail:
        result["trail"] = _boomerang_measurement(trail_count, total, exhaustive)
    baseline = None if fixed_input_bits is not None else _boomerang_baseline(
        alpha, beta, 1 << width, exclude_returning_quartets,
    )
    if baseline is not None:
        result["random_permutation_baseline_probability"] = baseline[1]
        result["differential_advantage_over_baseline"] = (
            result["differential"]["probability"] - baseline[1]
        )
    return _add_local_model_estimate(result, trail)


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
