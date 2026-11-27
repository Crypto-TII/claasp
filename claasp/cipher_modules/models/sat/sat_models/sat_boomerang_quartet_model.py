"""Count retained boomerang trails with four exact SAT cipher executions.

The construction extends the two-copy compound XOR cipher idea to four
executions. It uses the existing exact component SAT encoders, then counts
models projected onto the first data input. A local trail weight is not used.
"""

import math
import multiprocessing
import time
from copy import deepcopy
from queue import Empty

from claasp.cipher_modules.models.candidate_validation import (
    _boomerang_characteristic_constraints,
    _data_input,
)
from claasp.cipher_modules.models.sat.utils.utils import create_numerical_cnf
from claasp.name_mappings import CIPHER_OUTPUT, INPUT_KEY


def _bit(name, position):
    return f"{name}_{position}"


def _difference_clauses(left, right, value, width):
    """Fix the XOR of two MSB-first vectors without auxiliary variables."""
    clauses = []
    for position in range(width):
        a = _bit(left, position)
        b = _bit(right, position)
        if (value >> (width - position - 1)) & 1:
            clauses.extend((f"{a} {b}", f"-{a} -{b}"))
        else:
            clauses.extend((f"-{a} {b}", f"{a} -{b}"))
    return clauses


def _fixed_value_clauses(name, value, width):
    return [
        f"{'' if (value >> (width - position - 1)) & 1 else '-'}{_bit(name, position)}"
        for position in range(width)
    ]


def _nonzero_difference_clauses(left, right, width, prefix):
    """Require two vectors to differ at one or more bit positions."""
    indicators = [f"{prefix}_{bit}" for bit in range(width)]
    clauses = [" ".join(indicators)]
    for bit, indicator in enumerate(indicators):
        a, b = _bit(left, bit), _bit(right, bit)
        clauses.extend((f"-{indicator} {a} {b}",
                        f"-{indicator} -{a} -{b}",
                        f"{indicator} -{a} {b}",
                        f"{indicator} {a} -{b}"))
    return clauses


def _supported_component(component):
    from claasp.name_mappings import (
        CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN,
        PERMUTATION_COMPONENT, SBOX, WORD_OPERATION,
    )

    types = {CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER,
             MIX_COLUMN, PERMUTATION_COMPONENT, SBOX, WORD_OPERATION}
    operations = {"AND", "MODADD", "MODSUB", "NOT", "OR", "ROTATE",
                  "SHIFT", "SHIFT_BY_VARIABLE_AMOUNT", "XOR"}
    return (component.type in types
            and (component.type != WORD_OPERATION or component.description[0] in operations)
            and callable(getattr(component, "sat_constraints", None)))


def _count_worker(numeric, projection, epsilon, delta, seed, output):
    """Run the optional counter in a child so a time limit can stop it."""
    try:
        import pyapproxmc

        counter = pyapproxmc.Counter(seed=seed, epsilon=epsilon, delta=delta)
        for clause in numeric:
            counter.add_clause([int(literal) for literal in clause.split()])
        output.put(("ok", counter.count(projection)))
    except Exception as exc:  # Child exceptions must be reported to the caller.
        output.put(("error", repr(exc)))


def _check_supplied_inverse(cipher, inverse_cipher, data_width):
    """Check dimensions and deterministic round trips of a supplied inverse."""
    if (inverse_cipher.output_bit_size != data_width
            or inverse_cipher.inputs_bit_size != [data_width, *cipher.inputs_bit_size[1:]]):
        raise ValueError("Supplied inverse has incompatible input or output widths")
    probes = (0, 1, (1 << data_width) - 1,
              int("a5" * ((data_width + 7) // 8), 16) & ((1 << data_width) - 1))
    for key_value in (0, 1):
        extra_inputs = [key_value] if INPUT_KEY in cipher.inputs else []
        for plaintext in probes:
            ciphertext = cipher.evaluate([plaintext, *extra_inputs])
            if inverse_cipher.evaluate([ciphertext, *extra_inputs]) != plaintext:
                raise ValueError("Supplied inverse fails a deterministic round-trip check")


class SatBoomerangQuartetModel:
    """Build and count an exact retained trail on a CLAASP permutation.

    Four copies use the same key and non-data inputs. The upper differences
    connect copies (0,1) and (2,3); lower differences connect (0,2) and
    (1,3). See Kidmose and Tiessen, *A Formal Analysis of Boomerang
    Probabilities*, ToSC 2022(1), DOI 10.46586/tosc.v2022.i1.88-109.

    ``count`` requires the optional ``pyapproxmc`` package. ApproxMC gives
    a multiplicative ``1+epsilon`` counting tolerance with confidence
    ``1-delta``; this is distinct from a sampled plaintext confidence
    interval. The construction counts only first-input assignments and
    requires the cipher to be invertible for each fixed non-data input. A
    supplied inverse may certify an equivalent graph representation when
    CLAASP cannot construct an inverse of the searched graph. Deterministic
    round-trip probes reject obvious mismatches, but the caller must establish
    equivalence; these probes are not a proof.

    INPUT:

    - ``cipher`` -- a CLAASP cipher with one data input and optionally one
      key input, one equally sized output, and exact SAT component encoders.
    - ``inverse_cipher`` -- optional equivalent inverse graph. It must invert
      ``cipher`` for every input and fixed key, even if built from a different
      component representation.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.sat.sat_models.sat_boomerang_quartet_model import SatBoomerangQuartetModel
        sage: counter = SatBoomerangQuartetModel(SpeckBlockCipher(number_of_rounds=2))
        sage: counter.data_width
        32
    """

    def __init__(self, cipher, inverse_cipher=None):
        self.cipher = cipher
        self.data = _data_input(cipher)
        if any(name not in (self.data, INPUT_KEY) for name in cipher.inputs):
            raise NotImplementedError("Only one data input and an optional key are supported")
        self.data_width = cipher.inputs_bit_size[cipher.inputs.index(self.data)]
        outputs = [component for component in cipher.all_components()
                   if component.type == CIPHER_OUTPUT]
        if len(outputs) != 1 or outputs[0].output_bit_size != self.data_width:
            raise ValueError("Counting needs one output matching the data input size")
        self.output = outputs[0]
        for component in cipher.all_components():
            if not _supported_component(component):
                raise NotImplementedError(f"No exact SAT encoding for {component.id}")
        # The crossed output fixes the return input only for a bijection.
        if inverse_cipher is None:
            try:
                cipher.cipher_inverse()
            except (NotImplementedError, ValueError) as exc:
                raise ValueError("Counting needs a CLAASP-constructible inverse") from exc
        else:
            _check_supplied_inverse(cipher, inverse_cipher, self.data_width)

    def build(self, trail, fixed_key=None, fixed_input_bits=None,
              exclude_returning_quartets=False):
        """Return named CNF clauses, projected input bits and denominator bits.

        ``trail`` is a solved boomerang result with physical upper/lower
        differences. ``fixed_key`` is mandatory for keyed ciphers and absent
        for permutations. ``fixed_input_bits`` has ``mask``, ``value`` and
        ``scope`` (``'initial_pair'`` or ``'quartet'``), as in CLAASP's
        validator. With quartet scope, returned inputs must also keep those
        bits. ``exclude_returning_quartets`` requires the first and returned
        plaintexts to differ. The output is ``(clauses, projection,
        denominator_bits)``; no solver is run.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_boomerang_quartet_model import SatBoomerangQuartetModel
            sage: cipher = SpeckBlockCipher(number_of_rounds=2)
            sage: model = SatBoomerangQuartetModel(cipher)
            sage: trail = {'components_values': {'upper_plaintext': {'value': '0x1'}, 'lower_cipher_output_1_12': {'value': '0x1'}}}
            sage: clauses, projection, bits = model.build(trail, fixed_key=0)
            sage: len(projection), bits, bool(clauses)
            (32, 32, True)
        """
        keyed = INPUT_KEY in self.cipher.inputs
        if keyed != (fixed_key is not None):
            raise ValueError("Supply a fixed key exactly when the cipher has a key input")
        if keyed:
            fixed_key = int(fixed_key)
            key_width = self.cipher.inputs_bit_size[self.cipher.inputs.index(INPUT_KEY)]
            if not 0 <= fixed_key < 1 << key_width:
                raise ValueError("fixed_key does not fit the key width")
        differences = _boomerang_characteristic_constraints(self.cipher, trail)
        endpoints = {(side, name): value for side, name, value in differences}
        alpha = endpoints.get(("upper", self.data))
        beta = endpoints.get(("lower", self.output.id))
        if alpha is None or beta is None:
            raise ValueError("Trail needs upper input and lower output differences")
        mask, value, scope = self._fixed_bits(fixed_input_bits, alpha)
        widths = dict(zip(self.cipher.inputs, self.cipher.inputs_bit_size))
        widths.update((component.id, component.output_bit_size)
                      for component in self.cipher.all_components())
        clauses = []
        for execution in range(4):
            graph = deepcopy(self.cipher)
            graph.add_prefix(f"quartet_{execution}_")
            for component in graph.all_components():
                try:
                    _, encoded = component.sat_constraints()
                except (AttributeError, NotImplementedError) as exc:
                    raise NotImplementedError(f"No exact SAT encoding for {component.id}") from exc
                clauses.extend(encoded)
        if keyed:
            for execution in range(4):
                clauses.extend(_fixed_value_clauses(
                    f"quartet_{execution}_key", fixed_key, key_width,
                ))
        for side, name, expected in differences:
            pairs = ((0, 1), (2, 3)) if side == "upper" else ((0, 2), (1, 3))
            for left, right in pairs:
                clauses.extend(_difference_clauses(
                    f"quartet_{left}_{name}", f"quartet_{right}_{name}",
                    expected, widths[name],
                ))
        if fixed_input_bits is not None:
            executions = range(4) if scope == "quartet" else (0, 1)
            for execution in executions:
                name = f"quartet_{execution}_{self.data}"
                clauses.extend(
                    f"{'' if (value >> bit) & 1 else '-'}{_bit(name, self.data_width - bit - 1)}"
                    for bit in range(self.data_width) if (mask >> bit) & 1
                )
        if exclude_returning_quartets:
            for original in (0, 1):
                clauses.extend(_nonzero_difference_clauses(
                    f"quartet_{original}_{self.data}",
                    f"quartet_2_{self.data}", self.data_width,
                    f"quartet_return_difference_{original}",
                ))
        projection = [_bit(f"quartet_0_{self.data}", bit)
                      for bit in range(self.data_width) if not (mask >> (self.data_width - bit - 1)) & 1]
        return clauses, projection, self.data_width - mask.bit_count()

    def _fixed_bits(self, fixed_input_bits, alpha):
        if fixed_input_bits is None:
            return 0, 0, "initial_pair"
        if set(fixed_input_bits) != {"mask", "value", "scope"}:
            raise ValueError("fixed_input_bits needs mask, value, and scope")
        mask = int(fixed_input_bits["mask"])
        value = int(fixed_input_bits["value"])
        scope = fixed_input_bits["scope"]
        if scope not in ("initial_pair", "quartet"):
            raise ValueError("scope must be 'initial_pair' or 'quartet'")
        if not 0 <= mask < 1 << self.data_width or not 0 <= value < 1 << self.data_width or value & ~mask:
            raise ValueError("fixed input mask or value does not fit the data input")
        if alpha & mask:
            raise ValueError("input_pair_difference changes fixed input bits")
        return mask, value, scope

    def count(self, trail, fixed_key=None, fixed_input_bits=None,
              exclude_returning_quartets=False, epsilon=0.3, delta=0.05,
              seed=1, timeout_in_seconds=120):
        """Estimate the complete retained-trail probability by projected #SAT.

        Arguments are as in :meth:`build`. ``epsilon`` is the relative
        counting tolerance and ``delta`` the counter's failure probability;
        both must lie strictly between zero and one. ``seed`` makes the
        counter reproducible. ``timeout_in_seconds`` bounds the counting
        phase (default: 120); a timeout returns status ``TIMEOUT`` without a
        probability. Requires ``pyapproxmc`` installed in the Sage
        environment. A completed result includes the count, probability,
        base-two weight, settings and elapsed time. This is a fixed-key
        estimate for a block cipher, or a keyless estimate for a permutation;
        it is not a random-key mean or a plaintext sampling interval.

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_boomerang_quartet_model import SatBoomerangQuartetModel
            sage: toy = Cipher('identity', 'permutation', ['plaintext'], [4], 4)
            sage: toy.add_round()
            sage: _ = toy.add_cipher_output_component(['plaintext'], [list(range(4))], 4)
            sage: trail = {'components_values': {'upper_plaintext': {'value': '0x1'}, 'lower_cipher_output_0_0': {'value': '0x1'}}}
            sage: result = SatBoomerangQuartetModel(toy).count(trail)  # optional - pyapproxmc
            sage: result['probability']  # optional - pyapproxmc
            1.0
        """
        epsilon, delta, seed = float(epsilon), float(delta), int(seed)
        fixed_key = None if fixed_key is None else int(fixed_key)
        if fixed_input_bits is not None:
            if set(fixed_input_bits) != {"mask", "value", "scope"}:
                raise ValueError("fixed_input_bits needs mask, value, and scope")
            fixed_input_bits = {
                "mask": int(fixed_input_bits["mask"]),
                "value": int(fixed_input_bits["value"]),
                "scope": fixed_input_bits["scope"],
            }
        if not 0 < epsilon < 1 or not 0 < delta < 1:
            raise ValueError("epsilon and delta must lie strictly between zero and one")
        if timeout_in_seconds is not None and timeout_in_seconds <= 0:
            raise ValueError("timeout_in_seconds must be positive or None")
        try:
            import pyapproxmc  # noqa: F401 - check optional dependency before building
        except ImportError as exc:
            raise ImportError("Install pyapproxmc to count boomerang quartet solutions") from exc
        started = time.monotonic()
        clauses, projection, bits = self.build(
            trail, fixed_key=fixed_key, fixed_input_bits=fixed_input_bits,
            exclude_returning_quartets=exclude_returning_quartets,
        )
        names, numeric = create_numerical_cnf(clauses)
        ids = {name: i + 1 for i, name in enumerate(names)}
        missing = [name for name in projection if name not in ids]
        projection_ids = [ids[name] for name in projection if name in ids]
        context = multiprocessing.get_context(
            "fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn"
        )
        output = context.Queue()
        process = context.Process(
            target=_count_worker,
            args=(numeric, projection_ids, epsilon, delta, seed, output),
        )
        process.start()
        process.join(timeout_in_seconds)
        metadata = {
            "event": "retained_boomerang_trail",
            "method": "four_execution_projected_model_count",
            "fixed_key": fixed_key, "fixed_input_bits": fixed_input_bits,
            "exclude_returning_quartets": exclude_returning_quartets,
            "epsilon": epsilon, "delta": delta, "seed": seed,
            "timeout_in_seconds": timeout_in_seconds,
            "clauses": len(clauses), "variables": len(names),
        }
        if process.is_alive():
            process.terminate()
            process.join()
            output.close()
            return {**metadata, "status": "TIMEOUT", "probability": None,
                    "elapsed_seconds": time.monotonic() - started}
        try:
            outcome, payload = output.get(timeout=1)
        except Empty as exc:
            raise RuntimeError(
                f"ApproxMC process exited without a result: {process.exitcode}"
            ) from exc
        finally:
            output.close()
        if outcome != "ok":
            raise RuntimeError(f"ApproxMC failed: {payload}")
        base, exponent = payload
        approximate_count = (base << exponent) << len(missing)
        log2_probability = (math.log2(approximate_count) - bits
                            if approximate_count else None)
        probability = approximate_count / (1 << bits)
        return {
            **metadata, "status": "ESTIMATED",
            "approximate_count": approximate_count,
            "input_space_size": 1 << bits,
            "probability": probability,
            "probability_interval_at_confidence": [
                probability / (1 + epsilon), min(1.0, probability * (1 + epsilon))
            ],
            "confidence_at_least": 1 - delta,
            "log2_probability": log2_probability,
            "weight": -log2_probability if log2_probability is not None else None,
            "elapsed_seconds": time.monotonic() - started,
        }
