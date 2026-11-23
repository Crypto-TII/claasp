# ****************************************************************************
# Copyright 2026 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************

"""Empirical word-wise rotational distinguisher searches.

The evaluator is the same vectorized evaluator used by ``AvalancheTests``.
Instead of XORing a single-bit input difference, this module rotates every
word in one selected cipher input.  The partner output is rotated back before
the two outputs are compared, so each reported probability is

``Pr[F(A)[j] != F(R_n(A))[R_n(j)]]``.

The test is deliberately empirical.  A result identifies a reproducible
related-input bias; it does not prove why the bias exists or that the chosen
word partition is cryptographically meaningful for a particular cipher.
"""

import heapq
import math

import numpy as np

from claasp.cipher_modules import evaluator
from claasp.name_mappings import CIPHER_OUTPUT, INTERMEDIATE_OUTPUT


class RotationalTests:
    """Search a CLAASP cipher for word-wise rotational output biases."""

    def __init__(self, cipher):
        self._cipher = cipher

    def rotational_tests(self, number_of_samples=1024, word_size=None, rotations=None, input_index=0,
                         output_word_size=None, output_tags=None, seed=None, top=10,
                         validation_samples=0, validation_seed=None):
        """Return the most biased single-bit rotational comparisons.

        ``word_size`` partitions the selected input into consecutive words.
        Each nonzero value in ``rotations`` rotates every such word to the
        left.  Other cipher inputs (for example, a key when the plaintext is
        selected) are sampled randomly but kept equal inside each pair.

        Output words are aligned using ``output_word_size``, which defaults to
        ``word_size``.  By default only ``cipher_output`` is searched.  Pass,
        for example, ``("round_output", "cipher_output")`` to include round
        outputs exposed by the cipher graph.

        Candidates are selected on the discovery samples.  If
        ``validation_samples`` is nonzero, the frozen candidates are evaluated
        on a second independently seeded sample set.

        INPUT:

        - ``number_of_samples`` -- positive integer; discovery pair count
        - ``word_size`` -- positive integer; input word size in bits.  When
          omitted, common CLAASP cipher word-size attributes are inspected
        - ``rotations`` -- iterable of offsets in ``1..word_size-1``; defaults
          to every nonzero offset
        - ``input_index`` -- index of the cipher input to rotate
        - ``output_word_size`` -- output alignment word size; defaults to
          ``word_size``
        - ``output_tags`` -- output descriptions to search; defaults to only
          ``cipher_output``
        - ``seed`` -- NumPy random seed for discovery
        - ``top`` -- number of candidates retained
        - ``validation_samples`` -- independent validation pair count, or zero
        - ``validation_seed`` -- validation seed; must differ from ``seed``

        EXAMPLES::

            sage: from claasp.cipher_modules.rotational_diffusion_tests import RotationalTests
            sage: from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation
            sage: keccak = KeccakPermutation(number_of_rounds=4)
            sage: result = RotationalTests(keccak).rotational_tests(
            ....:     number_of_samples=32, word_size=64, rotations=[63], seed=1, top=1)
            sage: result["cipher"] == keccak.id
            True
        """

        word_size = self._resolve_word_size(word_size)
        output_word_size = word_size if output_word_size is None else output_word_size
        tags = (CIPHER_OUTPUT,) if output_tags is None else tuple(output_tags)
        if validation_samples and validation_seed is None and seed is not None:
            validation_seed = seed + 1
        rotations = self._validate_parameters(number_of_samples, word_size, rotations, input_index,
                                              output_word_size, tags, top, validation_samples,
                                              validation_seed, seed)
        descriptors = self._output_descriptors(tags, output_word_size)
        total_tests = len(rotations) * sum(
            descriptor["output_bit_size"] for values in descriptors.values() for descriptor in values
        )
        include_intermediate_outputs = any(tag != CIPHER_OUTPUT for tag in tags)
        compiled_evaluator = evaluator.create_vectorized_evaluator(
            self._cipher, intermediate_output=include_intermediate_outputs, verbosity=False
        )

        rng = np.random.default_rng(seed)
        inputs = self._generate_random_inputs(number_of_samples, rng)
        candidates = self._scan(inputs, rotations, input_index, word_size, output_word_size,
                                descriptors, top, total_tests, compiled_evaluator)

        if validation_samples:
            validation_rng = np.random.default_rng(validation_seed)
            validation_inputs = self._generate_random_inputs(validation_samples, validation_rng)
            self._validate_candidates(validation_inputs, candidates, input_index, word_size,
                                      output_word_size, descriptors, compiled_evaluator)

        return {
            "cipher": self._cipher.id,
            "test_name": "rotational_tests",
            "input": self._cipher.inputs[input_index],
            "input_index": input_index,
            "input_bit_size": self._cipher.inputs_bit_size[input_index],
            "word_size": word_size,
            "output_word_size": output_word_size,
            "rotations": list(rotations),
            "output_tags": list(tags),
            "number_of_samples": number_of_samples,
            "seed": seed,
            "tested_candidates": total_tests,
            "top": top,
            "validation_samples": validation_samples,
            "validation_seed": validation_seed if validation_samples else None,
            "relation": "rotate every selected-input word left; align partner-output words by the same rotation",
            "candidates": candidates,
        }

    def rotational_rounds_tests(self, number_of_samples=1024, word_size=None, rotations=None, input_index=0,
                                output_word_size=None, seed=None, top=5, validation_samples=4096,
                                validation_seed=None, significance_level=0.01):
        """Search consecutive round outputs until no validated distinguisher is found.

        The supplied cipher must expose its consecutive states through canonical
        ``round_output`` components and a final ``cipher_output`` component.  All
        rounds are evaluated in one vectorized pass per rotation.  For each round,
        the ``top`` discovery candidates are frozen and checked on independent
        validation data.

        A round is marked as having a distinguisher when at least one candidate:

        - has a Bonferroni-corrected discovery p-value below
          ``significance_level``;
        - has a validation p-value corrected over every retained round candidate
          below ``significance_level``; and
        - preserves the discovery event direction on validation data.

        Returned round results end at the first round that fails this rule.
        """

        if not validation_samples:
            raise ValueError("validation_samples must be positive for a round stopping search")
        if not 0 < significance_level < 1:
            raise ValueError("significance_level must be between zero and one")
        word_size = self._resolve_word_size(word_size)
        output_word_size = word_size if output_word_size is None else output_word_size
        tags = ("round_output", CIPHER_OUTPUT)
        if validation_seed is None and seed is not None:
            validation_seed = seed + 1
        rotations = self._validate_parameters(number_of_samples, word_size, rotations, input_index,
                                              output_word_size, tags, top, validation_samples,
                                              validation_seed, seed)
        descriptors = self._output_descriptors(tags, output_word_size)
        tests_per_round = self._tests_per_round(descriptors, len(rotations))
        compiled_evaluator = evaluator.create_vectorized_evaluator(
            self._cipher, intermediate_output=True, verbosity=False
        )

        discovery_rng = np.random.default_rng(seed)
        discovery_inputs = self._generate_random_inputs(number_of_samples, discovery_rng)
        candidates_by_round = self._scan_by_round(
            discovery_inputs, rotations, input_index, word_size, output_word_size,
            descriptors, top, tests_per_round, compiled_evaluator
        )
        all_candidates = [
            candidate
            for round_id in sorted(candidates_by_round)
            for candidate in candidates_by_round[round_id]
        ]

        validation_rng = np.random.default_rng(validation_seed)
        validation_inputs = self._generate_random_inputs(validation_samples, validation_rng)
        self._validate_candidates(validation_inputs, all_candidates, input_index, word_size,
                                  output_word_size, descriptors, compiled_evaluator)

        round_results = []
        first_round_without_distinguisher = None
        for round_id in sorted(candidates_by_round):
            candidates = candidates_by_round[round_id]
            qualifying = [
                candidate for candidate in candidates
                if candidate["bonferroni_p"] < significance_level
                and candidate["validation"]["bonferroni_p"] < significance_level
                and candidate["validation"]["event_frequency"] > 0.5
            ]
            found = bool(qualifying)
            result = {
                "round": round_id + 1,
                "round_id": round_id,
                "tested_candidates": tests_per_round[round_id],
                "distinguisher_found": found,
                "best_qualifying_candidate": qualifying[0] if qualifying else None,
                "candidates": candidates,
            }
            round_results.append(result)
            if not found:
                first_round_without_distinguisher = round_id + 1
                break

        return {
            "cipher": self._cipher.id,
            "test_name": "rotational_rounds_tests",
            "input": self._cipher.inputs[input_index],
            "input_index": input_index,
            "input_bit_size": self._cipher.inputs_bit_size[input_index],
            "word_size": word_size,
            "output_word_size": output_word_size,
            "rotations": list(rotations),
            "number_of_samples": number_of_samples,
            "seed": seed,
            "validation_samples": validation_samples,
            "validation_seed": validation_seed,
            "significance_level": significance_level,
            "validation_hypotheses": len(all_candidates),
            "first_round_without_distinguisher": first_round_without_distinguisher,
            "rounds": round_results,
        }

    def _resolve_word_size(self, word_size):
        if word_size is not None:
            return word_size
        for attribute in ("word_bit_size", "word_size"):
            value = getattr(self._cipher, attribute, None)
            if type(value) is int and value > 1:
                return value
        value = self._cipher.is_power_of_2_word_based()
        if type(value) is int and value > 1:
            return value
        raise ValueError("word_size is required when it cannot be inferred from the cipher")

    def _validate_parameters(self, number_of_samples, word_size, rotations, input_index,
                             output_word_size, tags, top, validation_samples, validation_seed, seed):
        if type(number_of_samples) is not int or number_of_samples <= 0:
            raise ValueError("number_of_samples must be a positive integer")
        if type(validation_samples) is not int or validation_samples < 0:
            raise ValueError("validation_samples must be a nonnegative integer")
        if type(top) is not int or top <= 0:
            raise ValueError("top must be a positive integer")
        if type(word_size) is not int or word_size <= 1:
            raise ValueError("word_size must be an integer greater than one")
        if type(output_word_size) is not int or output_word_size <= 1:
            raise ValueError("output_word_size must be an integer greater than one")
        if type(input_index) is not int or not 0 <= input_index < len(self._cipher.inputs):
            raise ValueError("input_index is outside the cipher input list")
        if self._cipher.inputs_bit_size[input_index] % word_size:
            raise ValueError("word_size must divide the selected input bit size")
        if not tags or any(type(tag) is not str for tag in tags):
            raise ValueError("output_tags must contain at least one string")
        if validation_samples and seed is not None and validation_seed == seed:
            raise ValueError("validation_seed must differ from the discovery seed")

        values = range(1, word_size) if rotations is None else rotations
        try:
            values = tuple(dict.fromkeys(values))
        except TypeError as error:
            raise ValueError("rotations must be an iterable of integers") from error
        if not values or any(type(value) is not int or not 1 <= value < word_size for value in values):
            raise ValueError("rotations must be nonempty integers in 1..word_size-1")
        return values

    def _output_descriptors(self, tags, output_word_size):
        descriptors = {tag: [] for tag in tags}
        for cipher_round in self._cipher.rounds_as_list:
            for component in cipher_round.components:
                if component.type not in (INTERMEDIATE_OUTPUT, CIPHER_OUTPUT):
                    continue
                tag = component.description[0]
                if tag not in descriptors:
                    continue
                if component.output_bit_size % output_word_size:
                    raise ValueError(
                        f"output_word_size does not divide {tag} component {component.id}"
                    )
                descriptors[tag].append({
                    "component_id": component.id,
                    "round": cipher_round.id,
                    "output_bit_size": component.output_bit_size,
                })
        missing = [tag for tag, values in descriptors.items() if not values]
        if missing:
            raise ValueError(f"cipher does not expose requested output tags: {missing}")
        return descriptors

    def _generate_random_inputs(self, number_of_samples, rng):
        inputs = []
        for bit_size in self._cipher.inputs_bit_size:
            byte_size = math.ceil(bit_size / 8)
            values = rng.integers(0, 256, size=(byte_size, number_of_samples), dtype=np.uint8)
            padding = byte_size * 8 - bit_size
            if padding:
                values[0] &= (1 << (8 - padding)) - 1
            inputs.append(values)
        return inputs

    @staticmethod
    def _rotate_selected_input(inputs, input_index, input_bit_size, word_size, rotation):
        partner_inputs = list(inputs)
        values = inputs[input_index]
        bits = np.unpackbits(values, axis=0)
        padding = bits.shape[0] - input_bit_size
        significant = bits[padding:].reshape((-1, word_size, bits.shape[1]))
        significant = np.roll(significant, -rotation, axis=1)
        significant = significant.reshape((input_bit_size, bits.shape[1]))
        if padding:
            significant = np.concatenate((np.zeros((padding, bits.shape[1]), dtype=np.uint8), significant), axis=0)
        partner_inputs[input_index] = np.packbits(significant, axis=0)
        return partner_inputs

    @staticmethod
    def _unpack_output(values, output_bit_size):
        values = np.asarray(values, dtype=np.uint8)
        if values.ndim != 2:
            raise ValueError("vectorized evaluator returned an output with an unexpected shape")
        bits = np.unpackbits(values, axis=1)
        if bits.shape[1] < output_bit_size:
            raise ValueError("vectorized evaluator returned too few output bits")
        # Vectorized byte outputs are left-zero-padded when their bit size is
        # not a multiple of eight.  Drop that storage padding rather than
        # treating it as the most significant cipher-output bits.
        return bits[:, bits.shape[1] - output_bit_size:]

    @staticmethod
    def _aligned_disagreements(base_values, partner_values, output_bit_size, output_word_size, rotation):
        base_bits = RotationalTests._unpack_output(base_values, output_bit_size)
        partner_bits = RotationalTests._unpack_output(partner_values, output_bit_size)
        partner_words = partner_bits.reshape((partner_bits.shape[0], -1, output_word_size))
        # In MSB-first arrays, rotating the integer word right by n is a
        # positive np.roll.  This maps partner bit z+n back onto base bit z.
        aligned_partner = np.roll(partner_words, rotation, axis=2).reshape(partner_bits.shape)
        return base_bits ^ aligned_partner

    def _scan(self, inputs, rotations, input_index, word_size, output_word_size,
              descriptors, top, total_tests, compiled_evaluator):
        evaluated = compiled_evaluator(inputs)
        heap = []
        sequence = 0
        number_of_samples = inputs[0].shape[1]

        for rotation in rotations:
            partner_inputs = self._rotate_selected_input(
                inputs, input_index, self._cipher.inputs_bit_size[input_index], word_size, rotation
            )
            evaluated_partner = compiled_evaluator(partner_inputs)
            for tag, tag_descriptors in descriptors.items():
                base_occurrences = self._evaluated_occurrences(evaluated, tag)
                partner_occurrences = self._evaluated_occurrences(evaluated_partner, tag)
                for occurrence, descriptor in enumerate(tag_descriptors):
                    differences = self._aligned_disagreements(
                        base_occurrences[occurrence], partner_occurrences[occurrence],
                        descriptor["output_bit_size"], output_word_size, rotation
                    )
                    counts = np.count_nonzero(differences, axis=0)
                    deviations = np.abs(counts / number_of_samples - 0.5)
                    local_top = min(top, descriptor["output_bit_size"])
                    indexes = np.argpartition(deviations, -local_top)[-local_top:]
                    for output_bit in indexes:
                        record = self._candidate_record(
                            rotation, tag, occurrence, descriptor, int(output_bit), int(counts[output_bit]),
                            number_of_samples, output_word_size, total_tests
                        )
                        item = (record["absolute_bias"], sequence, record)
                        sequence += 1
                        if len(heap) < top:
                            heapq.heappush(heap, item)
                        elif item[:2] > heap[0][:2]:
                            heapq.heapreplace(heap, item)

        return [item[2] for item in sorted(heap, key=lambda value: (-value[0], value[1]))]

    @staticmethod
    def _tests_per_round(descriptors, number_of_rotations):
        tests_per_round = {}
        for values in descriptors.values():
            for descriptor in values:
                round_id = descriptor["round"]
                tests_per_round[round_id] = tests_per_round.get(round_id, 0) + (
                    number_of_rotations * descriptor["output_bit_size"]
                )
        return tests_per_round

    def _scan_by_round(self, inputs, rotations, input_index, word_size, output_word_size,
                       descriptors, top, tests_per_round, compiled_evaluator):
        evaluated = compiled_evaluator(inputs)
        heaps = {round_id: [] for round_id in tests_per_round}
        sequence = 0
        number_of_samples = inputs[0].shape[1]

        for rotation in rotations:
            partner_inputs = self._rotate_selected_input(
                inputs, input_index, self._cipher.inputs_bit_size[input_index], word_size, rotation
            )
            evaluated_partner = compiled_evaluator(partner_inputs)
            for tag, tag_descriptors in descriptors.items():
                base_occurrences = self._evaluated_occurrences(evaluated, tag)
                partner_occurrences = self._evaluated_occurrences(evaluated_partner, tag)
                for occurrence, descriptor in enumerate(tag_descriptors):
                    differences = self._aligned_disagreements(
                        base_occurrences[occurrence], partner_occurrences[occurrence],
                        descriptor["output_bit_size"], output_word_size, rotation
                    )
                    counts = np.count_nonzero(differences, axis=0)
                    deviations = np.abs(counts / number_of_samples - 0.5)
                    local_top = min(top, descriptor["output_bit_size"])
                    indexes = np.argpartition(deviations, -local_top)[-local_top:]
                    round_id = descriptor["round"]
                    heap = heaps[round_id]
                    for output_bit in indexes:
                        record = self._candidate_record(
                            rotation, tag, occurrence, descriptor, int(output_bit), int(counts[output_bit]),
                            number_of_samples, output_word_size, tests_per_round[round_id]
                        )
                        item = (record["absolute_bias"], sequence, record)
                        sequence += 1
                        if len(heap) < top:
                            heapq.heappush(heap, item)
                        elif item[:2] > heap[0][:2]:
                            heapq.heapreplace(heap, item)

        return {
            round_id: [item[2] for item in sorted(heap, key=lambda value: (-value[0], value[1]))]
            for round_id, heap in heaps.items()
        }

    @staticmethod
    def _candidate_record(rotation, tag, occurrence, descriptor, output_bit, count,
                          number_of_samples, output_word_size, total_tests):
        frequency = count / number_of_samples
        z_score = (count - number_of_samples / 2) / math.sqrt(number_of_samples / 4)
        p_value = math.erfc(abs(z_score) / math.sqrt(2))
        bit_in_word = output_word_size - 1 - output_bit % output_word_size
        partner_bit_in_word = (bit_in_word + rotation) % output_word_size
        partner_output_bit = (
            output_bit // output_word_size * output_word_size
            + output_word_size - 1 - partner_bit_in_word
        )
        event = int(frequency >= 0.5)
        event_count = count if event else number_of_samples - count
        return {
            "rotation": rotation,
            "output_tag": tag,
            "occurrence": occurrence,
            "round": descriptor["round"],
            "component_id": descriptor["component_id"],
            "output_bit": output_bit,
            "output_word_index": output_bit // output_word_size,
            "output_bit_in_word": bit_in_word,
            "partner_output_bit": partner_output_bit,
            "partner_output_bit_in_word": partner_bit_in_word,
            "event": event,
            "event_count": event_count,
            "event_frequency": event_count / number_of_samples,
            "disagreement_count": count,
            "disagreement_frequency": frequency,
            "bias": frequency - 0.5,
            "absolute_bias": abs(frequency - 0.5),
            "null_z_score": z_score,
            "normal_two_sided_p": p_value,
            "bonferroni_p": min(1.0, p_value * total_tests),
            "wilson_95": RotationalTests._wilson_interval(count, number_of_samples),
        }

    def _validate_candidates(self, inputs, candidates, input_index, word_size,
                             output_word_size, descriptors, compiled_evaluator):
        evaluated = compiled_evaluator(inputs)
        number_of_samples = inputs[0].shape[1]
        selected_tests = len(candidates)
        descriptor_lookup = {
            (tag, occurrence): descriptor
            for tag, values in descriptors.items()
            for occurrence, descriptor in enumerate(values)
        }

        by_rotation = {}
        for candidate in candidates:
            by_rotation.setdefault(candidate["rotation"], []).append(candidate)
        for rotation, rotation_candidates in by_rotation.items():
            partner_inputs = self._rotate_selected_input(
                inputs, input_index, self._cipher.inputs_bit_size[input_index], word_size, rotation
            )
            evaluated_partner = compiled_evaluator(partner_inputs)
            differences_cache = {}
            for candidate in rotation_candidates:
                key = (candidate["output_tag"], candidate["occurrence"])
                if key not in differences_cache:
                    descriptor = descriptor_lookup[key]
                    base_occurrences = self._evaluated_occurrences(evaluated, key[0])
                    partner_occurrences = self._evaluated_occurrences(evaluated_partner, key[0])
                    differences_cache[key] = self._aligned_disagreements(
                        base_occurrences[key[1]], partner_occurrences[key[1]],
                        descriptor["output_bit_size"], output_word_size, rotation
                    )
                count = int(np.count_nonzero(differences_cache[key][:, candidate["output_bit"]]))
                z_score = (count - number_of_samples / 2) / math.sqrt(number_of_samples / 4)
                p_value = math.erfc(abs(z_score) / math.sqrt(2))
                frequency = count / number_of_samples
                event = candidate["event"]
                event_count = count if event else number_of_samples - count
                candidate["validation"] = {
                    "samples": number_of_samples,
                    "event": event,
                    "event_count": event_count,
                    "event_frequency": event_count / number_of_samples,
                    "disagreement_count": count,
                    "disagreement_frequency": frequency,
                    "bias": frequency - 0.5,
                    "null_z_score": z_score,
                    "normal_two_sided_p": p_value,
                    "bonferroni_p": min(1.0, p_value * selected_tests),
                    "wilson_95": self._wilson_interval(count, number_of_samples),
                }

    @staticmethod
    def _evaluated_occurrences(evaluated, tag):
        if isinstance(evaluated, dict):
            return evaluated[tag]
        if tag != CIPHER_OUTPUT:
            raise ValueError("intermediate output requested from a final-output-only evaluation")
        return evaluated

    @staticmethod
    def _wilson_interval(count, number_of_samples):
        frequency = count / number_of_samples
        z_value = 1.959963984540054
        denominator = 1 + z_value * z_value / number_of_samples
        center = (frequency + z_value * z_value / (2 * number_of_samples)) / denominator
        half_width = z_value * math.sqrt(
            frequency * (1 - frequency) / number_of_samples
            + z_value * z_value / (4 * number_of_samples * number_of_samples)
        ) / denominator
        return [center - half_width, center + half_width]
