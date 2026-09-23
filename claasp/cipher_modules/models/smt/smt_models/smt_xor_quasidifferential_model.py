# ****************************************************************************
#Copyright 2023 Technology Innovation Institute
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
# XOR Quasidifferential SMT Model
# ****************************************************************************

import time
from collections import defaultdict

from claasp.cipher_modules.models.smt import solvers
from claasp.cipher_modules.models.smt.smt_model import SmtModel
from claasp.cipher_modules.models.smt.utils import constants, utils
from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values, set_component_solution

from claasp.name_mappings import (
    CIPHER_OUTPUT,
    CONSTANT,
    INPUT_KEY,
    INTERMEDIATE_OUTPUT,
    LINEAR_LAYER,
    MIX_COLUMN,
    PERMUTATION_COMPONENT,
    SBOX,
    WORD_OPERATION,
    XOR_QUASIDIFFERENTIAL,
)


class SmtXorQuasidifferentialModel(SmtModel):
    """
    SMT model of the XOR quasidifferential trails of a cipher (Beyne &
    Rijmen, *Differential Cryptanalysis in the Fixed-Key Model*).

    Where ``SmtXorDifferentialModel`` searches differential
    characteristics, and so reports a probability averaged over all
    keys, this model searches quasidifferential trails: a characteristic
    together with a MASK on every intermediate state. Summing the signed
    correlation of the trails of one differential gives its probability
    for a FIXED key (Theorem 4.1), which can differ substantially from
    the average.

    The trail whose masks are all zero IS the differential
    characteristic, with the same weight, so the lowest weight found
    here always equals the one the differential model finds.

    INPUT:

    - ``cipher`` -- **Cipher object**; the cipher to model
    - ``counter`` -- **string** (default: `sequential`); the weight
      counter to use. ``"parallel"`` is not supported, as in
      ``SmtXorDifferentialModel``.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
        sage: speck = SpeckBlockCipher(number_of_rounds=2)
        sage: smt = SmtXorQuasidifferentialModel(speck)
        sage: smt.cipher_id
        'speck_p32_k64_o32_r2'
    """

    def __init__(self, cipher, counter="sequential"):
        """
        Build the model, and map once which components read each wire bit.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: smt = SmtXorQuasidifferentialModel(SpeckBlockCipher(number_of_rounds=2))

        Bit 16 of the plaintext is read by two components, so it is a fork:

            sage: smt._wire_consumers[('plaintext', 16)]
            [('modadd_0_1', 0), ('rot_0_3', 0)]
        """

        super().__init__(cipher, counter)
        self.sboxes_qdt_templates = {}
        self.sboxes_qdt_matrices = {}

        # Which components read each wire bit, and which ids are read at
        # all. A consumer is recorded once per READ, not once per
        # component: see _component_wire_reads.
        self._wire_consumers = defaultdict(list)
        self._consumed_component_ids = set()

        for component in cipher.get_all_components():
            for source_id, position, read_index in self._component_wire_reads(component):
                self._consumed_component_ids.add(source_id)
                self._wire_consumers[(source_id, position)].append((component.id, read_index))

    def build_xor_quasidifferential_trail_model(self, weight=-1, fixed_variables=[]):
        """
        Build the SMT model of the quasidifferential trails.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`); bound the total
          weight to at most this value. ``-1`` leaves it unbounded.
        - ``fixed_variables`` -- **list** (default: `[]`); DIFFERENCE
          constraints, built with ``set_fixed_variables``. Masks cannot
          be fixed this way: see ``estimate_fixed_key_probability``.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: smt.build_xor_quasidifferential_trail_model()
            sage: smt.model_constraints[0]
            '(set-option :print-success false)'

        A wire read by two components gets one branch mask per reader,
        tied to the source by an XOR:

            sage: any('qdt_plaintext_16_to_modadd_0_1' in constraint
            ....:     for constraint in smt.model_constraints)
            True
        """

        self._variables_list = []

        if fixed_variables == []:
            fixed_variables = get_single_key_scenario_format_for_fixed_values(self._cipher)

        constraints = self.fix_variables_value_constraints(fixed_variables)
        component_types = (
            CIPHER_OUTPUT,
            CONSTANT,
            INTERMEDIATE_OUTPUT,
            LINEAR_LAYER,
            MIX_COLUMN,
            PERMUTATION_COMPONENT,
            SBOX,
            WORD_OPERATION,
        )

        operation_types = ("AND", "MODADD", "MODSUB", "NOT", "OR", "ROTATE", "SHIFT", "XOR")

        for component in self._cipher.get_all_components():
            operation = component.description[0]

            if component.type not in component_types or (
                component.type == WORD_OPERATION and operation not in operation_types
            ):
                print(f"{component.id} not yet implemented")
                continue

            try:
                variables, component_constraints = component.smt_xor_quasidifferential_propagation_constraints(self)

            except NotImplementedError:
                print(f"{component.id} not yet implemented")

                continue

            self._variables_list.extend(variables)

            constraints.extend(component_constraints)

        if weight != -1:
            counter_variables, weight_constraints = self.weight_constraints(weight)

            self._variables_list.extend(counter_variables)

            constraints.extend(weight_constraints)

        fork_variables, fork_constraints = self._fork_constraints()
        self._variables_list.extend(fork_variables)
        constraints.extend(fork_constraints)

        constraints.extend(self._unread_input_mask_constraints())
        constraints.extend(self._terminal_tap_mask_constraints())

        self._variables_list.extend(self.cipher_input_variables())

        self._variables_list.extend(
            f"qdt_{variable_name}" for variable_name in self.cipher_input_variables()
        )

        self._declarations_builder()

        self._model_constraints = constants.MODEL_PREFIX + self._declarations + constraints + constants.MODEL_SUFFIX



    def _qdt_local_weight_variables(
        self,
        component,
        max_weight,
    ):
        """
        The local weight indicators ``hw_qdt_<component id>_<i>`` of a component.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = XorCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._qdt_local_weight_variables(cipher.component_from_id('xor_0_0'), 3)
            ['hw_qdt_xor_0_0_0', 'hw_qdt_xor_0_0_1', 'hw_qdt_xor_0_0_2']
        """

        return [f"hw_qdt_{component.id}_{i}" for i in range(int(max_weight))]

    def _qdt_weight_constraints(
        self,
        weight_variables,
        weight,
    ):
        """
        Thermometer encoding of ``weight``: the first ``weight`` indicators true, the others false.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = XorCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._qdt_weight_constraints(['hw_0', 'hw_1', 'hw_2'], 2)
            ['hw_0', 'hw_1', '(not hw_2)']
        """

        return [variable if i < weight else utils.smt_not(variable) for i, variable in enumerate(weight_variables)]

    def calculate_component_weight(
        self,
        component,
        out_suffix,
        output_values_dict,
    ):
        """
        Calculate the local quasidifferential weight.

        Generalized to any component that declares hw_qdt_{component.id}_*
        weight-bit variables (currently: Sbox, via a thermometer
        encoding; And, via a single per-bit OR indicator -- see
        And.smt_xor_quasidifferential_propagation_constraints). For
        components with no such variables (XOR, LinearLayer, ...) the
        sum is naturally 0, since none match the prefix.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: xor = speck.component_from_id('xor_0_2')
            sage: smt.calculate_component_weight(xor, '', {})
            0

        """

        prefix = f"hw_qdt_{component.id}_"

        return sum(value for variable, value in output_values_dict.items() if variable.startswith(prefix))

    @staticmethod
    def get_qdt_transitions(weights):
        """
        Flatten a QDT weight table into explicit transitions.

        INPUT:

            weights[(b, a)][weight_loss] = [(v, u), ...]

        OUTPUT:

            [
                {
                    "a": ...,
                    "u": ...,
                    "b": ...,
                    "v": ...,
                    "weight": ...
                },
                ...
            ]

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: weights = {(0x2, 0x1): {1: [(0x3, 0x4)]}}
            sage: SmtXorQuasidifferentialModel.get_qdt_transitions(weights)
            [{'a': 1, 'b': 2, 'u': 4, 'v': 3, 'weight': 1}]

        """

        transitions = []

        for (b, a), weight_dict in weights.items():
            for weight_loss, mask_pairs in weight_dict.items():
                for v, u in mask_pairs:
                    transitions.append(
                        {
                            "a": a,
                            "u": u,
                            "b": b,
                            "v": v,
                            "weight": weight_loss,
                        }
                    )

        return transitions

    @staticmethod
    def _component_wire_reads(component):
        """
        Yield ``(source_id, position, read_index)`` for every input bit a
        component reads, in the order its constraints use them.

        ``read_index`` counts how many times THIS component has already
        read THIS bit. A component may read the same wire bit more than
        once -- DES's expansion feeds 16 bits of ``permutation_0_0`` into
        both halves of ``xor_0_7`` -- and each read is a separate branch
        of the copy map, so each needs its own mask variable. Keying a
        branch by consumer id alone gives the two reads one name, and
        ``_fork_constraints`` then emits it twice inside one ``xor``,
        where it cancels: the branch drops out of the source relation
        entirely.

        ``__init__``, ``_qdt_input_bit_ids`` and
        ``_read_component_input_mask`` all walk the reads through this
        one generator, so the three stay aligned by construction.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = XorCipher(word_bit_size=2, number_of_inputs=2)
            sage: list(SmtXorQuasidifferentialModel._component_wire_reads(cipher.component_from_id('xor_0_0')))
            [('plaintext', 0, 0), ('plaintext', 1, 0), ('key', 0, 0), ('key', 1, 0)]
        """

        reads_so_far = defaultdict(int)

        for input_id, bit_positions in zip(
            component.input_id_links,
            component.input_bit_positions,
        ):
            for position in bit_positions:
                read_index = reads_so_far[(input_id, position)]
                reads_so_far[(input_id, position)] += 1

                yield input_id, position, read_index

    @staticmethod
    def _branch_mask_id(
        source_id,
        position,
        consumer_id,
        read_index,
    ):
        """
        Name of the branch mask through which ``consumer_id``'s
        ``read_index``-th read of ``source_id`` bit ``position`` sees the
        wire. The first read keeps the plain ``_to_<consumer>`` form.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: SmtXorQuasidifferentialModel._branch_mask_id('plaintext', 16, 'modadd_0_1', 0)
            'qdt_plaintext_16_to_modadd_0_1'

        A further read of the same bit by the same component, as in DES:

            sage: SmtXorQuasidifferentialModel._branch_mask_id('permutation_0_0', 63, 'xor_0_7', 1)
            'qdt_permutation_0_0_63_to_xor_0_7_read1'
        """

        suffix = "" if read_index == 0 else f"_read{read_index}"

        return f"qdt_{source_id}_{position}_to_{consumer_id}{suffix}"

    def qdt_input_bit_id(
        self,
        component,
        source_id,
        position,
        read_index=0,
    ):
        """
        Mask variable through which ``component``'s ``read_index``-th
        read of bit ``position`` of ``source_id`` sees that wire.

        A wire read exactly once keeps the shared name, which is
        correct: the XOR of a single branch mask is that mask. A FORKED
        wire gets one variable per read, tied to the source by the XOR
        constraint in ``_fork_constraints``.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: smt = SmtXorQuasidifferentialModel(speck)

        Bit 16 of the plaintext is read by two components, so each read
        sees the wire through its own branch mask:

            sage: smt.qdt_input_bit_id(speck.component_from_id('modadd_0_1'), 'plaintext', 16)
            'qdt_plaintext_16_to_modadd_0_1'

        Bit 0 has a single reader, and keeps the shared name -- the XOR
        of one branch is that branch:

            sage: smt.qdt_input_bit_id(speck.component_from_id('rot_0_0'), 'plaintext', 0)
            'qdt_plaintext_0'

        """

        consumers = self._wire_consumers.get((source_id, position), ())

        if len(consumers) <= 1:
            return f"qdt_{source_id}_{position}"

        return self._branch_mask_id(source_id, position, component.id, read_index)

    def _fork_constraints(self):
        """
        At a fork the source mask is the XOR of the branch masks -- the
        dual of the XOR-of-differences rule at a join point.

        Verified against Equation (4) on the copy map F(x) = (x, x):
        over all 3-bit combinations, 512 transitions have a nonzero
        coefficient, and ALL of them satisfy u = v1 xor v2, while only
        8 satisfy u = v1 = v2. Sharing one variable among consumers --
        which is what the plain qdt_ naming does -- imposes the latter,
        a constraint 64 times too strong.

        Forks are the normal structure of a cipher, not an edge case:
        Speck has 96 forked wires at two rounds and 320 at six,
        RECTANGLE 172 at a single round.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: smt = SmtXorQuasidifferentialModel(SpeckBlockCipher(number_of_rounds=2))
            sage: variables, constraints = smt._fork_constraints()
            sage: len(constraints), len(variables)
            (96, 256)
            sage: constraints[0]
            '(assert (= qdt_plaintext_16 (xor qdt_plaintext_16_to_modadd_0_1 qdt_plaintext_16_to_rot_0_3)))'
        """

        variables = []
        constraints = []

        for (source_id, position), consumers in self._wire_consumers.items():
            if len(consumers) <= 1:
                continue

            source = f"qdt_{source_id}_{position}"
            branches = [
                self._branch_mask_id(source_id, position, consumer_id, read_index)
                for consumer_id, read_index in consumers
            ]

            variables.extend(branches)

            equation = utils.smt_equivalent([source, utils.smt_xor(branches)])
            constraints.append(utils.smt_assert(equation))

        return variables, constraints

    def _unread_input_mask_constraints(self):
        """
        Force to zero the mask of every cipher-input bit that no
        component reads.

        Such a bit does not influence the cipher, so a trail carrying a
        non-zero mask on it has correlation zero -- it is not a trail.
        Leaving the variable free is also expensive: nothing in the
        model constrains it, yet ``_qdt_get_operands`` puts every
        primary-input mask bit into the blocking clause, so each of its
        2^k assignments would be enumerated as a distinct trail and
        summed again by ``estimate_fixed_key_probability``. Speck 8/16
        at one round has 12 such bits, Speck 32/64 at two rounds has 32.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1)
            sage: constraints = SmtXorQuasidifferentialModel(speck)._unread_input_mask_constraints()
            sage: len(constraints), constraints[0]
            (12, '(assert (not qdt_key_0))')
        """

        constraints = []

        for input_id, bit_size in zip(
            self._cipher.inputs,
            self._cipher.inputs_bit_size,
        ):
            for position in range(bit_size):
                if self._wire_consumers.get((input_id, position)):
                    continue

                constraints.append(
                    utils.smt_assert(utils.smt_not(f"qdt_{input_id}_{position}"))
                )

        return constraints

    def _terminal_tap_mask_constraints(self):
        """
        Force to zero the mask of every IntermediateOutput that no
        component reads.

        Such a component is an observation point -- it exposes a wire
        without consuming it -- and is not a coordinate of the function
        the trail describes. Theorem 3.2's copy rule still hands it a
        fork branch, though (the source mask is the XOR of ALL
        branches), and leaving that branch free lets the solver push
        arbitrary mask into the tap, decoupling a producer's
        Theorem-constrained output mask from what the next round reads.
        On 2-round Speck that admits a spurious weight-2 trail whose
        sign cancels the genuine one, turning a fixed-key probability
        of 2^-2 into 0.

        CipherOutput is deliberately NOT included: its bits ARE
        coordinates of the cipher's output -- in Speck the round output
        is read by the next round AND exposed, a genuine fan-out -- and
        their masks are the boundary masks of Theorem 4.1, which the
        caller pins through ``fixed_masks``. An IntermediateOutput that
        some component does read is likewise a real wire in the data
        path and keeps a free mask.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1)
            sage: constraints = SmtXorQuasidifferentialModel(speck)._terminal_tap_mask_constraints()
            sage: len(constraints), constraints[0]
            (4, '(assert (not qdt_intermediate_output_0_5_0))')
        """

        constraints = []

        for component in self._cipher.get_all_components():
            if component.type != INTERMEDIATE_OUTPUT:
                continue

            if component.id in self._consumed_component_ids:
                continue

            constraints.extend(
                utils.smt_assert(utils.smt_not(f"qdt_{component.id}_{position}"))
                for position in range(component.output_bit_size)
            )

        return constraints

    def _qdt_input_bit_ids(
        self,
        component,
    ):
        """
        Return QDT mask variables corresponding to component inputs,
        using per-read branch variables on forked wires.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = XorCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._qdt_input_bit_ids(cipher.component_from_id('xor_0_0'))
            ['qdt_plaintext_0', 'qdt_plaintext_1', 'qdt_key_0', 'qdt_key_1']
        """

        return [
            self.qdt_input_bit_id(component, input_id, position, read_index)
            for input_id, position, read_index in self._component_wire_reads(component)
        ]

    def _bit_moving_propagation_constraints(
        self,
        component,
        mask_pairs,
    ):
        """
        Quasidifferential constraints of a component that only moves,
        copies or drops bits: NOT, Permutation, Rotate and Shift.

        The difference goes through the component's own differential
        constraints. On the mask side, each ``(output, input)`` entry of
        ``mask_pairs`` ties output mask bit ``output`` to input mask bit
        ``input``; an entry ``(None, input)`` forces that input mask bit
        to zero, because the map discards the bit. Entries are emitted in
        the order given.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = RotateCipher(bit_size=2, rotation_amount=1)
            sage: rotate = cipher.component_from_id('rot_0_0')
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: variables, constraints = smt._bit_moving_propagation_constraints(rotate, [(0, 1), (1, 0)])
            sage: constraints
            ['(assert (= rot_0_0_0 plaintext_1))',
             '(assert (= rot_0_0_1 plaintext_0))',
             '(assert (= qdt_rot_0_0_0 qdt_plaintext_1))',
             '(assert (= qdt_rot_0_0_1 qdt_plaintext_0))']

        An input bit the map discards gets a zero mask:

            sage: smt._bit_moving_propagation_constraints(rotate, [(0, 1), (None, 0)])[1][-1]
            '(assert (not qdt_plaintext_0))'
        """

        output_bit_ids, diff_constraints = component.smt_xor_differential_propagation_constraints(self)

        qdt_input_bit_ids = self._qdt_input_bit_ids(component)
        qdt_output_bit_ids = [f"qdt_{bit_id}" for bit_id in output_bit_ids]

        mask_constraints = []

        for output_position, input_position in mask_pairs:
            input_mask = qdt_input_bit_ids[input_position]

            if output_position is None:
                mask_constraints.append(utils.smt_assert(utils.smt_not(input_mask)))
            else:
                equation = utils.smt_equivalent([qdt_output_bit_ids[output_position], input_mask])
                mask_constraints.append(utils.smt_assert(equation))

        return output_bit_ids + qdt_output_bit_ids, diff_constraints + mask_constraints

    def _constrain_weight_exactly(self, weight):
        """
        Turn the "total weight <= weight" bound that
        ``weight_constraints`` imposes into "total weight == weight",
        for any weight, including the two the sequential counter cannot
        express.

        ``_sequential_counter_greater_or_equal`` rewrites "at least w"
        as "at most n - w" over the negated indicators, so w == n makes
        its inner dimension zero and it raises ``IndexError`` -- which
        is reachable through the public API: on 8-bit Speck at one round
        the model has few enough ``hw_`` indicators that asking for
        weight 4 crashes. Both edge cases have an exact, cheap encoding:

        - ``weight == n``: "at least all of them" is just all of them;
        - ``weight > n``: no assignment has that weight, so the model is
          unsatisfiable and should say so rather than raise.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: from claasp.cipher_modules.models.smt.utils import constants
            sage: smt = SmtXorQuasidifferentialModel(SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1))
            sage: smt.build_xor_quasidifferential_trail_model(weight=1)
            sage: len([variable for variable in smt._variables_list if variable.startswith('hw_')])
            4

        Asking for more weight than there are indicators makes the model
        unsatisfiable instead of raising:

            sage: smt._constrain_weight_exactly(5)
            sage: smt._model_constraints[-len(constants.MODEL_SUFFIX) - 1]
            '(assert false)'
        """

        hw_list = [variable_id for variable_id in self._variables_list if variable_id.startswith("hw_")]

        if weight > len(hw_list):
            extra = [utils.smt_assert("false")]
        elif weight == len(hw_list):
            extra = [utils.smt_assert(variable_id) for variable_id in hw_list]
        else:
            if self._counter == self._sequential_counter:
                self._sequential_counter_greater_or_equal(weight, "dummy_hw_1")
            return

        self._model_constraints = (
            self._model_constraints[: -len(constants.MODEL_SUFFIX)] + extra + constants.MODEL_SUFFIX
        )

    def find_one_xor_quasidifferential_trail(
        self,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Find one XOR quasidifferential trail.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: trail = smt.find_one_xor_quasidifferential_trail()
            sage: trail['total_weight'] >= 0
            True

        Every component reports a mask next to its difference:

            sage: 'mask' in trail['components_values']['cipher_output_0_6']
            True

        """

        start_building_time = time.time()

        self.build_xor_quasidifferential_trail_model(fixed_variables=fixed_values)

        end_building_time = time.time()

        solution = self.solve(
            XOR_QUASIDIFFERENTIAL,
            solver_name=solver_name,
        )

        solution["building_time_seconds"] = end_building_time - start_building_time

        solution["test_name"] = "find_one_xor_quasidifferential_trail"

        return solution

    def find_one_xor_quasidifferential_trail_with_fixed_weight(
        self,
        fixed_weight,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Find one XOR quasidifferential trail with a fixed total
        weight loss.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: trail = smt.find_one_xor_quasidifferential_trail_with_fixed_weight(3)
            sage: trail['total_weight']
            3.0

        """

        start_building_time = time.time()

        self.build_xor_quasidifferential_trail_model(
            weight=fixed_weight,
            fixed_variables=fixed_values,
        )

        self._constrain_weight_exactly(fixed_weight)

        end_building_time = time.time()

        solution = self.solve(
            XOR_QUASIDIFFERENTIAL,
            solver_name=solver_name,
        )

        solution["building_time_seconds"] = end_building_time - start_building_time

        solution["test_name"] = "find_one_xor_quasidifferential_trail_with_fixed_weight"

        return solution

    def find_lowest_weight_xor_quasidifferential_trail(
        self,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Return the solution representing a quasidifferential trail
        with the lowest total weight loss.

        Mirrors SmtXorDifferentialModel.find_lowest_weight_xor_differential_trail:
        increases the weight bound from 0 until a solution is found.


        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: trail = smt.find_lowest_weight_xor_quasidifferential_trail()
            sage: trail['total_weight']
            9.0

        This is the weight ``SmtXorDifferentialModel`` reports for the
        same cipher, and it must be: the lowest-weight trail is the one
        with all masks zero, which is the differential characteristic
        itself.

        """

        current_weight = 0

        start_building_time = time.time()
        self.build_xor_quasidifferential_trail_model(weight=current_weight, fixed_variables=fixed_values)
        end_building_time = time.time()

        solution = self.solve(XOR_QUASIDIFFERENTIAL, solver_name=solver_name)
        solution["building_time_seconds"] = end_building_time - start_building_time

        total_time = solution["solving_time_seconds"]
        max_memory = solution["memory_megabytes"]

        while solution["total_weight"] is None:
            current_weight += 1

            start_building_time = time.time()
            self.build_xor_quasidifferential_trail_model(weight=current_weight, fixed_variables=fixed_values)
            end_building_time = time.time()

            solution = self.solve(XOR_QUASIDIFFERENTIAL, solver_name=solver_name)
            solution["building_time_seconds"] = end_building_time - start_building_time

            total_time += solution["solving_time_seconds"]
            max_memory = max((max_memory, solution["memory_megabytes"]))

        solution["solving_time_seconds"] = total_time
        solution["memory_megabytes"] = max_memory
        solution["test_name"] = "find_lowest_weight_xor_quasidifferential_trail"

        return solution

    def _qdt_get_operands(self, solution):
        """
        Build the list of SMT literals that pin down a solution's
        primary-input boundary condition, for use in a blocking
        clause. Unlike the ordinary differential model's
        ``get_operands`` (which only needs to block the primary
        input DIFFERENCE, since the mask side does not exist there),
        a quasidifferential trail's boundary also includes the
        primary input MASK -- two trails sharing the same input
        difference but differing in input mask are genuinely
        different trails and must not be treated as duplicates.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: smt = SmtXorQuasidifferentialModel(SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1))
            sage: smt.build_xor_quasidifferential_trail_model(weight=0)
            sage: solution = smt.solve('xor_quasidifferential')
            sage: len(smt._qdt_get_operands(solution))
            48

        Difference and mask of the 8-bit plaintext and of the 16-bit key.
        """

        operands = []

        for input_, bit_len in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            operands.extend(self._excluding_literals(input_, solution["components_values"][input_], bit_len))

        return operands

    @staticmethod
    def _excluding_literals(
        variable_prefix,
        values,
        bit_len,
    ):
        """
        The blocking-clause literals that exclude both the difference
        and the mask recorded in ``values`` on the ``bit_len`` bits named
        ``<variable_prefix>_<j>`` and ``qdt_<variable_prefix>_<j>``, most
        significant bit first.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: SmtXorQuasidifferentialModel._excluding_literals('x', {'value': '0x2', 'mask': '0x1'}, 2)
            ['(not x_0)', 'x_1', 'qdt_x_0', '(not qdt_x_1)']
        """

        literals = []

        for prefix, value in (
            (variable_prefix, int(values["value"], 16)),
            (f"qdt_{variable_prefix}", int(values.get("mask", "0x0"), 16)),
        ):
            # Excluding a value means forcing its complement, bit by bit.
            complement = value ^ ((1 << bit_len) - 1)
            literals.extend(
                SmtXorQuasidifferentialModel._value_literals([f"{prefix}_{j}" for j in range(bit_len)], complement)
            )

        return literals

    @staticmethod
    def _value_literals(
        bit_ids,
        value,
    ):
        """
        The literals that force ``bit_ids`` to spell ``value``, most
        significant bit first.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: SmtXorQuasidifferentialModel._value_literals(['x_0', 'x_1', 'x_2'], 5)
            ['x_0', '(not x_1)', 'x_2']
        """

        size = len(bit_ids)

        return [
            bit_id if (value >> (size - 1 - index)) & 1 else utils.smt_not(bit_id)
            for index, bit_id in enumerate(bit_ids)
        ]

    def _is_nonlinear_component(
        self,
        component,
    ):
        """
        True for components that introduce genuine degrees of freedom
        into a quasidifferential trail, i.e. the ones whose specific
        (difference, mask) transition must be blocked when enumerating
        distinct trails.

        These are exactly the components with a nontrivial QDT: Sbox,
        AND and MODADD. Every other currently-implemented component
        (XOR, LinearLayer, Permutation, Rotate, MixColumn,
        CipherOutput, IntermediateOutput, Constant) is deterministic
        given its inputs on both the difference and the mask side, so
        blocking it would be redundant.


        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: smt._is_nonlinear_component(speck.component_from_id('modadd_0_1'))
            True
            sage: smt._is_nonlinear_component(speck.component_from_id('rot_0_0'))
            False
        """

        if SBOX in component.type:
            return True

        if component.type == WORD_OPERATION and component.description[0] in (
            "AND",
            "MODADD",
            "MODSUB",
            "OR",
        ):
            return True

        return False

    def _blocking_clause_operands(
        self,
        solution,
    ):
        """
        Build the full list of literals for a blocking clause that
        excludes exactly the trail described by `solution`: the primary
        input boundary (difference AND mask, via _qdt_get_operands)
        plus every nonlinear component's own difference and mask.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: smt = SmtXorQuasidifferentialModel(SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1))
            sage: smt.build_xor_quasidifferential_trail_model(weight=0)
            sage: solution = smt.solve('xor_quasidifferential')
            sage: len(smt._blocking_clause_operands(solution))
            56

        The 48 literals of the primary inputs, plus difference and mask of the
        one 4-bit modular addition.
        """

        operands = self._qdt_get_operands(solution)

        for component in self._cipher.get_all_components():
            if self._is_nonlinear_component(component):
                operands.extend(
                    self._excluding_literals(
                        component.id,
                        solution["components_values"][component.id],
                        component.output_bit_size,
                    )
                )

        return operands

    def find_all_xor_quasidifferential_trails_with_fixed_weight(
        self,
        fixed_weight,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Return a list of solutions containing all the XOR
        quasidifferential trails having the ``fixed_weight`` total
        weight loss.

        Mirrors SmtXorDifferentialModel.find_all_xor_differential_trails_with_fixed_weight.
        A quasidifferential trail is fully determined by its
        primary-input boundary (difference AND mask -- see
        ``_qdt_get_operands``) together with the specific transition
        chosen at each NONLINEAR component (Sbox, AND, MODADD -- see
        ``_is_nonlinear_component``). Every other component (XOR,
        LinearLayer, Permutation, Rotate, MixColumn, ...) is fully
        deterministic given its inputs, on both the difference and the
        mask side, so it contributes no extra degrees of freedom to
        block on.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: trails = smt.find_all_xor_quasidifferential_trails_with_fixed_weight(0)
            sage: len(trails)
            96

        Ninety-six trails at weight 0 on one round of 8-bit Speck: they
        share the characteristic and differ in their masks, which is
        what makes a trail finer than a characteristic.

        """

        solutions, _ = self._solutions_at_weight(fixed_weight, fixed_values, [], solver_name, None, None)

        for solution in solutions:
            solution["test_name"] = "find_all_xor_quasidifferential_trails_with_fixed_weight"

        return solutions

    def find_all_xor_quasidifferential_trails_with_weight_at_most(
        self,
        max_weight,
        min_weight=0,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Return a list of solutions containing all the XOR
        quasidifferential trails having weight in
        ``[min_weight, max_weight]``.

        Mirrors SmtXorDifferentialModel.find_all_xor_differential_trails_with_weight_at_most.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: trails = smt.find_all_xor_quasidifferential_trails_with_weight_at_most(0)
            sage: len(trails)
            96

        """

        solutions_list = []

        for weight in range(min_weight, max_weight + 1):
            solutions = self.find_all_xor_quasidifferential_trails_with_fixed_weight(
                weight, fixed_values=fixed_values, solver_name=solver_name
            )

            for solution in solutions:
                solution["test_name"] = "find_all_xor_quasidifferential_trails_with_weight_at_most"

            solutions_list.extend(solutions)

        return solutions_list

    def estimate_fixed_key_probability(
        self,
        max_weight,
        min_weight=0,
        fixed_values=[],
        fixed_masks=None,
        solver_name=solvers.SOLVER_DEFAULT,
        key=None,
        max_trails_per_weight=None,
        timeout_per_weight=None,
    ):
        """
        Estimate a correlation/probability by summing the SIGNED
        correlation of every quasidifferential trail found with weight
        in [min_weight, max_weight] (Beyne & Rijmen, Theorem 4.1 /
        Equation 5).

        ``key`` selects WHICH probability is returned, and the two
        answers are different quantities:

        - ``key=None`` (default) -- the AVERAGE probability over all
          keys. A trail's contribution carries the factor
          chi_u(k) = (-1)^<u, k> for the mask ``u`` on the key input,
          and averaging that over all keys kills every trail with a
          non-zero key mask, so only the zero-key-mask trails are
          summed. Exact, and independent of any particular key.

        - ``key=<integer>`` -- the FIXED-KEY probability for that key:
          every trail is summed, each multiplied by its own
          chi_u(key) = (-1)^popcount(key_mask & key).

        Without the key factor the sum is neither: it is the fixed-key
        probability of the all-zero key, which is why ``key`` has no
        "just add them all up" setting. On a 6-round Simon
        characteristic of weight 12 the three correction trails carry
        non-zero key masks, and the fixed-key probability ranges from
        2^-12.83 to 2^-11.36 across key classes while the average stays
        at 2^-12.

        Each entry of ``"trails"`` records the trail's ``"key_mask"``,
        so a caller can re-evaluate the sum for other keys without
        re-solving.

        signed_correlation = sign * 2**(-weight), summed
        over all trails.

        INPUT:

        - ``max_weight`` / ``min_weight`` -- weight range to enumerate.
        - ``fixed_values`` -- ordinary DIFFERENCE constraints, built
          with set_fixed_variables as everywhere else in this codebase.
        - ``fixed_masks`` -- **list** (default: `None`); QDT MASK
          constraints, which set_fixed_variables cannot express (it
          only fixes ordinary difference bits, never qdt_-prefixed
          ones). Each entry is a dict:

          | {
          |     'component_id': 'plaintext',
          |     'bit_positions': range(64),
          |     'bit_values': [0] * 64
          |   }

          Theorem 4.1 requires the BOUNDARY masks to be zero
          (u_1 = u_{r+1} = 0) for the sum to equal the fixed-key
          probability of a specific differential -- pass those here,
          typically for the primary cipher inputs and the cipher
          output component.
        - ``solver_name`` -- the solver to use.
        - ``max_trails_per_weight`` -- **integer** (default: `None`);
          stop enumerating a weight after this many trails.
        - ``timeout_per_weight`` -- **integer** (default: `None`);
          stop enumerating a weight after this many seconds. Checked
          between solver calls, so one slow call can overrun it.

        A weight is reported truncated whenever a bound stopped the loop,
        even if no further trail existed: telling the two apart would
        take the very solver call the bound was there to avoid.

        Masks admit many trails per weight and each one costs a full
        solve, so on most ciphers the exhaustive sum does not terminate:
        those two bounds make the search finish. What they return is not
        the same quantity. **Only an exhaustive sum is the fixed-key
        probability of Theorem 4.1**; when a bound cuts a weight short
        the value is the contribution of the trails that were found and
        nothing more, and the result says so in ``"truncated"`` and
        ``"truncated_weights"``. A truncated sum of a signed series is
        not even an approximation with a known direction -- the trails
        left out can carry either sign.

        This method runs its own build-and-enumerate loop (rather than
        delegating to find_all_xor_quasidifferential_trails_with_weight_at_most)
        precisely so that fixed_masks can be injected into the model
        after each rebuild -- the same _model_constraints manipulation
        technique already used by the sign cross-validation tests.
        Nothing outside this file is modified, so no other model
        (differential, linear, ...) that shares
        fix_variables_value_constraints is affected.

        Inherits the same known scaling limits as the underlying
        blocking-clause enumeration: practical mainly when most
        DIFFERENCES are already fixed (e.g. matching a known
        differential characteristic, as in rectangle.py's own
        reference script), leaving primarily masks to enumerate.

        Returns a dict with:

        - ``"trails"``: one entry per found trail, with its ``"sign"``,
          ``"weight"``, and signed ``"correlation"``;
        - ``"estimated_probability"``: the sum of all signed
          correlations;
        - ``"num_trails"``: how many trails were found and summed;
        - ``"truncated"``: whether a bound cut any weight short, i.e.
          whether ``"estimated_probability"`` is a partial sum;
        - ``"truncated_weights"``: the weights it cut short.

        EXAMPLES::

            sage: from claasp.ciphers.toys.toyspn1 import ToySPN1
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT
            sage: toyspn = ToySPN1(number_of_rounds=2)

        The differential 0x02 -> 0x20, with its boundary masks pinned to
        zero as Theorem 4.1 requires:

            sage: fixed_values = [
            ....:     set_fixed_variables(INPUT_KEY, 'equal', range(6), (0,) * 6),
            ....:     set_fixed_variables(INPUT_PLAINTEXT, 'equal', range(6), integer_to_bit_list(0x02, 6, 'big')),
            ....:     set_fixed_variables('cipher_output_1_6', 'equal', range(6), integer_to_bit_list(0x20, 6, 'big')),
            ....: ]
            sage: fixed_masks = [
            ....:     {'component_id': INPUT_PLAINTEXT, 'bit_positions': range(6), 'bit_values': [0] * 6},
            ....:     {'component_id': 'cipher_output_1_6', 'bit_positions': range(6), 'bit_values': [0] * 6},
            ....: ]

        Averaged over all keys, only the two zero-key-mask trails
        survive out of the four found:

            sage: average = SmtXorQuasidifferentialModel(toyspn).estimate_fixed_key_probability(
            ....:     max_weight=8, fixed_values=fixed_values, fixed_masks=fixed_masks)
            sage: average['estimated_probability']
            0.125
            sage: average['num_trails'], average['num_trails_found']
            (2, 4)

        For a single key all four count, each with its own character,
        and the answer is a different number -- twice the average for
        key 0, and zero for key 2, where the two key-masked trails
        cancel the others exactly:

            sage: for key in (0x00, 0x02):
            ....:     result = SmtXorQuasidifferentialModel(toyspn).estimate_fixed_key_probability(
            ....:         max_weight=8, fixed_values=fixed_values, fixed_masks=fixed_masks, key=key)
            ....:     print(key, result['estimated_probability'], result['truncated'])
            0 0.25 False
            2 0.0 False

        Both values are exact: counting over all 64 plaintexts gives
        0.25 for key 0 and 0 for key 2.

        """

        if fixed_masks is None:
            fixed_masks = []

        key_input = INPUT_KEY if INPUT_KEY in self._cipher.inputs else None

        trails = []
        total = 0.0
        num_trails = 0
        num_trails_found = 0
        truncated_weights = []

        for weight in range(min_weight, max_weight + 1):

            solutions, truncated = self._solutions_at_weight(
                weight,
                fixed_values,
                fixed_masks,
                solver_name,
                max_trails_per_weight,
                timeout_per_weight,
            )

            if truncated:
                truncated_weights.append(weight)

            num_trails_found += len(solutions)

            for solution in solutions:
                trail = self._trail_record(solution, key_input, key)

                if trail is None:
                    continue

                trails.append(trail)
                total += trail["correlation"]
                num_trails += 1

        return {
            "trails": trails,
            "estimated_probability": total,
            "num_trails": num_trails,
            "num_trails_found": num_trails_found,
            "key": key,
            "averaged_over_keys": key is None,
            "truncated": bool(truncated_weights),
            "truncated_weights": truncated_weights,
        }

    def _solutions_at_weight(
        self,
        weight,
        fixed_values,
        fixed_masks,
        solver_name,
        max_trails_per_weight,
        timeout_per_weight,
    ):
        """
        Every trail of exactly ``weight``, and whether a bound cut the
        enumeration short.

        The build-and-enumerate loop lives here, rather than delegating
        to find_all_xor_quasidifferential_trails_with_weight_at_most, so
        that fixed_masks can be injected into the model after each
        rebuild -- set_fixed_variables cannot express a mask.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: from claasp.cipher_modules.models.smt import solvers
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1)
            sage: model = SmtXorQuasidifferentialModel(speck)
            sage: solutions, truncated = model._solutions_at_weight(0, [], [], solvers.SOLVER_DEFAULT, None, None)
            sage: len(solutions), truncated
            (96, False)

        A bound stops the enumeration, and says so:

            sage: solutions, truncated = model._solutions_at_weight(0, [], [], solvers.SOLVER_DEFAULT, 5, None)
            sage: len(solutions), truncated
            (5, True)
        """

        start_building_time = time.time()

        self.build_xor_quasidifferential_trail_model(
            weight=weight,
            fixed_variables=fixed_values,
        )

        self._constrain_weight_exactly(weight)

        mask_constraints = self._build_fixed_mask_constraints(fixed_masks)

        if mask_constraints:
            self._model_constraints = (
                self._model_constraints[: -len(constants.MODEL_SUFFIX)]
                + mask_constraints
                + constants.MODEL_SUFFIX
            )

        building_time = time.time() - start_building_time

        solutions = []
        started_at = time.time()

        solution = self.solve(XOR_QUASIDIFFERENTIAL, solver_name=solver_name)

        while solution["total_weight"] is not None:
            solution["building_time_seconds"] = building_time
            solutions.append(solution)

            if max_trails_per_weight is not None and len(solutions) >= max_trails_per_weight:
                return solutions, True

            if timeout_per_weight is not None and time.time() - started_at >= timeout_per_weight:
                return solutions, True

            clause = utils.smt_or(self._blocking_clause_operands(solution))
            self._model_constraints = (
                self._model_constraints[: -len(constants.MODEL_SUFFIX)]
                + [utils.smt_assert(clause)]
                + constants.MODEL_SUFFIX
            )

            solution = self.solve(XOR_QUASIDIFFERENTIAL, solver_name=solver_name)

        return solutions, False

    def _trail_record(
        self,
        solution,
        key_input,
        key,
    ):
        """
        One entry of ``"trails"``, or ``None`` for a trail the key
        factor kills.

        Averaging over keys kills every trail whose key mask is
        non-zero: chi_u averages to 0 unless u = 0. For a specific key
        nothing is killed, and the factor is that trail's own
        character.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: smt = SmtXorQuasidifferentialModel(SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1))
            sage: smt.build_xor_quasidifferential_trail_model(weight=0)
            sage: solution = smt.solve('xor_quasidifferential')
            sage: record = smt._trail_record(solution, 'key', 0)
            sage: sorted(record)
            ['correlation', 'key_mask', 'sign', 'weight']
            sage: record['weight']
            0.0
        """

        key_mask = 0

        if key_input is not None:
            key_mask = int(solution["components_values"][key_input].get("mask", "0x0"), 16)

        if key is None:
            key_factor = 0 if key_mask else 1
        else:
            key_factor = -1 if bin(key_mask & key).count("1") % 2 else 1

        if not key_factor:
            return None

        sign = self.compute_trail_sign(solution)
        weight = solution["total_weight"]

        return {
            "sign": sign,
            "weight": weight,
            "key_mask": key_mask,
            "correlation": key_factor * sign * (2.0 ** (-weight)),
        }

    def _build_fixed_mask_constraints(
        self,
        fixed_masks,
    ):
        """
        Turn a fixed_masks list (see estimate_fixed_key_probability)
        into SMT assertions on the qdt_-prefixed mask variables.

        This is the mask-side counterpart of
        fix_variables_value_constraints, kept local to this file rather
        than extending that shared method (which is used by the
        differential, linear and other models).

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = XorCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._build_fixed_mask_constraints([
            ....:     {'component_id': 'plaintext', 'bit_positions': range(2), 'bit_values': [1, 0]}
            ....: ])
            ['(assert qdt_plaintext_0)', '(assert (not qdt_plaintext_1))']
        """

        constraints = []

        for entry in fixed_masks:
            component_id = entry["component_id"]
            bit_positions = entry["bit_positions"]
            bit_values = entry["bit_values"]

            for position, value in zip(bit_positions, bit_values):
                variable_name = f"qdt_{component_id}_{position}"

                if value:
                    constraints.append(utils.smt_assert(variable_name))
                else:
                    constraints.append(utils.smt_assert(utils.smt_not(variable_name)))

        return constraints

    def solve(self, model_type, solver_name=solvers.SOLVER_DEFAULT):
        """
        Solve, and attach the raw variable assignment to the solution.

        Branch masks on forked wires belong to no component, so they
        have no ``components_values`` entry and ``compute_trail_sign``
        has to read them from the assignment. Keeping that assignment on
        the model alone makes the sign of a STORED solution wrong: every
        later ``solve`` overwrites the single slot, so
        ``compute_trail_sign(solutions[0])`` would pair trail 0's
        differences with the last trail's masks. Carrying it on the
        solution makes the argument mean what its name says.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: smt.build_xor_quasidifferential_trail_model(weight=0)
            sage: solution = smt.solve('xor_quasidifferential')
            sage: solution['total_weight']
            0.0

        The raw assignment travels with the solution, so the sign of a
        stored trail stays its own:

            sage: 'qdt_variable_assignment' in solution
            True

        """

        solution = super().solve(model_type, solver_name=solver_name)

        if solution["total_weight"] is None:
            solution["qdt_variable_assignment"] = {}
        else:
            solution["qdt_variable_assignment"] = dict(getattr(self, "_variable2value", {}))

        return solution

    def _parse_solver_output(
        self,
        variable2value,
    ):
        """
        Parse the solver output.

        The ordinary component value contains the XOR difference.
        The QDT masks are recorded alongside it (under the "mask"
        key of each component's solution) so that callers -- notably
        the blocking-clause logic in
        find_all_xor_quasidifferential_trails_with_fixed_weight --
        can distinguish trails that share the same differences but
        differ in their masks.

        The raw assignment is kept on the model as well: branch masks on
        forked wires belong to no component, so they have no
        ``components_values`` entry and ``_read_component_input_mask``
        has to read them from here.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: smt = SmtXorQuasidifferentialModel(SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1))
            sage: smt.build_xor_quasidifferential_trail_model(weight=0)
            sage: solution = smt.solve('xor_quasidifferential')
            sage: components, weight = smt._parse_solver_output(solution['qdt_variable_assignment'])
            sage: weight, 'mask' in components['plaintext']
            (0, True)
        """

        self._variable2value = variable2value

        out_suffix = ""

        components_solutions = self._get_cipher_inputs_components_solutions(
            out_suffix,
            variable2value,
        )

        # The cipher-input entries built by _get_cipher_inputs_components_solutions
        # only carry the ordinary difference value; add their QDT mask
        # value too, using the same qdt_{input_id}_{position} naming
        # used everywhere else in this model.
        for input_id, bit_len in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            if input_id not in components_solutions:
                continue

            components_solutions[input_id]["mask"] = self._mask_hex_value(input_id, bit_len, variable2value)

        total_weight = 0

        for component in self._cipher.get_all_components():
            hex_value = utils.get_component_hex_value(
                component,
                out_suffix,
                variable2value,
            )

            mask_hex_value = self._mask_hex_value(component.id, component.output_bit_size, variable2value)

            weight = self.calculate_component_weight(
                component,
                out_suffix,
                variable2value,
            )

            component_solution = set_component_solution(
                hex_value,
                weight,
            )

            component_solution["mask"] = mask_hex_value

            components_solutions[f"{component.id}{out_suffix}"] = component_solution

            total_weight += weight

        return (
            components_solutions,
            total_weight,
        )

    @staticmethod
    def _mask_hex_value(
        identifier,
        bit_size,
        variable2value,
    ):
        """
        The mask on ``identifier`` -- a cipher input or a component -- as a
        hex string, read from the ``qdt_<identifier>_<i>`` variables of a
        solver assignment. Bits the assignment does not mention are 0.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: SmtXorQuasidifferentialModel._mask_hex_value('xor_0_0', 2, {'qdt_xor_0_0_0': 1, 'qdt_xor_0_0_1': 0})
            '0x2'
        """

        value = 0

        for position in range(bit_size):
            value = (value << 1) | variable2value.get(f"qdt_{identifier}_{position}", 0)

        hex_digits = bit_size // 4 + (bit_size % 4 != 0)

        return f"{value:#0{hex_digits + 2}x}"

    # TRAIL SIGN (post-processing on an already-solved trail)
    #
    # Everything above finds trails and their WEIGHT (-log2|correlation|).
    # This section computes the SIGN of the correlation for an
    # already-solved trail, mirroring rectangle.py's compute_sign,
    # common.py's compute_sign_speck, and simon_32.py's
    # correlation_sign_and -- but as pure Python post-processing on a
    # solved `solution` dict, exactly like those reference scripts do,
    # rather than as new SMT constraints (sign never affects the
    # weight-based SAT search itself, only the final numeric
    # correlation once a trail is found).
    #
    # Per Definition 4.1, a trail's correlation is the PRODUCT of each
    # component's local D^Fi coefficient, so the sign is the product of
    # each component's local sign. Only SBOX, AND, MODADD (Theorem 5.1
    # / 5.2's proofs) and CONSTANT (Theorem 3.2 (4)'s chi_v(t) factor)
    # contribute a sign other than +1; every other currently-implemented
    # component (XOR of data branches, LinearLayer, Permutation, Rotate,
    # MixColumn, CipherOutput, IntermediateOutput) is a pure linear or
    # identity map with a delta-function (always-nonnegative)
    # correlation (Theorem 3.2 (5)), contributing +1.

    def compute_trail_sign(
        self,
        solution,
    ):
        """
        Compute the overall correlation sign of an already-solved
        quasidifferential trail, e.g. as returned by
        find_one_xor_quasidifferential_trail or
        find_one_xor_quasidifferential_trail_with_fixed_weight.

        Returns +1 or -1.

        Reads the mask assignment carried by ``solution`` itself, so a
        solution stored earlier -- one element of the list returned by
        ``find_all_xor_quasidifferential_trails_with_fixed_weight``, say
        -- still gets its own sign and not the latest solve's.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: smt.build_xor_quasidifferential_trail_model(weight=0)
            sage: solution = smt.solve('xor_quasidifferential')
            sage: smt.compute_trail_sign(solution)
            1

        """

        assignment = solution.get("qdt_variable_assignment")
        previous_assignment = getattr(self, "_variable2value", None)

        if assignment is not None:
            self._variable2value = assignment

        try:
            return self._compute_trail_sign(solution)
        finally:
            if assignment is not None:
                self._variable2value = previous_assignment

    def _compute_trail_sign(self, solution):
        """
        The sign of a solved trail, read with the assignment the model currently holds; see ``compute_trail_sign``.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: smt = SmtXorQuasidifferentialModel(SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1))
            sage: smt.build_xor_quasidifferential_trail_model(weight=0)
            sage: solution = smt.solve('xor_quasidifferential')
            sage: smt._compute_trail_sign(solution) in (-1, 1)
            True
        """

        components_solutions = solution["components_values"]

        sign = 1

        for component in self._cipher.get_all_components():
            local_sign = self._local_sign_rule(component)

            if local_sign is not None:
                sign *= local_sign(component, components_solutions)

        return sign

    def _local_sign_rule(self, component):
        """
        The rule giving this component's local sign, or ``None`` when it
        has none -- a pure linear map or the identity contributes +1 and
        drops out of the product.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: smt = SmtXorQuasidifferentialModel(speck)
            sage: smt._local_sign_rule(speck.component_from_id('modadd_0_1')).__name__
            '_modadd_local_sign'
            sage: smt._local_sign_rule(speck.component_from_id('rot_0_0')) is None
            True
        """

        if SBOX in component.type:
            return self._sbox_local_sign

        if CONSTANT in component.type:
            return self._constant_local_sign

        if component.type != WORD_OPERATION:
            return None

        return {
            "AND": self._and_local_sign,
            "MODADD": self._modadd_local_sign,
            "MODSUB": self._modsub_local_sign,
            "NOT": self._not_local_sign,
            "OR": self._or_local_sign,
        }.get(component.description[0])

    @staticmethod
    def _parity(
        value,
    ):
        """
        Parity of the number of set bits of ``value``.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: SmtXorQuasidifferentialModel._parity(0b1011)
            1
        """

        return bin(value).count("1") % 2

    def _bit_size_of(
        self,
        id_,
    ):
        """
        Return the bit width of a cipher input or a component's own
        output, given only its id string.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = XorCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._bit_size_of('plaintext'), smt._bit_size_of('xor_0_0')
            (2, 2)
        """

        for input_id, input_bit_size in zip(
            self._cipher.inputs,
            self._cipher.inputs_bit_size,
        ):
            if input_id == id_:
                return input_bit_size

        for component in self._cipher.get_all_components():
            if component.id == id_:
                return component.output_bit_size

        raise ValueError(f"{id_}: unknown cipher input or component id")

    def _read_component_input_integer(
        self,
        component,
        field,
        components_solutions,
    ):
        """
        Reconstruct the full input integer (difference "value" or QDT
        "mask") for a component, by reading the requested bits from its
        upstream producers' (or primary inputs') already-solved hex
        value/mask, in the same order used everywhere else in this
        model to build input bit ids (_generate_input_ids,
        _qdt_input_bit_ids): for each (input_id, bit_positions) pair in
        component.input_id_links / component.input_bit_positions, in
        order, each position in bit_positions in order (position 0 =
        MSB of the upstream id's own value/mask).

        For ``field="mask"`` on a FORKED wire the value must come from
        this component's own BRANCH variable, not from the producer's
        mask: the producer's mask is the XOR of all branches, while the
        component's constraints were written over its own branch. Using
        the producer's value there yields a transition the solver never
        asserted -- for an sbox, one whose QDT coefficient may be zero.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = XorCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: solution = {'plaintext': {'value': '0x2'}, 'key': {'value': '0x1'}}
            sage: smt._read_component_input_integer(cipher.component_from_id('xor_0_0'), 'value', solution)
            9

        The plaintext bits ``10`` followed by the key bits ``01``.
        """

        if field == "mask":
            return self._read_component_input_mask(component)

        result = 0

        for input_id, bit_positions in zip(
            component.input_id_links,
            component.input_bit_positions,
        ):
            upstream_size = self._bit_size_of(input_id)
            upstream_value = int(components_solutions[input_id][field], 16)

            for position in bit_positions:
                bit = (upstream_value >> (upstream_size - 1 - position)) & 1
                result = (result << 1) | bit

        return result

    def _read_component_input_mask(
        self,
        component,
    ):
        """
        Reconstruct a component's input MASK from the solver's variable
        assignment, using the branch variable on forked wires.

        Reads ``self._variable2value``, populated by
        ``_parse_solver_output``, because branch variables have no
        ``components_values`` entry of their own: they belong to no
        component.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = XorCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._variable2value = {'qdt_plaintext_0': 1, 'qdt_plaintext_1': 0, 'qdt_key_0': 0, 'qdt_key_1': 1}
            sage: smt._read_component_input_mask(cipher.component_from_id('xor_0_0'))
            9
        """

        variable2value = getattr(self, "_variable2value", None)

        if not variable2value:
            raise ValueError(
                f"{component.id}: no solver assignment available for mask "
                f"reconstruction -- _parse_solver_output must run first."
            )

        result = 0

        for input_id, position, read_index in self._component_wire_reads(component):
            variable = self.qdt_input_bit_id(component, input_id, position, read_index)
            result = (result << 1) | variable2value.get(variable, 0)

        return result

    def _read_component_input_operands(
        self,
        component,
        field,
        components_solutions,
        num_operands,
        word_size,
    ):
        """
        Like _read_component_input_integer, but split into
        `num_operands` separate word_size-bit integers (one per
        AND/MODADD operand), matching the same
        [:word_size], [word_size:2*word_size], ... slicing convention
        used by And/ModAdd's own
        smt_xor_quasidifferential_propagation_constraints.

        Delegates the reconstruction to _read_component_input_integer,
        which on forked wires reads the component's own BRANCH mask
        rather than the producer's -- see the note there.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = XorCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: solution = {'plaintext': {'value': '0x2'}, 'key': {'value': '0x1'}}
            sage: smt._read_component_input_operands(cipher.component_from_id('xor_0_0'), 'value', solution, 2, 2)
            [2, 1]
        """

        full_value = self._read_component_input_integer(component, field, components_solutions)
        total_bits = num_operands * word_size
        mask = (1 << word_size) - 1

        return [
            (full_value >> (total_bits - (index + 1) * word_size)) & mask
            for index in range(num_operands)
        ]

    def _sbox_local_sign(
        self,
        component,
        components_solutions,
    ):
        """
        Look up the sign of the sbox's QDT coefficient at the specific
        (a, u, b, v) point the solver found, directly from the cached
        deinterleaved QDT matrix (see Sbox.smt_xor_quasidifferential_propagation_constraints,
        which populates model.sboxes_qdt_matrices).

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = SboxCipher(bit_size=2, lookup_table=[0, 1, 3, 2])
            sage: sbox = cipher.component_from_id('sbox_0_0')
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: _ = sbox.smt_xor_quasidifferential_propagation_constraints(smt)
            sage: smt._variable2value = {'qdt_plaintext_0': 0, 'qdt_plaintext_1': 0}
            sage: smt._sbox_local_sign(sbox, {'plaintext': {'value': '0x1'}, 'sbox_0_0': {'value': '0x1', 'mask': '0x0'}})
            1
        """

        cache_key = str(component.description)
        qdt = self.sboxes_qdt_matrices.get(cache_key)

        if qdt is None:
            raise ValueError(
                f"{component.id}: no cached QDT matrix found for sign "
                f"lookup -- was smt_xor_quasidifferential_propagation_constraints "
                f"called for this sbox before solving?"
            )

        n = component.input_bit_size
        m = component.output_bit_size

        a = self._read_component_input_integer(component, "value", components_solutions)
        u = self._read_component_input_integer(component, "mask", components_solutions)
        b = int(components_solutions[component.id]["value"], 16)
        v = int(components_solutions[component.id]["mask"], 16)

        coefficient = qdt[(2**m) * b + v, (2**n) * a + u]

        if coefficient == 0:
            raise ValueError(
                f"{component.id}: the solved (a={a:#x}, u={u:#x}, "
                f"b={b:#x}, v={v:#x}) transition has a zero QDT "
                f"coefficient -- this should never happen for a valid "
                f"SAT solution."
            )

        return 1 if coefficient > 0 else -1

    def _two_operand_values(
        self,
        component,
        components_solutions,
    ):
        """
        ``(a, b, c, u, v, w, word_size)`` of a solved two-operand word
        operation: input differences, output difference, input masks,
        output mask. The sign rules of AND, OR, MODADD and MODSUB all
        start from these.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = AndCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._variable2value = {'qdt_plaintext_0': 0, 'qdt_plaintext_1': 1, 'qdt_key_0': 1, 'qdt_key_1': 0}
            sage: solution = {'plaintext': {'value': '0x3'}, 'key': {'value': '0x1'},
            ....:             'and_0_0': {'value': '0x1', 'mask': '0x3'}}
            sage: smt._two_operand_values(cipher.component_from_id('and_0_0'), solution)
            (3, 1, 1, 1, 2, 3, 2)
        """

        if component.description[1] != 2:
            raise NotImplementedError(
                f"{component.id}: sign computation for {component.description[0]} is only "
                f"implemented for 2 operands."
            )

        word_size = component.output_bit_size

        a, b = self._read_component_input_operands(component, "value", components_solutions, 2, word_size)
        u, v = self._read_component_input_operands(component, "mask", components_solutions, 2, word_size)
        c = int(components_solutions[component.id]["value"], 16)
        w = int(components_solutions[component.id].get("mask", "0x0"), 16)

        return a, b, c, u, v, w, word_size

    def _and_local_sign(
        self,
        component,
        components_solutions,
    ):
        """
        Sign of a solved AND transition (Theorem 5.1).

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = AndCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._variable2value = {'qdt_plaintext_0': 0, 'qdt_plaintext_1': 1, 'qdt_key_0': 1, 'qdt_key_1': 0}
            sage: solution = {'plaintext': {'value': '0x3'}, 'key': {'value': '0x1'},
            ....:             'and_0_0': {'value': '0x1', 'mask': '0x3'}}
            sage: smt._and_local_sign(cipher.component_from_id('and_0_0'), solution)
            1
        """

        a, b, c, u, v, _, word_size = self._two_operand_values(component, components_solutions)

        return self._and_sign_word(a, b, c, u, v, word_size)

    def _modadd_local_sign(
        self,
        component,
        components_solutions,
    ):
        """
        Sign of a solved MODADD transition (Theorem 5.2).

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.modadd_cipher import ModaddCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = ModaddCipher(word_bit_size=2, number_of_inputs=2, modulus=4)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._variable2value = {'qdt_plaintext_0': 0, 'qdt_plaintext_1': 0, 'qdt_key_0': 0, 'qdt_key_1': 0}
            sage: solution = {'plaintext': {'value': '0x0'}, 'key': {'value': '0x0'},
            ....:             'modadd_0_0': {'value': '0x0', 'mask': '0x0'}}
            sage: smt._modadd_local_sign(cipher.component_from_id('modadd_0_0'), solution)
            1
        """

        a, b, c, u, v, w, word_size = self._two_operand_values(component, components_solutions)

        return self._modadd_sign_word(a, b, c, u, v, w, word_size)

    def _not_local_sign(
        self,
        component,
        components_solutions,
    ):
        """
        chi_v(t) with t = all-ones: NOT is the affine map x -> x xor 1,
        so by Theorem 3.2 (4) its only contribution is the sign factor
        (-1)^(v . 1) = (-1)^popcount(v), where v is the component's
        output mask. Differences and masks themselves pass through
        unchanged (see
        Not.smt_xor_quasidifferential_propagation_constraints).

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = NotCipher(bit_size=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: component = cipher.component_from_id('not_0_0')
            sage: smt._not_local_sign(component, {'not_0_0': {'mask': '0x1'}})
            -1
            sage: smt._not_local_sign(component, {'not_0_0': {'mask': '0x3'}})
            1
        """

        v = int(components_solutions[component.id]["mask"], 16)

        return -1 if self._parity(v) else 1

    def _or_local_sign(
        self,
        component,
        components_solutions,
    ):
        """
        Sign of a solved OR transition: AND's sign times (-1)^(u + v + w).

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.or_cipher import OrCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = OrCipher(word_bit_size=2, number_of_inputs=2)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._variable2value = {'qdt_plaintext_0': 0, 'qdt_plaintext_1': 1, 'qdt_key_0': 0, 'qdt_key_1': 0}
            sage: solution = {'plaintext': {'value': '0x0'}, 'key': {'value': '0x0'},
            ....:             'or_0_0': {'value': '0x0', 'mask': '0x0'}}
            sage: smt._or_local_sign(cipher.component_from_id('or_0_0'), solution)
            -1

        One input mask bit is set, so the parity of ``u + v + w`` is odd.
        """

        a, b, c, u, v, w, word_size = self._two_operand_values(component, components_solutions)

        return self._or_sign_word(a, b, c, u, v, w, word_size)

    def _modsub_local_sign(
        self,
        component,
        components_solutions,
    ):
        """
        Sign of a solved MODSUB transition, computed as MODADD with permuted roles.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.modsub_cipher import ModsubCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = ModsubCipher(word_bit_size=2, number_of_inputs=2, modulus=4)
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: smt._variable2value = {'qdt_plaintext_0': 0, 'qdt_plaintext_1': 0, 'qdt_key_0': 0, 'qdt_key_1': 0}
            sage: solution = {'plaintext': {'value': '0x0'}, 'key': {'value': '0x0'},
            ....:             'modsub_0_0': {'value': '0x0', 'mask': '0x0'}}
            sage: smt._modsub_local_sign(cipher.component_from_id('modsub_0_0'), solution)
            1
        """

        a, b, c, u, v, w, word_size = self._two_operand_values(component, components_solutions)

        # z = x - y is x = z + y, so MODSUB(a, b, c, u, v, w) is MODADD
        # with the roles of the first input and the output swapped.
        return self._modadd_sign_word(c, b, a, w, v, u, word_size)

    @staticmethod
    def _or_sign_word(
        a,
        b,
        c,
        u,
        v,
        w,
        word_size,
    ):
        """
        Word-level sign of a bitwise-OR quasidifferential transition.

        OR is AND conjugated by complementation
        (x1 | x2 = ~(~x1 & ~x2)). Complementation does not change
        differences, so OR's validity conditions and |coefficients| --
        and hence its WEIGHT -- are IDENTICAL to AND's; only the sign
        differs, by the translation factors of Theorem 3.2 (4).

        Verified by exhaustive brute force of Equation (4) on the
        1-bit case (all 64 combinations: same validity, same absolute
        value, sign ratio exactly (-1)^(u+v+w) per bit), then
        cross-checked at word level against the per-bit tensor product
        over 200000 random 4-bit vectors (8403 valid transitions, 0
        mismatches).

        Note that unlike AND's sign, OR's DOES depend on the output
        mask w.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: SmtXorQuasidifferentialModel._or_sign_word(0, 0, 0, 1, 0, 0, 1)
            -1
        """

        base = SmtXorQuasidifferentialModel._and_sign_word(a, b, c, u, v, word_size)

        correction_parity = (
            SmtXorQuasidifferentialModel._parity(u)
            + SmtXorQuasidifferentialModel._parity(v)
            + SmtXorQuasidifferentialModel._parity(w)
        ) % 2

        return base * ((-1) ** correction_parity)

    def _constant_local_sign(
        self,
        component,
        components_solutions,
    ):
        """
        chi_v(t) = (-1)^(v . t): Theorem 3.2 (4), the translation-sign
        factor for a constant addition. The constant's own difference
        contribution is always 0 (see Constant.smt_xor_quasidifferential_propagation_constraints),
        so only its mask v and its known value t matter here.

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.constant_cipher import ConstantCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = ConstantCipher(output_bit_size=3, value=2)
            sage: constant = cipher.component_from_id('constant_0_0')
            sage: constant.description
            ['0b010']
            sage: smt = SmtXorQuasidifferentialModel(cipher)

        The mask ``0b010`` sees the one set bit of the constant, so the sign flips;
        the mask ``0b001`` does not see it:

            sage: smt._constant_local_sign(constant, {'constant_0_0': {'mask': '0x2'}})
            -1
            sage: smt._constant_local_sign(constant, {'constant_0_0': {'mask': '0x1'}})
            1
        """

        # Base 0 reads both forms CLAASP uses for constants: '0x...' and
        # '0b...'. Base 16 would accept '0b010' silently, as 0xb010.
        t = int(component.description[0], 0)
        v = int(components_solutions[component.id]["mask"], 16)

        return -1 if self._parity(t & v) else 1

    @staticmethod
    def _and_sign_word(
        a,
        b,
        c,
        u,
        v,
        word_size,
    ):
        """
        Word-level sign of a bitwise-AND quasidifferential transition
        (Beyne & Rijmen, Theorem 5.1 and its proof in Appendix A.3),
        applied bit-independently across the whole word via Theorem
        3.2 (2) ("boxed maps": the sign of the word-level transition is
        the product of the per-bit signs, since each bit's AND is an
        independent sub-function acting on its own disjoint pair of
        input bits).

        Transliterated from simon_32.py's correlation_sign_and (the
        paper authors' own reference implementation) and verified
        against a direct brute-force evaluation of Equation (4) for
        the 1-bit case (29 valid transitions, 0 mismatches) before
        being encoded here.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: SmtXorQuasidifferentialModel._and_sign_word(0, 0, 0, 0, 0, 2)
            1
            sage: SmtXorQuasidifferentialModel._and_sign_word(0, 0, 0, 1, 1, 1)
            -1
        """

        mask = (1 << word_size) - 1

        comp_a = a ^ mask
        comp_b = b ^ mask
        comp_c = c ^ mask

        term1 = ((comp_a & u) ^ (c & v)) & ((comp_b & v) ^ (c & u))
        term2 = (u & v) & (c ^ (a & b & comp_c))

        p = SmtXorQuasidifferentialModel._parity(term1)
        q = SmtXorQuasidifferentialModel._parity(term2)

        return -1 if (p ^ q) else 1

    @staticmethod
    def _modadd_sign_word(
        a,
        b,
        c,
        u,
        v,
        w,
        word_size,
    ):
        """
        Word-level sign of a modular-addition quasidifferential
        transition (Beyne & Rijmen, Theorem 5.2), computed via the
        same AND-sign formula applied to the primed variables
        (a' = b xor c, b' = a xor c, c' = M+(a xor b xor c),
        u' = u xor w, v' = v xor w) -- since MODADD's theory is
        derived via CCZ-equivalence to a quadratic function "nearly
        the same as bitwise-and" (paper, Section 5.2 / Appendix A.4).

        Transliterated from common.py's compute_sign_speck (the paper
        authors' own reference implementation), using the SAME
        u' = u xor w / v' = v xor w substitution already used, and
        already verified, for the validity/weight constraints in
        ModAdd.smt_xor_quasidifferential_propagation_constraints --
        NOT compute_sign_speck's extra inter-round rotation logic,
        which is specific to how Speck wires masks between rounds and
        is already handled separately by claasp's own Rotate
        components.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: SmtXorQuasidifferentialModel._modadd_sign_word(0, 0, 0, 0, 0, 0, 2)
            1
        """

        mask = (1 << word_size) - 1

        abc_xor = a ^ b ^ c
        shifted_left = (abc_xor << 1) & mask
        c_prime = (abc_xor ^ shifted_left) >> 1

        a_prime = b ^ c
        b_prime = a ^ c
        u_prime = u ^ w
        v_prime = v ^ w

        return SmtXorQuasidifferentialModel._and_sign_word(
            a_prime, b_prime, c_prime, u_prime, v_prime, word_size
        )


