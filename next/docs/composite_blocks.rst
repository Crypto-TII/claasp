Reusable composite blocks
=========================

A composite block is an immutable, typed graph recipe with named inputs and
outputs.  Instantiating it in a primitive retains a queryable scope while
lowering ordinary leaf components into the canonical graph.  Consequently the
same block can be evaluated alone, reused many times, or passed to an existing
analysis or constraint representation.

Building AES from blocks
------------------------

``AESKeySchedule`` and ``AESRound`` are normal reusable definitions.  The
following function assembles an AES-derived graph explicitly.  The canonical
``AES`` source is deliberately direct and pseudocode-oriented; this example
shows the alternative reusable-block style used by ``CustomAES``.

.. doctest::

   >>> from claasp_next import Primitive
   >>> from claasp_next.components import Add
   >>> from claasp_next.composites import AESKeySchedule, AESRound
   >>> def block_aes128():
   ...     schedule_definition = AESKeySchedule(128, 10)
   ...     middle_round = AESRound(mix_columns=True)
   ...     final_round = AESRound(mix_columns=False)
   ...     primitive = Primitive("aes_from_blocks", {
   ...         "plaintext": middle_round.inputs["state"],
   ...         "key": schedule_definition.inputs["key"],
   ...     })
   ...     primitive.add_round()
   ...     key_schedule = primitive.add_composite(
   ...         schedule_definition, {"key": primitive.input("key")},
   ...         scope_id="key_schedule")
   ...     state = primitive.add_component(Add((
   ...         primitive.input("plaintext"), key_schedule.output[0])))
   ...     for number in range(1, 11):
   ...         primitive.add_round()
   ...         definition = final_round if number == 10 else middle_round
   ...         block = primitive.add_composite(definition, {
   ...             "state": state,
   ...             "round_key": key_schedule.output[number],
   ...         }, scope_id=f"round_{number}")
   ...         state = block.output()
   ...     primitive.set_output(state)
   ...     return primitive
   >>> built = block_aes128()
   >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
   >>> key = 0x000102030405060708090A0B0C0D0E0F
   >>> f"{built.evaluate(plaintext, key):032x}"
   '69c4e0d86a7b0430d8cdb78070b4c55a'
   >>> built.scope("round_1").definition.name
   'AESRound'
   >>> built.scope("key_schedule/sub_word_1").definition.name
   'ParallelSBoxLayer'

Experimental changes use ``CustomAES`` so results cannot be mistaken for
standard AES.  A replacement table applies to both round SubBytes and SubWord
in the key schedule. ``ToyAES`` has a different purpose: small teaching and
exhaustive-analysis instances.

.. doctest::

   >>> from claasp_next.primitives import AES, CustomAES
   >>> alternate = CustomAES(sbox_table=tuple(range(256)))
   >>> no_mix = CustomAES(include_mix_columns=False, number_of_rounds=2)
   >>> alternate.family_name, no_mix.family_name
   ('custom_aes', 'custom_aes')
   >>> dict(no_mix.provenance)
   {'derived_from': 'AES', 'modifications': 'removed MixColumns'}
   >>> any(component.component_id.endswith("/mix_columns") for component in no_mix.components)
   False
   >>> no_mix.evaluate(plaintext, key) != AES(number_of_rounds=2).evaluate(plaintext, key)
   True

Evaluating and modelling a block
--------------------------------

A definition evaluates independently.  Named outputs are useful for a block
such as the ChaCha quarter round.

.. doctest::

   >>> from claasp_next.composites import ChaChaQuarterRound
   >>> quarter_round = ChaChaQuarterRound()
   >>> hex(quarter_round.evaluate(
   ...     0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567))
   '0xea2a92f4cb1cf8ce4581472e5881c4bb'
   >>> hex(quarter_round.evaluate(
   ...     0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567, output="a"))
   '0xea2a92f4'

Existing representations consume ``definition.as_primitive()``.  Here a
two-nibble parallel S-box layer is lowered to a Boolean CNF formula; no solver
logic lives in the block itself.

.. doctest::

   >>> from claasp_next.composites import ParallelSBoxLayer
   >>> from claasp_next.representations.constraints.sat import BooleanCNFModel
   >>> present_sbox = (0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2)
   >>> layer = ParallelSBoxLayer(present_sbox, 2)
   >>> hex(layer.evaluate(0x0F))
   '0xc2'
   >>> formula = BooleanCNFModel(layer.as_primitive()).cnf_formula()
   >>> formula.variable_count, formula.clause_count
   (16, 128)
   >>> quarter_formula = BooleanCNFModel(quarter_round.as_primitive()).cnf_formula()
   >>> quarter_formula.variable_count > 128 and quarter_formula.clause_count > 0
   True

An instance is also a scope.  ``scope.value_from(result, name)`` reads one of
its named boundaries from a parent evaluation, while ``scope.as_primitive()``
projects the reusable definition for focused evaluation or modelling.
