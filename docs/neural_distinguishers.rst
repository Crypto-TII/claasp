Neural distinguisher
====================

CLAASP defines neural datasets and experiment requests independently of a
machine-learning framework. Generating data therefore requires neither NumPy
nor TensorFlow, and an optional training driver can consume the same immutable
contract.

The black-box experiment labels real primitive outputs with one and random
outputs with zero. Features contain the varied input followed by the output,
using MSB-first bits:

.. doctest::

   >>> from claasp.analysis import black_box_dataset
   >>> from claasp.primitives import Speck
   >>> primitive = Speck(number_of_rounds=1)
   >>> data = black_box_dataset(primitive, "plaintext", samples=4, seed=41)
   >>> data.kind, data.sample_count, data.feature_width
   ('black_box', 4, 64)
   >>> data == black_box_dataset(primitive, "plaintext", samples=4, seed=41)
   True

The differential generator labels related pairs with one and independently
random pairs with zero:

.. doctest::

   >>> from claasp.analysis import xor_differential_dataset
   >>> data = xor_differential_dataset(
   ...     primitive, {"plaintext": 0x00400000, "key": 0}, samples=4, seed=7
   ... )
   >>> data.kind, data.feature_width
   ('xor_differential', 64)

``NeuralExperiment`` records architecture, split, seed, epochs, and batch
size. An optional framework adapter implements ``NeuralTrainingDriver`` and
returns ``NeuralExperimentResult``. Framework imports, tensor conversion,
devices, training, and checkpoints belong to that driver rather than the core
contracts.

Dataset partitions and run provenance
-------------------------------------

Splits are explicit sample-index contracts rather than framework-owned hidden
state. They may be label-stratified and are reproducible from their own seed:

.. doctest::

   >>> from claasp.analysis import deterministic_partition, dataset_digest
   >>> partition = deterministic_partition(
   ...     data, validation_fraction=0.25, testing_fraction=0.25,
   ...     seed=19, stratified=False,
   ... )
   >>> partition.training, partition.validation, partition.testing
   ((0, 2), (1,), (3,))
   >>> len(dataset_digest(data))
   64

``NeuralRunProvenance`` binds a run to the exact dataset digest, primitive
realization, dataset and partition seeds, driver version, and canonical scalar
options. ``NeuralRun.validate_for`` rejects stale datasets and partitions that
do not cover every sample exactly once.

Round and component projections
--------------------------------

``component_output_dataset`` and ``xor_differential_component_dataset`` can
train or evaluate a distinguisher on an intermediate round state, a round
key, or an arbitrary component instead of only the primitive's final output.
They read the requested component's value directly from the primitive's typed
``ExecutionTrace`` (see ``claasp.annotations``), produced by
``Primitive.evaluate_with_trace``. ``round_component_ids`` selects every
component CLAASP added while building one round, so passing it as
``component_ids`` projects that round's full state, while a single id targets
one exact wire:

.. doctest::

   >>> from claasp.analysis import component_output_dataset, round_component_ids
   >>> reduced = Speck(number_of_rounds=2)
   >>> round_component_ids(reduced, 0)[:3]
   ('rotate_0_0', 'modular_add_0_1', 'xor_0_2')
   >>> right_word = reduced.graph.round_outputs[0][1].owner_id
   >>> projected = component_output_dataset(
   ...     reduced, "plaintext", right_word, samples=4, seed=5
   ... )
   >>> projected.kind, projected.sample_count, projected.feature_width
   ('black_box', 4, 48)
   >>> projected.feature_names[-1]
   'xor_0_4[15]'

``xor_differential_component_dataset`` projects the same way for related
input pairs, replacing ``xor_differential_dataset``'s final-output pair with
one from a chosen component. Both functions validate every id against the
primitive's graph up front and raise ``KeyError`` for an id that is not one
of its inputs or components.

Optional ML training drivers
-----------------------------

``NeuralTrainingDriver`` implementations live under
``claasp.drivers.neural`` and are never imported by
``claasp``'s core. The bundled ``SklearnMLPDriver`` trains a small
``sklearn.neural_network.MLPClassifier``. The optional ``ml`` extra (installed
with ``pip install 'claasp[ml]'``) uses scikit-learn; an equivalent TensorFlow,
Keras, or PyTorch driver can implement the same protocol. The
scikit-learn import happens inside ``train``, so constructing a
``SklearnMLPDriver`` never requires the extra -- only calling ``train`` does::

   from claasp.drivers.neural import SklearnMLPDriver

   dataset = xor_differential_dataset(
       reduced, {"plaintext": 0x00400000, "key": 0}, samples=3000, seed=11
   )
   experiment = NeuralExperiment("mlp", epochs=15, batch_size=64, seed=2)
   result = SklearnMLPDriver(hidden_layer_sizes=(32, 32)).train(dataset, experiment)
   result.validation_accuracy[-1]  # tolerance-based evidence, e.g. > 0.8

``result.validation_accuracy`` is tolerance/threshold-based experimental
evidence, never an exact cross-platform fixture: the dedicated
``neural-ml-execution`` CI job trains this same reduced-round Speck32/64
differential distinguisher and only asserts that the final accuracy clears a
documented threshold, not a specific value.

Automated difference search and staged training
-----------------------------------------------

``primitive.analysis.find_good_neural_input_difference`` provides the seeded
evolutionary input-difference search formerly exposed by AutoND.
``train_staged_neural_distinguisher`` trains successive reduced-round graphs
until validation accuracy falls below the configured statistical threshold,
and ``run_autond`` composes both phases. Dataset generation, candidate ranking,
round limits, and seeds are explicit; a real TensorFlow CI job constructs both
legacy architectures and performs a bounded training run.
