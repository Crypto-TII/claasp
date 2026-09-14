Neural distinguisher experiments
================================

CLAASP defines neural datasets and experiment requests independently of a
machine-learning framework. Generating data therefore requires neither NumPy
nor TensorFlow, and an optional training driver can consume the same immutable
contract.

The black-box experiment labels real primitive outputs with one and random
outputs with zero. Features contain the varied input followed by the output,
using MSB-first bits:

.. doctest::

   >>> from claasp_next.analysis import black_box_dataset
   >>> from claasp_next.ciphers import SpeckBlockCipher
   >>> primitive = SpeckBlockCipher(number_of_rounds=1)
   >>> data = black_box_dataset(primitive, "plaintext", samples=4, seed=41)
   >>> data.kind, data.sample_count, data.feature_width
   ('black_box', 4, 64)
   >>> data == black_box_dataset(primitive, "plaintext", samples=4, seed=41)
   True

The differential generator labels related pairs with one and independently
random pairs with zero:

.. doctest::

   >>> from claasp_next.analysis import xor_differential_dataset
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

   >>> from claasp_next.analysis import deterministic_partition, dataset_digest
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
