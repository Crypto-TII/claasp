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
