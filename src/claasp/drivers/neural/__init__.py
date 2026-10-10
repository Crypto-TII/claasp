"""Optional machine-learning training drivers for neural distinguishers.

Importing this package never requires scikit-learn or any other ML
framework; only calling a driver's ``train`` method does (implemented in
``claasp.drivers.neural.sklearn_driver``).
"""

from claasp.drivers.neural.sklearn_driver import SklearnMLPDriver
from claasp.drivers.neural.tensorflow_driver import (
    TensorFlowDistinguisherDriver,
    build_dbitnet,
    build_gohr_resnet,
)

__all__ = [
    "SklearnMLPDriver",
    "TensorFlowDistinguisherDriver",
    "build_dbitnet",
    "build_gohr_resnet",
]
