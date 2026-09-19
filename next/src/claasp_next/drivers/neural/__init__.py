"""Optional machine-learning training drivers for neural distinguishers.

Importing this package never requires scikit-learn or any other ML
framework; only calling a driver's ``train`` method does (implemented in
``claasp_next.drivers.neural.sklearn_driver``).
"""

from claasp_next.drivers.neural.sklearn_driver import SklearnMLPDriver

__all__ = ["SklearnMLPDriver"]
