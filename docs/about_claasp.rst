About CLAASP
============

CLAASP is a Python workbench for describing, evaluating, and analyzing
symmetric cryptographic primitives. It provides one common representation for
block ciphers, permutations, hash-oriented constructions, and smaller teaching
examples.

The central object in CLAASP is a primitive graph. Its inputs, operations,
round boundaries, intermediate values, and output are recorded explicitly.
The same description can then be evaluated, inspected, transformed, or passed
to an analysis backend without implementing the primitive again.

CLAASP is intended for primitive designers, cryptanalysts, researchers, and
students. Ready-made primitives support quick experiments, while the authoring
interface supports new designs and controlled variants of existing ones.

The core package runs on ordinary Python. Specialized solvers, computer
algebra systems, and machine-learning frameworks are optional and are needed
only for the analyses that use them.
