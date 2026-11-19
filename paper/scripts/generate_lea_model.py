"""Generate the 16-round LEA experiment previously kept in the pytest tree.

The split is E0/Em/E1 = 8/1/7 CLAASP rounds. For modelling assumptions and
references, see MznHadipourBoomerangModel and paper/README.md.

Run with Sage's Python from an environment containing the PR's CLAASP version:
    sage -python paper/scripts/generate_lea_model.py /tmp/lea-model
"""

import argparse
from pathlib import Path

import sage.all  # noqa: F401 -- initialize Sage extensions before CLAASP imports

from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import (
    MznHadipourBoomerangModel,
)
from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher


def main():
    """Parse an output directory, build the 8/1/7 LEA model, and export it.

    INPUT: one command-line argument, the output directory (created if needed).
    OUTPUT: a MiniZinc model file in that directory. No solver is invoked.
    Existing files with the same generated filename are overwritten.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()
    model = MznHadipourBoomerangModel(
        LeaBlockCipher(number_of_rounds=16),
        {
            "top_part_number_of_rounds": 8,
            "middle_part_number_of_rounds": 1,
            "bottom_part_number_of_rounds": 7,
        },
    )
    model.build_hadipour_boomerang_model()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    model.write_minizinc_model_to_file(str(args.output_directory))


if __name__ == "__main__":
    main()
