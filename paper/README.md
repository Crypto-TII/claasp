# Boomerang paper experiments

This directory holds the research material that accompanied CLAASP PR #735.
It can be copied into a separate paper artifact repository. CLAASP itself does
not import these files, and the archived searches are not unit tests.

- `manifest.json`: original paths, relocated paths, and original Git blob IDs.
- `scripts/`: historical batch launchers, the standalone BCT table evaluator,
  and the 16-round LEA 8/1/7 model generator formerly stored as a pytest.
  Run the generator with `sage -python paper/scripts/generate_lea_model.py OUTPUT_DIR`.
- `experimental_results/`: original generated MiniZinc models, solver logs,
  parameter files, and the original JSON result. The original experiment
  directory names are retained, including `test_new_*` and `test_single_key_*`.
  These names are provenance, not an assertion that a result is final.

The relocation preserves the contents of the archived results. The standalone
`bct_entry128` helper now normalizes the exact integer count at the end; its
previous intermediate integer division truncated fractional probabilities. Some runs are
unfinished or have empty logs. A solver's best incumbent is not necessarily a
proved optimum. Do not compare the numerical weight to a measured whole-cipher
boomerang probability without accounting for the model's assumptions.

## Requirements

Use a CLAASP checkout containing the boomerang model, SageMath, and MiniZinc.
The historical batch scripts used MiniZinc 2.9.5 and Gurobi 13.0.2 on Linux.
Gurobi needs a suitable installation and license. For the Python examples,
use a working Gecode installation. CLAASP's Linux image installs Gecode 6.3.0
with matching MiniZinc definitions via `docker/install_gecode.sh`; Ubuntu's
older FlatZinc library alone is incompatible with MiniZinc 2.9.4. Set `MZN` to your MiniZinc
binary if it is not on PATH, and `GUROBI_DLL` to the Gurobi shared library.
The parameter files specify seeds, thread counts, and potentially multi-day
limits. Inspect them before starting a batch. The launchers run in the
matching `experimental_results` directory and overwrite their named log files;
copy the directory before rerunning if you want to preserve the archive.

## Python workflow

Generate and solve a small example directly, without shell parsing:

```python
import sage.all
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel

cipher = SpeckBlockCipher(number_of_rounds=3)
model = MznHadipourBoomerangModel(cipher, {
    "top_part_number_of_rounds": 1,
    "middle_part_number_of_rounds": 1,
    "bottom_part_number_of_rounds": 1,
})
solution = model.find_one_boomerang_trail(
    solver_name="gecode", timeout_in_seconds=30,
)
print(solution["status"], solution.get("total_weight"))
```

`find_lowest_weight_boomerang_trail` minimizes the encoded objective;
`find_one_boomerang_trail_with_fixed_weight` fixes it.
`find_all_boomerang_trails_with_fixed_weight` and
`find_all_boomerang_trails_with_weight_at_most` enumerate encoded assignments.
Check `solver_status` for completion/optimality. Fixed component IDs use
`upper_` and `lower_` prefixes. Block-cipher key inputs have zero differences
by default. For permutation models such as ChaCha, fix the constant/key bits
of the input state explicitly through `fixed_values` for the intended setting.

To fix an external difference, use the usual CLAASP fixed-variable format:

```python
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list

fixed = [set_fixed_variables(
    "upper_plaintext", "equal", list(range(32)),
    integer_to_bit_list(1, 32, "big"),
)]
solution = model.find_one_boomerang_trail(
    fixed_values=fixed, timeout_in_seconds=30,
)
```

For model export, call `build_hadipour_boomerang_model()` followed by
`write_minizinc_model_to_file(output_directory)`. Building alone writes no file.

## Probability interpretation

Weights are negative base-two logarithms in bits. Internal integer weights use
hundredths of a bit. The objective is `2*upper + middle + 2*lower`.
The modular switch uses the original piecewise probability-to-weight
approximation; its error is larger than 0.01 bits and it saturates at 32 bits
for sufficiently small probabilities. Thus a proved solver optimum is an
optimum of this approximate model, not a proof of the best real probability.
The modular connectivity predicates also restrict the number of half-size
transitions to half the word size, following the existing search heuristic.

The model supports two-input AND and modular-addition/subtraction nonlinear
components. It does not yet support S-box/OR switches, mixed modular word
sizes, or related-key searches. Multi-round switch composition retains the
paper implementation's local independence assumptions. Compatibility is imposed
per nonlinear component; valid whole-cipher switches that rely on cancellation
between nonlinear terms combined by XOR can be excluded. Verify reported
external differences with independent experiments before making a cipher-level
claim.

References:

- Cid et al., [Boomerang Connectivity Table: A New Cryptanalysis Tool](https://doi.org/10.1007/978-3-319-78375-8_22), EUROCRYPT 2018.
- Wang, Wang and Sun, [SAT-aided Automatic Search of Boomerang Distinguishers for ARX Ciphers](https://doi.org/10.46586/tosc.v2023.i1.152-191), ToSC 2023(1).
- Boukerrou et al., [On the Feistel Counterpart of the Boomerang Connectivity Table: Introduction and Analysis of the FBCT](https://doi.org/10.13154/tosc.v2020.i1.331-362), ToSC 2020(1).
- Yu and Teh, [Revisiting boomerang attacks on lightweight ARX and AND-RX ciphers with applications to KATAN, SIMON and CHAM](https://doi.org/10.1016/j.jisa.2024.103950), JISA 89 (2025).
- Bellini et al., [Fully Automated Differential-Linear Attacks Against ARX Ciphers](https://doi.org/10.1007/978-3-031-30872-7_10), CT-RSA 2023 (piecewise-linear modeling approach).
