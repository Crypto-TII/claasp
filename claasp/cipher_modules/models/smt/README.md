# SMT model

## Bit based

In order to correctly build the SMT bit based model of a cipher and retrieve a
trail, please go to the root directory of the project and follow this little guide.

### Fast Example

If you want to have a fast introduction to the SMT module, you can simply run 
the following code. Pay attention, to correctly run the code you need to build
a reduced version of Speck: block size = 32 (2 words x 16 bits), key size = 64
(4 words x 16 bits), rounds = 4. Suppose also that the cipher is in 
`tii.cipher.ciphers.block_ciphers.speck_block_cipher` file.

```python
from claasp.ciphers import SpeckBlockCipher
from claasp.cipher_modules.models.smt import SmtModel

cipher = SpeckBlockCipher(number_of_rounds=4)
M = SmtModel(cipher)
fixed_values = []
fixed_values.append(set_fixed_variables('key', 'equal', list(range(64)), integer_to_bit_list(0, 64, 'big')))
fixed_values.append(
    set_fixed_variables('plaintext', 'not_equal', list(range(32)), integer_to_bit_list(0, 32, 'big')))
M.find_lowest_weight_xor_differential_trail(fixed_values)
```
### Commands

We are going to give a list of commands that you can use to explore trails of
differential analysis for ARX ciphers.

- `from tii.cipher.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher`  
  This command will import the cipher for Speck.
- `from claasp.cipher_modules.models.smt.smt_model import SmtModel`  
  This command will import the python class that handles the cipher. 
- `cipher = SpeckBlockCipher(number_of_rounds=4).get_cipher_dictionary()` 
  This command will create a cipher of 4 rounds of Speck. After this, run `M =
  SmtModel(cipher)` to instantiate the class.
- `fixed_values.append(M.set_fixed_variables('key', 'equal', list(range(64)), M.integer_to_bit_list(0, 64, 'big')))`
  This command will fix the value of the `key` variable to zero
- `fixed_values.append(M.set_fixed_variables('plaintext', 'not_equal', list(range(32)), M.integer_to_bit_list(0, 32, 'big')))`
  This command will fix the value of the `plaintext` variable to zero

At this time, we can start the search for the lowest weight xor differential trail

- `M.find_lowest_weight_xor_differential_trail(fixed_values)` This command will start a
  search for the lowest weight xor differential trail.

## Available Solvers

Available solvers for SMT model are the followings. Please use
`solver_name='<solver_name>'` inside commands in which they are optionally required.
- [Z3](https://github.com/Z3Prover/z3)
  + `solver_name='z3'`
- [Yices](https://yices.csl.sri.com/) 
  + `solver_name='yices-smt2'`
- [MathSAT](https://mathsat.fbk.eu/)
  + `solver_name='mathsat'`

## Directory tmp/

The directory `tmp/` can be safely removed whenever you want.

## Tables

To allow a better comparison between ciphers and solvers, you can use
`table.py` module. Before that you should produce some files using various
ciphers and solvers.

When solving an SMT model, please use the same set of solvers for all ciphers.
The success is not guaranteed in any other case.

Execute:

```python
from claasp.cipher_modules.models.smt import Table
```

to import the class Table. In order to retrieve the solver's information, you
have to run the mandatory method

`Table.setup()`

Table is thought as a static class that can not be instantiated. There are 4
methods you can call to see a comparison between ciphers/solvers.

1. `Table.select_solver('solver_selected')`  
   Replace `solver_selected` with one of: cryptominisat, mathsat, minisat,
   glucose, glucose-syrup, yices-sat. A table containing information about
   ciphers analyzed, time execution and memory consumed will be printed.

2. `Table.select_cipher('cipher_selected')`  
   Replace `cipher_selected` with the correct name of the file containing it.
   For a list, you can check the directory
   `tii/cipher_modules/analysis/models/smt/tmp/solver_output/(any_solver)`. Before requesting a cipher
   please make sure to have generated it. A table containing information about
   solvers analyzed, time execution and memory consumed will be printed.

3. `Table.matrix()`  
   It will be printed a table with all retrievable information. Each entry of the
   table is a couple of numbers: execution time (s) and memory consumed (MB).

4. `Table.total()`
   It will print a ranking with all retrievable information. Each entry
   of the ranking is a line containing: solver name, cipher name, execution
   time (s) and memory consumed (MB).

**IMPORTANT.** Every method has an optional parameter called `struct`. The
default value is `'bit'`, but you can use `'word'`.

Every method has the **LaTeX** version just appending `_latex` at the end of
the name of the method. It means that, for instance, you can type
`Table.matrix_latex()` and retrieve the LaTeX code ready to be used in a source
file.

