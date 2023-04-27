# SAT model

## Available solvers

Available solvers for SAT model are the followings. Please use
`solver_name='...'` inside commands in which they are optionally
required.

- [CryptoMiniSat](https://github.com/msoos/cryptominisat)
  + `solver_name='cryptominisat'`
- [Glucose](https://www.labri.fr/perso/lsimon/glucose/) and
  [Glucose Syrup](https://www.labri.fr/perso/lsimon/glucose/)
  + `solver_name='glucose'` 
  + `solver_name='glucose-syrup'`
- [MathSAT](https://mathsat.fbk.eu/)
  + `solver_name='mathsat'`
- [Minisat](https://github.com/niklasso/minisat)
  + `solver_name='minisat'`
- [Yices-sat](https://yices.csl.sri.com/)
  + `solver_name='yices-sat'`

## Example of reversing the cipher

The following is an example of a key recover fixing some bits of the plaintext
and some others of the ciphertext.

```python
from claasp.ciphers import TeaBlockCipher
from claasp.cipher_modules import SatModel

cipher = TeaBlockCipher(number_of_rounds=32)
T = SatModel(cipher)

# Fixing 12.5% of plaintext and ciphertext words
fixed_variables = [{
    'component_id': 'plaintext',
    'constraint_type': 'equal',
    'bit_positions': [0, 1, 2, 3],
    'bit_values': [0, 1, 0, 0]
}, {
    'component_id': 'plaintext',
    'constraint_type': 'equal',
    'bit_positions': [32, 33, 34, 35],
    'bit_values': [0, 0, 1, 0]
}, {
    'component_id': 'cipher_output_31_16',
    'constraint_type': 'equal',
    'bit_positions': [0, 1, 2, 3],
    'bit_values': [0, 0, 0, 1]
}, {
    'component_id': 'cipher_output_31_16',
    'constraint_type': 'equal',
    'bit_positions': [32, 33, 34, 35],
    'bit_values': [1, 0, 1, 0]
}]

T.build_cipher_model(fixed_variables)
solution = T.solve('cipher')
print('#------- 12.5% -------#')
print(f'time : {solution["time"]}')
print(f'memory : {solution["memory"]}')
print(f'key : {solution["components_values"]["plaintext"]["value"]}')
```

The following is an example of a full key recover fixing the plaintext and the
ciphertext. It could take a lot of time.

```python
from claasp.ciphers import TeaBlockCipher
from claasp.cipher_modules import SatModel

plaintext = 0x3d5966f448ef47b2
key = 0xa81b7c5f73a2103503cc3c29a2efd958
ciphertext = 0xfcc078f5c8536398

cipher = TeaBlockCipher(number_of_rounds=32)
T = SatModel(cipher)

# Fixing 100% of plaintext and ciphertext words
fixed_variables = [{
    'component_id': 'plaintext',
    'constraint_type': 'equal',
    'bit_positions': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                      27, 28, 29, 30, 31],
    'bit_values': [0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0]
}, {
    'component_id': 'plaintext',
    'constraint_type': 'equal',
    'bit_positions': [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
                      56, 57, 58, 59, 60, 61, 62, 63],
    'bit_values': [0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0]
}, {
    'component_id': 'cipher_output_31_16',
    'constraint_type': 'equal',
    'bit_positions': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                      27, 28, 29, 30, 31],
    'bit_values': [0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1]
}, {
    'component_id': 'cipher_output_31_16',
    'constraint_type': 'equal',
    'bit_positions': [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
                      56, 57, 58, 59, 60, 61, 62, 63],
    'bit_values': [1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1]
}]

T.build_cipher_model(fixed_variables)
solution = T.solve('cipher')
print('#------- 100% -------#')
print(f'time : {solution["time"]}')
print(f'memory : {solution["memory"]}')
print(f'key : {solution["components_values"]["plaintext"]["value"]}')
print(f'key (expected) : {key}')
```

