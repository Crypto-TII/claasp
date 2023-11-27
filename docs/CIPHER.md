# Cipher Specifications

[1 Description of cipher](#1-description-of-cipher)
  - [1.1 Description of cipher parts](#11-description-of-cipher-parts)
  - [1.2 Cipher types](#12-cipher-types)
    - [1.2.1 Block ciphers](#121-block-ciphers)
    - [1.2.2 Hash functions](#122-hash-functions)
    - [1.2.3 Permutations](#123-permutations)
    - [1.2.4 Stream ciphers](#124-stream-ciphers)
  - [1.3 Cipher as python dictionary example](#13-cipher-as-python-dictionary-example)
[2 Description of component](#2-description-of-component)
[3 Description of the methods that can be called from a cipher instance](#3-description-of-the-methods-that-can-be-called-from-a-cipher-instance)

---
## 1 Description of cipher

### 1.1 Description of cipher parts

We now describe the parts of the Cipher.

#### 1.1.1 id

**Type**: python string

**Description:** 

Must be a unique id representing the cipher. There should not be two ciphers with the same id.

#### 1.1.2 type

**Type**: python string

**Description:**

This entry can be only one of the following values:

-   "block_cipher"
-   "tweakable_block_cipher"
-   "permutation"
-   "hash_function"
-   "stream_cipher"

The main differences in the above types is in the input they can receive:

- A block cipher receives as input a key and a plaintext (message) and returns a ciphertext as output.
- A tweakable block cipher received as input a tweak, a key and a plaintext and returns a ciphertext as output.
- A permutation receives as input a bitstring and returns a bitstring (no key is used, though notice 
  that often the input is composed of different parts representing a key, and IV or a Nonce, and/or some constants).
- A hash function receives as input a message and a state and returns a digest.
- A stream cipher receives as input a key, possibly an Initialization Vector (IV) or a Nonce, and returns a bit stream
  (at least one bit) in output.

Plaintext, ciphertext, key, IV, Nonce, input/output bitstring, and constant should be a bitstring of length ranging 
from 0 bits (empty string) to 4096 bits (in the future we might require even larger strings, up to MBytes if we include
asymmetric ciphers).

In the future, we might need to add other types (such as "mac", "aead", "pke", "kem", "signature").

#### 1.1.3 inputs

**Type**: list of strings

**Description:**

This is a list of strings representing the inputs of the cipher. Possible inputs are:

```
plaintext
key
state
message
iv
nonce
constant
tweak
```

#### 1.1.4 inputs_bit_size

**Type**: list of positive integers

**Description:**

This is a list of integers representing the bit size of each input listed in the field [1.1.3 inputs](#113-inputs). 
Thus, there must be a 1-to-1 correspondence between this list and the list in the field [1.1.3 inputs](#113-inputs).

#### 1.1.5 output_bit_size

**Type**: positive integer

**Description:**

This represents the output bit size of the cipher. It has to be an integer from 1 to 4096 (we might need to use much 
larger integers for asymmetric ciphers in the future, up to MBytes).

#### 1.1.6 rounds

**Type**: round object list.

**Description:**

This entry list contains a round object for each round.

Each round contains a list of component objects.

The description of component objects is in the section [2.1 Description of component parts](#21-description-of-component-parts)

#### 1.1.7 family_name

**Type**: string.

**Description:**

The name of the cipher. E.g.: fancy_block_cipher, chacha_permutation, ...

#### 1.1.8 reference_code

**Type**: string.

**Description:**

Code in string format to evaluate the cipher.

### 1.2 Cipher types
List of different types of cipher with an example of its creation.

#### 1.2.1 Block ciphers

##### 1.2.1.1 aes
- ``number_of_rounds``: number of rounds of the cipher. Default value is 10.
- ``word_size``: size of each word of the state. Must be equal to 2, 3, 4 or 8. Default value is 8.
- ``state_size``: number of rows of the state represented as a matrix. Must be equal to 2, 3 or 4. Default value is 4.

Example:
```
sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
sage: aes = AESBlockCipher()
```

##### 1.2.1.1 bea1
- ``number_of_rounds``: number of rounds of the cipher. Default value is 11.

Example:
```
sage: from claasp.ciphers.block_ciphers.bea1_block_cipher import BEA1BlockCipher
sage: bea = BEA1BlockCipher()
```

##### 1.2.1.2 constant
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 3.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 3.

Example:
```
sage: from claasp.ciphers.block_ciphers.constant_block_cipher import ConstantBlockCipher
sage: constant = ConstantBlockCipher(block_bit_size=32, number_of_rounds=8)
```

##### 1.2.1.3 des
- ``number_of_rounds``: number of rounds of the cipher. Must be less or equal than 16. Default value is 16.
- ``number_of_sboxes``: number of SBoxes considered. Must be equal to 2, 4, 6 or 8. Default value is 8.

Example:
```
sage: from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher
sage: des = DESBlockCipher()
```

##### 1.2.1.4 fancy
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 24.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 24.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 20.

Example:
```
sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
sage: fancy = FancyBlockCipher()
```

##### 1.2.1.5 hight
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 64.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 128.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 0. The cipher uses the corresponding amount
       given the other parameters (if available) when number_of_rounds is 0. 
- ``sub_keys_zero``: Default value is False.
- ``transformations_flag``: Default value is True.

Example:
```
sage: from claasp.ciphers.block_ciphers.hight_block_cipher import HightBlockCipher
sage: hight = HightBlockCipher(number_of_rounds=3)
```

##### 1.2.1.6 identity
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 32.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 32.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 1.

Example:
```
sage: from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher
sage: identity = IdentityBlockCipher()
```

##### 1.2.1.7 lea
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 128.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 192.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 0. The cipher uses the corresponding amount
       given the other parameters (if available) when number_of_rounds is 0.
- ``reorder_input_and_output``: Default value is True.

Example:
```
sage: from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher
sage: lea = LeaBlockCipher()
```

##### 1.2.1.8 lowmc
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 128.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 128.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 0. The cipher uses the corresponding amount
       given the other parameters (if available) when number_of_rounds is 0.
- ``number_of_sboxes``: number of sboxes per round of the cipher.Default value is 0. The cipher uses the corresponding 
       amount given the other parameters (if available) when number_of_rounds is 0.

Example:
```
sage: from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher
sage: lowmc = LowMCBlockCipher()
```

##### 1.2.1.9 midori
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 64.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 128.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 0. The cipher uses the corresponding amount
       given the other parameters (if available) when number_of_rounds is 0.

Example:
```
sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
sage: midori = MidoriBlockCipher()
```

##### 1.2.1.10 present
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 80.
- ``number_of_rounds``: number of rounds of the cipher. Default value is None. The cipher uses the corresponding amount
       given the other parameters (if available) when number_of_rounds is None.

Example:
```
sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
sage: present = PresentBlockCipher()
```

##### 1.2.1.11 raiden
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 64.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 128.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 0. The cipher uses the corresponding 
   amount given the other parameters (if available) when number_of_rounds is 0.
- ``right_shift_amount``: number of bits to be shifted in each right shift of the cipher. Default value is 14.
- ``left_shift_amount``: number of bits to be shifted in each left shift of the cipher. Default value is 9.

Example:
```
sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
sage: raiden = RaidenBlockCipher()
```

##### 1.2.1.12 simon
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 32.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 64.
- ``number_of_rounds``: number of rounds of the cipher. Default value is None. The cipher uses the corresponding 
   amount given the other parameters (if available) when number_of_rounds is None.
- ``rotation_amount``: the list containing the 3 rotation amounts for the round function. Default value is [-1, -8, -2]

Example:
```
sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
sage: simon = SimonBlockCipher()
```

##### 1.2.1.13 skinny
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 128.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 384.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 40.

Example:
```
sage: from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
sage: skinny = SkinnyBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=10)
```

##### 1.2.1.14 sparx
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 64.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 128.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 0. The cipher uses the corresponding 
   amount given the other parameters (if available) when number_of_rounds is 0.
- ``steps``: number of steps for the ARX function. Default value is 0. The cipher uses the corresponding 
   amount given the other parameters (if available) when number_of_rounds is 0.

Example:
```
sage: from claasp.ciphers.block_ciphers.sparx_block_cipher import SparxBlockCipher
sage: sparx = SparxBlockCipher()
```

##### 1.2.1.15 speck
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 32.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 64.
- ``rotation_alpha``: Default value is None.
- ``rotation_beta``: Default value is None.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 0. The cipher uses the corresponding 
   amount given the other parameters (if available) when number_of_rounds is 0.

Example:
```
sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
sage: speck = SpeckBlockCipher()
```

##### 1.2.1.16 tea
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 64.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 128.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 0. The cipher uses the corresponding 
   amount given the other parameters (if available) when number_of_rounds is 0.
- ``right_shift_amount``: number of bits to be shifted in each right shift of the cipher. Default value is 5.
- ``left_shift_amount``: number of bits to be shifted in each left shift of the cipher. Default value is 4.

Example:
```
sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
sage: tea = TeaBlockCipher()
```

##### 1.2.1.17 threefish
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 256.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 256.
- ``tweak_bit_size``: cipher tweak bit size of the cipher. Default value is 128.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 0. The cipher uses the corresponding 
   amount given the other parameters (if available) when number_of_rounds is 0.

Example:
```
sage: from claasp.ciphers.block_ciphers.threefish_block_cipher import ThreefishBlockCipher
sage: threefish = ThreefishBlockCipher()
```

##### 1.2.1.18 twofish
- ``key_length``: length of the cipher master key. Must be an integer between 1 and 256 included. Default value is 256.
- ``number_of_rounds``: number of rounds of the cipher. Must be less or equal than 16. Default value is 16.

Example:
```
sage: from claasp.ciphers.block_ciphers.twofish_block_cipher import TwofishBlockCipher
sage: cipher = TwofishBlockCipher()
```

##### 1.2.1.19 xtea
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 64.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 128.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 0. The cipher uses the corresponding 
   amount given the other parameters (if available) when number_of_rounds is 0.
- ``right_shift_amount``: number of bits to be shifted in each right shift of the cipher. Default value is 5.
- ``left_shift_amount``: number of bits to be shifted in each left shift of the cipher. Default value is 4.

Example:
```
sage: from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher
sage: xtea = XTeaBlockCipher()
```

#### 1.2.2 Hash functions

##### 1.2.2.1 blake
- ``block_bit_size``: input block bit size of the hash. Default value is 512.
- ``state_bit_size``: state bit size of the hash. Default value is 512.
- ``number_of_rounds``: number of rounds of the hash. Default value is 0. The cipher uses the corresponding amount
       given the other parameters (if available) when number_of_rounds is 0. 
- ``word_size``: word size in bits, used to split each parameter accordingly (plaintext and state). Default value is 32.
- ``permutations``: list of index (from 0 to block_bit_size//word_size-1) permutations. Default value is None.
        The cipher uses the standard permutation for the chosen configuration.
- ``rot_amounts``: list of amounts of bits to be rotated for rotation operations. Default value is None. 
        The cipher uses the standard rotation amounts for the chosen configuration.
- ``constants``: list of constants used in the column and diagonal steps. Default value is None. 
        The cipher uses the standard constants for the chosen configuration.

Example:
```
sage: from claasp.ciphers.hash_functions.blake_hash_function import BlakeHashFunction
sage: blake = BlakeHashFunction()
```

##### 1.2.2.2 blake2
- ``block_bit_size``: input block bit size of the hash. Default value is 1024.
- ``state_bit_size``: state bit size of the hash. Default value is 1024.
- ``number_of_rounds``: number of rounds of the hash. Default value is 0. The cipher uses the corresponding amount
       given the other parameters (if available) when number_of_rounds is 0.
- ``word_size``: word size in bits, used to split each parameter accordingly (plaintext and state). 
        Default value is 64.
- ``permutations``: list of index (from 0 to block_bit_size//word_size-1) permutations. Default value is None.
        The cipher uses the standard permutation for the chosen configuration.
- ``rot_amounts``: list of amounts of bits to be rotated for rotation operations.Default value is None.
        The cipher uses the standard rotation amounts for the chosen configuration.

Example:
```
sage: from claasp.ciphers.hash_functions.blake2_hash_function import Blake2HashFunction
sage: blake2 = Blake2HashFunction()
```

##### 1.2.2.3 sha1
- ``word_size``: *int*, the size of the word. Default value is 32.
- ``number_of_rounds``: *int*, the number of rounds. Default value is 80.

Example:
```
sage: from claasp.ciphers.hash_functions.sha1_hash_function import SHA1HashFunction
sage: sha1 = SHA1HashFunction()
```

##### 1.2.2.4 sha2
- ``output_bit_size``: *int*, size of the cipher output, must be equal to 224, 256, 384, 512. Default value is 256.
- ``number_of_rounds``: *int*, the number of rounds. Default value is 64.

Example:
```
sage: from claasp.ciphers.hash_functions.sha2_hash_function import SHA2HashFunction 
sage: sha2 = SHA2HashFunction()
```

#### 1.2.3 Permutations

##### 1.2.3.1 ascon
- ``number_of_rounds``: number of rounds of the cipher. Default value is 12.

Example:
```
sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
sage: ascon = AsconPermutation()
```

##### 1.2.3.2 ascon sbox sigma no matrix
- ``number_of_rounds``: number of rounds of the permutation. Default value is 12.

Example:
```
sage: from claasp.ciphers.permutations.ascon_sbox_sigma_no_matrix_permutation import AsconSboxSigmaNoMatrixPermutation
sage: ascon = AsconSboxSigmaNoMatrixPermutation(number_of_rounds=12)
```

##### 1.2.3.3 ascon sbox sigma
- ``number_of_rounds``: number of rounds of the permutation. Default value is 12.

Example:
```
sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=12)
```

##### 1.2.3.4 chacha
- ``number_of_rounds``: Number of rounds of the permutation. Default value is 0. The cipher uses the corresponding 
   amount given the other parameters (if available) when number_of_rounds is 0.
- ``state_of_components``: Default value is None.
- ``cipher_family``: Default value is "chacha_permutation".
- ``cipher_type``: Default value is "permutation".
- ``inputs``: Default value is None.
- ``cipher_inputs_bit_size``: Default value is None.

Example:
```
sage: from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
sage: chacha = ChachaPermutation(number_of_rounds=2)
```

##### 1.2.3.5 gift
- ``number_of_rounds``: number of rounds of the permutation. Default value is 40.

Example:
```
sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
sage: gift = GiftPermutation()
```

##### 1.2.3.6 gift sbox
- ``number_of_rounds``: number of rounds of the permutation. Default value is 40.

Example:
```
sage: from claasp.ciphers.permutations.gift_sbox_permutation import GiftSboxPermutation
sage: gift = GiftSboxPermutation()
```

##### 1.2.3.7 gimli
- ``number_of_rounds``: number of rounds of the permutation. Default value is 24.
- ``word_size``: *int*, the size of the word. Default value is 32.

Example:
```
sage: from claasp.ciphers.permutations.gimli_permutation import GimliPermutation
sage: gimli = GimliPermutation(number_of_rounds=8, word_size=26)
```

##### 1.2.3.8 grain core
- ``number_of_rounds``: number of rounds of the permutation. Default value is None. The cipher uses the corresponding 
   amount given the other parameters (if available) when number_of_rounds is None.

Example:
```
sage: from claasp.ciphers.permutations.grain_core_permutation import GrainCorePermutation
sage: grain_core = GrainCorePermutation()
```

##### 1.2.3.9 keccak invertible
- ``number_of_rounds``: number of rounds of the permutation. Default value is 24.
- ``word_size``: *int*, the size of the word. Default value is 64.

Example:
```
sage: from claasp.ciphers.permutations.keccak_invertible_permutation import KeccakInvertiblePermutation
sage: keccak = KeccakInvertiblePermutation(number_of_rounds=3, word_size=32)
```

##### 1.2.3.10 keccak
- ``number_of_rounds``: number of rounds of the permutation. Default value is 24.
- ``word_size``: *int*, the size of the word. Default value is 64.

Example:
```
sage: from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation
sage: keccak = KeccakPermutation()
```

##### 1.2.3.11 keccak sbox
- ``number_of_rounds``: number of rounds of the permutation. Default value is 24.
- ``word_size``: *int*, the size of the word. Default value is 64.

Example:
```
sage: from claasp.ciphers.permutations.keccak_sbox_permutation import KeccakSboxPermutation
sage: keccak = KeccakSboxPermutation()
```

##### 1.2.3.12 photon
- ``t``: Default value is 256.

Example:
```
sage: from claasp.ciphers.permutations.photon_permutation import PhotonPermutation
sage: photon = PhotonPermutation()
```

##### 1.2.3.13 sparkle
- ``number_of_blocks``: Block size // 64. Default value is 4.
- ``number_of_steps``: Number of rounds of the permutation. Default value is 7.

Example:
```
sage: from claasp.ciphers.permutations.sparkle_permutation import SparklePermutation
sage: sparkle = SparklePermutation()
```

##### 1.2.3.14 spongent pi
- ``number_of_rounds``: number of rounds of the permutation. Default value is 80.
- ``state_bit_size``: Default value is 160.

Example:
```
sage: from claasp.ciphers.permutations.spongent_pi_permutation import SpongentPiPermutation
sage: spongentpi = SpongentPiPermutation(state_bit_size=160, number_of_rounds=80)
```

##### 1.2.3.15 spongent pi precomputation
- ``number_of_rounds``: number of rounds of the permutation. Default value is 80.
- ``state_bit_size``: Default value is 160.

Example:
```
sage: from claasp.ciphers.permutations.spongent_pi_precomputation_permutation import SpongentPiPrecomputationPermutation
sage: spongentpi = SpongentPiPrecomputationPermutation(state_bit_size=160, number_of_rounds=80)
```

##### 1.2.3.16 tinyjambu 32 bits word
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 128.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 640.

Example:
```
sage: from claasp.ciphers.permutations.tinyjambu_32bits_word_permutation import TinyJambuWordBasedPermutation
sage: tinyjambu = TinyJambuWordBasedPermutation()
```

##### 1.2.3.17 tinyjambu
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 128.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 640.

Example:
```
sage: from claasp.ciphers.permutations.tinyjambu_permutation import TinyJambuPermutation
sage: tinyjambu = TinyJambuPermutation()
```

##### 1.2.3.18 xoodoo invertible
- ``number_of_rounds``: number of rounds of the cipher. Default value is 12.

Example:
```
sage: from claasp.ciphers.permutations.xoodoo_invertible_permutation import XoodooInvertiblePermutation
sage: xoodoo_invertible_permutation = XoodooInvertiblePermutation(number_of_rounds=3)
```

##### 1.2.3.19 xoodoo
- ``number_of_rounds``: number of rounds of the cipher. Default value is 3.

Example:
```
sage: from claasp.ciphers.permutations.xoodoo_permutation import XoodooPermutation
sage: xoodoo_permutation = XoodooPermutation(number_of_rounds=3)
```

##### 1.2.3.20 xoodoo sbox
- ``number_of_rounds``: number of rounds of the cipher. Default value is 12.

Example:
```
sage: from claasp.ciphers.permutations.xoodoo_sbox_permutation import XoodooSboxPermutation
sage: xoodoo_permutation_sbox = XoodooSboxPermutation(number_of_rounds=3)
```

#### 1.2.4 Stream ciphers

##### 1.2.4.1 chacha
- ``block_bit_size``: cipher input and output block bit size of the cipher. Default value is 512.
- ``key_bit_size``: cipher key bit size of the cipher. Default value is 256.
- ``number_of_rounds``: number of rounds of the cipher. Default value is 20.
- ``block_count``: Default value is 1.
- ``chacha_constants``: Default value is int("0x617078653320646e79622d326b206574", 16).

Example:
```
sage: from claasp.ciphers.stream_ciphers.chacha_stream_cipher import ChachaStreamCipher
sage: sp = ChachaStreamCipher(number_of_rounds=1)
```

### 1.3 Cipher as python dictionary example

```
sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
sage: fancy = FancyBlockCipher(number_of_rounds=2)
sage: fancy.as_python_dictionary()
```

```
{'cipher_id': 'fancy_block_cipher_p24_k24_o24_r2',
 'cipher_type': 'block_cipher',
 'cipher_inputs': ['plaintext', 'key'],
 'cipher_inputs_bit_size': [24, 24],
 'cipher_output_bit_size': 24,
 'cipher_number_of_rounds': 2,
 'cipher_rounds': [[
   {'id': 'sbox_0_0',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['plaintext'],
    'input_bit_positions': [[0, 1, 2, 3]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'sbox_0_1',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['plaintext'],
    'input_bit_positions': [[4, 5, 6, 7]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'sbox_0_2',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['plaintext'],
    'input_bit_positions': [[8, 9, 10, 11]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'sbox_0_3',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['plaintext'],
    'input_bit_positions': [[12, 13, 14, 15]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'sbox_0_4',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['plaintext'],
    'input_bit_positions': [[16, 17, 18, 19]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'sbox_0_5',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['plaintext'],
    'input_bit_positions': [[20, 21, 22, 23]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'linear_layer_0_6',
    'type': 'linear_layer',
    'input_bit_size': 24,
    'input_id_link': ['sbox_0_0', 'sbox_0_1', 'sbox_0_2', 'sbox_0_3', 'sbox_0_4', 'sbox_0_5'],
    'input_bit_positions': [[0, 1, 2, 3],
                            [0, 1, 2, 3],
                            [0, 1, 2, 3],
                            [0, 1, 2, 3],
                            [0, 1, 2, 3],
                            [0, 1, 2, 3]],
    'output_bit_size': 24,
    'description': [[0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1],
                    [0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1],
                    [1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1],
                    [1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1],
                    [1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0],
                    [1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                    [0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0],
                    [1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1],
                    [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0],
                    [1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1],
                    [0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0],
                    [0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0],
                    [0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0],
                    [1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1],
                    [0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1],
                    [0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1],
                    [0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0],
                    [0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1],
                    [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1],
                    [0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1],
                    [0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0],
                    [1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1],
                    [0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1],
                    [1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1]]
   },
   {'id': 'xor_0_7',
    'type': 'word_operation',
    'input_bit_size': 24,
    'input_id_link': ['key', 'key'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                            [12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]],
    'output_bit_size': 12,
    'description': ['XOR', 2]
   },
   {'id': 'and_0_8',
    'type': 'word_operation',
    'input_bit_size': 24,
    'input_id_link': ['xor_0_7', 'key'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                            [12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]],
    'output_bit_size': 12,
    'description': ['AND', 2]
   },
   {'id': 'intermediate_output_0_9',
    'type': 'intermediate_output',
    'input_bit_size': 24,
    'input_id_link': ['xor_0_7', 'and_0_8'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]],
    'output_bit_size': 24,
    'description': ['round_key_output']
   },
   {'id': 'constant_0_10',
    'type': 'constant',
    'input_bit_size': 0,
    'input_id_link': [''],
    'input_bit_positions': [[]],
    'output_bit_size': 24,
    'description': ['0xfedcba']
   },
   {'id': 'xor_0_11',
    'type': 'word_operation',
    'input_bit_size': 72,
    'input_id_link': ['constant_0_10', 'linear_layer_0_6', 'xor_0_7', 'and_0_8'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
                            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
                            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]],
    'output_bit_size': 24,
    'description': ['XOR', 3]
   },
   {'id': 'intermediate_output_0_12',
    'type': 'intermediate_output',
    'input_bit_size': 24,
    'input_id_link': ['xor_0_11'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]],
    'output_bit_size': 24,
    'description': ['round_output']
   }
  ],
  [
   {'id': 'sbox_1_0',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['xor_0_11'],
    'input_bit_positions': [[0, 1, 2, 3]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'sbox_1_1',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['xor_0_11'],
    'input_bit_positions': [[4, 5, 6, 7]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'sbox_1_2',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['xor_0_11'],
    'input_bit_positions': [[8, 9, 10, 11]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'sbox_1_3',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['xor_0_11'],
    'input_bit_positions': [[12, 13, 14, 15]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'sbox_1_4',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['xor_0_11'],
    'input_bit_positions': [[16, 17, 18, 19]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'sbox_1_5',
    'type': 'sbox',
    'input_bit_size': 4,
    'input_id_link': ['xor_0_11'],
    'input_bit_positions': [[20, 21, 22, 23]],
    'output_bit_size': 4,
    'description': [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
   },
   {'id': 'xor_1_6',
    'type': 'word_operation',
    'input_bit_size': 24,
    'input_id_link': ['xor_0_7', 'and_0_8'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]],
    'output_bit_size': 12,
    'description': ['XOR', 2]
   },
   {'id': 'and_1_7',
    'type': 'word_operation',
    'input_bit_size': 24,
    'input_id_link': ['xor_1_6', 'and_0_8'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]],
    'output_bit_size': 12,
    'description': ['AND', 2]
   },
   {'id': 'intermediate_output_1_8',
    'type': 'intermediate_output',
    'input_bit_size': 24,
    'input_id_link': ['xor_1_6', 'and_1_7'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]],
    'output_bit_size': 24,
    'description': ['round_key_output']
   },
   {'id': 'modadd_1_9',
    'type': 'word_operation',
    'input_bit_size': 18,
    'input_id_link': ['xor_1_6', 'sbox_1_0', 'sbox_1_1', 'sbox_1_1', 'sbox_1_3'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5],
                            [0, 1, 2, 3],
                            [0, 1],
                            [2, 3],
                            [0, 1, 2, 3]],
    'output_bit_size': 6,
    'description': ['MODADD', 3]
   },
   {'id': 'modadd_1_10',
    'type': 'word_operation',
    'input_bit_size': 18,
    'input_id_link': ['xor_1_6', 'sbox_1_3', 'sbox_1_4', 'sbox_1_4', 'sbox_1_5'],
    'input_bit_positions': [[6, 7, 8, 9, 10, 11],
                            [0, 1, 2, 3],
                            [0, 1],
                            [2, 3],
                            [0, 1, 2, 3]],
    'output_bit_size': 6,
    'description': ['MODADD', 3]
   },
   {'id': 'rot_1_11',
    'type': 'word_operation',
    'input_bit_size': 6,
    'input_id_link': ['sbox_1_1', 'sbox_1_2'],
    'input_bit_positions': [[2, 3], [0, 1, 2, 3]],
    'output_bit_size': 6,
    'description': ['ROTATE', -3]
   },
   {'id': 'shift_1_12',
    'type': 'word_operation',
    'input_bit_size': 6,
    'input_id_link': ['sbox_1_4', 'sbox_1_5'],
    'input_bit_positions': [[2, 3], [0, 1, 2, 3]],
    'output_bit_size': 6,
    'description': ['SHIFT', 3]
   },
   {'id': 'xor_1_13',
    'type': 'word_operation',
    'input_bit_size': 18,
    'input_id_link': ['modadd_1_9', 'rot_1_11', 'and_1_7'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5],
                            [0, 1, 2, 3, 4, 5],
                            [0, 1, 2, 3, 4, 5]],
    'output_bit_size': 6,
    'description': ['XOR', 3]
   },
   {'id': 'xor_1_14',
    'type': 'word_operation',
    'input_bit_size': 18,
    'input_id_link': ['modadd_1_10', 'shift_1_12', 'and_1_7'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5],
                            [0, 1, 2, 3, 4, 5],
                            [6, 7, 8, 9, 10, 11]],
    'output_bit_size': 6,
    'description': ['XOR', 3]
   },
   {'id': 'cipher_output_1_15',
    'type': 'cipher_output',
    'input_bit_size': 24,
    'input_id_link': ['modadd_1_9', 'xor_1_13', 'modadd_1_10', 'xor_1_14'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5],
                            [0, 1, 2, 3, 4, 5],
                            [0, 1, 2, 3, 4, 5],
                            [0, 1, 2, 3, 4, 5]],
    'output_bit_size': 24,
    'description': ['cipher_output']
   }
  ]
 ],
 'cipher_reference_code': None}
```

## 2 Description of component

### 2.1 Description of component parts

We now describe the parts of the Cipher.

#### 2.1.1 id

**Type**: python string

**Description:** 

Must be a unique id representing the component. There should not be two components with the same id.

#### 2.1.2 type

**Type**: python string

**Description:**

Component type. E.g.: sbox, constant, linear layer, ...
See all types in [2.2 Component types](#22-component-types).

#### 2.1.3 inputs

**Type**: input object 

**Description:**

Object contains:
- bit_size: component input bit size.
- id_links: components that are input of current component.
- bit_positions: input bits from id_links.

#### 2.1.4 output_bit_size

**Type**: positive integer

**Description:**

This represents the output bit size of the component.

#### 2.1.5 description

**Type**: list.

**Description:**

Description of component.

### 2.2 Component types

#### 2.2.1 sbox

**String type**: _sbox_

**Input bit size**: from 2 to 32

**Output bit size**: from 2 to 32. Note the output bit size can be different from input bit size.

**Description**:

Any sbox can be described as a list of integers from 0 to 2\^sbox_input_bit_size.

This list specifies that an integer j is mapped to the integer sbox[j].

Note the input integer is in fact the integer represented by the binary expression given as input.

#### Code example:

##### Example 1: sbox permutation over 2 bits

SBox = [0, 2, 1, 3]

```
{
  "id" : "sbox_0_0",
  "type" : "sbox",
  "input_bit_size" : 2,
  "input_id_link" : ['cipher_input'],
  "input_bit_positions" : [[0, 1]],
  "output_bit_size" : 2,
  "description" : [0, 2, 1, 3]
}
```

##### Example 2: sbox from 3 to 2 bits

SBox = [0, 1, 2, 3, 3, 2, 1, 0]

```
{
  "id" : "sbox_0_0",
  "type" : "sbox",
  "input_bit_size" : 3,
  "input_id_link" : ['cipher_input'],
  "input_bit_positions" : [[0, 1, 2]],
  "output_bit_size" : 2,
  "description" : [0, 1, 2, 3, 3, 2, 1, 0]
}
```

##### Example 3: sbox from 2 to 3 bits

SBox = [1, 7, 2, 5]

```
{
  "id" : "sbox_0_0",
  "type" : "sbox",
  "input_bit_size" : 2,
  "input_id_link" : ['cipher_input'],
  "input_bit_positions" : [[0, 1]],
  "output_bit_size" : 3,
  "description" : [1, 7, 2, 5]
}
```

### 2.2.2 word_operation

**String type**: _word_operation_

**Input bit size**: from 1 to any integer

**Output bit size**: from 1 to any integer. 

**Description**: 

Any word operation is defined by the type of operations it performs (NOT, ROTATE, MODADD, etc.), 
and some extra parameters (only available for some operations, such as the rotation or shift amount).
The number of inputs can be derived by dividing the input bit size by the output bit size.
This information is contained in the description field.

The description field can be one of the below:

- single input operators
  - `["NOT", null]`
  - `["ROTATE", <rotation_amount>]`, "+" is right rotation, "-" is left rotation
  - `["SHIFT", <shift_amount>]`, "+" is right shift, "-" is left shift

- multi input operators
  - `["OR", <number_of_inputs>]`
  - `["AND", <number_of_inputs>]`
  - `["XOR", <number_of_inputs>]`
  - `["MODULAR_ADDITION", <number_of_inputs>]`
  - `["MODULAR_MULTIPLICATION", <number_of_inputs>]`

- variable input operators
  - `["ROTATE_BY_VARIABLE_AMOUNT", <direction>]`
  - `["SHIFT_BY_VARIABLE_AMOUNT", <direction>]`

#### Code example: 

##### Example 1: NOT

```
{
  "id" : "not_0_0",
  "type" : "word_operation",
  "input_bit_size" : 8,
  "input_id_link" : ['plaintext'],
  "input_bit_positions" : [[0,1,2,3,4,5,6,7]],
  "output_bit_size" : 8,
  "description" : ["NOT", null]
}
```

##### Example 2: ROTATE

Left rotation by 1 bit of an 8 bits word:

```
{
  "id" : "lrot_0_0",
  "type" : "word_operation",
  "input_bit_size" : 8,
  "input_id_link" : ['plaintext'],
  "input_bit_positions" : [[0,1,2,3,4,5,6,7]],
  "output_bit_size" : 8,
  "description" : ["ROTATE", -1]
}
```

##### Example 3: SHIFT

Right shift by 2 bits of an 8 bit word:

```
{
  "id" : "rsh_0_0",
  "type" : "word_operation",
  "input_bit_size" : 8,
  "input_id_link" : ['plaintext'],
  "input_bit_positions" : [[0,1,2,3,4,5,6,7]],
  "output_bit_size" : 8,
  "description" : ["SHIFT", +2]
}
```

##### Example 4: OR

OR between two words of 4 bits:

```
{
  "id" : "or_0_0",
  "type" : "word_operation",
  "input_bit_size" : 8,
  "input_id_link" : ['plaintext','key'],
  "input_bit_positions" : [[0,1,2,3],[4,5,6,7]],
  "output_bit_size" : 4,
  "description" : ["OR", 2]
}
```

Note: AND, XOR, MODADD, and MODMUL have the same structure as a OR operation.

##### Example 5: ROTATE_BY_VARIABLE_AMOUNT

Rotate the first word by an amount defined by the second word.
The direction is defined by the sign in the second element of the description:
-1 indicates left, +1 right.

```
{
  "id" : "or_0_0",
  "type" : "word_operation",
  "input_bit_size" : 8,
  "input_id_link" : ['plaintext','key'],
  "input_bit_positions" : [[0,1,2,3],[4,5,6,7]],
  "output_bit_size" : 4,
  "description" : ["ROTATE_BY_VARIABLE_AMOUNT", -1]
}
```

Note: SHIFT_BY_VARIABLE_AMOUNT has the same structure as ROTATE_BY_VARIABLE_AMOUNT.

### 2.2.3 linear_layer

**String type**: _linear_layer_

**Input bit size**: from 2 to any integer

**Output bit size**: from 2 to any integer. 
Note that the output bit size should be the same as the input bit size.

**Description**: 

A linear layer is defined by a square binary invertible matrix, 
represented as a list of bits. 

##### Example: Linear layer

Bit-based linear layer. 

```
{
  "id" : "linear_layer_0_6",
  "type" : "linear_layer",
  "input_bit_size" : 24,
  "input_id_link" : ['sbox_0_0', 'sbox_0_1', 'sbox_0_2', 'sbox_0_3', 'sbox_0_4', 'sbox_0_5'],
  "input_bit_positions" : [[0, 1, 2, 3], 
                           [0, 1, 2, 3], 
                           [0, 1, 2, 3], 
                           [0, 1, 2, 3], 
                           [0, 1, 2, 3], 
                           [0, 1, 2, 3]],
  "output_bit_size" : 24,
  "description" : [[0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1], 
                   [0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1], 
                   [1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1], 
                   [1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1], 
                   [1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0], 
                   [1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], 
                   [0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0], 
                   [1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1], 
                   [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0], 
                   [1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1], 
                   [0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0], 
                   [0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0], 
                   [0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0], 
                   [1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1], 
                   [0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1], 
                   [0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1], 
                   [0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0], 
                   [0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1], 
                   [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1], 
                   [0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1], 
                   [0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0], 
                   [1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1], 
                   [0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1], 
                   [1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1]],
}
```

### 2.2.4 shift_row

**String type**: _shift_row_

**Input bit size**: from 2 to any integer

**Output bit size**: from 2 to any integer. 
Note that the output bit size should be the same as the input bit size.

**Description**: 

This operation is a special case of ROTATE operation, and it is 
completely defined by the amount of the rotation. 
This amount represents the bit rotation amount. 
Note that in the shift row operations, 
the bit rotation amount is always a multiple of the word bit size.
A positive integer will indicate a right rotation, 
while a negative integer a left rotation.
This field also contains the keywork `'ROTATE'`, which is used internally 
(TODO: in the future we could specialize shift row and remove the `ROTATE` keyword).

##### Example: Shift row

Rotate to the left the matrix
`(a1, a2, a3, b1, b2, b3)` by 3 (one word of 3 bits). 
The output is 
`(b1, b2, b3, a1, a2, a3)`

```
{
    "id" : "ShiftRows_0_5",
    "type" : "word_operation",
    "input_bit_size" : 6,
    "input_id_link" : ['SubBytes_0_1', 'SubBytes_0_3'],
    "input_bit_positions" : [[0, 1, 2], [0, 1, 2]],
    "output_bit_size" : 6,
    "description" : ['ROTATE', -3]
}
```

### 2.2.5 mix_column

**String type**: _mix_column_

**Input bit size**: from 2 to any integer

**Output bit size**: from 2 to any integer. 
Note that the output bit size should be the same as the input bit size.

**Description**: 

The operation is completely defined by:
- a matrix with integer entries 
(where each integer represents a binary polynomial);
- an integer representing a binary irreducible polynomial;
- an integer representing the word size.

##### Example: Mix column

Multiply a 2x2 matrix 
by the matrix `[[2, 3], [3, 2]]`
(which represents the matrix `[[x, x+1], [x+1, x]]`).
All multiplications are performed modulo the polynomial
`11`, representing the irreducible polynomial 
`x^3 + x + 1` in GF(2^3).
The word size is 3 (each element is in GF(2^3))

```
{
    "id" : "MixColumn_0_6",
    "type" : "mix_column",
    "input_bit_size" : 6,
    "input_id_link" : ['ShiftRows_0_4', 'ShiftRows_0_5'],
    "input_bit_positions" : [[0, 1, 2], [0, 1, 2]],
    "output_bit_size" : 6,
    "description" : [[[2, 3], [3, 2]], 11, 3],
}
```

### 2.2.6 constant

**String type**: _constant_

**Input bit size**: this value is not used, so it can be left empty, or set to 0.

**Output bit size**: from 1 to any integer.

**Description**: 
A binary string representing the binary value of the constant. 
The string starts with `0b`.

##### Example: Constant

The constant `0b001000000000`.

```
{
    "id" : "RCon_0_11",
    "type" : "constant",
    "input_bit_size" : ,
    "input_id_link" : [''],
    "input_bit_positions" : [[]],
    "output_bit_size" : 6,
    "description" : ['0b001000000000'],
}
```

### 2.2.7 intermediate_output

**String type**: _intermediate_output_

**Input bit size**: from 2 to any integer.

**Output bit size**: from 2 to any integer.

**Description**: This component is used to tag the output of a certain set of components. For example one could tag:
- the set of components that determine the output of every round
- the set of components that output the round key
- the set of components representing the output of the linear or nonlinear layer of every round
  The name used for the tag is arbitrary, but it needs to be the same for all set of components that are meant to be on 
- the same list (for example all round output components should be tagged with the same tag).

NOTE: this component is not part of the cipher itself, but it is useful to fix the focus of the analysis on the output 
of some specific components.

##### Example: Intermediate output

The following component sets a tag for the output of `xor_0_7` and `and_0_8` components, 
to identify them as a round key.

```
  {
    # round = 0 - round component = 9
    "id" : "round_key_output_0",
    "type" : "intermediate_output",
    "input_bit_size" : 24,
    "input_id_link" : ['xor_0_7', 'and_0_8'],
    "input_bit_positions" : [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]],
    "output_bit_size" : 24,
    "description" : ['round_key_output'],
  }
```

### 2.2.8 cipher_output

**String type**: _cipher_output_

**Input bit size**: from 2 to any integer.

**Output bit size**: from 2 to any integer.

**Description**: This component is used to tag the output of a certain set of components as the cipher output. 
The name used for the tag is arbitrary, but it is recommended to use the string `round_output` or `cipher_output` to 
avoid confusion.
This component should be used only once, at the end of the cipher.

NOTE: this component is not part of the cipher itself, but it is used to identify which round components constitute the
output of the cipher.

##### Example: Cipher output 

The following component sets a tag for the output of `modadd_1_8`, `xor_1_12`, `modadd_1_9` and `xor_1_13` components, 
to identify them as the output of the cipher.

```
  {
    # round = 1 - round component = 15
    "id" : "round_output_1",
    "type" : "cipher_output",
    "input_bit_size" : 24,
    "input_id_link" : ['modadd_1_8', 'xor_1_12', 'modadd_1_9', 'xor_1_13'],
    "input_bit_positions" : [[0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5]],
    "output_bit_size" : 24,
    "description" : ['round_output'],
  }
```
