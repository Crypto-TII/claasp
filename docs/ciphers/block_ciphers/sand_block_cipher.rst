-----------------
Sand block cipher
-----------------

``SandBlockCipher`` builds SAND-64/128 and SAND-128/128 with their published
master-key schedule. The optional ``number_of_rounds`` argument constructs a
reduced-round instance of the same design.

For example, the first test vector in Appendix A of the SAND paper can be
checked directly::

    from claasp.ciphers.block_ciphers.sand_block_cipher import SandBlockCipher

    cipher = SandBlockCipher()
    plaintext = 0x0F1F2F3F4F5F6F7F
    key = 0x0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFFF
    assert cipher.evaluate([plaintext, key]) == 0x4DE90F3B2B5E706B

Source: Shiyao Chen, Yanhong Fan, Ling Sun, Yong Fu, Haibo Zhou, Yongqing Li,
Meiqin Wang, Weijia Wang and Chun Guo, *SAND: an AND-RX Feistel lightweight
block cipher supporting S-box-based security evaluations*, Designs, Codes and
Cryptography 90, 155--198 (2022),
https://doi.org/10.1007/s10623-021-00970-9. The `open paper
<https://eprint.iacr.org/2021/1560>`_ contains the cipher specification in
Section 2, test vectors in Appendix A, and reference code in Appendix B.

.. automodule:: ciphers.block_ciphers.sand_block_cipher
   :members:
   :undoc-members:
   :inherited-members:
   :show-inheritance:
