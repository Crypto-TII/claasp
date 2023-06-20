from claasp.cipher import Cipher

class ToySPN(Cipher):
    def __init__(self):
        super().__init__(family_name="toyspn",
                         cipher_type="block_cipher",
                         cipher_inputs=["plaintext", "key"],
                         cipher_inputs_bit_size=[6, 6],
                         cipher_output_bit_size=6)

        sbox = [0, 5, 3, 2, 6, 1, 4, 7]
        self.add_round()
        xor = self.add_XOR_component(["plaintext", "key"],[[0,1,2,3,4,5],[0,1,2,3,4,5]],6)
        sbox1 = self.add_SBOX_component([xor.id], [[0, 1, 2]], 3, sbox)
        sbox2 = self.add_SBOX_component([xor.id], [[3, 4, 5]], 3, sbox)
        rotate = self.add_rotate_component([sbox1.id, sbox2.id],[[0, 1, 2], [0, 1, 2]], 6, 1)
        self.add_round_output_component([rotate.id], [[0, 1, 2, 3, 4, 5]], 6)

        self.add_round()
        xor = self.add_XOR_component([rotate.id, "key"],[[0,1,2,3,4,5],[0,1,2,3,4,5]],6)
        sbox1 = self.add_SBOX_component([xor.id], [[0, 1, 2]], 3, sbox)
        sbox2 = self.add_SBOX_component([xor.id], [[3, 4, 5]], 3, sbox)
        rotate = self.add_rotate_component([sbox1.id, sbox2.id],[[0, 1, 2], [0, 1, 2]], 6, 1)
        self.add_cipher_output_component([rotate.id], [[0, 1, 2, 3, 4, 5]], 6)

toyspn = ToySPN()
print(f'{hex(toyspn.evaluate([0x3F, 0x3F], verbosity=True)) = }')