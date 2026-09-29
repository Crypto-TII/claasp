# ****************************************************************************
# Copyright 2026 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************

from claasp.cipher import Cipher
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT


BLOCK_BIT_SIZE = 64
WORD_BIT_SIZE = 32
NUMBER_OF_ROUNDS = 16

input_types = [INPUT_PLAINTEXT]

PARAMETERS_CONFIGURATION_LIST = [
    {"key": 0, "key_bit_size": 128, "number_of_rounds": 16}
]

MASK32 = 0xFFFFFFFF


P_ARRAY = [
    0x243F6A88,
    0x85A308D3,
    0x13198A2E,
    0x03707344,
    0xA4093822,
    0x299F31D0,
    0x082EFA98,
    0xEC4E6C89,
    0x452821E6,
    0x38D01377,
    0xBE5466CF,
    0x34E90C6C,
    0xC0AC29B7,
    0xC97C50DD,
    0x3F84D5B5,
    0xB5470917,
    0x9216D5D9,
    0x8979FB1B,
]

SBOX_1 = int(
    "d1310ba698dfb5ac2ffd72dbd01adfb7b8e1afed6a267e96ba7c9045f12c7f9924a19947b3916cf70801f2e2858efc16"
    "636920d871574e69a458fea3f4933d7e0d95748f728eb658718bcd5882154aee7b54a41dc25a59b59c30d5392af26013"
    "c5d1b023286085f0ca417918b8db38ef8e79dcb0603a180e6c9e0e8bb01e8a3ed71577c1bd314b2778af2fda55605c60"
    "e65525f3aa55ab945748986263e8144055ca396a2aab10b6b4cc5c341141e8cea15486af7c72e993b3ee1411636fbc2a"
    "2ba9c55d741831f6ce5c3e169b87931eafd6ba336c24cf5c7a325381289586773b8f48986b4bb9afc4bfe81b66282193"
    "61d809ccfb21a991487cac605dec8032ef845d5de98575b1dc262302eb651b8823893e81d396acc50f6d6ff383f44239"
    "2e0b4482a484200469c8f04a9e1f9b5e21c66842f6e96c9a670c9c61abd388f06a51a0d2d8542f68960fa728ab5133a3"
    "6eef0b6c137a3be4ba3bf0507efb2a98a1f1651d39af017666ca593e82430e888cee8619456f9fb47d84a5c33b8b5ebe"
    "e06f75d885c12073401a449f56c16aa64ed3aa62363f77061bfedf72429b023d37d0d724d00a1248db0fead349f1c09b"
    "075372c980991b7b25d479d8f6e8def7e3fe501ab6794c3b976ce0bd04c006bac1a94fb6409f60c45e5c9ec2196a2463"
    "68fb6faf3e6c53b51339b2eb3b52ec6f6dfc511f9b30952ccc814544af5ebd09bee3d004de334afd660f2807192e4bb3"
    "c0cba85745c8740fd20b5f39b9d3fbdb5579c0bd1a60320ad6a100c6402c7279679f25fefb1fa3cc8ea5e9f8db3222f8"
    "3c7516dffd616b152f501ec8ad0552ab323db5fafd23876053317b483e00df829e5c57bbca6f8ca01a87562edf1769db"
    "d542a8f6287effc3ac6732c68c4f5573695b27b0bbca58c8e1ffa35db8f011a010fa3d98fd2183b84afcb56c2dd1d35b"
    "9a53e479b6f84565d28e49bc4bfb9790e1ddf2daa4cb7e3362fb1341cee4c6e8ef20cada36774c01d07e9efe2bf11fb4"
    "95dbda4dae909198eaad8e716b93d5a0d08ed1d0afc725e08e3c5b2f8e7594b78ff6e2fbf2122b648888b812900df01c"
    "4fad5ea0688fc31cd1cff191b3a8c1ad2f2f2218be0e1777ea752dfe8b021fa1e5a0cc0fb56f74e818acf3d6ce89e299"
    "b4a84fe0fd13e0b77cc43b81d2ada8d9165fa2668095770593cc7314211a1477e6ad206577b5fa86c75442f5fb9d35cf"
    "ebcdaf0c7b3e89a0d6411bd3ae1e7e4900250e2d2071b35e226800bb57b8e0af2464369bf009b91e5563911d59dfa6aa"
    "78c14389d95a537f207d5ba202e5b9c5832603766295cfa911c819684e734a41b3472dca7b14a94a1b5100529a532915"
    "d60f573fbc9bc6e42b60a47681e6740008ba6fb5571be91ff296ec6b2a0dd915b6636521e7b9f9b6ff34052ec5855664"
    "53b02d5da99f8fa108ba47996e85076a"
    , 16,
)

SBOX_2 = int(
    "4b7a70e9b5b32944db75092ec4192623ad6ea6b049a7df7d9cee60b88fedb266ecaa8c71699a17ff5664526cc2b19ee1"
    "193602a575094c29a0591340e4183a3e3f54989a5b429d656b8fe4d699f73fd6a1d29c07efe830f54d2d38e6f0255dc1"
    "4cdd20868470eb266382e9c6021ecc5e09686b3f3ebaefc93c9718146b6a70a1687f358452a0e286b79c5305aa500737"
    "3e07841c7fdeae5c8e7d44ec5716f2b8b03ada37f0500c0df01c1f040200b3ffae0cf51a3cb574b225837a58dc0921bd"
    "d19113f97ca92ff69432477322f547013ae5e58137c2dadcc8b576349af3dda7a94461460fd0030eecc8c73ea4751e41"
    "e238cd993bea0e2f3280bba1183eb3314e548b384f6db9086f420d03f60a04bf2cb8129024977c795679b072bcaf89af"
    "de9a771fd9930810b38bae12dccf3f2e5512721f2e6b7124501adde69f84cd877a5847187408da17bc9f9abce94b7d8c"
    "ec7aec3adb851dfa63094366c464c3d2ef1c18473215d908dd433b3724c2ba1612a14d432a65c45150940002133ae4dd"
    "71dff89e10314e5581ac77d65f11199b043556f1d7a3c76b3c11183b5924a509f28fe6ed97f1fbfa9ebabf2c1e153c6e"
    "86e34570eae96fb1860e5e0a5a3e2ab3771fe71c4e3d06fa2965dcb999e71d0f803e89d65266c8252e4cc9789c10b36a"
    "c6150eba94e2ea78a5fc3c531e0a2df4f2f74ea7361d2b3d1939260f19c279605223a708f71312b6ebadfe6eeac31f66"
    "e3bc4595a67bc883b17f37d1018cff28c332ddefbe6c5aa56558218568ab9802eecea50fdb2f953b2aef7dad5b6e2f84"
    "1521b62829076170ecdd4775619f151013cca830eb61bd960334fe1eaa0363cfb5735c904c70a239d59e9e0bcbaade14"
    "eecc86bc60622ca79cab5cabb2f3846e648b1eaf19bdf0caa02369b9655abb5040685a323c2ab4b3319ee9d5c021b8f7"
    "9b540b19875fa09995f7997e623d7da8f837889a97e32d7711ed935f166812810e358829c7e61fd696dedfa17858ba99"
    "57f584a51b2272639b83c3ff1ac24696cdb30aeb532e30548fd948e46dbc312858ebf2ef34c6ffeafe28ed61ee7c3c73"
    "5d4a14d9e864b7e342105d14203e13e045eee2b6a3aaabeadb6c4f15facb4fd0c742f442ef6abbb5654f3b1d41cd2105"
    "d81e799e86854dc7e44b476a3d816250cf62a1f25b8d2646fc8883a0c1c7b6a37f1524c369cb749247848a0b5692b285"
    "095bbf00ad19489d1462b17423820e0058428d2a0c55f5ea1dadf43e233f70613372f0928d937e41d65fecf16c223bdb"
    "7cde3759cbee74604085f2a7ce77326ea607808419f8509ee8efd85561d99735a969a7aac50c06c25a04abfc800bcadc"
    "9e447a2ec3453484fdd567050e1e9ec9db73dbd3105588cd675fda79e3674340c5c43465713e38d83d28f89ef16dff20"
    "153e21e78fb03d4ae6e39f2bdb83adf7"
    , 16,
)

SBOX_3 = int(
    "e93d5a68948140f7f64c261c94692934411520f77602d4f7bcf46b2ed4a20068d40824713320f46a43b7d4b7500061af"
    "1e39f62e9724454614214f74bf8b88404d95fc1d96b591af70f4ddd366a02f45bfbc09ec03bd97857fac6dd031cb8504"
    "96eb27b355fd3941da2547e6abca0a9a28507825530429f40a2c86dae9b66dfb68dc1462d7486900680ec0a427a18dee"
    "4f3ffea2e887ad8cb58ce0067af4d6b6aace1e7cd3375fecce78a399406b2a4220fe9e35d9f385b9ee39d7ab3b124e8b"
    "1dc9faf74b6d185626a36631eae397b23a6efa74dd5b43326841e7f7ca7820fbfb0af54ed8feb397454056acba489527"
    "55533a3a20838d87fe6ba9b7d096954b55a867bca1159a58cca9296399e1db33a62a4a563f3125f95ef47e1c9029317c"
    "fdf8e80204272f7080bb155c05282ce395c11548e4c66d2248c1133fc70f86dc07f9c9ee41041f0f404779a45d886e17"
    "325f51ebd59bc0d1f2bcc18f41113564257b7834602a9c60dff8e8a31f636c1b0e12b4c202e1329eaf664fd1cad18115"
    "6b2395e0333e92e13b240b62eebeb92285b2a20ee6ba0d99de720c8c2da2f728d012784595b794fd647d0862e7ccf5f0"
    "5449a36f877d48fac39dfd27f33e8d1e0a476341992eff743a6f6eabf4f8fd37a812dc60a1ebddf8991be14cdb6e6b0d"
    "c67b55106d672c372765d43bdcd0e804f1290dc7cc00ffa3b5390f92690fed0b667b9ffbcedb7d9ca091cf0bd9155ea3"
    "bb132f88515bad247b9479bf763bd6eb37392eb3cc1159798026e297f42e312d6842ada7c66a2b3b12754ccc782ef11c"
    "6a124237b79251e706a1bbe64bfb63501a6b101811caedfa3d25bdd8e2e1c3c9444216590a121386d90cec6ed5abea2a"
    "64af674eda86a85fbebfe98864e4c3fe9dbc8057f0f7c08660787bf86003604dd1fd8346f6381fb07745ae04d736fccc"
    "83426b33f01eab71b08041873c005e5f77a057bebde8ae2455464299bf582e614e58f48ff2ddfda2f474ef388789bdc2"
    "5366f9c3c8b38e74b475f25546fcd9b97aeb26618b1ddf84846a0e79915f95e2466e598e20b457708cd55591c902de4c"
    "b90bace1bb8205d011a862487574a99eb77f19b6e0a9dc09662d09a1c4324633e85a1f0209f0be8c4a99a0251d6efe10"
    "1ab93d1d0ba5a4dfa186f20f2868f169dcb7da83573906fea1e2ce9b4fcd7f5250115e01a70683faa002b5c40de6d027"
    "9af88c27773f8641c3604c0661a806b5f0177a28c0f586e0006058aa30dc7d6211e69ed72338ea6353c2dd94c2c21634"
    "bbcbee5690bcb6deebfc7da1ce591d766f05e4094b7c018839720a3d7c927c2486e3725f724d9db91ac15bb4d39eb8fc"
    "ed54557808fca5b5d83d7cd34dad0fc41e50ef5eb161e6f8a28514d96c51133c6fd5c7e756e14ec4362abfceddc6c837"
    "d79a323492638212670efa8e406000e0"
    , 16,
)

SBOX_4 = int(
    "3a39ce37d3faf5cfabc277375ac52d1b5cb0679e4fa33742d382274099bc9bbed5118e9dbf0f7315d62d1c7ec700c47b"
    "b78c1b6b21a19045b26eb1be6a366eb45748ab2fbc946e79c6a376d26549c2c8530ff8ee468dde7dd5730a1d4cd04dc6"
    "2939bbdba9ba4650ac9526e8be5ee304a1fad5f06a2d519a63ef8ce29a86ee22c089c2b843242ef6a51e03aa9cf2d0a4"
    "83c061ba9be96a4d8fe51550ba645bd62826a2f9a73a3ae14ba99586ef5562e9c72fefd3f752f7da3f046f6977fa0a59"
    "80e4a91587b086019b09e6ad3b3ee593e990fd5a9e34d7972cf0b7d9022b8b5196d5ac3a017da67dd1cf3ed67c7d2d28"
    "1f9f25cfadf2b89b5ad6b4725a88f54ce029ac71e019a5e647b0acfded93fa9be8d3c48d283b57ccf8d5662979132e28"
    "785f0191ed756055f7960e44e3d35e8c15056dd488f46dba03a161250564f0bdc3eb9e153c9057a297271aeca93a072a"
    "1b3f6d9b1e6321f5f59c66fb26dcf3197533d928b155fdf5035634828aba3cbb28517711c20ad9f8abcc5167ccad925f"
    "4de817513830dc8e379d58629320f991ea7a90c2fb3e7bce5121ce64774fbe32a8b6e37ec3293d4648de53696413e680"
    "a2ae0810dd6db22469852dfd09072166b39a460a6445c0dd586cdecf1c20c8ae5bbef7dd1b588d40ccd2017f6bb4e3bb"
    "dda26a7e3a59ff453e350a44bcb4cdd572eacea8fa6484bb8d6612aebf3c6f47d29be463542f5d9eaec2771bf64e6370"
    "740e0d8de75b1357f8721671af537d5d4040cb084eb4e2cc34d2466a0115af84e1b0042895983a1d06b89fb4ce6ea048"
    "6f3f3b823520ab82011a1d4b277227f8611560b1e7933fdcbb3a792b344525bda08839e151ce794b2f32c9b7a01fbac9"
    "e01cc87ebcc7d1f6cf0111c3a1e8aac71a908749d44fbd9ad0dadecbd50ada380339c32ac69136678df9317ce0b12b4f"
    "f79e59b743f5bb3af2d519ff27d9459cbf97222c15e6fc2a0f91fc719b941525fae59361ceb69cebc2a8645912baa8d1"
    "b6c1075ee3056a0c10d25065cb03a442e0ec6e0e1698db3b4c98a0be3278e9649f1f9532e0d392dfd3a0342b8971f21e"
    "1b0a74414ba3348cc5be7120c37632d8df359f8d9b992f2ee60b6f470fe3f11de54cda541edad891ce6279cfcd3e7e6f"
    "1618b166fd2c1d05848fd2c5f6fb2299f523f357a632762393a8353156cccd02acf081625a75ebb56e16369788d273cc"
    "de96629281b949d04c50901b71c65614e6c6c7bd327a140a45e1d006c3f27b9ac9aa53fd62a80f00bb25bfe235bdd2f6"
    "71126905b2040222b6cbcf7ccd769c2b53113ec01640e3d338abbd602547adf0ba38209cf746ce7677afa1c520756060"
    "85cbfe4e8ae88dd87aaaf9b04cf9aa7e1948c25c02fb8a8c01c36ae4d6ebe1f990d4f869a65cdea03f09252dc208e69f"
    "b74e6132ce77e25b578fdfe33ac372e6"
    , 16,
)

SBOXES = [SBOX_1, SBOX_2, SBOX_3, SBOX_4]


class BlowfishBlockCipher(Cipher):
    """
    Return a cipher object of the Blowfish block cipher.

    The Blowfish key is passed as a constructor parameter rather than as a
    symbolic CLAASP input. The key schedule is computed in Python because it
    generates key-dependent S-boxes, which are then embedded in the CLAASP
    circuit as constant S-box tables.

    The implementation follows the original Blowfish specification [Sch1994]_.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.blowfish_block_cipher import BlowfishBlockCipher
        sage: blowfish = BlowfishBlockCipher()
        sage: blowfish.id
        'blowfish_p64_o64_r16'
        sage: blowfish.number_of_rounds
        16

        sage: blowfish = BlowfishBlockCipher(key=0xF0E1D2C3, key_bit_size=32)
        sage: plaintext = 0xFEDCBA9876543210
        sage: blowfish.evaluate([plaintext]) == 0xBE1E639408640F05
        True
    """

    def __init__(
        self,
        key=0,
        key_bit_size=128,
        number_of_rounds=NUMBER_OF_ROUNDS,
    ):
        super().__init__(
            family_name="blowfish",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[BLOCK_BIT_SIZE],
            cipher_output_bit_size=BLOCK_BIT_SIZE,
        )

        p_array, sboxes = self._expand_key_python(key, key_bit_size)

        self._encrypt_plaintext(
            p_array,
            sboxes,
            number_of_rounds,
        )

    @staticmethod
    def _sbox_to_words(value):
        return [
            (value >> ((255 - i) * WORD_BIT_SIZE)) & MASK32
            for i in range(256)
        ]

    @staticmethod
    def _f_python(x, sboxes):
        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF

        value = (sboxes[0][a] + sboxes[1][b]) & MASK32
        value ^= sboxes[2][c]
        return (value + sboxes[3][d]) & MASK32

    @classmethod
    def _encrypt_block_python(cls, left, right, p_array, sboxes):
        for round_index in range(NUMBER_OF_ROUNDS):
            left ^= p_array[round_index]
            right ^= cls._f_python(left, sboxes)
            left, right = right, left

        left, right = right, left

        right ^= p_array[NUMBER_OF_ROUNDS]
        left ^= p_array[NUMBER_OF_ROUNDS + 1]

        return left & MASK32, right & MASK32

    @classmethod
    def _expand_key_python(cls, key, key_bit_size):
        key = int(key)
        key_bit_size = int(key_bit_size)

        if key_bit_size < 32 or key_bit_size > 448 or key_bit_size % 8 != 0:
            raise ValueError(
                "Blowfish key size must be a multiple of 8 between 32 and 448 bits."
        )

        if key_bit_size < 32 or key_bit_size > 448 or key_bit_size % 8 != 0:
            raise ValueError(
                "Blowfish key size must be a multiple of 8 between 32 and 448 bits."
            )

        if key < 0 or key >= (1 << key_bit_size):
            raise ValueError("The key does not fit in key_bit_size bits.")

        p_array = P_ARRAY.copy()
        sboxes = [
            cls._sbox_to_words(value)
            for value in SBOXES
        ]

        key_bytes = key.to_bytes(key_bit_size // 8, byteorder="big")

        key_index = 0
        for i in range(len(p_array)):
            key_word = 0

            for _ in range(4):
                key_word = (key_word << 8) | key_bytes[key_index]
                key_index = (key_index + 1) % len(key_bytes)

            p_array[i] ^= key_word

        left = 0
        right = 0

        for i in range(0, len(p_array), 2):
            left, right = cls._encrypt_block_python(
                left,
                right,
                p_array,
                sboxes,
            )

            p_array[i] = left
            p_array[i + 1] = right

        for sbox in sboxes:
            for i in range(0, len(sbox), 2):
                left, right = cls._encrypt_block_python(
                    left,
                    right,
                    p_array,
                    sboxes,
                )

                sbox[i] = left
                sbox[i + 1] = right

        return p_array, sboxes

    def _f_function(self, x, sboxes):
        byte_positions = [
            list(range(0, 8)),
            list(range(8, 16)),
            list(range(16, 24)),
            list(range(24, 32)),
        ]

        s1 = self.add_sbox_component(
            [x[0]],
            [byte_positions[0]],
            WORD_BIT_SIZE,
            sboxes[0],
        )

        s2 = self.add_sbox_component(
            [x[0]],
            [byte_positions[1]],
            WORD_BIT_SIZE,
            sboxes[1],
        )

        s3 = self.add_sbox_component(
            [x[0]],
            [byte_positions[2]],
            WORD_BIT_SIZE,
            sboxes[2],
        )

        s4 = self.add_sbox_component(
            [x[0]],
            [byte_positions[3]],
            WORD_BIT_SIZE,
            sboxes[3],
        )

        word_positions = list(range(WORD_BIT_SIZE))

        add_1 = self.add_modadd_component(
            [s1.id, s2.id],
            [word_positions, word_positions],
            WORD_BIT_SIZE,
        )

        xor = self.add_xor_component(
            [add_1.id, s3.id],
            [word_positions, word_positions],
            WORD_BIT_SIZE,
        )

        add_2 = self.add_modadd_component(
            [xor.id, s4.id],
            [word_positions, word_positions],
            WORD_BIT_SIZE,
        )

        return [add_2.id, word_positions]

    def _encrypt_plaintext(self, p_array, sboxes, number_of_rounds):
        word_positions = list(range(WORD_BIT_SIZE))

        left = [
            INPUT_PLAINTEXT,
            list(range(WORD_BIT_SIZE)),
        ]
        right = [
            INPUT_PLAINTEXT,
            list(range(WORD_BIT_SIZE, BLOCK_BIT_SIZE)),
        ]

        for round_index in range(number_of_rounds):
            self.add_round()

            p_word = self.add_constant_component(
                WORD_BIT_SIZE,
                p_array[round_index],
            )

            xor_left = self.add_xor_component(
                [left[0], p_word.id],
                [left[1], word_positions],
                WORD_BIT_SIZE,
            )
            left = [xor_left.id, word_positions]

            f_output = self._f_function(left, sboxes)

            xor_right = self.add_xor_component(
                [right[0], f_output[0]],
                [right[1], f_output[1]],
                WORD_BIT_SIZE,
            )
            right = [xor_right.id, word_positions]

            left, right = right, left

            if round_index < number_of_rounds - 1:
                self.add_round_output_component(
                    [left[0], right[0]],
                    [left[1], right[1]],
                    BLOCK_BIT_SIZE,
                )

        left, right = right, left

        p_right = self.add_constant_component(
            WORD_BIT_SIZE,
            p_array[number_of_rounds],
        )
        xor_right = self.add_xor_component(
            [right[0], p_right.id],
            [right[1], word_positions],
            WORD_BIT_SIZE,
        )
        right = [xor_right.id, word_positions]

        p_left = self.add_constant_component(
            WORD_BIT_SIZE,
            p_array[number_of_rounds + 1],
        )
        xor_left = self.add_xor_component(
            [left[0], p_left.id],
            [left[1], word_positions],
            WORD_BIT_SIZE,
        )
        left = [xor_left.id, word_positions]

        self.add_round_output_component(
            [left[0], right[0]],
            [left[1], right[1]],
            BLOCK_BIT_SIZE,
        )

        self.add_cipher_output_component(
            [left[0], right[0]],
            [left[1], right[1]],
            BLOCK_BIT_SIZE,
        )
