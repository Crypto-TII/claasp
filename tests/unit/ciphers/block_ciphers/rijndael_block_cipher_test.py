# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
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

"""Unit tests for Rijndael block cipher vectors.

REFERENCES:

Daemen, J., & Rijmen, V. (2002). A Specification for Rijndael, the AES Algorithm.
https://asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf [RijndaelSpec]_.

Daemen, J., & Rijmen, V. (2001). The Design of Rijndael AES -- The
Advanced Encryption Standard.
https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_2002.pdf [RijndaelDesign]_.
"""


import pytest

from claasp.ciphers.block_ciphers.rijndael_block_cipher import RijndaelBlockCipher

D3_VECTOR_SETS = [
    (128, 128, [
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "66E94BD4EF8A2C3B884CFA59CA342B2E",
        ),
        (
            "66E94BD4EF8A2C3B884CFA59CA342B2E",
            "00000000000000000000000000000000",
            "F795BD4A52E29ED713D313FA20E98DBC",
        ),
    ]),
    (160, 128, [
        (
            "0000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "9E38B8EB1D2025A1665AD4B1F5438BB5CAE1AC3F",
        ),
        (
            "9E38B8EB1D2025A1665AD4B1F5438BB5CAE1AC3F",
            "00000000000000000000000000000000",
            "939C167E7F916D45670EE21BFC939E1055054A96",
        ),
    ]),
    (192, 128, [
        (
            "000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "A92732EB488D8BB98ECD8D95DC9C02E052F250AD369B3849",
        ),
        (
            "A92732EB488D8BB98ECD8D95DC9C02E052F250AD369B3849",
            "00000000000000000000000000000000",
            "106F34179C3982DDC6750AA01936B7A180E6B0B9D8D690EC",
        ),
    ]),
    (224, 128, [
        (
            "00000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0623522D88F7B9C63437537157F625DD5697AB628A3B9BE2549895C8",
        ),
        (
            "0623522D88F7B9C63437537157F625DD5697AB628A3B9BE2549895C8",
            "00000000000000000000000000000000",
            "93F93CBDABE23415620E6990B0443D621F6AFBD6EDEFD6990A1965A8",
        ),
    ]),
    (256, 128, [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "A693B288DF7DAE5B1757640276439230DB77C4CD7A871E24D6162E54AF434891",
        ),
        (
            "A693B288DF7DAE5B1757640276439230DB77C4CD7A871E24D6162E54AF434891",
            "00000000000000000000000000000000",
            "5F05857C80B68EA42CCBC759D42C28D5CD490F1D180C7A9397EE585BEA770391",
        ),
    ]),
    (128, 160, [
        (
            "00000000000000000000000000000000",
            "0000000000000000000000000000000000000000",
            "94B434F8F57B9780F0EFF1A9EC4C112C",
        ),
        (
            "94B434F8F57B9780F0EFF1A9EC4C112C",
            "0000000000000000000000000000000000000000",
            "35A00EC955DF43417CEAC2AB2B3F3E76",
        ),
    ]),
    (160, 160, [
        (
            "0000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000",
            "33B12AB81DB7972E8FDC529DDA46FCB529B31826",
        ),
        (
            "33B12AB81DB7972E8FDC529DDA46FCB529B31826",
            "0000000000000000000000000000000000000000",
            "97F03EB018C0BB9195BF37C6A0AECE8E4CB8DE5F",
        ),
    ]),
    (192, 160, [
        (
            "000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000",
            "528E2FFF6005427B67BB1ED31ECC09A69EF41531DF5BA5B2",
        ),
        (
            "528E2FFF6005427B67BB1ED31ECC09A69EF41531DF5BA5B2",
            "0000000000000000000000000000000000000000",
            "71C7687A4C93EBC35601E3662256E10115BEED56A410D7AC",
        ),
    ]),
    (224, 160, [
        (
            "00000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000",
            "58A0C53F3822A32464704D409C2FD0521F3A93E1F6FCFD4C87F1C551",
        ),
        (
            "58A0C53F3822A32464704D409C2FD0521F3A93E1F6FCFD4C87F1C551",
            "0000000000000000000000000000000000000000",
            "D8E93EF2EB49857049D6F6E0F40B67516D2696F94013C065283F7F01",
        ),
    ]),
    (256, 160, [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000",
            "938D36E0CB6B7937841DAB7F1668E47B485D3ACD6B3F6D598B0A9F923823331D",
        ),
        (
            "938D36E0CB6B7937841DAB7F1668E47B485D3ACD6B3F6D598B0A9F923823331D",
            "0000000000000000000000000000000000000000",
            "7B44491D1B24A93B904D171F074AD69669C2B70B134A4D2D773250A4414D78BE",
        ),
    ]),
    (128, 192, [
        (
            "00000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000",
            "AAE06992ACBF52A3E8F4A96EC9300BD7",
        ),
        (
            "AAE06992ACBF52A3E8F4A96EC9300BD7",
            "000000000000000000000000000000000000000000000000",
            "52F674B7B9030FDAB13D18DC214EB331",
        ),
    ]),
    (160, 192, [
        (
            "0000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000",
            "33060F9D4705DDD2C7675F0099140E5A98729257",
        ),
        (
            "33060F9D4705DDD2C7675F0099140E5A98729257",
            "000000000000000000000000000000000000000000000000",
            "012CAB64982156A5710E790F85EC442CE13C520F",
        ),
    ]),
    (192, 192, [
        (
            "000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000",
            "C6348BE20007BAC4A8BD62890C8147A2432E760E9A9F9AB8",
        ),
        (
            "C6348BE20007BAC4A8BD62890C8147A2432E760E9A9F9AB8",
            "000000000000000000000000000000000000000000000000",
            "EB9DEF13C253F81C1FC2829426ED166A65A105C6A04CA33D",
        ),
    ]),
    (224, 192, [
        (
            "00000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000",
            "3856B17BEA77C4611E3397066828AADDA004706A2C8009DF40A811FE",
        ),
        (
            "3856B17BEA77C4611E3397066828AADDA004706A2C8009DF40A811FE",
            "000000000000000000000000000000000000000000000000",
            "160AD76A97AE2C1E05942FDE3DA2962684A92CCC74B8DC23BDE4F469",
        ),
    ]),
    (256, 192, [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000",
            "F927363EF5B3B4984A9EB9109844152EC167F08102644E3F9028070433DF9F2A",
        ),
        (
            "F927363EF5B3B4984A9EB9109844152EC167F08102644E3F9028070433DF9F2A",
            "000000000000000000000000000000000000000000000000",
            "4E03389C68B2E3F623AD8F7F6BFC88613B86F334F4148029AE25F50DB144B80C",
        ),
    ]),
    (128, 224, [
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000",
            "73F8DFF62A36F3EBF31D6F73A56FF279",
        ),
        (
            "73F8DFF62A36F3EBF31D6F73A56FF279",
            "00000000000000000000000000000000000000000000000000000000",
            "3A72F21E10B6473EA9FF14A232E675B4",
        ),
    ]),
    (160, 224, [
        (
            "0000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000",
            "E9F5EA0FA39BB6AD7339F28E58E2E7535F261827",
        ),
        (
            "E9F5EA0FA39BB6AD7339F28E58E2E7535F261827",
            "00000000000000000000000000000000000000000000000000000000",
            "06EF9BC82905306D45810E12D0807796A3D338F9",
        ),
    ]),
    (192, 224, [
        (
            "000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000",
            "ECBE9942CD6703E16D358A829D542456D71BD3408EB23C56",
        ),
        (
            "ECBE9942CD6703E16D358A829D542456D71BD3408EB23C56",
            "00000000000000000000000000000000000000000000000000000000",
            "FD10458ED034368A34047905165B78A6F0591FFEEBF47CC7",
        ),
    ]),
    (224, 224, [
        (
            "00000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000",
            "FE1CF0C8DDAD24E3D751933100E8E89B61CD5D31C96ABFF7209C495C",
        ),
        (
            "FE1CF0C8DDAD24E3D751933100E8E89B61CD5D31C96ABFF7209C495C",
            "00000000000000000000000000000000000000000000000000000000",
            "515D8E2F2B9C5708F112C6DE31CACA47AFB86838B716975A24A09CD4",
        ),
    ]),
    (256, 224, [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000",
            "BC18BF6D369C955BBB271CBCDD66C368356DBA5B33C0005550D2320B1C617E21",
        ),
        (
            "BC18BF6D369C955BBB271CBCDD66C368356DBA5B33C0005550D2320B1C617E21",
            "00000000000000000000000000000000000000000000000000000000",
            "60ABA1D2BE45D8ABFDCF97BCB39F6C17DF29985CF321BAB75E26A26100AC00AF",
        ),
    ]),
    (128, 256, [
        (
            "00000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "DC95C078A2408989AD48A21492842087",
        ),
        (
            "DC95C078A2408989AD48A21492842087",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "08C374848C228233C2B34F332BD2E9D3",
        ),
    ]),
    (160, 256, [
        (
            "0000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "30991844F72973B3B2161F1F11E7F8D9863C5118",
        ),
        (
            "30991844F72973B3B2161F1F11E7F8D9863C5118",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "EEF8B7CC9DBE0F03A1FE9D82E9A759FD281C67E0",
        ),
    ]),
    (192, 256, [
        (
            "000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "17004E806FAEF168FC9CD56F98F070982075C70C8132B945",
        ),
        (
            "17004E806FAEF168FC9CD56F98F070982075C70C8132B945",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "BED33B0AF364DBF15F9C2F3FB24FBDF1D36129C586EEA6B7",
        ),
    ]),
    (224, 256, [
        (
            "00000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "9BF26FAD5680D56B572067EC2FE162F449404C86303F8BE38FAB6E02",
        ),
        (
            "9BF26FAD5680D56B572067EC2FE162F449404C86303F8BE38FAB6E02",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "658F144A34AF44AAE66CFDDAB955C483DFBCB4EE9A19A6701F158A66",
        ),
    ]),
    (256, 256, [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "C6227E7740B7E53B5CB77865278EAB0726F62366D9AABAD908936123A1FC8AF3",
        ),
        (
            "C6227E7740B7E53B5CB77865278EAB0726F62366D9AABAD908936123A1FC8AF3",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "9843E807319C32AD1EA3935EF56A2BA96E4BF19C30E47D88A2B97CBBF2E159E7",
        ),
    ]),
]

D3_TEST_VECTORS = []
for block_bits, key_bits, vector_triples in D3_VECTOR_SETS:
    for idx, (plaintext_hex, key_hex, ciphertext_hex) in enumerate(vector_triples, start=1):
        D3_TEST_VECTORS.append((block_bits, key_bits, idx, key_hex, plaintext_hex, ciphertext_hex))


D3_TEST_IDS = [
    f"test_rijndael_b{block_bits}_k{key_bits}_test_vector_{idx}"
    for block_bits, key_bits, idx, _, _, _ in D3_TEST_VECTORS
]


ROUND_COUNT_CASES = [
    (128, 128, 10),
    (128, 160, 11),
    (128, 192, 12),
    (128, 224, 13),
    (128, 256, 14),
    (160, 128, 11),
    (160, 160, 11),
    (160, 192, 12),
    (160, 224, 13),
    (160, 256, 14),
    (192, 128, 12),
    (192, 160, 12),
    (192, 192, 12),
    (192, 224, 13),
    (192, 256, 14),
    (224, 128, 13),
    (224, 160, 13),
    (224, 192, 13),
    (224, 224, 13),
    (224, 256, 14),
    (256, 128, 14),
    (256, 160, 14),
    (256, 192, 14),
    (256, 224, 14),
    (256, 256, 14),
]

ROUND_COUNT_IDS = [
    f"b{block_bit_size}_k{key_bit_size}_rounds_{expected_rounds}"
    for block_bit_size, key_bit_size, expected_rounds in ROUND_COUNT_CASES
]


class TestRijndaelBlockCipher:
    """Test class for Rijndael block cipher."""

    def test_rijndael_b128_k128_test_vector_1(self):
        """Test Rijndael-128-128: Test vector 1 from specification.

        Reference: [RijndaelSpec]_.
        """
        rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=128)
        key = 0x2b7e151628aed2a6abf7158809cf4f3c
        plaintext = 0x3243f6a8885a308d313198a2e0370734
        expected = 0x3925841d02dc09fbdc118597196a0b32
        assert rijndael.evaluate([key, plaintext]) == expected

    def test_rijndael_b128_k192_test_vector_1(self):
        """Test Rijndael-128-192: Test vector 1 from specification.

        Reference: [RijndaelSpec]_.
        """
        rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=192)
        key = 0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5
        plaintext = 0x3243f6a8885a308d313198a2e0370734
        expected = 0xf9fb29aefc384a250340d833b87ebc00
        assert rijndael.evaluate([key, plaintext]) == expected

    def test_rijndael_b128_k256_test_vector_1(self):
        """Test Rijndael-128-256: Test vector 1 from specification.

        Reference: [RijndaelSpec]_.
        """
        rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=256)
        key = 0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe
        plaintext = 0x3243f6a8885a308d313198a2e0370734
        expected = 0x1a6e6c2c662e7da6501ffb62bc9e93f3
        assert rijndael.evaluate([key, plaintext]) == expected

    def test_rijndael_default_construction(self):
        """Test default cipher construction."""
        rijndael = RijndaelBlockCipher()
        assert rijndael.number_of_rounds == 10  # 128-bit key gives 4 words, so 4+6=10

    def test_rijndael_192_bit_key_rounds(self):
        """Test that 192-bit key gives correct number of rounds."""
        rijndael = RijndaelBlockCipher(key_bit_size=192)
        assert rijndael.number_of_rounds == 12  # 192-bit key gives 6 words, so 6+6=12

    def test_rijndael_256_bit_key_rounds(self):
        """Test that 256-bit key gives correct number of rounds."""
        rijndael = RijndaelBlockCipher(key_bit_size=256)
        assert rijndael.number_of_rounds == 14  # 256-bit key gives 8 words, so 8+6=14

    @pytest.mark.parametrize(
        "block_bit_size,key_bit_size,expected_rounds",
        ROUND_COUNT_CASES,
        ids=ROUND_COUNT_IDS,
    )
    def test_rijndael_round_count_table(self, block_bit_size, key_bit_size, expected_rounds):
        """Check the Rijndael round count table for all supported block/key sizes."""
        rijndael = RijndaelBlockCipher(
            block_bit_size=block_bit_size,
            key_bit_size=key_bit_size,
        )
        assert rijndael.number_of_rounds == expected_rounds

    def test_rijndael_invalid_block_size(self):
        """Test that invalid block size raises error."""
        with pytest.raises(ValueError):
            RijndaelBlockCipher(block_bit_size=96)

    def test_rijndael_invalid_key_size(self):
        """Test that invalid key size raises error."""
        with pytest.raises(ValueError):
            RijndaelBlockCipher(key_bit_size=512)

    @pytest.mark.parametrize(
        "block_bit_size,key_bit_size,vector_idx,key_hex,plaintext_hex,ciphertext_hex",
        D3_TEST_VECTORS,
        ids=D3_TEST_IDS,
    )
    def test_rijndael_d3_vectors(
        self,
        block_bit_size,
        key_bit_size,
        vector_idx,
        key_hex,
        plaintext_hex,
        ciphertext_hex,
    ):
        """Validate D.3 vectors from [RijndaelDesign]_ across all Rijndael sizes."""
        key = int(key_hex, 16)
        plaintext = int(plaintext_hex, 16)
        expected = int(ciphertext_hex, 16)
        rijndael = RijndaelBlockCipher(block_bit_size=block_bit_size, key_bit_size=key_bit_size)
        assert rijndael.evaluate([key, plaintext]) == expected
