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

import pytest


def test_idea_cipher_creation():
    """Test that IDEA cipher can be created with correct parameters."""
    from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher
    
    idea = IdeaBlockCipher()
    
    assert idea.family_name == "idea"
    assert idea.type == "block_cipher"
    assert idea.number_of_rounds == 10  # 1 key schedule + 8 rounds + 1 output transformation
    assert idea.inputs == ['plaintext', 'key']
    assert idea.inputs_bit_size == [64, 128]
    assert idea.output_bit_size == 64


def test_idea_cipher_components():
    """Test that IDEA cipher has the expected component structure."""
    from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher
    
    idea = IdeaBlockCipher(number_of_rounds=1)
    
    # Round 0 is key schedule with ROTATE components
    first_component = idea.component_from(0, 0)
    assert first_component.type == "word_operation"
    assert first_component.description[0] == "ROTATE"
    
    # Round 1 should start with idea_modmul (first cipher round)
    first_cipher_component = idea.component_from(1, 0)
    assert first_cipher_component.type == "word_operation"
    assert first_cipher_component.description[0] == "IDEA_MODMUL"
    assert first_cipher_component.description[2] == 65537  # modulus 2^16 + 1
    
    # Check that we have various component types in the cipher
    all_components = idea.get_all_components()
    component_types = {c.description[0] if c.type == "word_operation" else c.type for c in all_components}
    
    # IDEA should use idea_modmul, MODADD, XOR, and ROTATE (for key schedule)
    assert "IDEA_MODMUL" in component_types
    assert "MODADD" in component_types
    assert "XOR" in component_types
    assert "ROTATE" in component_types


def test_idea_cipher_word_size():
    """Test that IDEA uses 16-bit words."""
    from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher
    
    idea = IdeaBlockCipher()
    
    assert idea.WORD_SIZE == 16
    assert idea.MODULUS_MUL == 65537  # 2^16 + 1
    assert idea.MODULUS_ADD == 65536  # 2^16


def test_idea_cipher_full_rounds():
    """Test that IDEA with 8 rounds has correct structure."""
    from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher
    
    idea = IdeaBlockCipher(number_of_rounds=8)
    
    # 1 key schedule round + 8 cipher rounds + 1 output transformation round = 10 total
    assert idea.number_of_rounds == 10
    
    # Count idea_modmul operations: each cipher round has 4 MUL operations
    # 8 rounds × 4 = 32, plus 2 more in output transformation = 34 total
    all_components = idea.get_all_components()
    modmul_components = [c for c in all_components if c.type == "word_operation" and c.description[0] == "IDEA_MODMUL"]
    
    # Each round: 2 idea_modmul (X1*Z1, X4*Z4) + 2 idea_modmul in MA box (T1*Z5, U2*Z6) = 4 per round
    # 8 rounds × 4 = 32, plus 2 in output transformation (X1*Z1, X4*Z4) = 34 total
    assert len(modmul_components) == 34, f"Expected 34 idea_modmul components, got {len(modmul_components)}"


def test_idea_cipher_component_ids():
    """Test that IDEA components have proper IDs."""
    from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher
    
    idea = IdeaBlockCipher(number_of_rounds=1)
    
    # Check that component IDs follow pattern
    # Round 0 is key schedule with ROTATE
    first_component = idea.component_from(0, 0)
    assert first_component.id.startswith("rot_0_")
    
    # Round 1 is first cipher round with idea_modmul
    first_cipher_component = idea.component_from(1, 0)
    assert first_cipher_component.id.startswith("idea_modmul_1_")
    
    # Check that all components have valid IDs
    all_components = idea.get_all_components()
    for component in all_components:
        assert "_" in component.id
        parts = component.id.split("_")
        assert len(parts) >= 3  # type_round_index format


def test_idea_cipher_inputs():
    """Test that IDEA cipher correctly references plaintext and key inputs."""
    from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher
    
    idea = IdeaBlockCipher(number_of_rounds=1)
    
    # Round 0 has key schedule (ROTATE component references key)
    first_component = idea.component_from(0, 0)
    assert len(first_component.input_id_links) == 1
    assert "key" in first_component.input_id_links[0]
    
    # Round 1 (first cipher round) should reference plaintext and key/subkeys
    first_cipher_component = idea.component_from(1, 0)
    assert len(first_cipher_component.input_id_links) == 2
    # One input should be plaintext, the other should be a key or subkey component
    input_sources = set(first_cipher_component.input_id_links)
    assert any("plaintext" in src for src in input_sources) or any("key" in src or "rot_" in src for src in input_sources)


def test_idea_cipher_evaluation():
    """Test IDEA cipher encryption with a simple test case.
    
    This test verifies that the cipher can evaluate correctly.
    For full validation, official IDEA test vectors should be used.
    """
    from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher
    
    idea = IdeaBlockCipher(number_of_rounds=8)
    
    # Test with zero plaintext and zero key (simple sanity check)
    plaintext = 0x0000000000000000
    key = 0x00000000000000000000000000000000

    # Evaluate cipher
    ciphertext = idea.evaluate([plaintext, key])

    # Check that we get a valid output
    assert ciphertext is not None

    # Output should be 64 bits
    assert 0 <= ciphertext < 2**64, f"Ciphertext {hex(ciphertext)} is not a valid 64-bit value"
    
    # Verify evaluate_vectorized produces same result
    assert idea.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    # Test that different inputs produce different outputs
    plaintext2 = 0xf129a6601ef62a47
    key2 = 0x2bd6459f82c5b300952c49104881ff48
    ciphertext2 = idea.evaluate([plaintext2, key2])

    assert ciphertext2 != ciphertext, "Different inputs should produce different outputs"
    assert idea.evaluate_vectorized([plaintext2, key2], evaluate_api=True) == ciphertext2


def test_idea_cipher_official_vector():
    """
    Official test vector from https://link.springer.com/content/pdf/10.1007/3-540-46877-3_35.pdf
    Verify IDEA implementation against an official test vector (paper appendix)."""
    from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher

    cipher = IdeaBlockCipher()

    # Format: (name, plaintext, key, expected_ciphertext)
    test_vectors = [
        (
            "Lai-Massey Simple Vector",
            0x0000000100020003,
            0x00010002000300040005000600070008, 
            0x11fbed2b01986de5  
        )
    ]
    for name, plaintext, key, expected_ciphertext in test_vectors:
        actual_ciphertext = cipher.evaluate([plaintext, key])
        assert actual_ciphertext == expected_ciphertext, (
            f"Test Vector '{name}' (evaluate) mismatch: "
            f"expected {hex(expected_ciphertext)}, got {hex(actual_ciphertext)}"
        )
        vectorized_result = cipher.evaluate_vectorized([plaintext, key], evaluate_api=True)
        assert vectorized_result == expected_ciphertext, (
            f"Test Vector '{name}' (evaluate_vectorized) mismatch: "
            f"expected {hex(expected_ciphertext)}, got {hex(vectorized_result)}"
        )


def test_idea_cipher_all_zeros_plaintext():
    """Verify IDEA encryption for all-zero plaintext with a given key."""
    from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher

    cipher = IdeaBlockCipher()

    plaintext = 0x0000000000000000
    key = 0x0
    expected_ciphertext = 0x1000100000000

    actual_ciphertext = cipher.evaluate([plaintext, key])

    assert actual_ciphertext == expected_ciphertext, (
        f"All-zero plaintext test vector mismatch: expected {hex(expected_ciphertext)}, got {hex(actual_ciphertext)}"
    )
    assert cipher.evaluate_vectorized([plaintext, key], evaluate_api=True) == expected_ciphertext


# NESSIE test vectors from https://github.com/bozhu/IDEA-Python/blob/master/test.py
# Format: (key, plaintext, ciphertext)
NESSIE_TEST_VECTORS = [
    # Set 1: Keys with single bit set, plaintext = all zeros
    (0x80000000000000000000000000000000, 0x0000000000000000, 0xb1f5f7f87901370f),
    (0x40000000000000000000000000000000, 0x0000000000000000, 0xb3927dffb6358626),
    (0x20000000000000000000000000000000, 0x0000000000000000, 0xe987e0029fb99785),
    (0x10000000000000000000000000000000, 0x0000000000000000, 0x754a03ce08db7daa),
    (0x08000000000000000000000000000000, 0x0000000000000000, 0xf015f9fb0cfc7e1c),
    (0x04000000000000000000000000000000, 0x0000000000000000, 0x69c9fe6007b8fcdf),
    (0x02000000000000000000000000000000, 0x0000000000000000, 0x8da7bc0e63b40dd0),
    (0x01000000000000000000000000000000, 0x0000000000000000, 0x2c49bf7de28c666b),
    (0x00800000000000000000000000000000, 0x0000000000000000, 0x9a4717e8f935712b),
    (0x00400000000000000000000000000000, 0x0000000000000000, 0x90c77c47804bedcc),
    (0x00200000000000000000000000000000, 0x0000000000000000, 0x156e976ee8194241),
    (0x00100000000000000000000000000000, 0x0000000000000000, 0x168a0ad30485fc27),
    (0x00080000000000000000000000000000, 0x0000000000000000, 0x3f3b32602c5b4fed),
    (0x00040000000000000000000000000000, 0x0000000000000000, 0x7c282ea23ca3b968),
    (0x00020000000000000000000000000000, 0x0000000000000000, 0x13ea33701f98cce5),
    (0x00010000000000000000000000000000, 0x0000000000000000, 0x7c92bc91c48f0084),
    
    # Set 2: Repeated byte patterns
    (0x01010101010101010101010101010101, 0x0101010101010101, 0xe3f8aff7a3795615),
    (0x02020202020202020202020202020202, 0x0202020202020202, 0x93d8c66f869189b9),
    (0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f, 0xc0b13df73b24f9b3),
    (0xffffffffffffffffffffffffffffffff, 0xffffffffffffffff, 0xcd1ab2c1211041fb),
    
    # Set 3: Sequential and specific patterns  
    (0x000102030405060708090a0b0c0d0e0f, 0x0011223344556677, 0xf526ab9a62c0d258),
    (0x2bd6459f82c5b300952c49104881ff48, 0xea024714ad5c4d84, 0xc8fb51d3516627a8),
    
    # Set 4: Plaintext with single bit set, key = all zeros
    (0x00000000000000000000000000000000, 0x8000000000000000, 0x8001000180008000),
    (0x00000000000000000000000000000000, 0x4000000000000000, 0xc00180014000c000),
    (0x00000000000000000000000000000000, 0x0000000100000000, 0x0001000000010001),
    (0x00000000000000000000000000000000, 0x0000000000000001, 0x0013fff500120009),
    (0x00000000000000000000000000000000, 0x0000000000000000, 0x0001000100000000),
]


@pytest.mark.parametrize("key,plaintext,expected_ciphertext", NESSIE_TEST_VECTORS)
def test_idea_cipher_nessie_vectors(key, plaintext, expected_ciphertext):
    """Test IDEA cipher against NESSIE test vectors."""
    from claasp.ciphers.block_ciphers.idea_block_cipher import IdeaBlockCipher
    
    cipher = IdeaBlockCipher()
    actual_ciphertext = cipher.evaluate([plaintext, key])
    
    assert actual_ciphertext == expected_ciphertext, (
        f"NESSIE vector failed:\n"
        f"  Key: {hex(key)}\n"
        f"  Plaintext: {hex(plaintext)}\n"
        f"  Expected: {hex(expected_ciphertext)}\n"
        f"  Got: {hex(actual_ciphertext)}"
    )
    assert cipher.evaluate_vectorized([plaintext, key], evaluate_api=True) == expected_ciphertext
