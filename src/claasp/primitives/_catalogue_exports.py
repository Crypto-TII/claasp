"""Generated public primitive catalogue exports.

Regenerate with ``tools/generate_primitive_exports.py``.
"""

from importlib import import_module

CATEGORY_EXPORTS = {
    "block_ciphers": {
        "AES": "claasp.primitives.block_ciphers.aes",
        "Aradi": "claasp.primitives.block_ciphers.aradi",
        "AradiSBox": "claasp.primitives.block_ciphers.aradi.sbox",
        "AradiSBoxCompactLinearMap": "claasp.primitives.block_ciphers.aradi.sbox_compact_linear_map",
        "BEA1": "claasp.primitives.block_ciphers.bea1",
        "Baksheesh": "claasp.primitives.block_ciphers.baksheesh",
        "Ballet": "claasp.primitives.block_ciphers.ballet",
        "CHAM": "claasp.primitives.block_ciphers.cham",
        "Cast": "claasp.primitives.block_ciphers.cast",
        "DES": "claasp.primitives.block_ciphers.des",
        "DESExactKeyLength": "claasp.primitives.block_ciphers.des.exact_key_length",
        "Gift": "claasp.primitives.block_ciphers.gift",
        "GiftSbox": "claasp.primitives.block_ciphers.gift.sbox",
        "Gost": "claasp.primitives.block_ciphers.gost",
        "HIGHT": "claasp.primitives.block_ciphers.hight",
        "IDEA": "claasp.primitives.block_ciphers.idea",
        "Kalyna": "claasp.primitives.block_ciphers.kalyna",
        "Kasumi": "claasp.primitives.block_ciphers.kasumi",
        "Katan": "claasp.primitives.block_ciphers.katan",
        "KatanFSR": "claasp.primitives.block_ciphers.katan.fsr",
        "Ktantan": "claasp.primitives.block_ciphers.ktantan",
        "KtantanFSR": "claasp.primitives.block_ciphers.ktantan.fsr",
        "LBlock": "claasp.primitives.block_ciphers.lblock",
        "LEA": "claasp.primitives.block_ciphers.lea",
        "Led": "claasp.primitives.block_ciphers.led",
        "LowMC": "claasp.primitives.block_ciphers.lowmc",
        "MSX": "claasp.primitives.block_ciphers.msx",
        "Midori": "claasp.primitives.block_ciphers.midori",
        "Piccolo": "claasp.primitives.block_ciphers.piccolo",
        "Present": "claasp.primitives.block_ciphers.present",
        "Prince": "claasp.primitives.block_ciphers.prince",
        "PrinceV2": "claasp.primitives.block_ciphers.prince_v2",
        "RC5": "claasp.primitives.block_ciphers.rc5",
        "Raiden": "claasp.primitives.block_ciphers.raiden",
        "Rectangle": "claasp.primitives.block_ciphers.rectangle",
        "Rijndael": "claasp.primitives.block_ciphers.rijndael",
        "SM4": "claasp.primitives.block_ciphers.sm4",
        "SPARX": "claasp.primitives.block_ciphers.sparx",
        "Saecham": "claasp.primitives.block_ciphers.saecham",
        "Serpent": "claasp.primitives.block_ciphers.serpent",
        "Simeck": "claasp.primitives.block_ciphers.simeck",
        "SimeckSbox": "claasp.primitives.block_ciphers.simeck.sbox",
        "Simon": "claasp.primitives.block_ciphers.simon",
        "SimonSbox": "claasp.primitives.block_ciphers.simon.sbox",
        "Skinny": "claasp.primitives.block_ciphers.skinny",
        "Skipjack": "claasp.primitives.block_ciphers.skipjack",
        "Speck": "claasp.primitives.block_ciphers.speck",
        "Speedy": "claasp.primitives.block_ciphers.speedy",
        "Splight": "claasp.primitives.block_ciphers.splight",
        "Subterranean": "claasp.primitives.block_ciphers.subterranean",
        "TEA": "claasp.primitives.block_ciphers.tea",
        "TinyJambu": "claasp.primitives.block_ciphers.tinyjambu",
        "TinyJambuFSRWordBased": "claasp.primitives.block_ciphers.tinyjambu.fsr_word",
        "TinyJambuWordBased": "claasp.primitives.block_ciphers.tinyjambu.word",
        "Twine": "claasp.primitives.block_ciphers.twine",
        "Twofish": "claasp.primitives.block_ciphers.twofish",
        "UKNIT": "claasp.primitives.block_ciphers.uknit",
        "Ublock": "claasp.primitives.block_ciphers.ublock",
        "UblockSingleLinearLayer": "claasp.primitives.block_ciphers.ublock.single_linear_layer",
        "Warp": "claasp.primitives.block_ciphers.warp",
        "XTEA": "claasp.primitives.block_ciphers.xtea",
    },
    "block_functions": {
        "A51": "claasp.primitives.block_functions.a5_1",
        "A52": "claasp.primitives.block_functions.a5_2",
        "Bivium": "claasp.primitives.block_functions.bivium",
        "ChaChaKeystreamBlock": "claasp.primitives.block_functions.chacha",
        "SiphashMAC": "claasp.primitives.block_functions.siphash",
        "Snow3G": "claasp.primitives.block_functions.snow3g",
        "Trivium": "claasp.primitives.block_functions.trivium",
        "Zuc": "claasp.primitives.block_functions.zuc",
    },
    "functions": {
        "Blake": "claasp.primitives.functions.blake",
        "Blake2": "claasp.primitives.functions.blake2",
        "BluetoothE0": "claasp.primitives.functions.bluetooth_e0",
        "MD5": "claasp.primitives.functions.md5",
        "SHA1": "claasp.primitives.functions.sha1",
        "SHA2": "claasp.primitives.functions.sha2",
        "Whirlpool": "claasp.primitives.functions.whirlpool",
    },
    "permutations": {
        "Ascon": "claasp.primitives.permutations.ascon",
        "AsconSboxSigma": "claasp.primitives.permutations.ascon.sbox_sigma",
        "AsconSboxSigmaNoMatrix": "claasp.primitives.permutations.ascon.sbox_sigma_no_matrix",
        "ChaCha": "claasp.primitives.permutations.chacha",
        "ChaskeyPi": "claasp.primitives.permutations.chaskeypi",
        "Forro": "claasp.primitives.permutations.forro",
        "Gaston": "claasp.primitives.permutations.gaston",
        "GastonSbox": "claasp.primitives.permutations.gaston.sbox",
        "GastonSboxTheta": "claasp.primitives.permutations.gaston.sbox_theta",
        "Gimli": "claasp.primitives.permutations.gimli",
        "GimliSbox": "claasp.primitives.permutations.gimli.sbox",
        "GrainCore": "claasp.primitives.permutations.grain_core",
        "Keccak": "claasp.primitives.permutations.keccak",
        "KeccakInvertible": "claasp.primitives.permutations.keccak.invertible",
        "KeccakSbox": "claasp.primitives.permutations.keccak.sbox",
        "Knot": "claasp.primitives.permutations.knot",
        "Norx": "claasp.primitives.permutations.norx",
        "Photon": "claasp.primitives.permutations.photon",
        "Salsa": "claasp.primitives.permutations.salsa",
        "Sparkle": "claasp.primitives.permutations.sparkle",
        "Speckey": "claasp.primitives.permutations.speckey",
        "SpongentPi": "claasp.primitives.permutations.spongent_pi",
        "SpongentPiFSR": "claasp.primitives.permutations.spongent_pi.fsr",
        "SpongentPiPrecomputation": "claasp.primitives.permutations.spongent_pi.precomputation",
        "Xoodoo": "claasp.primitives.permutations.xoodoo",
        "XoodooInvertible": "claasp.primitives.permutations.xoodoo.invertible",
        "XoodooSbox": "claasp.primitives.permutations.xoodoo.sbox",
    },
    "single_component_primitives": {
        "Add": "claasp.primitives.single_component_primitives.add",
        "BinaryAffineMap": "claasp.primitives.single_component_primitives.binary_affine_map",
        "BitVectorSBox": "claasp.primitives.single_component_primitives.bit_vector_sbox",
        "BitwiseAnd": "claasp.primitives.single_component_primitives.bitwise_and",
        "BitwiseNot": "claasp.primitives.single_component_primitives.bitwise_not",
        "BitwiseOr": "claasp.primitives.single_component_primitives.bitwise_or",
        "Constant": "claasp.primitives.single_component_primitives.constant",
        "FeedbackRegister": "claasp.primitives.single_component_primitives.feedback_register",
        "IDEAMultiply": "claasp.primitives.single_component_primitives.idea_multiply",
        "Identity": "claasp.primitives.single_component_primitives.identity",
        "LinearMap": "claasp.primitives.single_component_primitives.linear_map",
        "ModularAdd": "claasp.primitives.single_component_primitives.modular_add",
        "ModularMultiply": "claasp.primitives.single_component_primitives.modular_multiply",
        "ModularSubtract": "claasp.primitives.single_component_primitives.modular_subtract",
        "Multiply": "claasp.primitives.single_component_primitives.multiply",
        "Permutation": "claasp.primitives.single_component_primitives.permutation",
        "Power": "claasp.primitives.single_component_primitives.power",
        "Rotate": "claasp.primitives.single_component_primitives.rotate",
        "SBox": "claasp.primitives.single_component_primitives.sbox",
        "Shift": "claasp.primitives.single_component_primitives.shift",
        "VariableRotate": "claasp.primitives.single_component_primitives.variable_rotate",
        "VariableShift": "claasp.primitives.single_component_primitives.variable_shift",
        "Xor": "claasp.primitives.single_component_primitives.xor",
    },
    "toy_primitives": {
        "CipherFour": "claasp.primitives.toy_primitives.cipherfour",
        "Fancy": "claasp.primitives.toy_primitives.fancy",
        "Heys": "claasp.primitives.toy_primitives.heys",
        "ToyAES": "claasp.primitives.toy_primitives.toyaes",
        "ToyFeistel": "claasp.primitives.toy_primitives.toyfeistel",
        "ToySPN1": "claasp.primitives.toy_primitives.toyspn1",
        "ToySPN2": "claasp.primitives.toy_primitives.toyspn2",
    },
    "tweakable_block_ciphers": {
        "BipBip": "claasp.primitives.tweakable_block_ciphers.bipbip",
        "Blink": "claasp.primitives.tweakable_block_ciphers.blink",
        "Chilow": "claasp.primitives.tweakable_block_ciphers.chilow",
        "Mantis": "claasp.primitives.tweakable_block_ciphers.mantis",
        "QARMAv2": "claasp.primitives.tweakable_block_ciphers.qarmav2",
        "QARMAv2MixColumn": "claasp.primitives.tweakable_block_ciphers.qarmav2.mixcolumn",
        "SCARF": "claasp.primitives.tweakable_block_ciphers.scarf",
        "Threefish": "claasp.primitives.tweakable_block_ciphers.threefish",
        "Trax": "claasp.primitives.tweakable_block_ciphers.trax",
    },
}

ALL_EXPORTS = {
    name: module for exports in CATEGORY_EXPORTS.values() for name, module in exports.items()
}


def load_export(name: str, exports=ALL_EXPORTS):
    """Load one public primitive class without eagerly importing the catalogue.

    Unknown export names are reported as attributes because this loader backs
    the package-level lazy attribute boundary.

    EXAMPLES::

        >>> load_export("AES").__name__
        'AES'
        >>> try:
        ...     load_export("not-a-primitive")
        ... except AttributeError as error:
        ...     print(error)
        not-a-primitive
    """

    try:
        module_name = exports[name]
    except KeyError as error:
        raise AttributeError(name) from error
    return getattr(import_module(module_name), name)


__all__ = ["ALL_EXPORTS", "CATEGORY_EXPORTS", "load_export"]
