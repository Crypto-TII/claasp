from claasp.ciphers.hash_functions.whirlpool_hash_function import  WhirlpoolHashFunction

def test_whirlpool_hash_function():
    whirlpool = WhirlpoolHashFunction()
    assert whirlpool.type == 'hash_function'
    assert whirlpool.family_name == 'whirlpool_hash_function'
    assert whirlpool.id == 'whirlpool_hash_function_i512_o512_r10'
    assert whirlpool.component_from(0,0).id == 'constant_0_0'

    whirlpool = WhirlpoolHashFunction(number_of_rounds=4)
    assert whirlpool.number_of_rounds == 4
    assert whirlpool.id == 'whirlpool_hash_function_i512_o512_r4'
    assert whirlpool.component_from(3,0).id == 'sbox_3_0'

    # The following test vector values have been obtained from the reference implementation of Whirlpool
    # available at https://web.archive.org/web/20171129084214/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html

    whirlpool = WhirlpoolHashFunction()
    message = 0x61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018
    digest = 0x4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5
    assert whirlpool.evaluate([message]) == digest
    assert whirlpool.evaluate_vectorized([message], evaluate_api=True) == digest

    message = 0x61800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008
    digest = 0x8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a
    assert whirlpool.evaluate([message]) == digest
    assert whirlpool.evaluate_vectorized([message], evaluate_api=True) == digest

    message = 0x6d657373616765206469676573748000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000070
    digest = 0x378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e
    assert whirlpool.evaluate([message]) == digest
    assert whirlpool.evaluate_vectorized([message], evaluate_api=True) == digest

    message = 0x6162636465666768696a6b6c6d6e6f707172737475767778797a80000000000000000000000000000000000000000000000000000000000000000000000000d0
    digest = 0xf1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b
    assert whirlpool.evaluate([message]) == digest
    assert whirlpool.evaluate_vectorized([message], evaluate_api=True) == digest

    #The following test vector values have been hand made

    message = 0x68656c6c6f686f77617265796f758000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000070
    digest = 0x2600a67308114432afa3193d3ae9c4ef0babb2442527dc639d09bea96cae5ece16ffddf15cb81bf2830ecbab906b4518d12c88fbd8a3ff769f61c9ac29350d38
    assert whirlpool.evaluate([message]) == digest
    assert whirlpool.evaluate_vectorized([message], evaluate_api=True) == digest

    whirlpool = WhirlpoolHashFunction()
    message = 0x6162636462636465636465666465666765666768666768696768696a68696a6b8000000000000000000000000000000000000000000000000000000000000000
    digest = 0x7738e1b541a036ea458d50f80fa01c447288ce97d1a0dcf01695ffd6e71d092533be309f012a5909729114595f086e760718afe365bc09deb6afa180bcec2a98
    assert whirlpool.evaluate([message]) == digest
    assert whirlpool.evaluate_vectorized([message], evaluate_api=True) == digest
