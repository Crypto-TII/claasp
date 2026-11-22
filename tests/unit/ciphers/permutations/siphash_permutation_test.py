"""Independent full-word SipRound evaluation and inverse regression."""
import random
import pytest
from claasp.ciphers.permutations.siphash_permutation import SipHashPermutation


def reference(state, rounds):
    mask=(1<<64)-1
    words=[(state>>(64*(3-i)))&mask for i in range(4)]
    def rol(x,n):return ((x<<n)|(x>>(64-n)))&mask
    a,b,c,d=words
    for _ in range(rounds):
        a=(a+b)&mask;b=rol(b,13)^a;a=rol(a,32)
        c=(c+d)&mask;d=rol(d,16)^c
        a=(a+d)&mask;d=rol(d,21)^a
        c=(c+b)&mask;b=rol(b,17)^c;c=rol(c,32)
    return (a<<192)|(b<<128)|(c<<64)|d


@pytest.mark.parametrize('rounds',[1,2,4])
def test_sipround_values_and_inverse(rounds):
    cipher=SipHashPermutation(number_of_rounds=rounds)
    inverse=cipher.cipher_inverse()
    rng=random.Random(20261122)
    for state in [0,1,(1<<256)-1]+[rng.getrandbits(256) for _ in range(8)]:
        expected=reference(state,rounds)
        assert cipher.evaluate([state])==expected
        assert inverse.evaluate([expected])==state


@pytest.mark.parametrize('rounds',[0,-1,True,1.5])
def test_sipround_rejects_invalid_counts(rounds):
    with pytest.raises(ValueError,match='positive integer'):
        SipHashPermutation(number_of_rounds=rounds)
