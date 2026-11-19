"""Reference modular-addition BCT evaluator used in the paper experiments.

Wang, Wang and Sun, ToSC 2023(1), DOI 10.46586/tosc.v2023.i1.152-191.
Inputs are integer XOR differences for F(left_bit,r)=(left_bit+r mod 2**n, r).
"""


def carry(a: bool, b: bool, c: bool) -> bool:
    """Return the carry bit of three input bits (the majority function)."""
    return (a & b) ^ (a & c) ^ (b & c)


def borrow(a: bool, b: bool, c: bool) -> bool:
    """Return the outgoing borrow of a - b - c, for three input bits."""
    na = a ^ 1
    return (na & b) | (na & c) | (a & b & c)


def bct_transfer(
    state: int, left_bit: bool, r: bool, dL: bool, dR: bool, nL: bool, nR: bool
) -> int:
    """Advance the four carry/borrow bits for one bit of a boomerang quartet.

    ``state`` encodes the four incoming bits; left_bit/r are the data bits, and
    dL/dR/nL/nR are upper/lower difference bits. Return a four-bit integer.
    """
    c1 = bool((state >> 0) & 1)
    b1 = bool((state >> 1) & 1)
    c2 = bool((state >> 2) & 1)
    b2 = bool((state >> 3) & 1)

    tmp1 = carry(left_bit, r, c1)
    tmp2 = borrow(left_bit ^ r ^ c1 ^ nL, r ^ nR, b1)
    tmp3 = carry(left_bit ^ dL, r ^ dR, c2)
    tmp4 = borrow(left_bit ^ dL ^ r ^ dR ^ c2 ^ nL, r ^ dR ^ nR, b2)

    return (tmp4 << 3) ^ (tmp3 << 2) ^ (tmp2 << 1) ^ (tmp1 << 0)


BCT_TABLE = (
    (4, 2, 2, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0),
    (2, 2, 0, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2),
    (2, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0),
    (2, 0, 0, 0, 2, 4, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2),
    (2, 0, 2, 2, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0, 2),
    (2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0),
    (0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0),
    (0, 0, 0, 0, 0, 2, 2, 2, 0, 0, 2, 0, 0, 2, 0, 2),
    (2, 0, 2, 0, 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 0, 0),
    (0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0),
    (0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2),
    (2, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0, 2, 2, 0, 2),
    (2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 4, 2, 0, 0, 0, 2),
    (0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 2, 2, 0, 0, 2, 2),
    (2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 0, 2, 2),
    (0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 2, 4),
)


def bct_entry(dL: int, dR: int, nL: int, nR: int, nbit: int = 16) -> int:
    """Count successful quartets for four nbit-wide XOR differences.

    The dynamic program uses least-significant bits first and ignores the
    final carry. Return an integer in [0, 2**(2*nbit)], not a probability.

    Example: bct_entry(0, 0, 0, 0, 4) == 256.
    """
    if nbit < 1 or any(value < 0 or value >= 1 << nbit for value in (dL, dR, nL, nR)):
        raise ValueError("Differences must fit in a positive word size")

    cnt = [1, 0, 0, 0]

    for _ in range(nbit - 1):
        bdL = bool(dL & 1)
        bdR = bool(dR & 1)
        bnL = bool(nL & 1)
        bnR = bool(nR & 1)

        tmp = [0, 0, 0, 0]

        index = (bnR << 3) | (bnL << 2) | (bdR << 1) | (bdL << 0)
        tr = BCT_TABLE[index]

        tmp[0] = tr[0] * cnt[0] + tr[1] * cnt[1] + tr[2] * cnt[2] + tr[3] * cnt[3]
        tmp[1] = tr[4] * cnt[0] + tr[5] * cnt[1] + tr[6] * cnt[2] + tr[7] * cnt[3]
        tmp[2] = tr[8] * cnt[0] + tr[9] * cnt[1] + tr[10] * cnt[2] + tr[11] * cnt[3]
        tmp[3] = tr[12] * cnt[0] + tr[13] * cnt[1] + tr[14] * cnt[2] + tr[15] * cnt[3]

        if sum(tmp) == 0:
            return 0

        cnt = tmp

        dL >>= 1
        dR >>= 1
        nL >>= 1
        nR >>= 1

    return 4 * sum(cnt)


def bct_entry128(dL: int, dR: int, nL: int, nR: int, nbit: int) -> float:
    """Return the normalized BCT entry as a float for nbit-wide differences.

    Arguments have the same meaning as in ``bct_entry``. Python integers
    preserve the count until the final division, including widths above 64.
    The historical name is retained for experiment compatibility.

    Example: bct_entry128(0, 0, 0, 0, 4) == 1.0.
    """
    return bct_entry(dL, dR, nL, nR, nbit) / (1 << (2 * nbit))
