def carry(a: bool, b: bool, c: bool) -> bool:
    return (a & b) ^ (a & c) ^ (b & c)

def borrow(a: bool, b: bool, c: bool) -> bool:
    na = a ^ 1
    return (na & b) | (na & c) | (a & b & c)

def bct_transfer(state: int, l: bool, r: bool, dL: bool, dR: bool, nL: bool, nR: bool) -> int:
    c1 = bool((state >> 0) & 1)
    b1 = bool((state >> 1) & 1)
    c2 = bool((state >> 2) & 1)
    b2 = bool((state >> 3) & 1)
    
    tmp1 = carry(l, r, c1)
    tmp2 = borrow(l ^ r ^ c1 ^ nL, r ^ nR, b1)
    tmp3 = carry(l ^ dL, r ^ dR, c2)
    tmp4 = borrow(l ^ dL ^ r ^ dR ^ c2 ^ nL, r ^ dR ^ nR, b2)
    
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
    (0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 2, 4)
)

def bct_entry(dL: int, dR: int, nL: int, nR: int, nbit: int = 16) -> int:

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
            return 0.0 
            
        cnt = tmp
        
        dL >>= 1
        dR >>= 1
        nL >>= 1
        nR >>= 1

    dp_sum = sum(cnt)

    pt = 1 << (nbit - 1)
    
    dp_div_nbit = dp_sum // pt
    
    if pt == 0:
        return 0.0
    
    return dp_div_nbit / pt