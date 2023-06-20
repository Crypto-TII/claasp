word_bit_size = 3
# for i in range(2**(2*word_bit_size)):
#     for j in range(2 ** (2 * word_bit_size)):


modadd_ddt = []
for i in range(2**(2*word_bit_size)):
    modadd_ddt.append([])
    for j in range(2 ** (word_bit_size)):
        modadd_ddt[i].append(0)

# modadd(x,y) ^ modadd(x+a,y+b)
# delta = modadd(x) ^ modadd(x+a)
def modadd(x, word_bit_size):
    x_left = x >> word_bit_size
    # print(f'{x_left = } = {x_left:0{word_bit_size}b}')
    x_right = x & (2**word_bit_size-1)
    # print(f'{x_right = } = {x_right:0{word_bit_size}b}')
    return (x_left + x_right) % (2**word_bit_size)

for x in range(2**(2*word_bit_size)):
    for a in range(2 ** (2 * word_bit_size)):
        b = modadd(x,word_bit_size) ^ modadd(x^a,word_bit_size)
        modadd_ddt[a][b] = modadd_ddt[a][b] + 1

for a in range(2**(2*word_bit_size)):
    print(f'{a:0{2*word_bit_size}b}', end='')
    for b in range(2 ** (word_bit_size)):
        print(f'{modadd_ddt[a][b]:{4}d}', end='')
    print()
