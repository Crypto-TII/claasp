from gurobipy import *


def anf_ascon_sbox(model, x, y):
    ########## Copying (create var for each occurence of xi)
    # x = model.addVars(list(range(5)), vtype=GRB.BINARY, name="x")
    # y = model.addVars(list(range(5)), vtype=GRB.BINARY, name="y")

    copy_x0 = model.addVars(list(range(7)), vtype=GRB.BINARY)
    for i in range(7):
        model.addConstr(x[0] >= copy_x0[i])
    model.addConstr(sum(copy_x0[i] for i in range(7)) >= x[0])

    copy_x1 = model.addVars(list(range(12)), vtype=GRB.BINARY)
    for i in range(12):
        model.addConstr(x[1] >= copy_x1[i])
    model.addConstr(sum(copy_x1[i] for i in range(12)) >= x[1])

    copy_x2 = model.addVars(list(range(7)), vtype=GRB.BINARY)
    for i in range(7):
        model.addConstr(x[2] >= copy_x2[i])
    model.addConstr(sum(copy_x2[i] for i in range(7)) >= x[2])

    copy_x3 = model.addVars(list(range(8)), vtype=GRB.BINARY)
    for i in range(8):
        model.addConstr(x[3] >= copy_x3[i])
    model.addConstr(sum(copy_x3[i] for i in range(8)) >= x[3])

    copy_x4 = model.addVars(list(range(8)), vtype=GRB.BINARY)
    for i in range(8):
        model.addConstr(x[4] >= copy_x4[i])
    model.addConstr(sum(copy_x4[i] for i in range(8)) >= x[4])

    a = model.addVars(list(range(11)), vtype=GRB.BINARY, name="a")

    ########### Constraints for each of the 5 equations (ai for each occurence of products)
    model.addConstr(a[0] == copy_x4[0]), model.addConstr(a[0] == copy_x1[0])  # x4x1
    model.addConstr(a[1] == copy_x2[0]), model.addConstr(a[1] == copy_x1[1])  # x2x1
    model.addConstr(a[2] == copy_x0[0]), model.addConstr(a[2] == copy_x1[2])  # x0x1
    model.addConstr(
        y[0] == a[0] + a[1] + a[2] + copy_x3[0] + copy_x2[1] + copy_x1[3] + copy_x0[1])

    model.addConstr(a[3] == copy_x3[1]), model.addConstr(a[3] == copy_x2[2])  # x3x2
    model.addConstr(a[4] == copy_x3[2]), model.addConstr(a[4] == copy_x1[4])  # x3x1
    model.addConstr(a[5] == copy_x2[3]), model.addConstr(a[5] == copy_x1[5])  # x2x1
    model.addConstr(
        y[1] == a[3] + a[4] + a[5] + copy_x4[1] + copy_x3[3] + copy_x2[4] + copy_x1[6] + copy_x0[2])

    model.addConstr(a[6] == copy_x4[2]), model.addConstr(a[6] == copy_x3[4])  # x4x3
    model.addConstr(
        y[2] >= a[6] + copy_x4[3] + copy_x2[5] + copy_x1[7])

    model.addConstr(a[7] == copy_x4[4]), model.addConstr(a[7] == copy_x0[3])  # x4x0
    model.addConstr(a[8] == copy_x3[5]), model.addConstr(a[8] == copy_x0[4])  # x3x0
    model.addConstr(
        y[3] == a[7] + a[8] + copy_x4[5] + copy_x3[6] + copy_x1[8] + copy_x2[6] + copy_x0[5])

    model.addConstr(a[9] == copy_x4[6]), model.addConstr(a[9] == copy_x1[9])  # x4x1
    model.addConstr(a[10] == copy_x0[6]), model.addConstr(a[10] == copy_x1[10])  # x0x1
    model.addConstr(
        y[4] == a[9] + a[10] + copy_x4[7] + copy_x3[7] + copy_x1[11])

    model.update()


# [x0, x1, 1 + x2, x3, x4] --> [y0, y1, y2, y3, y4]
def anf_ascon_sbox_with_const(model, x, y):
    ########## Copying (create var for each occurence of xi)
    # x = model.addVars(list(range(5)), vtype=GRB.BINARY, name="x")
    # y = model.addVars(list(range(5)), vtype=GRB.BINARY, name="y")

    copy_x0 = model.addVars(list(range(7)), vtype=GRB.BINARY)
    for i in range(7):
        model.addConstr(x[0] >= copy_x0[i])
    model.addConstr(sum(copy_x0[i] for i in range(7)) >= x[0])

    copy_x1 = model.addVars(list(range(10)), vtype=GRB.BINARY)
    for i in range(10):
        model.addConstr(x[1] >= copy_x1[i])
    model.addConstr(sum(copy_x1[i] for i in range(10)) >= x[1])

    copy_x2 = model.addVars(list(range(7)), vtype=GRB.BINARY)
    for i in range(7):
        model.addConstr(x[2] >= copy_x2[i])
    model.addConstr(sum(copy_x2[i] for i in range(7)) >= x[2])

    copy_x3 = model.addVars(list(range(7)), vtype=GRB.BINARY)
    for i in range(7):
        model.addConstr(x[3] >= copy_x3[i])
    model.addConstr(sum(copy_x3[i] for i in range(7)) >= x[3])

    copy_x4 = model.addVars(list(range(8)), vtype=GRB.BINARY)
    for i in range(8):
        model.addConstr(x[4] >= copy_x4[i])
    model.addConstr(sum(copy_x4[i] for i in range(8)) >= x[4])

    a = model.addVars(list(range(11)), vtype=GRB.BINARY, name="a")

    ########### Constraints for each of the 5 equations (ai for each occurence of products)
    model.addConstr(a[0] == copy_x0[0]), model.addConstr(a[0] == copy_x1[0])  # x0x1
    model.addConstr(a[1] == copy_x1[1]), model.addConstr(a[1] == copy_x2[0])  # x2x1
    model.addConstr(a[2] == copy_x1[2]), model.addConstr(a[2] == copy_x4[0])  # x4x1
    model.addConstr(
        y[0] >= a[0] + a[1] + a[2] + copy_x3[0] + copy_x2[1] + copy_x0[1])

    model.addConstr(a[3] == copy_x1[3]), model.addConstr(a[3] == copy_x2[2])  # x3x1
    model.addConstr(a[4] == copy_x1[4]), model.addConstr(a[4] == copy_x3[1])  # x2x1
    model.addConstr(a[5] == copy_x2[3]), model.addConstr(a[5] == copy_x3[2])  # x3x2
    model.addConstr(
        y[1] >= a[3] + a[4] + a[5] + copy_x4[1] + copy_x2[4] + copy_x0[2])

    model.addConstr(a[6] == copy_x3[3]), model.addConstr(a[6] == copy_x4[2])  # x4x3
    model.addConstr(
        y[2] == a[6] + copy_x4[3] + copy_x2[5] + copy_x1[5])

    model.addConstr(a[7] == copy_x0[3]), model.addConstr(a[7] == copy_x3[4])  # x3x0
    model.addConstr(a[8] == copy_x4[4]), model.addConstr(a[8] == copy_x0[4])  # x4x0
    model.addConstr(
        y[3] >= a[7] + a[8] + copy_x4[5] + copy_x3[5] + copy_x1[6] + copy_x2[6] + copy_x0[5])

    model.addConstr(a[9] == copy_x0[6]), model.addConstr(a[9] == copy_x1[7])  # x0x1
    model.addConstr(a[10] == copy_x4[6]), model.addConstr(a[10] == copy_x1[8])  # x4x1
    model.addConstr(
        y[4] == a[9] + a[10] + copy_x4[7] + copy_x3[6] + copy_x1[9])

    model.update()


# [0, x1, x2, x3, x3] --> [y0, y1, y2, y3, y4]
def anf_ascon_sbox_0eq(model, x, y):
    ########## Copying (create var for each occurence of xi)
    # x = model.addVars(list(range(5)), vtype=GRB.BINARY, name="x")
    # y = model.addVars(list(range(5)), vtype=GRB.BINARY, name="y")

    copy_x1 = model.addVars(list(range(10)), vtype=GRB.BINARY)
    for i in range(10):
        model.addConstr(x[0] >= copy_x1[i])
    model.addConstr(quicksum(copy_x1[i] for i in range(10)) >= x[0])

    copy_x2 = model.addVars(list(range(7)), vtype=GRB.BINARY)
    for i in range(7):
        model.addConstr(x[1] >= copy_x2[i])
    model.addConstr(quicksum(copy_x2[i] for i in range(7)) >= x[1])

    copy_x3 = model.addVars(list(range(5)), vtype=GRB.BINARY)
    for i in range(5):
        model.addConstr(x[2] >= copy_x3[i])
    model.addConstr(quicksum(copy_x3[i] for i in range(5)) >= x[2])

    a = model.addVars(list(range(6)), vtype=GRB.BINARY, name="a")

    ########### Constraints for each of the 5 equations (ai for each occurence of products)
    model.addConstr(a[0] == copy_x1[0]), model.addConstr(a[0] == copy_x2[0])  # x2x1
    model.addConstr(a[1] == copy_x1[1]), model.addConstr(a[1] == copy_x3[0])  # x3x1
    model.addConstr(
        y[0] == a[0] + a[1] + copy_x3[1] + copy_x2[1] + copy_x1[2])

    model.addConstr(a[2] == copy_x2[2]), model.addConstr(a[2] == copy_x1[3])  # x2x1
    model.addConstr(a[3] == copy_x3[2]), model.addConstr(a[3] == copy_x1[4])  # x3x1
    model.addConstr(a[4] == copy_x3[3]), model.addConstr(a[4] == copy_x2[3])  # x3x2
    model.addConstr(
        y[1] == a[3] + a[4] + a[2] + copy_x2[4] + copy_x1[5])

    model.addConstr(
        y[2] >= copy_x2[5] + copy_x1[6])

    model.addConstr(
        y[3] == copy_x1[7] + copy_x2[6])

    model.addConstr(a[5] == copy_x3[4]), model.addConstr(a[5] == copy_x1[8])  # x3x1
    model.addConstr(
        y[4] == a[5] + copy_x1[9])

    model.update()


# [1, x1, x2, x3, x3] --> [y0, y1, y2, y3, y4]
def anf_ascon_sbox_1eq(model, x, y):
    ########## Copying (create var for each occurence of xi)
    # x = model.addVars(list(range(5)), vtype=GRB.BINARY, name="x")
    # y = model.addVars(list(range(5)), vtype=GRB.BINARY, name="y")

    copy_x1 = model.addVars(list(range(8)), vtype=GRB.BINARY)
    for i in range(8):
        model.addConstr(x[0] >= copy_x1[i])
    model.addConstr(sum(copy_x1[i] for i in range(8)) >= x[0])

    copy_x2 = model.addVars(list(range(7)), vtype=GRB.BINARY)
    for i in range(7):
        model.addConstr(x[1] >= copy_x2[i])
    model.addConstr(sum(copy_x2[i] for i in range(7)) >= x[1])

    copy_x3 = model.addVars(list(range(5)), vtype=GRB.BINARY)
    for i in range(5):
        model.addConstr(x[2] >= copy_x3[i])
    model.addConstr(sum(copy_x3[i] for i in range(5)) >= x[2])

    a = model.addVars(list(range(6)), vtype=GRB.BINARY, name="a")

    ########### Constraints for each of the 5 equations (ai for each occurence of products)
    model.addConstr(a[0] == copy_x2[0]), model.addConstr(a[0] == copy_x1[0])  # x2x1
    model.addConstr(a[1] == copy_x3[0]), model.addConstr(a[1] == copy_x1[1])  # x3x1
    model.addConstr(
        y[0] >= a[0] + a[1] + copy_x3[1] + copy_x2[1])

    model.addConstr(a[2] == copy_x2[2]), model.addConstr(a[2] == copy_x1[2])  # x2x1
    model.addConstr(a[3] == copy_x3[2]), model.addConstr(a[3] == copy_x1[3])  # x3x1
    model.addConstr(a[4] == copy_x3[3]), model.addConstr(a[4] == copy_x2[3])  # x3x2
    model.addConstr(
        y[1] >= a[2] + a[3] + a[4] + copy_x2[4] + copy_x1[4])

    model.addConstr(
        y[2] >= copy_x2[5] + copy_x1[5])

    model.addConstr(
        y[3] >= copy_x1[6] + copy_x2[6])

    model.addConstr(a[5] == copy_x3[4]), model.addConstr(a[5] == copy_x1[7])  # x3x1
    model.addConstr(
        y[4] == a[5])

    model.update()


# [0, x1, 1 + x2, x3, x3] --> [y0, y1, y2, y3, y4]
def anf_ascon_sbox_with_const_0eq(model, x, y):
    ########## Copying (create var for each occurence of xi)
    # x = model.addVars(list(range(5)), vtype=GRB.BINARY, name="x")
    # y = model.addVars(list(range(5)), vtype=GRB.BINARY, name="y")

    copy_x1 = model.addVars(list(range(8)), vtype=GRB.BINARY)
    for i in range(8):
        model.addConstr(x[0] >= copy_x1[i])
    model.addConstr(sum(copy_x1[i] for i in range(8)) >= x[0])

    copy_x2 = model.addVars(list(range(7)), vtype=GRB.BINARY)
    for i in range(7):
        model.addConstr(x[1] >= copy_x2[i])
    model.addConstr(sum(copy_x2[i] for i in range(7)) >= x[1])

    copy_x3 = model.addVars(list(range(6)), vtype=GRB.BINARY)
    for i in range(6):
        model.addConstr(x[2] >= copy_x3[i])
    model.addConstr(sum(copy_x3[i] for i in range(6)) >= x[2])

    a = model.addVars(list(range(6)), vtype=GRB.BINARY, name="a")

    ########### Constraints for each of the 5 equations (ai for each occurence of products)
    model.addConstr(a[0] == copy_x2[0]), model.addConstr(a[0] == copy_x1[0])  # x2x1
    model.addConstr(a[1] == copy_x3[0]), model.addConstr(a[1] == copy_x1[1])  # x3x1
    model.addConstr(
        y[0] >= a[0] + a[1] + copy_x3[1] + copy_x2[1])

    model.addConstr(a[2] == copy_x2[2]), model.addConstr(a[2] == copy_x1[2])  # x2x1
    model.addConstr(a[3] == copy_x3[2]), model.addConstr(a[3] == copy_x1[3])  # x3x1
    model.addConstr(a[4] == copy_x3[3]), model.addConstr(a[4] == copy_x2[3])  # x3x2
    model.addConstr(
        y[1] >= a[2] + a[3] + a[4] + copy_x2[4] + copy_x3[4])

    model.addConstr(
        y[2] == copy_x2[5] + copy_x1[4])

    model.addConstr(
        y[3] >= copy_x1[5] + copy_x2[6])

    model.addConstr(a[5] == copy_x3[5]), model.addConstr(a[5] == copy_x1[6])  # x3x1
    model.addConstr(
        y[4] == a[5] + copy_x1[7])

    model.update()


def sigma(model, X, Y, rot1, rot2):
    # A = [[],[],[]]
    # for i in range(64):
    #     A[0].append(model.addVar(vtype=GRB.BINARY))
    #     A[1].append(model.addVar(vtype=GRB.BINARY))
    #     A[2].append(model.addVar(vtype=GRB.BINARY))
    A = [model.addVars(list(range(64)), vtype=GRB.BINARY) for i in range(3)]

    for i in range(64):
        model.addConstr(X[i] >= A[0][i])
        model.addConstr(X[i] >= A[1][i])
        model.addConstr(X[i] >= A[2][i])
        model.addConstr(A[0][i] + A[1][i] + A[2][i] >= X[i])

    for i in range(64):
        model.addConstr(Y[i] == A[0][i] + A[1][(64 - rot1 + i) % 64] + A[2][(64 - rot2 + i) % 64])
    model.update()


def linear_layer(model, Y, X):
    Y0 = [0] * 64
    Y1 = [0] * 64
    Y2 = [0] * 64
    Y3 = [0] * 64
    Y4 = [0] * 64
    X0 = [0] * 64
    X1 = [0] * 64
    X2 = [0] * 64
    X3 = [0] * 64
    X4 = [0] * 64

    for i in range(64):
        Y0[i] = Y[i]
        Y1[i] = Y[64 + i]
        Y2[i] = Y[128 + i]
        Y3[i] = Y[192 + i]
        Y4[i] = Y[256 + i]

        X0[i] = X[i]
        X1[i] = X[64 + i]
        X2[i] = X[128 + i]
        X3[i] = X[192 + i]
        X4[i] = X[256 + i]

    sigma(model, Y0, X0, 19, 28)
    sigma(model, Y1, X1, 61, 39)
    sigma(model, Y2, X2, 1, 6)
    sigma(model, Y3, X3, 10, 17)
    sigma(model, Y4, X4, 7, 41)
    model.update()


def substitution(model, X, Y, rc):
    # tmpx = model.addVars(list(range(5)))
    # tmpy = model.addVars(list(range(5)))
    tmpx = [0] * 5
    tmpy = [0] * 5

    for i in range(64):
        tmpx[0] = X[i]
        tmpx[1] = X[64 + i]
        tmpx[2] = X[128 + i]
        tmpx[3] = X[192 + i]
        tmpx[4] = X[256 + i]

        tmpy[0] = Y[i]
        tmpy[1] = Y[64 + i]
        tmpy[2] = Y[128 + i]
        tmpy[3] = Y[192 + i]
        tmpy[4] = Y[256 + i]

        if i >= 56:
            t = (rc >> (63 - i)) & 1
            if t == 1:
                anf_ascon_sbox_with_const(model, tmpx, tmpy)
            else:
                anf_ascon_sbox(model, tmpx, tmpy)
        else:
            anf_ascon_sbox(model, tmpx, tmpy)

    model.update()


def pretty_print(monomials):
    l = []
    for monomial in monomials:
        tmp = ""
        if len(monomial) != 1:
            for var in monomial[:-1]:
                if var <= 127:
                    tmp += "k" + str(var)
                else:
                    tmp += "v" + str(var % 128)
        else:
            tmp += str(1)
        # l.append((tmp, monomial[-1]))
        l.append(tmp)
    print(l)


def term_enumeration(rounds, flag, target):
    model = Model()
    model.Params.LogToConsole = 0
    model.setParam("PoolSolutions", 2000000)

    S = model.addVars(list(range(192)), vtype=GRB.BINARY)
    X = [model.addVars(list(range(320)), vtype=GRB.BINARY) for i in range(rounds)]
    Y = [model.addVars(list(range(320)), vtype=GRB.BINARY) for i in range(rounds)]
    model.update()

    constant = 0x80400C0600000000;
    RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]

    for i in range(64):
        flag[i] = (constant >> (63 - i)) & 1

    # Round 0:
    # for i in range(64):
    #     model.addConstr(X[0][i] == 0)

    for i in range(64):
        tmpx = [0] * 3
        tmpy = [0] * 5

        # tmpx[0] = S[i]
        # tmpx[1] = S[64 + i]
        # tmpx[2] = S[128 + i]

        tmpx[0] = S[i]
        tmpx[1] = S[64 + i]
        tmpx[2] = S[128 + i]
        # tmpx[3] = X[0][192 + i]
        # tmpx[4] = X[0][256 + i]

        tmpy[0] = Y[0][i]
        tmpy[1] = Y[0][64 + i]
        tmpy[2] = Y[0][128 + i]
        tmpy[3] = Y[0][192 + i]
        tmpy[4] = Y[0][256 + i]

        if i >= 56:
            t = (RC[0] >> (63 - i)) & 1
            if t == 1:
                anf_ascon_sbox_with_const_0eq(model, tmpx, tmpy)
            else:
                anf_ascon_sbox_0eq(model, tmpx, tmpy)
        else:
            if flag[i] == 1:
                anf_ascon_sbox_1eq(model, tmpx, tmpy)
            else:
                anf_ascon_sbox_0eq(model, tmpx, tmpy)
                # anf_ascon_sbox_with_const(model, tmpx, tmpy)

    # model.write("model_python.lp");

    linear_layer(model, Y[0], X[0])

    for r in range(1, rounds):
        # print(f'fohsfpdjfdjk : {r}')
        substitution(model, X[r - 1], Y[r], RC[r])
        linear_layer(model, Y[r], X[r])

    model.addConstr(S[128] == 1)
    model.addConstr(S[129] == 1)
    model.addConstr(S[130] == 1)

    ks = model.addVar()
    model.addConstr(ks == sum(X[rounds - 1][i] for i in range(320)))
    model.addConstr(ks == 1)
    model.addConstr(X[rounds - 1][target] == 1)
    model.update()

    # ll = model.addVar()
    # model.addConstr(ll == sum(tmpy[i] for i in range(5)))
    # model.addConstr(ll == 1)
    # model.addConstr(tmpy[target] == 1)

    model.setParam(GRB.Param.PoolSearchMode, 2)

    model.optimize()
    solCount = model.SolCount
    print('Number of solutions found: ' + str(solCount))
    monomials = []
    for sol in range(solCount):
        model.setParam(GRB.Param.SolutionNumber, sol)
        values = model.Xn
        # print(values)
        # print(len(values))
        # print("X:", X)
        # print(values[:192])
        # print("y:", y)
        tmp = []
        # for index, v in enumerate([X[rounds-1][i], X[rounds-1][i+64], X[rounds-1][i+128], X[rounds-1][i+192], X[rounds-1][i+256]]): #values[:320]
        # for index, v in enumerate([values[0], values[64], values[128], values[192], values[256]]):
        for index, v in enumerate(values[:192]):
            if v == 1:
                tmp.append(index)
        # if tmp not in monomials:
        monomials.append(tmp)
    monomials_with_occurences = [x + [monomials.count(x)] for x in monomials]
    monomials_duplicates_removed = list(set(tuple(i) for i in monomials_with_occurences))
    monomials_even_occurences_removed = [x for x in monomials_duplicates_removed if x[-1] % 2 == 1]
    pretty_print(monomials_even_occurences_removed)


def rate_anf(rounds):
    flag = [2 for i in range(192)]
    cube = [0 for i in range(64)]
    degree = [0 for i in range(320)]

    # target = 1
    for sbox in [0]:  # 64
        for i in range(5):
            print("monomials in y" + str(64 * i + sbox) + ":")
            term_enumeration(rounds, flag, 64 * i + sbox)
            # print("monomials in y" + str(i) + ":")
            # term_enumeration(rounds, flag, i)

