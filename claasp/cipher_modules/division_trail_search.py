from gurobipy import *

class MilpDivisionTrailModel():
    """
    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
        sage: from claasp.cipher_modules.division_trail_search import *
        sage: milp = MilpDivisionTrailModel(speck)
        sage: milp.build_gurobi_model()
        sage: milp.add_constraints()

    """

    def __init__(self, cipher):
        self._cipher = cipher
        self._variables_list = []
        self._model_constraints = []
        self._model = None

    def build_gurobi_model(self):
        model = Model()
        model.Params.LogToConsole = 0
        model.setParam("PoolSolutions", 200000000)
        model.setParam(GRB.Param.PoolSearchMode, 2)
        self._model = model

    def add_constraints(self):
        return self._cipher.get_all_components()