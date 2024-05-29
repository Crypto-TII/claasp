import os

MILP_AUXILIARY_FILE_PATH = os.getcwd()

if os.access(os.path.join(os.path.dirname(__file__), 'utils'), os.W_OK):
    MILP_AUXILIARY_FILE_PATH = os.path.join(os.path.dirname(__file__), 'utils')
