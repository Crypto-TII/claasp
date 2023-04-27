INPUT_BIT_ID_SUFFIX = '_i'
OUTPUT_BIT_ID_SUFFIX = '_o'
MODEL_PREFIX = ['(set-option :print-success false)', '(set-logic QF_UF)']
MODEL_SUFFIX = ['(check-sat)', '(get-model)', '(get-info :all-statistics)', '(exit)']
SMT_SOLVERS = {
    'mathsat': {
        'command': ['mathsat', '-model', '-stats'],
        'time': 'time-seconds',
        'memory': 'memory-mb'
    },
    'yices-smt2': {
        'command': ['yices-smt2', '--stats'],
        'time': 'total-run-time',
        'memory': 'mem-usage'
    },
    'z3': {
        'command': ['z3', '-st', '-in'],
        'time': 'total-time',
        'memory': 'memory'
    }
}
