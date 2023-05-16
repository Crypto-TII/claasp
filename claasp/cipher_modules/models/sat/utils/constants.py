INPUT_BIT_ID_SUFFIX = '_i'
OUTPUT_BIT_ID_SUFFIX = '_o'
SAT_SOLVERS_DIMACS_COMPLIANT = (
    'cadical', 'cryptominisat', 'glucose', 'glucose-syrup', 'kissat', 'mathsat'
)
SAT_SOLVERS = {
    'cadical': {
        'command': ['cadical'],
        'time': 'real time',
        'memory': 'size of process'
    },
    'cryptominisat': {
        'command': ['cryptominisat5', '--verb=1'],
        'time': 'c Total time (this thread)',
        'memory': 'c Max Memory (rss)'
    },
    'glucose': {
        'command': ['glucose', '-model'],
        'time': 'CPU time',
        'memory': None
    },
    'glucose-syrup': {
        'command': ['glucose-syrup', '-model'],
        'time': 'cpu time',
        'memory': 'Total Memory'
    },
    'kissat': {
        'command': ['kissat'],
        'time': 'process-time',
        'memory': 'maximum-resident-set-size'
    },
    'parkissat': {
        'command': ['parkissat', '-shr-sleep=500000', '-shr-lit=1500', '-initshuffle'],
        'time': None,
        'memory': None
    },
    'mathsat': {
        'command': ['mathsat', '-stats', '-model', '-input=dimacs'],
        'time': 'CPU Time',
        'memory': 'Memory used'
    },
    'minisat': {
        'command': ['minisat'],
        'time': 'CPU time',
        'memory': 'Memory used'
    },
    'yices-sat': {
        'command': ['yices-sat', '--stats', '--model'],
        'time': 'Search time',
        'memory': 'Memory used'
    }
}
