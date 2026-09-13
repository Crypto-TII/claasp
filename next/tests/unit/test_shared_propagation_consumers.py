from claasp_next.ciphers import PresentBlockCipher
from claasp_next.components import BitVectorSBox
from claasp_next.interpretations import XOR_DIFFERENTIAL
from claasp_next.interpretations.cryptanalysis import (
    ComponentSemanticsBinding, PropagationProblem,
)
from claasp_next.representations.constraints.milp import PresentDifferentialMILPModel
from claasp_next.representations.constraints.smt import PresentDifferentialSMTModel


def test_smt_and_milp_composition_consume_the_same_component_override():
    cipher = PresentBlockCipher(number_of_rounds=2)
    component = next(item for item in cipher.components if isinstance(item, BitVectorSBox))
    base = PropagationProblem(cipher, XOR_DIFFERENTIAL).registry
    calls = {"smt": 0, "milp": 0}

    class CountingProvider:
        def __init__(self, provider, counter):
            self.provider = provider
            self.counter = counter

        def transition(self, input_patterns, output_pattern):
            calls[self.counter] += 1
            return self.provider.transition(input_patterns, output_pattern)

    def problem_for(counter, maximum_weight=None):
        registry = base.register(ComponentSemanticsBinding(
            XOR_DIFFERENTIAL,
            BitVectorSBox,
            lambda selected: CountingProvider(
                base.provider(selected, XOR_DIFFERENTIAL), counter
            ),
            component_id=component.component_id,
        ))
        return PropagationProblem(
            cipher, XOR_DIFFERENTIAL, registry=registry,
            maximum_weight=maximum_weight,
        )

    PresentDifferentialSMTModel(problem_for("smt", 4)).smt_formula()
    PresentDifferentialMILPModel(problem_for("milp")).milp_model()

    assert calls == {"smt": 256, "milp": 256}
