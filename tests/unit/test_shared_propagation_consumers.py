from claasp.components import BitVectorSBox
from claasp.primitives import Present
from claasp.representations.constraints.cp import PresentDifferentialCPModel
from claasp.representations.constraints.milp import PresentDifferentialMILPModel
from claasp.representations.constraints.smt import PresentDifferentialSMTModel
from claasp.semantics import XOR_DIFFERENTIAL
from claasp.semantics.cryptanalysis import (
    ComponentSemanticsBinding,
    PropagationProblem,
)


def test_smt_milp_and_cp_composition_consume_the_same_component_override():
    primitive = Present(number_of_rounds=2)
    component = next(item for item in primitive.components if isinstance(item, BitVectorSBox))
    base = PropagationProblem(primitive, XOR_DIFFERENTIAL).registry
    calls = {"smt": 0, "milp": 0, "cp": 0}

    class CountingProvider:
        def __init__(self, provider, counter):
            self.provider = provider
            self.counter = counter

        def transition(self, input_patterns, output_pattern):
            calls[self.counter] += 1
            return self.provider.transition(input_patterns, output_pattern)

    def problem_for(counter, maximum_weight=None):
        registry = base.register(
            ComponentSemanticsBinding(
                XOR_DIFFERENTIAL,
                BitVectorSBox,
                lambda selected: CountingProvider(
                    base.provider(selected, XOR_DIFFERENTIAL), counter
                ),
                component_id=component.component_id,
            )
        )
        return PropagationProblem(
            primitive,
            XOR_DIFFERENTIAL,
            registry=registry,
            maximum_weight=maximum_weight,
        )

    PresentDifferentialSMTModel(problem_for("smt", 4)).smt_formula()
    PresentDifferentialMILPModel(problem_for("milp")).milp_model()
    PresentDifferentialCPModel(problem_for("cp", 4)).cp_model()

    assert calls == {"smt": 256, "milp": 256, "cp": 256}
