"""Exact Boolean encodings of signed quasidifferential trail magnitudes.

Atomic modular addition/subtraction use Beyne–Rijmen,
"Differential Cryptanalysis in the Fixed-Key Model" (2022), Theorem 5.2
(https://eprint.iacr.org/2022/837), with an
independent carry-DP coefficient checker. Lookup transitions retain exact
integer numerators. Fork masks XOR back to their source mask, per read.
"""

from collections.abc import Callable
from dataclasses import dataclass, replace
from fractions import Fraction
from functools import lru_cache, partial
from itertools import chain

from claasp.components import (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    Identity,
    LinearMap,
    ModularAdd,
    ModularSubtract,
    Permutation,
    Rotate,
    SBox,
    Shift,
    Xor,
)
from claasp.graph import as_selection
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _verified_model,
)
from claasp.representations.constraints.sat.model import CNFFormula
from claasp.representations.constraints.sat.trails import _at_most
from claasp.representations.constraints.smt._probability_encoding import (
    _add_bound,
    _add_weight_interval,
    _encode_probability_product,
    _ProductCircuit,
    _weight_interval,
)
from claasp.semantics.cryptanalysis.quasidifferential import (
    QuasidifferentialSemantics,
    QuasidifferentialTransition,
)
from claasp.unit_types import BinaryExtensionField, Bit, UnitType, Word
from claasp.utils.finite_fields import binary_field_multiply


def _negate(value):
    return not value if isinstance(value, bool) else -value


class _BooleanBuilder:
    def __init__(self, variables=(), clauses=(), labels=()):
        self.variables = list(variables)
        self.indices = {name: index + 1 for index, name in enumerate(variables)}
        self.clauses = list(clauses)
        self.labels = list(labels)
        self.logic = _ProductCircuit(
            lambda name: self.allocate("logic_" + name), self.indices, self.add
        )

    def allocate(self, name):
        if name in self.indices:
            return name
        self.variables.append(name)
        self.indices[name] = len(self.variables)
        return name

    def fresh(self, label):
        name = self.allocate(f"{label}_{len(self.variables)}")
        return self.indices[name]

    def add(self, clause, label="quasidifferential"):
        if any(value is True for value in clause):
            return
        literals = tuple(value for value in clause if value is not False)
        if not literals:
            variable = self.fresh("contradiction")
            self.clauses.extend(((variable,), (-variable,)))
            self.labels.extend((label, label))
        else:
            self.clauses.append(literals)
            self.labels.append(label)

    def require(self, value, label="quasidifferential"):
        self.add((value,), label)

    def equal(self, left, right):
        self.add((_negate(left), right))
        self.add((left, _negate(right)))

    def xor(self, values):
        result = False
        for value in values:
            result = self.logic.gate("xor", result, value)
        return result

    def and_(self, values):
        result = True
        for value in values:
            result = self.logic.gate("and", result, value)
        return result

    def or_(self, values):
        return _negate(self.and_(_negate(value) for value in values))

    def formula(self):
        return CNFFormula(tuple(self.variables), tuple(self.clauses), tuple(self.labels))


def _width(array_type):
    width = array_type.encoded_bit_size
    if width is None:
        raise TypeError("quasidifferential analysis requires canonical binary encodings")
    return width


def _unit_width(unit: UnitType) -> int:
    width = unit.encoded_bit_size
    if width is None:
        raise TypeError("unit type must have a canonical binary encoding")
    return width


def _packed(bits, assignment, variables):
    result = 0
    for bit in bits:
        value = (
            bool(bit)
            if isinstance(bit, bool)
            else bool(assignment[variables[abs(bit) - 1]]) == (bit > 0)
        )
        result = (result << 1) | int(value)
    return result


@lru_cache(maxsize=32)
def _lookup_rows(table, output_width, input_difference, output_difference):
    rows: list[tuple[int, int, int, int, int]] = []
    for a in range(len(table)) if input_difference is None else (input_difference,):
        groups: dict[int, list[int]] = {}
        for x, y in enumerate(table):
            b = y ^ table[x ^ a]
            if output_difference is None or output_difference == b:
                groups.setdefault(b, []).append(x)
        for b, inputs in groups.items():
            for v in range(1 << output_width):
                walsh = [0] * len(table)
                for x in inputs:
                    walsh[x] = -1 if (table[x] & v).bit_count() & 1 else 1
                stride = 1
                while stride < len(table):
                    for start in range(0, len(table), 2 * stride):
                        for bit in range(stride):
                            left, right = walsh[start + bit], walsh[start + bit + stride]
                            walsh[start + bit], walsh[start + bit + stride] = (
                                left + right,
                                left - right,
                            )
                    stride *= 2
                rows.extend((a, b, u, v, count) for u, count in enumerate(walsh) if count)
    return tuple(rows)


def _affine_coefficient(
    difference, output_difference, mask, output_mask, *, rows, offset, input_width
):
    expected = 0
    transpose = 0
    for index, columns in enumerate(rows):
        value = sum((difference >> (input_width - 1 - column)) & 1 for column in columns) & 1
        expected = (expected << 1) | value
        if output_mask & (1 << (len(rows) - 1 - index)):
            for column in columns:
                transpose ^= 1 << (input_width - 1 - column)
    if output_difference != expected or mask != transpose:
        return Fraction(0)
    return Fraction(-1 if (output_mask & offset).bit_count() & 1 else 1)


@dataclass(frozen=True, slots=True)
class _Local:
    name: str
    differences: tuple
    output_difference: tuple
    masks: tuple
    output_mask: tuple
    checker: Callable[[int, int, int, int], Fraction]


def _affine_map(component):
    widths = [_width(selection.array_type) for selection in component.inputs]
    n = sum(widths)
    m = _width(component.output_type)
    rows: list[list[int]] = [[] for _ in range(m)]
    offset = 0
    unit_width = _unit_width(component.output_type.unit_type)
    if unit_width is None:
        raise TypeError("affine component requires a binary encoding")
    if isinstance(component, Constant):
        for value in component.values:
            offset = (offset << unit_width) | value
    elif isinstance(component, (Xor, Add)):
        if isinstance(component, Add) and not isinstance(
            component.output_type.unit_type, (Bit, BinaryExtensionField)
        ):
            raise NotImplementedError("quasidifferential Add requires characteristic-two units")
        for bit in range(m):
            rows[bit] = [sum(widths[:operand]) + bit for operand in range(len(widths))]
    elif isinstance(component, (Identity, BitwiseNot)):
        rows = [[bit] for bit in range(m)]
        if isinstance(component, BitwiseNot):
            offset = (1 << m) - 1
    elif isinstance(component, Permutation):
        rows = [
            [source * unit_width + bit] for source in component.mapping for bit in range(unit_width)
        ]
    elif isinstance(component, (Rotate, Shift)):
        for bit in range(m):
            unit, position = divmod(bit, unit_width)
            source = position + (
                component.amount if component.direction == "left" else -component.amount
            )
            if isinstance(component, Rotate):
                source %= unit_width
            if 0 <= source < unit_width:
                rows[bit] = [unit * unit_width + source]
    elif isinstance(component, BinaryAffineMap):
        rows = []
        for unit in range(component.output_type.unit_count):
            for coefficients in component.matrix:
                rows.append(
                    [
                        unit * unit_width + bit
                        for bit, coefficient in enumerate(coefficients)
                        if coefficient
                    ]
                )
            offset = (offset << unit_width) | component.offset
    elif isinstance(component, LinearMap):
        field = component.output_type.unit_type
        if not isinstance(field, (Bit, BinaryExtensionField)):
            raise NotImplementedError("linear QDT components require characteristic-two fields")
        for row, coefficients in enumerate(component.matrix):
            for column, coefficient in enumerate(coefficients):
                for bit in range(unit_width):
                    basis = 1 << (unit_width - 1 - bit)
                    value = (
                        coefficient & basis
                        if isinstance(field, Bit)
                        else binary_field_multiply(field, coefficient, basis)
                    )
                    for out in range(unit_width):
                        if value & (1 << (unit_width - 1 - out)):
                            rows[row * unit_width + out].append(column * unit_width + bit)
    else:
        raise NotImplementedError(
            f"no quasidifferential semantics for {type(component).__name__}: {component.component_id}"
        )
    return tuple(tuple(row) for row in rows), offset, n


class QuasidifferentialSATModel:
    """Compile atomic QDT relations, preserving exact magnitudes and fork masks.

    ``fixed_differences`` and ``fixed_masks`` address input or component names.
    Masks on public inputs and the final output default to zero; key masks
    stay free. Key differences default to zero unless explicitly supplied.
    Large lookup tables require fixed local differences or a larger explicit
    table budget. Unsupported operations raise; none are silently skipped.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = QuasidifferentialSATModel(Speck(number_of_rounds=1))
        >>> model.cnf_formula().variable_count > 0
        True
    """

    model_provenance = _verified_model(
        ConstraintBackend.SAT,
        "QuasidifferentialSATModel",
        "xor_quasidifferential",
        "exact signed lookup coefficients and modular-addition logical constraints",
        "10.1007/978-3-031-15982-4_23",
        "Differential Cryptanalysis in the Fixed-Key Model",
        "Definition 3.2; Theorem 4.1; section 5.1; Theorems 5.1 and 5.2 (pp. 702--703)",
    )

    def __init__(
        self,
        primitive,
        *,
        fixed_differences=None,
        output_difference=None,
        fixed_masks=None,
        output_mask=0,
        nonzero_input=True,
        maximum_table_entries=1 << 20,
        maximum_weight=None,
        minimum_weight=None,
        fixed_weight=None,
        weight_tolerance=0,
    ):
        if primitive.graph.output is None:
            raise ValueError("primitive must have an output")
        arrays = [array.array_type for array in primitive.graph.input_arrays.values()] + [
            component.output_type for component in primitive.graph.components
        ]
        if not all(
            isinstance(array.unit_type, (Bit, Word, BinaryExtensionField)) for array in arrays
        ):
            raise TypeError("QDT analysis requires binary encodings")
        if (
            not isinstance(maximum_table_entries, int)
            or isinstance(maximum_table_entries, bool)
            or maximum_table_entries <= 0
        ):
            raise ValueError("maximum_table_entries must be positive")
        self.primitive = primitive
        self.interval = _weight_interval(
            maximum_weight, fixed_weight, minimum_weight, weight_tolerance
        )
        self.context = _BooleanBuilder()
        self.locals: list[_Local] = []
        self.weights: list[str] = []
        self.factors: list[tuple[int, tuple[int | bool, ...]]] = []
        self.known: dict[int, int] = {}
        self.differences: dict[str, tuple[int, ...]] = {}
        self.masks: dict[str, tuple[int, ...]] = {}
        self.reads: dict[int, list[int]] = {}
        self.maximum_table_entries = maximum_table_entries
        self._make_wires()
        fixed = dict(fixed_differences or {})
        for name in primitive.graph.secret_inputs:
            fixed.setdefault(name, 0)
        self._fix(self.differences, fixed)
        masks = dict(fixed_masks or {})
        for name in primitive.graph.input_arrays:
            if name not in primitive.graph.secret_inputs:
                masks.setdefault(name, 0)
        self._fix(self.masks, masks)
        self.output_differences = tuple(
            self.differences[source][bit]
            for source, bit in primitive.graph.selection_bit_sources(primitive.graph.output)
        )
        if output_difference is not None:
            self._fix_bits(self.output_differences, output_difference, known=True)
        for component in primitive.graph.components:
            self._component(component)
        self.output_masks = tuple(
            self.context.fresh("output_mask") for _ in self.output_differences
        )
        if output_mask is not None:
            self._fix_bits(self.output_masks, output_mask)
        for (source, bit), mask in zip(
            primitive.graph.selection_bit_sources(primitive.graph.output), self.output_masks
        ):
            self.reads[self.masks[source][bit]].append(mask)
        for source in self.masks.values():
            for mask in source:
                self.context.equal(mask, self.context.xor(self.reads[mask]))
        if nonzero_input:
            public = chain.from_iterable(
                bits
                for name, bits in self.differences.items()
                if name in primitive.graph.input_arrays
                and name not in primitive.graph.secret_inputs
            )
            self.context.require(self.context.or_(public), "nonzero_public_difference")
        self.projection = tuple(range(1, len(self.context.variables) + 1))
        self.probability_bits: tuple[int | bool, ...] = ()
        self.probability_denominator: int | None = None
        if self.factors:
            self.probability_bits, self.probability_denominator = _encode_probability_product(
                self.factors,
                self.weights,
                lambda name: self.context.allocate("objective_" + name),
                self.context.indices,
                self.context.add,
            )
        self.base_formula = self.context.formula()

    def _make_wires(self):
        sizes = {
            name: _width(array.array_type)
            for name, array in self.primitive.graph.input_arrays.items()
        }
        sizes.update(
            (component.component_id, _width(component.output_type))
            for component in self.primitive.graph.components
        )
        for name, width in sizes.items():
            self.differences[name] = tuple(self.context.fresh("difference") for _ in range(width))
            self.masks[name] = tuple(self.context.fresh("mask") for _ in range(width))
            for mask in self.masks[name]:
                self.reads[mask] = []

    def _boundary_bits(self, value, width):
        if value is None:
            return (None,) * width
        if isinstance(value, str):
            if len(value) != width or any(bit not in "01?*" for bit in value):
                raise ValueError(
                    "binary boundary patterns must have the boundary width and use 0, 1, ?, or *"
                )
            return tuple(int(bit) if bit in "01" else None for bit in value)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << width:
            raise ValueError("fixed value must fit its boundary")
        return tuple((value >> (width - 1 - bit)) & 1 for bit in range(width))

    def _fix_bits(self, bits, value, known=False):
        for literal, selected in zip(bits, self._boundary_bits(value, len(bits))):
            if selected is None:
                continue
            self.context.require(literal if selected else -literal, "fixed_qdt_boundary")
            if known:
                self.known[literal] = selected

    def _fix(self, wires, mapping):
        for name, value in mapping.items():
            if name in wires:
                bits = wires[name]
            else:
                try:
                    selection = as_selection(self.primitive.graph.unit_array(name))
                    bits = tuple(
                        wires[source][bit]
                        for source, bit in self.primitive.graph.selection_bit_sources(selection)
                    )
                except KeyError as error:
                    raise ValueError(f"unknown QDT boundary: {name}") from error
            self._fix_bits(bits, value, known=wires is self.differences)

    def _known(self, bits):
        if not all(bit in self.known for bit in bits):
            return None
        return sum(self.known[bit] << (len(bits) - 1 - index) for index, bit in enumerate(bits))

    def _weight(self, literal):
        if literal is False:
            return
        name = self.context.allocate(f"weight_{len(self.weights)}")
        self.context.equal(self.context.indices[name], literal)
        self.weights.append(name)

    def _component(self, component):
        differences = []
        masks = []
        for selection in component.inputs:
            d_bits = []
            m_bits = []
            for source, bit in self.primitive.graph.selection_bit_sources(selection):
                d_bits.append(self.differences[source][bit])
                branch = self.context.fresh("read_mask")
                self.reads[self.masks[source][bit]].append(branch)
                m_bits.append(branch)
            differences.append(tuple(d_bits))
            masks.append(tuple(m_bits))
        d = tuple(differences)
        m = tuple(masks)
        output_d = self.differences[component.component_id]
        output_m = self.masks[component.component_id]
        if isinstance(component, (ModularAdd, ModularSubtract)):
            if len(d) != 2:
                raise NotImplementedError("atomic modular QDT requires exactly two operands")
            width = _unit_width(component.output_type.unit_type)
            if isinstance(component, ModularAdd) and component.modulus not in (None, 1 << width):
                raise NotImplementedError("atomic modular QDT requires power-of-two modulus")
            for start in range(0, len(output_d), width):
                ds = tuple(bits[start : start + width] for bits in d)
                ms = tuple(bits[start : start + width] for bits in m)
                od = output_d[start : start + width]
                om = output_m[start : start + width]
                if isinstance(component, ModularSubtract):
                    self._modadd(od, ds[1], ds[0], om, ms[1], ms[0])
                else:
                    self._modadd(ds[0], ds[1], od, ms[0], ms[1], om)
                check = partial(
                    _addition_coefficient,
                    width=width,
                    subtract=isinstance(component, ModularSubtract),
                )
                self.locals.append(
                    _Local(f"{component.component_id}:{start // width}", ds, od, ms, om, check)
                )
        elif isinstance(component, (BitwiseAnd, BitwiseOr)):
            count = len(d)
            table = tuple(
                int(x == (1 << count) - 1) if isinstance(component, BitwiseAnd) else int(x != 0)
                for x in range(1 << count)
            )
            for bit in range(len(output_d)):
                ds = tuple((bits[bit],) for bits in d)
                ms = tuple((bits[bit],) for bits in m)
                self._table(
                    table,
                    1,
                    ds,
                    (output_d[bit],),
                    ms,
                    (output_m[bit],),
                    f"{component.component_id}:{bit}",
                )
        elif isinstance(component, (SBox, BitVectorSBox)):
            if isinstance(component, BitVectorSBox):
                self._table(
                    tuple(component.table),
                    len(output_d),
                    d,
                    output_d,
                    m,
                    output_m,
                    component.component_id,
                )
            else:
                width = _unit_width(component.output_type.unit_type)
                for start in range(0, len(output_d), width):
                    self._table(
                        tuple(component.table),
                        width,
                        (d[0][start : start + width],),
                        output_d[start : start + width],
                        (m[0][start : start + width],),
                        output_m[start : start + width],
                        f"{component.component_id}:{start // width}",
                    )
        else:
            rows, offset, n = _affine_map(component)
            flat_d = tuple(chain.from_iterable(d))
            flat_m = tuple(chain.from_iterable(m))
            for bit, columns in enumerate(rows):
                self.context.equal(
                    output_d[bit], self.context.xor(flat_d[column] for column in columns)
                )
                if all(flat_d[column] in self.known for column in columns):
                    self._fix_bits(
                        (output_d[bit],),
                        sum(self.known[flat_d[column]] for column in columns) & 1,
                        known=True,
                    )
            for column, literal in enumerate(flat_m):
                self.context.equal(
                    literal,
                    self.context.xor(
                        output_m[row] for row, columns in enumerate(rows) if column in columns
                    ),
                )
            self.locals.append(
                _Local(
                    component.component_id,
                    d,
                    output_d,
                    m,
                    output_m,
                    partial(_affine_coefficient, rows=rows, offset=offset, input_width=n),
                )
            )

    def _table(self, table, width, d, od, m, om, name):
        flat_d = tuple(chain.from_iterable(d))
        flat_m = tuple(chain.from_iterable(m))
        a = self._known(flat_d)
        b = self._known(od)
        if a == 0 and b is None:
            b = 0
            self._fix_bits(od, 0, known=True)
        input_width = len(flat_d)
        entries = (
            (len(table) if a is None else 1)
            * ((1 << width) if b is None else 1)
            * (1 << (input_width + width))
        )
        if entries > self.maximum_table_entries:
            raise ValueError(
                f"{name}: dense QDT exceeds maximum_table_entries; fix local differences or explicitly increase the budget"
            )
        rows = _lookup_rows(table, width, a, b)
        selectors = []
        all_bits = flat_d + od + flat_m + om
        for av, bv, uv, vv, _count in rows:
            selector = self.context.fresh("lookup_row")
            selectors.append(selector)
            packed = (
                (av << (width + input_width + width))
                | (bv << (input_width + width))
                | (uv << width)
                | vv
            )
            for bit, literal in enumerate(all_bits):
                self.context.add(
                    (-selector, literal if packed & (1 << (len(all_bits) - 1 - bit)) else -literal),
                    "exact_qdt_lookup",
                )
        self.context.require(self.context.or_(selectors), "nonzero_qdt_coefficient")
        if all(abs(row[-1]) & (abs(row[-1]) - 1) == 0 for row in rows):
            costs = [input_width - (abs(row[-1]).bit_length() - 1) for row in rows]
            for threshold in range(1, max(costs, default=0) + 1):
                self._weight(
                    self.context.or_(
                        selector for selector, cost in zip(selectors, costs) if cost >= threshold
                    )
                )
        else:
            numerator = tuple(
                self.context.or_(
                    selector for selector, row in zip(selectors, rows) if abs(row[-1]) & (1 << bit)
                )
                for bit in range(input_width + 1)
            )
            self.factors.append((input_width, numerator))
        self.locals.append(
            _Local(
                name, d, od, m, om, partial(_lookup_coefficient, table=table, output_width=width)
            )
        )

    def _modadd(self, a, b, c, u, v, w):
        q = self.context
        size = len(a)
        ap = [q.xor((bb, cc)) for bb, cc in zip(b, c)]
        bp = [q.xor((aa, cc)) for aa, cc in zip(a, c)]
        abc = [q.xor(bits) for bits in zip(a, b, c)]
        cp = [False] + [q.xor((abc[i], abc[i - 1])) for i in range(1, size)]
        up = [q.xor(bits) for bits in zip(u, w)]
        vp = [q.xor(bits) for bits in zip(v, w)]
        uvw = [q.xor(bits) for bits in zip(u, v, w)]
        wp = [False]
        for i in range(1, size):
            wp.append(q.xor((wp[-1], uvw[i - 1])))
        for i in range(size):
            if i == size - 1:
                q.require(_negate(abc[i]))
            else:
                equal = q.and_(
                    (_negate(q.xor((a[i + 1], b[i + 1]))), _negate(q.xor((a[i + 1], c[i + 1]))))
                )
                q.require(q.or_((_negate(equal), _negate(q.xor((a[i], b[i], c[i], b[i + 1]))))))
            q.require(q.or_((_negate(q.or_((up[i], vp[i]))), q.or_((ap[i], bp[i], wp[i])))))
            q.equal(q.xor((q.and_((ap[i], up[i])), q.and_((bp[i], vp[i])))), q.and_((cp[i], wp[i])))
            if i == 0:
                q.require(
                    q.or_(
                        (
                            q.and_((_negate(ap[i]), _negate(bp[i]))),
                            _negate(q.xor((q.and_((ap[i], up[i])), q.xor((up[i], vp[i]))))),
                        )
                    )
                )
            else:
                self._weight(q.or_((ap[i], bp[i], wp[i])))

    def cnf_formula(self, *, maximum_cost=None, minimum_score=None):
        """Return the exact Boolean formula with optional certified objective bounds."""
        q = _BooleanBuilder(
            self.base_formula.variables, self.base_formula.clauses, self.base_formula.provenance
        )
        if self.factors:
            _add_weight_interval(
                self.probability_bits,
                self.probability_denominator,
                self.interval,
                lambda name: q.allocate("bound_" + name),
                q.indices,
                q.add,
            )
            if minimum_score is not None:
                _add_bound(
                    self.probability_bits,
                    minimum_score,
                    lambda name: q.allocate("score_" + name),
                    q.indices,
                    q.add,
                )
        else:
            from decimal import ROUND_CEILING, ROUND_FLOOR

            lower, upper = self.interval
            minimum = 0 if lower is None else int(lower.to_integral_value(rounding=ROUND_CEILING))
            maximum = (
                len(self.weights)
                if upper is None
                else int(upper.to_integral_value(rounding=ROUND_FLOOR))
            )
            if maximum_cost is not None:
                maximum = min(maximum, maximum_cost)
            _at_most(self.weights, maximum, q.allocate, q.indices, q.add, "qdt_maximum")
            if minimum:
                opposite = []
                for name in self.weights:
                    inverse = q.allocate("opposite_" + name)
                    q.equal(q.indices[inverse], -q.indices[name])
                    opposite.append(inverse)
                _at_most(
                    opposite,
                    len(self.weights) - minimum,
                    q.allocate,
                    q.indices,
                    q.add,
                    "qdt_minimum",
                )
        return replace(
            q.formula(),
            constraint_models=(
                ConstraintModelApplication(
                    self.model_provenance,
                    tuple(
                        component.component_id
                        for component in self.primitive.graph.components
                        if component.component_id is not None
                    ),
                ),
            ),
        )

    def decode(self, assignment):
        """Independently validate each selected atomic coefficient and its product."""
        steps = []
        for local in self.locals:
            ds = tuple(
                _packed(bits, assignment, self.base_formula.variables) for bits in local.differences
            )
            ms = tuple(
                _packed(bits, assignment, self.base_formula.variables) for bits in local.masks
            )
            od = _packed(local.output_difference, assignment, self.base_formula.variables)
            om = _packed(local.output_mask, assignment, self.base_formula.variables)
            flat_d = _packed(
                tuple(chain.from_iterable(local.differences)),
                assignment,
                self.base_formula.variables,
            )
            flat_m = _packed(
                tuple(chain.from_iterable(local.masks)), assignment, self.base_formula.variables
            )
            coefficient = local.checker(flat_d, od, flat_m, om)
            if not coefficient:
                raise RuntimeError(f"{local.name}: solver witness has a zero exact QDT coefficient")
            steps.append((local.name, QuasidifferentialTransition(ds, od, ms, om, coefficient)))
        coefficient = Fraction(1)
        for _, transition in steps:
            coefficient *= transition.coefficient
        if self.factors:
            assert self.probability_denominator is not None
            encoded = sum(
                (
                    int(bit)
                    if isinstance(bit, bool)
                    else int(
                        bool(assignment[self.base_formula.variables[abs(bit) - 1]]) == (bit > 0)
                    )
                )
                << index
                for index, bit in enumerate(self.probability_bits)
            )
            if abs(coefficient) != Fraction(encoded, self.probability_denominator):
                raise RuntimeError(
                    "encoded QDT product disagrees with independent exact coefficients"
                )
        else:
            cost = sum(bool(assignment[name]) for name in self.weights)
            if abs(coefficient) != Fraction(1, 1 << cost):
                raise RuntimeError(
                    "encoded QDT weight disagrees with independent exact coefficients"
                )
        return tuple(steps), coefficient


def _lookup_coefficient(a, b, u, v, *, table, output_width):
    return QuasidifferentialSemantics.lookup(table, a, b, u, v, output_width=output_width)


def _addition_coefficient(a, b, u, v, *, width, subtract):
    mask = (1 << width) - 1
    operation = (
        QuasidifferentialSemantics.modular_subtract
        if subtract
        else QuasidifferentialSemantics.modular_add
    )
    return operation(width, a >> width, a & mask, b, u >> width, u & mask, v)


__all__ = ["QuasidifferentialSATModel"]
