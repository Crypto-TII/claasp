Introduction to trail search and verification
=============================================

A **trail**, also called a **characteristic**, specifies intermediate differences
or masks through a primitive. Search selects a trail according to an objective,
such as its probability or correlation weight. An optimal result is optimal
only within the model and search scope reported by the analysis.

In an **XOR differential**, the difference between two values is their XOR.
In **XOR-linear analysis**, masks select bits whose XOR is a parity check.
These names describe the analysis, even when the primitive contains modular
addition or another nonlinear operation. Circle-linear analysis uses checks
compatible with a selected alternative addition.

Each topic has a Basic and an Advanced guide. Its Verification page
describes the checks actually available. Verification distinguishes three
questions:

Characteristic validation
-------------------------

Are the local transitions, graph connections, weights and signs consistent
with the declared model? General XOR-differential and XOR-linear model
objects expose ``check_characteristic()``. Their decoders also validate
solver witnesses. Passing this check validates the characteristic model;
it does not measure the actual endpoint probability or correlation.

Concrete trail realizability
----------------------------

Does at least one concrete input pair follow the specified differential
trail through the actual primitive, under the stated key assumptions?
This is stronger than accepting each local transition independently.
An existence proof still does not give a probability.

V5 currently has no general public concrete-pair trail checker. The legacy
SAT differential trail-and-checker construction is a distinct capability;
it should not be confused with v5's model-witness validators. For linear
trails, which are expansions in mask checks rather than paths followed by
input pairs, a realizability claim needs its own precise definition.
Unsupported checks are stated on the topic's Verification page rather than
represented by empty guides.

Distinguisher probability/correlation evaluation
------------------------------------------------

What probability or correlation occurs when the primitive is evaluated on
actual inputs? Exact enumeration answers this for a bounded complete domain.
Sampling estimates it, and the sample count and uncertainty matter.

A differential combines all compatible internal differential trails. A linear
or circle-linear endpoint correlation is a signed sum over compatible mask
trails, so contributions can reinforce or cancel. Evaluating an endpoint
distinguishes this combined quantity from one selected trail's weight.
Available evaluation tools differ by analysis; there is no uniform checker
interface across all topics.
