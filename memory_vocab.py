"""Single source of truth for the memory layer's symbolic vocabulary.

The whole point of the abstract symbols is that contracts learned from one
bug fire on any other bug whose conditions match the same shape, regardless
of project, file, or function names.

Both the LLM extractor (memory_layer.extract_conditions_llm) and the
deterministic extractor (memory_layer.extract_conditions_det) must speak
this exact vocabulary, otherwise their outputs cannot be reconciled.
"""
# there should be more types of bugs to be added here
# inlcuding but not limited to 
# Standard bug taxonomy. Aligned with ARVO/sanitizer crash_type categories so
# the deterministic extractor can map ARVO rows directly into bug_type facts.
BUG_TYPES = [
    'heap_buffer_overflow',
    'stack_buffer_overflow',
    'global_buffer_overflow',
    'container_overflow',
    'null_pointer_dereference',
    'use_after_free',
    'use_after_return',
    'double_free',
    'uninitialized_read',
    'integer_overflow',
    'signed_integer_overflow',
    'type_confusion',
    'memory_leak',
    'index_out_of_bounds',
    'bad cast'
    
]

# Abstract symbols. Constants in pyDatalog must be lowercase; rule-body
# variables (X, F, L, ...) are uppercase and live in memory_layer.py.
VAR_SYMBOLS = [f'var{i}' for i in range(1, 9)]    # values, pointers, buffers
FUNC_SYMBOLS = [f'func{i}' for i in range(1, 9)]  # functions, callees
LOC_SYMBOLS = [f'loc{i}' for i in range(1, 9)]    # source locations
TYPE_SYMBOLS = [f'type{i}' for i in range(1, 5)]
SIZE_SYMBOLS = [f'size{i}' for i in range(1, 5)]

# (name, arity, doc) - the doc is rendered into the LLM prompt.
PREDICATES = [
    # data flow
    ('passed_by_ref',         2, 'value/pointer VAR is passed by reference into FUNC'),
    ('returned_from',         2, 'VAR is the return value of FUNC'),
    ('aliased_with',          2, 'VAR1 and VAR2 reference the same memory'),
    ('derived_from',          2, 'VAR1 is computed from VAR2 (offset, cast, copy)'),

    # mutation
    ('modifies',              2, 'FUNC mutates VAR'),
    ('frees',                 2, 'FUNC frees VAR'),
    ('allocates',             2, 'FUNC allocates VAR'),
    ('reallocates',           2, 'FUNC reallocates VAR (size or address may change)'),

    # checks present in the code
    ('null_checked_before',   2, 'VAR is null-checked before LOC'),
    ('bounds_checked_before', 3, 'VAR is bounds-checked against SIZE before LOC'),
    ('type_checked_before',   3, 'VAR is type-checked against TYPE before LOC'),

    # uses
    ('dereferenced_at',       2, 'VAR is dereferenced at LOC'),
    ('indexed_at',            3, 'VAR is indexed by SIZE at LOC'),
    ('used_after',            2, 'VAR is used at LOC after some prior event'),

    # ordering
    ('happens_before',        2, 'LOC1 strictly precedes LOC2 on the relevant path'),
    ('on_error_path',         1, 'LOC is reachable only on an error/cleanup path'),

    # bug class tag (set per query so contracts can scope themselves to a class)
    ('bug_class',             1, 'the bug under consideration is of this BUG_TYPE'),
]

PREDICATE_NAMES = [p[0] for p in PREDICATES]
PREDICATE_ARITY = {p[0]: p[1] for p in PREDICATES}


def vocab_block() -> str:
    """Render the vocabulary as a block to splice into LLM prompts."""
    lines = ['BUG TYPES:']
    for b in BUG_TYPES:
        lines.append(f'  {b}')
    lines.append('')
    lines.append('ABSTRACT SYMBOLS (lowercase, used as constants):')
    lines.append(f'  variables: {", ".join(VAR_SYMBOLS)}')
    lines.append(f'  functions: {", ".join(FUNC_SYMBOLS)}')
    lines.append(f'  locations: {", ".join(LOC_SYMBOLS)}')
    lines.append(f'  types:     {", ".join(TYPE_SYMBOLS)}')
    lines.append(f'  sizes:     {", ".join(SIZE_SYMBOLS)}')
    lines.append('')
    lines.append('CONDITION PREDICATES (predicate/arity - meaning):')
    for name, arity, doc in PREDICATES:
        lines.append(f'  {name}/{arity} - {doc}')
    return '\n'.join(lines)
