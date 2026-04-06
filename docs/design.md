# Design Notes

## Goal

Provide a practical NeoVM symbolic executor that:

- accepts real NeoVM artifacts
- stays dependency-light and easy to run
- is explicit about unsupported semantics
- can be extended toward fuller contract analysis later

## Architecture

The implementation is organized into focused modules:

1. `opcodes.py`
   Defines NeoVM opcode metadata, numeric values, operand-width rules, and stack-item type constants.
2. `model.py`
   Defines core data structures: `Instruction` and `Program` with offset-indexed instruction lookup.
3. `bytecode.py`
   Decodes raw NeoVM script bytes into instructions addressed by real byte offsets.
4. `assembly.py` and `nef.py`
   Assemble NeoVM text into bytecode and extract scripts from `.nef` containers.
5. `expr.py`
   Models symbolic values and performs local simplification for integers, booleans, null, byte strings, and heap references.
6. `heap.py`
   Defines heap object types (`ArrayObject`, `StructObject`, `MapObject`, `BufferObject`) with allocation, cloning, and snapshot rendering.
7. `interop.py`
   Defines NeoVM syscall/interop descriptors, call flags, trigger constants, and SHA-256-based syscall hash computation.
8. `engine.py`
   Executes a single NeoVM frame symbolically, including stack operators, slot initialization, call frames, heap-backed buffers and collections, path splitting, terminal-state reporting, and execution-budget enforcement.
9. `source.py`
   Auto-detects source type from file extension and content, then dispatches to the appropriate decoder.

## Program Representation

The internal `Program` stores:

- the original script bytes
- decoded instructions
- real instruction offsets
- resolved absolute jump targets
- optional metadata such as source type or NEF compiler string

This keeps assembly, raw bytecode, JSON scripts, and NEF inputs on one execution path.

## Current NeoVM Semantics

The executor currently models:

- real relative jump targets based on instruction byte offsets
- `INITSLOT` and `INITSSLOT` semantics, including NeoVM argument-pop ordering
- local-variable, argument-slot, and static-field reads and writes
- cloned call frames for `CALL`, `CALL_L`, and `CALLA`, with shared evaluation stack and static fields
- heap-backed buffers, arrays, structs, and maps with NeoVM-style aliasing across duplicated references
- splice opcodes `NEWBUFFER`, `MEMCPY`, `CAT`, `SUBSTR`, `LEFT`, and `RIGHT`
- `PACK*`, `UNPACK`, `NEWARRAY*`, `NEWSTRUCT*`, and `NEWMAP`
- collection reads and mutations including `SIZE`, `HASKEY`, `KEYS`, `VALUES`, `PICKITEM`, `APPEND`, `SETITEM`, `REVERSEITEMS`, `REMOVE`, `CLEARITEMS`, and `POPITEM`
- symbolic branch splitting for map lookups and updates when key equality is unresolved
- symbolic primitive `SIZE`, `PICKITEM`, and bounded `CONVERT` reasoning for integers and byte strings
- NeoVM exception-handling control flow for `THROW`, `TRY*`, `ENDTRY*`, and `ENDFINALLY`, including call-frame unwinding
- NeoVM catchable engine exceptions for `PICKITEM` and `SETITEM` out-of-range or missing-key cases
- selected syscall execution for context-free runtime and contract introspection services, plus trace-only `System.Runtime.Log` and `System.Runtime.Notify`
- type operations `ISNULL`, buffer-aware `ISTYPE`, buffer-aware `CONVERT`, `ABORTMSG`, and `ASSERTMSG`
- stack manipulation opcodes such as `DUP`, `OVER`, `ROT`, `ROLL`, `REVERSE3`, `REVERSE4`, and `REVERSEN`
- arithmetic and comparison opcodes over integer expressions, including bounded `POW`, `SQRT`, `MODMUL`, and `MODPOW`
- generic equality for booleans, byte strings, and null values
- branch splitting for symbolic conditions
- fault splitting for symbolic `ASSERT`, `DIV`, and `MOD`

## Constraint Handling

Path conditions are handled without an SMT solver. The engine:

- constant-folds arithmetic and comparisons
- normalizes truthiness
- rewrites negated comparisons
- rejects directly contradictory conditions
- keeps branch conditions symbolic when they cannot be reduced further

This is conservative by design. It avoids hidden solver behavior and keeps failure modes easy to inspect.

## Resource Safety

Execution is intentionally bounded in two dimensions:

- path-exploration limits: steps, processed states, and visits per instruction
- concrete-allocation limits: maximum byte-buffer size, maximum collection size, and maximum heap-backed object count
- protocol limits: maximum invocation depth, maximum nested `TRY` depth, and maximum shift/exponent value for `SHL`, `SHR`, and `POW`
- interop context inputs: trigger, network magic, address version, call flags, optional script hash, and optional concrete `GasLeft`/`GetTime` values
- concrete NeoVM integer-result limit enforcement for operations that resolve to oversized integers

This keeps the executor usable against malformed or adversarial inputs without relying on the host process to absorb unbounded memory growth.

## Unsupported Areas

These NeoVM areas are intentionally incomplete today:

- syscall and interop effects
- catchability for broader engine faults beyond NeoVM's explicit `CatchableException` sites
- pointer/interoperability types
- full interop semantics for storage, notifications retrieval, script containers, iterators, crypto verification, and cross-contract calls
- general symbolic byte-level reasoning beyond primitive sizing, indexing, and bounded conversion
- symbolic modular arithmetic and concrete-only paths such as `SQRT`, `POW` with symbolic exponents, and `MODPOW`
- symbolic map reasoning beyond explicit equality-driven branching
- solver-backed reasoning over complex path constraints

Unsupported instructions are surfaced as stopped states rather than silently mis-executed paths.

## Near-Term Extensions

- extend `ISTYPE` and `CONVERT` to distinguish pointer and interop values
- lift buffer and splice reasoning beyond concrete byte content
- add deeper solver-backed reasoning for symbolic maps beyond equality-driven path splitting
- support contract-dispatch entry assumptions directly from manifests
- integrate an optional SMT backend for deeper satisfiability pruning
