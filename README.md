# neo-symbolic-executor

`neo-symbolic-executor` is a dependency-light symbolic executor for real NeoVM scripts. It can load NeoVM assembly, raw script bytes, NeoVM JSON-style script arrays, hexadecimal script blobs, and `.nef` containers, decode them into real opcode offsets, and explore reachable paths symbolically.

## What It Handles

The current implementation supports real NeoVM bytecode decoding plus symbolic execution for a focused but practical opcode set:

- constants: `PUSHM1` through `PUSH16`, `PUSHINT8` through `PUSHINT256`, `PUSHT`, `PUSHF`, `PUSHNULL`, `PUSHDATA1/2/4`, `PUSHA`
- control flow: `JMP*`, `JMPEQ*`, `JMPNE*`, `JMPGT*`, `JMPGE*`, `JMPLT*`, `JMPLE*`, `CALL`, `CALL_L`, `CALLA`, `ASSERT`, `ABORT`, `THROW`, `TRY*`, `RET`, `ENDTRY*`, `ENDFINALLY`
- stack ops: `DEPTH`, `DROP`, `NIP`, `XDROP`, `CLEAR`, `DUP`, `OVER`, `PICK`, `TUCK`, `SWAP`, `ROT`, `ROLL`, `REVERSE3`, `REVERSE4`, `REVERSEN`
- slots: `INITSSLOT`, `INITSLOT`, `LDSFLD*`, `STSFLD*`, `LDLOC*`, `STLOC*`, `LDARG*`, `STARG*`
- splice and buffer ops: `NEWBUFFER`, `MEMCPY`, `CAT`, `SUBSTR`, `LEFT`, `RIGHT`
- arithmetic and logic: `INVERT`, `AND`, `OR`, `XOR`, `EQUAL`, `NOTEQUAL`, `SIGN`, `ABS`, `NEGATE`, `INC`, `DEC`, `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, `POW`, `SQRT`, `MODMUL`, `MODPOW`, `SHL`, `SHR`, `NOT`, `BOOLAND`, `BOOLOR`, `NZ`, `NUMEQUAL`, `NUMNOTEQUAL`, `LT`, `LE`, `GT`, `GE`, `MIN`, `MAX`, `WITHIN`
- compound and type ops: `PACKMAP`, `PACKSTRUCT`, `PACK`, `UNPACK`, `NEWARRAY0`, `NEWARRAY`, `NEWARRAY_T`, `NEWSTRUCT0`, `NEWSTRUCT`, `NEWMAP`, `SIZE`, `HASKEY`, `KEYS`, `VALUES`, `PICKITEM`, `APPEND`, `SETITEM`, `REVERSEITEMS`, `REMOVE`, `CLEARITEMS`, `POPITEM`, `ISNULL`, `ISTYPE`, `CONVERT`
- selected interop/syscalls: `System.Runtime.Platform`, `GetTrigger`, `GetNetwork`, `GetAddressVersion`, `GetTime`, `GasLeft`, `GetRandom`, `GetInvocationCounter`, `GetExecutingScriptHash`, `GetEntryScriptHash`, `GetCallingScriptHash`, `System.Contract.GetCallFlags`, `System.Runtime.Log`, and `System.Runtime.Notify`
- message-bearing faults: `ABORTMSG`, `ASSERTMSG`

The symbolic value model currently understands:

- integers
- booleans
- null
- byte strings
- heap-backed buffers, arrays, structs, and maps with reference semantics
- symbolic variables for integers, booleans, and byte strings
- symbolic `SIZE`, `PICKITEM`, and primitive `CONVERT` expressions for integer and byte-string values
- path splitting for symbolic map lookups and updates against existing entries

## Input Formats

The CLI auto-detects:

- NeoVM assembly files such as `*.neoasm`
- raw hex scripts
- raw binary scripts
- `.nef` files
- JSON arrays in the same style NeoVM test vectors use, for example `["PUSH1", "PUSH0", "JMPEQ", "0x03", "RET"]`

## Quick Start

Run the NeoVM assembly example with one symbolic argument:

```bash
python3 -m neo_symbolic_executor --arg amount examples/branching.neoasm
```

Print the decoded script before execution:

```bash
python3 -m neo_symbolic_executor --disassemble --arg amount examples/branching.neoasm
```

Emit JSON:

```bash
python3 -m neo_symbolic_executor --json --arg amount examples/assertion.neoasm
```

Analyze a raw hex script directly from a file:

```bash
python3 -m neo_symbolic_executor --source-type hex path/to/script.hex
```

Analyze a compiled `.nef` contract artifact:

```bash
python3 -m neo_symbolic_executor contract.nef
```

Run the call-frame example:

```bash
python3 -m neo_symbolic_executor --disassemble --arg amount examples/call.neoasm
```

Run the collection example:

```bash
python3 -m neo_symbolic_executor examples/collections.neoasm
```

Run a symbolic map-key example:

```bash
python3 -m neo_symbolic_executor --arg key examples/symbolic_map.neoasm
```

Run the buffer/splice example:

```bash
python3 -m neo_symbolic_executor examples/buffer.neoasm
```

## NeoVM Assembly Example

```text
INITSLOT 0 1
LDARG0
PUSH0
JMPLT reject
LDARG0
PUSH10
JMPGT high
LDARG0
RET

high:
LDARG0
PUSH1
ADD
RET

reject:
ABORT
```

Use `--arg amount` so the initial evaluation stack is seeded for `INITSLOT 0 1`. The executor will split the negative path, the `<= 10` return path, and the `> 10` return path.

## CLI Notes

- `--arg <spec>` seeds the initial evaluation stack in NeoVM argument-pop order for `INITSLOT`.
- `--stack-item <spec>` pushes explicit initial evaluation-stack items.
- Bare identifiers like `amount` become symbolic integers.
- Typed values such as `bool:flag`, `bytes:payload`, `int:threshold`, `true`, `null`, and `0x0102` are supported.
- `--max-item-size`, `--max-collection-size`, `--max-heap-objects`, `--max-invocation-stack`, `--max-try-nesting-depth`, and `--max-shift` enforce NeoVM-style protocol and executor safety limits.
- `--trigger`, `--network-magic`, `--address-version`, `--call-flags`, `--script-hash`, `--gas-left`, and `--time` seed interop context for supported `SYSCALL` execution.
- terminal states now include heap snapshots in both human-readable and JSON output

## Testing

```bash
python3 -m unittest discover -s tests -v
```

```bash
python3 -m compileall neo_symbolic_executor tests fuzzing
```

```bash
python3 -m build
```

```bash
python3 fuzzing/run_all_fuzzers.py --duration 5 --corpus fuzzing/corpus --artifacts-dir /tmp/neo-fuzz-artifacts
```

## Development Setup

Use the development extras and the new pip install flags that will run in CI:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install --no-cache-dir --break-system-packages -e ".[dev]"
```

## Release Verification

Building the wheel ensures the published artifact matches the source tree:

```bash
python3 -m pip wheel . -w /tmp/neo-symbolic-executor-wheel
ls /tmp/neo-symbolic-executor-wheel
```

Validate the wheel before pushing by running `python3 -m pip install /tmp/neo-symbolic-executor-wheel/neo_symbolic_executor-*.whl` (add `--no-deps` if needed) and repeating the smoke tests above.

## Fuzzing

The `fuzzing/run_all_fuzzers.py` script runs the full harness suite with the existing seed corpus.

```bash
python3 fuzzing/run_all_fuzzers.py --duration 5 --corpus fuzzing/corpus --artifacts-dir /tmp/neo-fuzz-artifacts
```

Corpus files are stored in `fuzzing/corpus`; `run_all_fuzzers.py` copies that seed set into a temporary workspace per harness and writes crash artifacts under `--artifacts-dir` when you provide one.

## Repository Layout

```text
neo-symbolic-executor/
├── neo_symbolic_executor/
│   ├── __init__.py
│   ├── __main__.py
│   ├── assembly.py
│   ├── bytecode.py
│   ├── engine.py
│   ├── expr.py
│   ├── heap.py
│   ├── interop.py
│   ├── model.py
│   ├── nef.py
│   ├── opcodes.py
│   └── source.py
├── docs/
│   └── design.md
├── examples/
│   ├── assertion.neoasm
│   ├── buffer.neoasm
│   ├── branching.neoasm
│   ├── call.neoasm
│   ├── collections.neoasm
│   └── symbolic_map.neoasm
└── tests/
    ├── test_cli.py
    ├── test_engine.py
    └── test_parser.py
```

## Limitations

- `CALLT` is still stopped explicitly rather than executed. `THROW`, `TRY*`, `ENDTRY*`, `ENDFINALLY`, and NeoVM catchable compound-operation exceptions are modeled, but broader engine-fault catchability is still incomplete.
- Many common runtime syscalls now execute directly, but storage, witness, transaction-container, iterator, crypto, dynamic script loading, and cross-contract call syscalls still require richer interop context than the executor models today.
- Pointer and interop-interface distinctions are not modeled yet; related `ISTYPE` and `CONVERT` cases still stop rather than guessing.
- Buffer operations are modeled concretely. Symbolic primitive `SIZE`, `PICKITEM`, bounded `SHL`/`SHR`, concrete-exponent `POW`, and some `CONVERT` cases are covered, but general symbolic byte-level transformations and symbolic modular arithmetic are still limited.
- Symbolic map-key branching now covers equality-driven map construction, lookups, and updates, but there is still no solver-backed reasoning beyond those explicit equality splits.
- Execution is budgeted by step/state/visit limits and by concrete allocation limits so hostile scripts cannot grow buffers, collections, or heap objects without bound.
- Constraint reasoning is simplification-based and solver-free. There is no SMT backend yet.
- The executor models cloned call frames for `CALL`/`CALL_L`/`CALLA` and heap-backed collection aliasing, but it does not yet interpret full contract dispatch or interop side effects.

Those limits are explicit so the tool stays correct and debuggable while still being useful on real NeoVM artifacts.
