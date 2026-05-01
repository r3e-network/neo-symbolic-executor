# Neo.SymbolicExecutor.Fuzzer

A multi-target, multi-worker fuzzer for the Neo Symbolic Executor. Designed to run for
days or weeks against the engine, parsers, detectors, reports, and SMT translator, recording
unique crashes to a persistent corpus for triage.

## Targets

| Name | What it stresses | Properties checked |
|---|---|---|
| `decoder` | `ScriptDecoder.Decode` over random bytes + structured opcode mixes | Only `VmFaultException` may surface |
| `nef` | `NefFile.Parse` over fully random bytes | Only parser-typed exceptions allowed |
| `nef-mutation` | A valid NEF with one byte flipped | Validation paths beyond magic-mismatch |
| `manifest` | `ContractManifest.FromJson` over manifest-shaped JSON with random type errors | Only known parse-failure exceptions allowed |
| `engine` | `SymbolicEngine.Run` on random structured scripts | Every state reaches a terminal status; budgeted; no leaks |
| `engine-seeded` | Engine with random symbolic seeds on the stack | Drives symbolic-fork code paths |
| `clone-leak` | Cloned states must not share telemetry (audit C1/C6) | Mutation in one final state never affects another |
| `detectors` | `DetectorEngine.Run` on synthetic states | Deterministic across two runs of the same input |
| `engine-detectors` | `DetectorEngine.Run` on real engine-produced states | Same as above on realistic telemetry shapes |
| `pipeline` | Full `decode → run → detect → risk → gate → report` chain | JSON parses back; Markdown begins with the canonical H1 |
| `report` | `ReportGenerator.{ToJson,ToMarkdown}` on random findings | Output round-trips through `JsonNode.Parse` |
| `expr` | `Expr.*` simplifiers over random IR trees | No exceptions other than `VmFaultException` |
| `real-nef` | Real NEF corpus from `NEO_SYM_FUZZ_NEF_DIR` | Parses and runs available NEF/manifest pairs without unexpected exceptions |
| `structured-mutation` | Structured scripts with focused byte-level mutations | Mutations preserve bounded engine behavior |
| `engine-cov` | Coverage-guided engine inputs with persistent interesting corpus | Newly covered paths are retained and replayed |
| `engine-determinism` | Same generated script run twice | Final-state summaries stay deterministic |
| `clone-isolation` | Deep state clone oracle | Heap, stack, telemetry, and path mutations do not bleed across clones |
| `pipeline-consistency` | Full pipeline run twice on the same script | Findings and reports are stable |
| `report-roundtrip` | Generated reports with varied finding text | JSON report shape round-trips through `JsonNode` |
| `heap-invariants` | Heap-heavy engine scripts | Heap references remain valid and clone-safe |
| `differential-neovm` | Bounded scripts against Neo.VM reference execution | Clean Neo.VM halts should not become all-fault symbolic runs |
| `method-entry` | `SymbolicEngine.CreateMethodEntryState` over synthetic ABI methods | The CLI per-entrypoint analyze path produces no Running leftovers |

## Quick start

```bash
# Build
dotnet build src/Neo.SymbolicExecutor.Fuzzer -c Release

# Smoke run (60 seconds, all targets)
src/Neo.SymbolicExecutor.Fuzzer/bin/Release/net10.0/neo-sym-fuzz --seconds 60

# Overnight run (8 hours, more workers, persistent corpus)
src/Neo.SymbolicExecutor.Fuzzer/bin/Release/net10.0/neo-sym-fuzz \
    --hours 8 --workers 8 --corpus ./fuzz-corpus

# A single target only
neo-sym-fuzz --target engine,pipeline --seconds 600
```

## Long-running operation (days / weeks)

Use the supplied wrapper which restarts the campaign daily, rotates logs, and writes a daily
summary file:

```bash
nohup scripts/run-fuzzer-forever.sh ./fuzz-corpus 8 > /dev/null 2>&1 &
disown
```

The wrapper:
- Builds the fuzzer in Release mode if needed.
- Restarts every 24 hours so log files stay small and progress is checkpointed.
- Persists `./fuzz-corpus/crashes/<target>-<sig>/` directories across restarts.
- Writes `./fuzz-corpus/summary-YYYY-MM-DD.txt` per day listing all unique crashes seen so
  far (target, signature, first-seen timestamp).
- Stops cleanly on `SIGTERM` or by `touch ./fuzz-corpus/STOP`.

To stop:

```bash
# graceful: ask the wrapper to stop after the current chunk
touch ./fuzz-corpus/STOP
# or
pkill -TERM -f run-fuzzer-forever
```

## systemd unit (optional)

```ini
[Unit]
Description=Neo Symbolic Executor fuzzer
After=network.target

[Service]
Type=simple
User=neo
WorkingDirectory=/home/neo/git/neo-symbolic-executor
ExecStart=/home/neo/git/neo-symbolic-executor/scripts/run-fuzzer-forever.sh /var/lib/neo-sym/fuzz-corpus 8
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

## Crash artifacts

Every unique crash creates a directory under `<corpus>/crashes/`:

```
fuzz-corpus/crashes/engine-A1B2C3D4E5F6/
├── crash.txt    # exception type, message, stack trace
├── input.bin    # bytes that triggered the crash
└── meta.json    # target, seed, iteration, first-seen timestamp
```

Dedup signature: SHA-256 prefix of `target | exception type | first 3 stack frames`. Two
crashes with the same signature won't double-record across runs (the recorder loads existing
sigs at startup).

## Reproducing a recorded crash

Manually:

```bash
# Inspect the artifact
cat fuzz-corpus/crashes/engine-A1B2C3D4E5F6/crash.txt

# Replay using the seed
neo-sym-fuzz --target engine --seed 197456258 --seconds 1
```

The `--reproduce <input.bin>` flag is wired but its driver is target-dependent and still
maturing — for now, the seed-driven entry point is the canonical replay.

## Historical throughput baselines

On a developer laptop (4 worker threads, dotnet 10), the original 12-target campaign measured:

- ~150K–170K iterations/sec across the original 12 targets combined
- ~5 minutes ≈ 50M iterations
- ~24 hours ≈ ~14 billion iterations

Current 21-target campaigns include real-NEF, coverage-guided, consistency, heap-invariant,
and differential Neo.VM oracles, so throughput depends on the enabled target mix and corpus.

## Bug-hunting record

The first run of the original 12-target fuzzer (90 seconds) found 58 unique crashes covering
two underlying bug classes in the engine:

1. `CatchableVmException` leaking out of `SymbolicEngine.Run()` when PICKITEM/REMOVE
   produced an out-of-range index.
2. `OverflowException` from `(int)BigInteger` casts when a runtime-supplied index exceeded
   `Int32.MaxValue`.

Both fixed in `SymbolicEngine.cs`'s outer worklist try/catch; locked-in by
`tests/Neo.SymbolicExecutor.Tests/FuzzerRegressionTests.cs`. Subsequent 5-minute runs
(50M iterations) are clean.
