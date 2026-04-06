# Neo Symbolic Executor

Neo N3 smart contract symbolic execution and detector-based security analysis toolkit.

Current version: `0.3.0`

## Highlights

- NEF parser and disassembler for Neo N3 contracts.
- Symbolic execution engine for path exploration and state modeling.
- Security detector suite for reentrancy, overflow, access control, DoS, upgradeability, and related contract risks.
- CLI risk gates (`--fail-on-*`) for CI enforcement.
- Hardened NeoVM executor for assembly, raw bytecode, hex, JSON script arrays, and `.nef` containers.
- First-class fuzzing harnesses for the parser, source loader, decoder, NEF reader, and execution engine.
- DevPack corpus validation utility at `examples/validate_devpack_corpus.py`.

## Quick Start

1. Install the package in editable mode.
```bash
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```
2. Run a detector-backed contract analysis.
```bash
python3 -m neo_sym.cli analyze /path/to/contract.nef --manifest /path/to/contract.manifest.json --format json
```
3. Explore a NeoVM script with the hardened executor.
```bash
python3 -m neo_symbolic_executor --arg amount examples/branching.neoasm
```
4. Reach the same executor from the legacy CLI surface.
```bash
python3 -m neo_sym.cli explore --json examples/buffer.neoasm
```
5. Run tests.
```bash
pytest -q
```

## Full Corpus Validation (Neo DevPack dotnet)

Use this to validate analyzer stability and detector output across all DevPack `TestingArtifacts` contracts.

```bash
python3 examples/validate_devpack_corpus.py \
  --project-root /home/neo/git/neo-symbolic-executor \
  --devpack-root /tmp/neo-devpack-validation-1771475966/neo-devpack-dotnet \
  --output-root docs/validation/devpack-corpus \
  --clean
```

Validation outputs:

- `docs/validation/devpack-corpus/summary.md`
- `docs/validation/devpack-corpus/summary.json`
- `docs/validation/devpack-corpus/artifacts.index.json`
- Extracted corpus under `docs/validation/devpack-corpus/extracted`
- Per-contract reports under `docs/validation/devpack-corpus/analysis`

## CLI Quality Gates

You can enforce release and CI thresholds with:

- `--fail-on-total-findings`
- `--fail-on-max-severity`
- `--fail-on-weighted-score`
- `--fail-on-confidence-weighted-score`
- `--min-confidence`
- `--fail-on-severity-count`
- `--fail-on-detector-severity`

## Hardened Execution CLI

The additive `neo_symbolic_executor` package is now part of the repo under `src/neo_symbolic_executor`.

- input formats: NeoVM assembly, raw hex, raw binary, JSON script arrays, and `.nef`
- execution controls: stack, heap, visit, call-depth, item-size, collection-size, and try-depth budgets
- interop seeding: trigger, network magic, address version, call flags, gas left, time, and script hash
- output modes: human-readable state report or JSON

Examples:

```bash
python3 -m neo_symbolic_executor --json examples/buffer.neoasm
python3 -m neo_symbolic_executor --source-type hex path/to/script.hex
python3 -m neo_symbolic_executor contract.nef
```

## Release Notes

- Changelog: `CHANGELOG.md`
- Latest release notes: `docs/releases/v0.3.0.md`

## Release Artifacts

- `dist/neo-symbolic-executor-v0.3.0.tar.gz`
- `dist/neo-symbolic-executor-v0.3.0.sha256`
- `dist/neo-symbolic-executor-v0.3.0.manifest.json`

## Testing And Fuzzing

```bash
pytest -q
```

```bash
python3 -m compileall src tests fuzzing examples
```

```bash
python3 fuzzing/run_all_fuzzers.py --duration 5 --corpus fuzzing/corpus --artifacts-dir /tmp/neo-fuzz-artifacts
```
