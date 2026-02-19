# Neo Symbolic Executor

Neo N3 smart contract symbolic execution and detector-based security analysis toolkit.

Current version: `0.3.0`

## Highlights

- NEF parser and disassembler for Neo N3 contracts.
- Symbolic execution engine for path exploration and state modeling.
- Security detector suite for reentrancy, overflow, access control, DoS, upgradeability, and related contract risks.
- CLI risk gates (`--fail-on-*`) for CI enforcement.
- DevPack corpus validation utility at `examples/validate_devpack_corpus.py`.

## Quick Start

1. Install runtime dependencies.
```bash
python3 -m pip install click rich
```
2. Run a contract analysis.
```bash
PYTHONPATH=src python3 -m neo_sym.cli analyze /path/to/contract.nef --manifest /path/to/contract.manifest.json --format json
```
3. Run tests.
```bash
PYTHONPATH=src pytest -q
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

## Release Notes

- Changelog: `CHANGELOG.md`
- Latest release notes: `docs/releases/v0.3.0.md`

## Release Artifacts

- `dist/neo-symbolic-executor-v0.3.0.tar.gz`
- `dist/neo-symbolic-executor-v0.3.0.sha256`
- `dist/neo-symbolic-executor-v0.3.0.manifest.json`
