# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- Added the hardened `neo_symbolic_executor` package under `src/neo_symbolic_executor`.
- Added `neo_sym.cli explore` as a compatibility bridge to the standalone executor.
- Added fuzzing harnesses, curated seed corpus, executable NeoVM examples, and executor-focused regression tests.
- Added packaging metadata and CI coverage for the combined detector/analyzer and standalone executor repo layout.

## [0.3.0] - 2026-02-19

### Added

- Added `examples/validate_devpack_corpus.py` for end-to-end corpus extraction and validation against Neo DevPack `TestingArtifacts`.
- Added machine-readable and markdown validation report generation (`summary.json`, `summary.md`) with detector and severity distributions.
- Added `test_cli_reports_package_version` to enforce version consistency between package metadata and CLI output.
- Added release documentation at `docs/releases/v0.3.0.md`.
- Added release artifact bundle and checksum under `dist/`.

### Changed

- Bumped project version from `0.2.0` to `0.3.0`.
- Updated CLI version flag and runtime banner to use centralized package version (`neo_sym.__version__`).
- Added root `README.md` with usage, validation workflow, and release references.

### Validation

- Full Neo DevPack dotnet corpus run completed successfully (`149/149` contracts analyzed, `0` analyzer failures).

## [0.2.0] - 2026-02-19

### Added

- Advanced detector and policy-gate hardening across the symbolic analyzer.
