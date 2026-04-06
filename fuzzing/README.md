# Fuzzing neo-symbolic-executor

This directory contains fuzzing harnesses for the NeoVM symbolic executor using [atheris](https://github.com/google/atheris), Google's Python fuzzer.

## Setup

Install the fuzzing dependencies:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install --no-cache-dir -e ".[fuzzing]"
```

## Fuzzing Harnesses

### 1. `fuzz_nef_parser.py`
Tests the NEF file parser with arbitrary byte sequences.

```bash
python3 fuzzing/fuzz_nef_parser.py -max_total_time=300
```

### 2. `fuzz_bytecode_decoder.py`
Tests the NeoVM bytecode decoder with arbitrary bytes.

```bash
python3 fuzzing/fuzz_bytecode_decoder.py -max_total_time=300
```

### 3. `fuzz_assembly_parser.py`
Tests the assembly parser with arbitrary text inputs.

```bash
python3 fuzzing/fuzz_assembly_parser.py -max_total_time=300
```

### 4. `fuzz_execution_engine.py`
Tests the execution engine with decoded programs.

```bash
python3 fuzzing/fuzz_execution_engine.py -max_total_time=300
```

### 5. `fuzz_source_loader.py`
Tests source type detection and file loading with various formats.

```bash
python3 fuzzing/fuzz_source_loader.py -max_total_time=300
```

### 6. `fuzz_structured_bytecode.py`
Generates structured, valid-looking NeoVM bytecode for deeper execution path exploration.

```bash
python3 fuzzing/fuzz_structured_bytecode.py -max_total_time=300
```

## Runner

`fuzzing/run_all_fuzzers.py` orchestrates each harness and is used in CI.

```bash
python3 fuzzing/run_all_fuzzers.py --duration 5 --corpus fuzzing/corpus --artifacts-dir fuzzing/artifacts
```

The runner copies the seed corpus into a temporary workspace before each fuzzer, so your checked-in seeds stay stable across runs. If you pass `--artifacts-dir`, crashes are written there; otherwise libFuzzer crash files are emitted from the repo working directory.

## Reproducing Crashes

When a crash is found, the fuzzer saves a crash file. To reproduce:

```bash
python3 fuzzing/fuzz_nef_parser.py crash-12345...
```

## Coverage

To generate coverage reports from fuzzing:

```bash
python3 -m coverage run fuzzing/fuzz_bytecode_decoder.py -max_total_time=60
coverage report
coverage html
```
