"""Bridge tests for the legacy neo_sym CLI explore command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from neo_sym.cli import main


EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def test_explore_command_delegates_to_hardened_executor_json_output():
    runner = CliRunner()
    result = runner.invoke(main, ["explore", "--json", str(EXAMPLES_DIR / "buffer.neoasm")])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["program"]["metadata"]["source_type"] == "assembly"
    assert payload["program"]["instruction_count"] == 11


def test_explore_command_reports_validation_errors():
    runner = CliRunner()
    result = runner.invoke(main, ["explore", "--max-item-size", "0", str(EXAMPLES_DIR / "buffer.neoasm")])

    assert result.exit_code == 2
    assert "max_item_size must be positive" in result.output
