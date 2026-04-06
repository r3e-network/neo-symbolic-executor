from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, mock

from fuzzing import run_all_fuzzers


class FuzzCorpusTest(TestCase):
    def test_run_fuzzer_uses_temp_corpus(self) -> None:
        with TemporaryDirectory(prefix="test-fuzz-corpus-") as temp_dir:
            corpus = Path(temp_dir) / "seeds"
            corpus.mkdir()
            seed = corpus / "seed.neoasm"
            seed.write_text("PUSH1\nRET\n")

            captured: dict[str, object] = {}

            def fake_run(cmd, *, check, cwd, env):
                captured["cmd"] = cmd
                captured["cwd"] = cwd
                captured["env"] = env
                return SimpleNamespace(returncode=42)

            with mock.patch("fuzzing.run_all_fuzzers.subprocess.run", side_effect=fake_run):
                rc = run_all_fuzzers.run_fuzzer("fuzz_assembly_parser.py", duration=0, corpus_dir=corpus)

            self.assertEqual(rc, 42)
            self.assertNotEqual(captured["cmd"][-2], str(corpus))
            self.assertTrue(Path(captured["cmd"][-2]).parent.name.startswith("fuzz_assembly_parser-corpus-"))
            self.assertTrue(captured["cmd"][-1].startswith("-artifact_prefix="))
            self.assertEqual(captured["cwd"], run_all_fuzzers.Path(__file__).resolve().parent.parent)
            self.assertIn(
                str(run_all_fuzzers.Path(__file__).resolve().parent.parent),
                captured["env"]["PYTHONPATH"],
            )
            self.assertEqual(seed.read_text(), "PUSH1\nRET\n")

    def test_run_fuzzer_uses_named_artifacts_directory(self) -> None:
        with TemporaryDirectory(prefix="test-fuzz-artifacts-") as temp_dir:
            artifacts_dir = Path(temp_dir) / "artifacts"

            captured: dict[str, object] = {}

            def fake_run(cmd, *, check, cwd, env):
                captured["cmd"] = cmd
                captured["cwd"] = cwd
                captured["env"] = env
                return SimpleNamespace(returncode=7)

            with mock.patch("fuzzing.run_all_fuzzers.subprocess.run", side_effect=fake_run):
                rc = run_all_fuzzers.run_fuzzer(
                    "fuzz_bytecode_decoder.py",
                    duration=1,
                    artifacts_dir=artifacts_dir,
                )

            self.assertEqual(rc, 7)
            self.assertEqual(captured["cwd"], run_all_fuzzers.Path(__file__).resolve().parent.parent)
            self.assertEqual(
                captured["cmd"][-1],
                f"-artifact_prefix={(artifacts_dir / 'fuzz_bytecode_decoder').resolve().as_posix()}/",
            )
