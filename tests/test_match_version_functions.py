from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
MODULE_PATH = TOOLS / "match-version-functions.py"
SPEC = importlib.util.spec_from_file_location("match_version_functions", MODULE_PATH)
assert SPEC and SPEC.loader
matcher = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = matcher
SPEC.loader.exec_module(matcher)


def function(
    address: str,
    *,
    exact: str = "exact",
    shape: str = "shape",
    mnemonic: str = "mnemonic",
    size: int = 100,
    instructions: int = 10,
    calls: int = 2,
    anchors: list[str] | None = None,
    name: str | None = None,
) -> dict:
    return {
        "recordType": "function",
        "address": address,
        "minAddress": address,
        "maxAddress": address,
        "name": name or f"fn_{address}",
        "bodySize": size,
        "instructionCount": instructions,
        "exactHash": exact,
        "shapeHash": shape,
        "mnemonicHash": mnemonic,
        "directCallCount": calls,
        "stringAnchors": anchors or [],
    }


def program(label: str, function_count: int = 1) -> dict:
    return {
        "recordType": "program",
        "image": label,
        "language": "PowerPC:BE:32:XBOX",
        "source": "test-exporter",
        "fingerprintAlgorithm": "test-v1",
        "functionCount": function_count,
    }


def report(source: list[dict], target: list[dict]) -> dict:
    return matcher.match_functions(
        program("source", len(source)), source, program("target", len(target)), target
    )


class MatcherTests(unittest.TestCase):
    def test_exact_match_is_preferred(self) -> None:
        result = report(
            [function("0x100", exact="same", shape="source-shape")],
            [function("0x200", exact="same", shape="target-shape")],
        )
        item = result["matches"][0]
        self.assertEqual(item["status"], "exact")
        self.assertEqual(item["confidence"], "exact")
        self.assertEqual(item["candidateAddress"], "0x200")
        self.assertEqual(result["summary"]["exact"], 1)

    def test_unique_shape_and_instruction_count_is_strong(self) -> None:
        result = report(
            [function("0x100", exact="source-exact", shape="same")],
            [function("0x200", exact="target-exact", shape="same", instructions=10)],
        )
        item = result["matches"][0]
        self.assertEqual(item["status"], "strong")
        self.assertEqual(item["candidateTarget"], "0x200")

    def test_shared_anchor_yields_bounded_candidate(self) -> None:
        source = function(
            "0x100",
            exact="source-exact",
            shape="source-shape",
            mnemonic="source-mnemonic",
            anchors=["TXT_HELLO"],
        )
        target = function(
            "0x200",
            exact="target-exact",
            shape="target-shape",
            mnemonic="target-mnemonic",
            anchors=["TXT_HELLO"],
        )
        item = report([source], [target])["matches"][0]
        self.assertEqual(item["status"], "candidate")
        self.assertIn("shared string anchor", " ".join(item["reasons"]))

    def test_heuristic_scores_only_indexed_bounded_candidates(self) -> None:
        source = function(
            "0x100",
            exact="source-exact",
            shape="source-shape",
            mnemonic="source-mnemonic",
            anchors=["needle"],
        )
        indexed = function(
            "0x200",
            exact="indexed-exact",
            shape="indexed-shape",
            mnemonic="other-mnemonic",
            anchors=["needle"],
        )
        unrelated = [
            function(
                f"0x{index + 0x300:X}",
                exact=f"unrelated-{index}",
                shape=f"unrelated-shape-{index}",
                mnemonic=f"unrelated-mnemonic-{index}",
                anchors=[f"other-{index}"],
            )
            for index in range(1000)
        ]
        scored: list[str] = []
        original = matcher._heuristic_score

        def counting_score(source_record: dict, target_record: dict):
            scored.append(target_record["address"])
            return original(source_record, target_record)

        matcher._heuristic_score = counting_score
        try:
            item = report([source], [*unrelated, indexed])["matches"][0]
        finally:
            matcher._heuristic_score = original
        self.assertEqual(item["status"], "candidate")
        self.assertEqual(scored, ["0x200"])

    def test_common_mnemonic_bucket_is_capped_without_scoring(self) -> None:
        source = function(
            "0x100",
            exact="source-exact",
            shape="source-shape",
            mnemonic="common-mnemonic",
        )
        targets = [
            function(
                f"0x{index + 0x200:X}",
                exact=f"target-{index}",
                shape=f"target-shape-{index}",
                mnemonic="common-mnemonic",
            )
            for index in range(1000)
        ]
        scored: list[str] = []
        original = matcher._heuristic_score

        def counting_score(source_record: dict, target_record: dict):
            scored.append(target_record["address"])
            return original(source_record, target_record)

        matcher._heuristic_score = counting_score
        try:
            item = report([source], targets)["matches"][0]
        finally:
            matcher._heuristic_score = original
        self.assertEqual(item["status"], "ambiguous")
        self.assertEqual(item["candidateAddress"], None)
        self.assertEqual(
            len(item["ambiguity"]), matcher.MAX_HEURISTIC_CANDIDATES
        )
        self.assertIn("exceeds cap", " ".join(item["reasons"]))
        self.assertEqual(scored, [])

    def test_equal_heuristic_scores_are_rejected_as_ambiguous(self) -> None:
        source = function(
            "0x100", exact="source", shape="source", mnemonic="source", anchors=["A"]
        )
        targets = [
            function("0x200", exact="target-a", shape="target-a", mnemonic="other", anchors=["A"]),
            function("0x300", exact="target-b", shape="target-b", mnemonic="other", anchors=["A"]),
        ]
        item = report([source], targets)["matches"][0]
        self.assertEqual(item["status"], "ambiguous")
        self.assertIsNone(item["candidateAddress"])
        self.assertEqual(item["ambiguity"], ["0x200", "0x300"])

    def test_many_sources_cannot_claim_one_target(self) -> None:
        sources = [
            function("0x100", exact="same", shape="source-a"),
            function("0x110", exact="same", shape="source-b"),
        ]
        target = function("0x200", exact="same", shape="target")
        result = report(sources, [target])
        self.assertEqual(result["summary"]["exact"], 0)
        self.assertEqual(result["summary"]["ambiguous"], 2)
        for item in result["matches"]:
            self.assertEqual(item["status"], "ambiguous")
            self.assertIsNone(item["candidateAddress"])
            self.assertEqual(item["ambiguity"], ["0x200"])

    def test_incompatible_fingerprint_algorithms_are_rejected(self) -> None:
        source_metadata = program("source")
        target_metadata = program("target")
        target_metadata["fingerprintAlgorithm"] = "other-v1"
        with self.assertRaisesRegex(matcher.InputFormatError, "incompatible exports"):
            matcher.match_functions(
                source_metadata,
                [function("0x100")],
                target_metadata,
                [function("0x200")],
            )

    def test_malformed_and_duplicate_records_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            malformed = function("0x100")
            del malformed["shapeHash"]
            path.write_text(json.dumps(program("bad")) + "\n" + json.dumps(malformed) + "\n")
            with self.assertRaises(matcher.InputFormatError):
                matcher.load_export(path)

            count_mismatch = function("0x100")
            path.write_text(
                json.dumps(program("bad", 2))
                + "\n"
                + json.dumps(count_mismatch)
                + "\n"
            )
            with self.assertRaisesRegex(matcher.InputFormatError, "functionCount"):
                matcher.load_export(path)

            duplicate = function("0x100")
            path.write_text(
                "\n".join(
                    [json.dumps(program("bad")), json.dumps(duplicate), json.dumps(duplicate)]
                )
                + "\n"
            )
            with self.assertRaisesRegex(matcher.InputFormatError, "duplicate function address"):
                matcher.load_export(path)

    def test_results_and_json_are_deterministically_ordered(self) -> None:
        source = [
            function("0x300", exact="three", name="third"),
            function("0x100", exact="one", name="first"),
            function("0x200", exact="two", name="second"),
        ]
        target = [
            function("0x900", exact="two"),
            function("0x800", exact="one"),
            function("0xA00", exact="three"),
        ]
        first = report(source, target)
        second = report(list(reversed(source)), list(reversed(target)))
        self.assertEqual(first, second)
        self.assertEqual(
            [item["sourceAddress"] for item in first["matches"]],
            ["0x100", "0x200", "0x300"],
        )

    def test_cli_help_documents_inputs_and_confidence(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--help"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("--source", completed.stdout)
        self.assertIn("--target", completed.stdout)
        self.assertIn("--out", completed.stdout)
        self.assertIn("Confidence semantics", completed.stdout)


if __name__ == "__main__":
    unittest.main()
