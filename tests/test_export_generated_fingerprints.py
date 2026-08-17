from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "export-generated-fingerprints.py"
SPEC = importlib.util.spec_from_file_location("export_generated_fingerprints", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ExportGeneratedFingerprintsTests(unittest.TestCase):
    def write_chunk(self, root: Path, index: int, text: str) -> None:
        (root / f"sample_recomp.{index}.cpp").write_text(text, encoding="utf-8")

    def test_export_is_address_sorted_and_normalizes_branch_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_chunk(
                root,
                1,
                "DEFINE_REX_FUNC(sub_82000010) {\n"
                "  // bl 0x82100000\n"
                "  // addi r3,r3,4\n"
                "}\n",
            )
            self.write_chunk(
                root,
                0,
                "DEFINE_REX_FUNC(sub_82000000) {\n"
                "  // bl 0x82200000\n"
                "  // addi r3,r3,4\n"
                "}\n",
            )
            output = root / "fingerprints.jsonl"
            self.assertEqual(MODULE.export(root, "sample", output), 2)
            records = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(records[0]["functionCount"], 2)
            self.assertEqual(
                records[0]["fingerprintAlgorithm"], "rexglue-comment-v1"
            )
            self.assertEqual(
                [record["address"] for record in records[1:]],
                ["0x82000000", "0x82000010"],
            )
            self.assertNotEqual(records[1]["exactHash"], records[2]["exactHash"])
            self.assertEqual(records[1]["shapeHash"], records[2]["shapeHash"])
            self.assertEqual(records[1]["directCallCount"], 1)

    def test_duplicate_addresses_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            function = "DEFINE_REX_FUNC(sub_82000000) {\n  // blr\n}\n"
            self.write_chunk(root, 0, function)
            self.write_chunk(root, 1, function)
            with self.assertRaisesRegex(ValueError, "duplicate function addresses"):
                MODULE.parse_chunks(root, "sample")

    def test_computed_call_is_not_counted_as_direct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_chunk(
                root,
                0,
                "DEFINE_REX_FUNC(sub_82000000) {\n"
                "  // bctrl\n"
                "  // bl 0x82100000\n"
                "}\n",
            )
            records = MODULE.parse_chunks(root, "sample")
            self.assertEqual(records[0]["directCallCount"], 1)

    def test_missing_chunks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "no generated chunks"):
                MODULE.parse_chunks(Path(temporary), "sample")


if __name__ == "__main__":
    unittest.main()
