from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO / "tools" / "reference_data.py"
SPEC = importlib.util.spec_from_file_location("reference_data", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
reference_data = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reference_data
SPEC.loader.exec_module(reference_data)


class ReferenceDataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        (self.repo / "data").mkdir()
        (self.repo / "manifests").mkdir()
        (self.repo / "docs" / "reference").mkdir(parents=True)
        for relative in (
            "data/civilizations.csv",
            "data/era-bonus-definitions.csv",
            "manifests/civilization-bonus-storage.json",
            "docs/reference/civilization-bonuses.md",
        ):
            source = REPO / relative
            destination = self.repo / relative
            shutil.copyfile(source, destination)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _replace(self, relative: str, old: str, new: str) -> None:
        path = self.repo / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def test_repository_data_and_markdown_are_synchronized(self) -> None:
        data = reference_data.check_repository(REPO)
        self.assertEqual(len(data.civilizations), 16)
        self.assertEqual(len(data.bonus_effects), 45)

    def test_duplicate_civilization_id_is_rejected(self) -> None:
        self._replace(
            "data/civilizations.csv",
            "1,Egyptian,Egyptian",
            "0,Egyptian,Egyptian",
        )
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "unique and ordered"
        ):
            reference_data.load_reference_data(self.repo)

    def test_populated_starting_bonus_id_is_rejected(self) -> None:
        self._replace(
            "data/civilizations.csv",
            "Julius Caesar,,Code of Laws",
            "Julius Caesar,99,Code of Laws",
        )
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "starting_bonus_id must remain blank"
        ):
            reference_data.load_reference_data(self.repo)

    def test_malformed_csv_is_rejected(self) -> None:
        self._replace(
            "data/civilizations.csv",
            "0,Roman,Roman,Julius Caesar",
            '0,"Roman,Roman,Julius Caesar',
        )
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "malformed CSV"
        ):
            reference_data.load_reference_data(self.repo)

    def test_generated_marker_in_csv_is_rejected(self) -> None:
        self._replace(
            "data/civilizations.csv",
            "An Ancient Wonder",
            reference_data.BONUS_TABLE_END,
        )
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "contains a generated marker"
        ):
            reference_data.write_repository(self.repo)

    def test_conflicting_duplicate_bonus_definition_is_rejected(self) -> None:
        path = self.repo / "data" / "era-bonus-definitions.csv"
        with path.open("a", encoding="utf-8", newline="") as stream:
            stream.write("1,Conflicting road effect\n")
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "duplicate bonus_id 1"
        ):
            reference_data.load_reference_data(self.repo)

    def test_missing_assigned_bonus_definition_is_rejected(self) -> None:
        self._replace(
            "data/era-bonus-definitions.csv",
            "61,Longbow Archers gain +1 defense\n",
            "",
        )
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "missing assigned IDs 61"
        ):
            reference_data.load_reference_data(self.repo)

    def test_unused_bonus_definition_is_rejected(self) -> None:
        path = self.repo / "data" / "era-bonus-definitions.csv"
        with path.open("a", encoding="utf-8", newline="") as stream:
            stream.write("62,Unused effect\n")
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "unused IDs 62"
        ):
            reference_data.load_reference_data(self.repo)

    def test_manifest_name_disagreement_is_rejected(self) -> None:
        path = self.repo / "manifests" / "civilization-bonus-storage.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["storage"]["rows"][13]["name"] = "Zulu"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "internal name.*disagrees"
        ):
            reference_data.load_reference_data(self.repo)

    def test_manifest_shape_disagreement_is_rejected(self) -> None:
        path = self.repo / "manifests" / "civilization-bonus-storage.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["storage"]["shape"]["civilizations"] = 15
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "unexpected storage.shape"
        ):
            reference_data.load_reference_data(self.repo)

    def test_manifest_rows_must_be_a_list(self) -> None:
        path = self.repo / "manifests" / "civilization-bonus-storage.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["storage"]["rows"] = {}
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "storage.rows must be a list"
        ):
            reference_data.load_reference_data(self.repo)

    def test_manifest_boolean_index_is_rejected(self) -> None:
        path = self.repo / "manifests" / "civilization-bonus-storage.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["storage"]["rows"][0]["index"] = False
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "invalid row index"
        ):
            reference_data.load_reference_data(self.repo)

    def test_manifest_boolean_bonus_id_is_rejected(self) -> None:
        path = self.repo / "manifests" / "civilization-bonus-storage.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["storage"]["rows"][0]["bonuses"][0] = True
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "four positive bonus IDs"
        ):
            reference_data.load_reference_data(self.repo)

    def test_markdown_drift_is_rejected(self) -> None:
        self._replace(
            "docs/reference/civilization-bonuses.md",
            "Factories provide triple Production",
            "Factories provide quadruple Production",
        )
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "rendered tables are stale"
        ):
            reference_data.check_repository(self.repo)

    def test_crossed_generated_markers_are_rejected(self) -> None:
        path = self.repo / "docs" / "reference" / "civilization-bonuses.md"
        text = path.read_text(encoding="utf-8")
        begin = reference_data.BONUS_TABLE_BEGIN
        end = reference_data.BONUS_TABLE_END
        text = text.replace(begin, "MARKER_PLACEHOLDER", 1)
        text = text.replace(end, begin, 1)
        text = text.replace("MARKER_PLACEHOLDER", end, 1)
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(
            reference_data.ReferenceDataError, "crossed generated markers"
        ):
            reference_data.check_repository(self.repo)


if __name__ == "__main__":
    unittest.main()
