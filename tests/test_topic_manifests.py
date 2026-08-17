from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
MANIFESTS = REPO / "manifests"
ID_RE = re.compile(r"^RVA-F-[0-9]{4}$")
TOPIC_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FORBIDDEN_HISTORY_KEYS = {"commit", "migration", "relocation", "sourceEvidence"}
FORBIDDEN_CURRENT_EVIDENCE_KEYS = {
    "pairs",
    "source",
    "sourceAddress",
    "sourceInstructionCount",
    "sourceVtable",
    "target",
    "targetAddress",
    "targetInstructionCount",
    "targetVtable",
}


class TopicManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.documents = []
        for path in sorted(MANIFESTS.glob("*.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            if "topic" in document:
                cls.documents.append((path, document))

    def test_common_contract_and_unique_identity(self) -> None:
        ids: set[str] = set()
        topics: set[str] = set()
        for path, document in self.documents:
            self.assertEqual(document.get("schemaVersion"), 1, path.name)
            self.assertRegex(document.get("id", ""), ID_RE, path.name)
            self.assertRegex(document.get("topic", ""), TOPIC_RE, path.name)
            self.assertEqual(path.stem, document["topic"], path.name)
            self.assertEqual(document.get("image"), "image.json", path.name)
            self.assertIn(document.get("status"), {"open", "closed"}, path.name)
            self.assertIn(
                document.get("confidence"),
                {"confirmed", "strong", "candidate", "rejected"},
                path.name,
            )
            self.assertNotIn(document["id"], ids, path.name)
            self.assertNotIn(document["topic"], topics, path.name)
            ids.add(document["id"])
            topics.add(document["topic"])

    def test_current_dependencies_resolve_in_checkout(self) -> None:
        for path, document in self.documents:
            for dependency in document.get("dependencies", []):
                topic = dependency.get("topic", "")
                self.assertRegex(topic, TOPIC_RE, path.name)
                dependency_path = MANIFESTS / f"{topic}.json"
                self.assertTrue(dependency_path.is_file(), dependency_path.name)
                dependency_document = json.loads(
                    dependency_path.read_text(encoding="utf-8")
                )
                self.assertEqual(dependency_document.get("topic"), topic, path.name)

    def test_current_evidence_has_no_history_dependency(self) -> None:
        def visit(value: object, path: Path) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    self.assertNotIn(key, FORBIDDEN_HISTORY_KEYS, path.name)
                    visit(child, path)
            elif isinstance(value, list):
                for child in value:
                    visit(child, path)

        for path, document in self.documents:
            visit(document, path)

            current_evidence = document.get("currentEvidence", {})
            for key in current_evidence:
                self.assertNotIn(key, FORBIDDEN_CURRENT_EVIDENCE_KEYS, path.name)


if __name__ == "__main__":
    unittest.main()
