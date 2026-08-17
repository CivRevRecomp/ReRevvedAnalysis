from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from catalog_validator import (  # noqa: E402
    CatalogValidationError,
    load_contract,
    validate_catalog_documents,
    validate_local_references,
)


def evidence() -> list[dict[str, str]]:
    return [{"kind": "generated-code", "locator": "generated:test-fixture"}]


def qualification() -> dict[str, str]:
    return {"falsificationCondition": "The fixture is intentionally invalidated."}


def sample_documents() -> dict[str, dict]:
    return {
        "symbols": {
            "schemaVersion": 1,
            "catalog": "symbols",
            "records": [
                {
                    "id": "RVA-SYM-9001",
                    "name": "fixture_function",
                    "kind": "function",
                    "address": "0x82000000",
                    "image": "../image.json",
                    "claim": "Validator fixture symbol.",
                    "confidence": "candidate",
                    "evidence": evidence(),
                    "qualification": qualification(),
                },
                {
                    "id": "RVA-SYM-9002",
                    "name": "fixture_target",
                    "kind": "function",
                    "address": "0x82000004",
                    "image": "../image.json",
                    "claim": "Validator fixture target.",
                    "confidence": "candidate",
                    "evidence": evidence(),
                    "qualification": qualification(),
                },
            ],
        },
        "structs": {
            "schemaVersion": 1,
            "catalog": "structs",
            "records": [
                {
                    "id": "RVA-STR-9001",
                    "name": "fixture_struct",
                    "image": "../image.json",
                    "claim": "Validator fixture structure.",
                    "confidence": "candidate",
                    "evidence": evidence(),
                    "qualification": qualification(),
                    "fields": [
                        {
                            "id": "RVA-FLD-9001",
                            "name": "fixture_field",
                            "offset": "0x0",
                            "claim": "Validator fixture field.",
                            "confidence": "candidate",
                            "evidence": evidence(),
                            "qualification": qualification(),
                        }
                    ],
                }
            ],
        },
        "vtables": {
            "schemaVersion": 1,
            "catalog": "vtables",
            "records": [
                {
                    "id": "RVA-VTBL-9001",
                    "name": "fixture_vtable",
                    "address": "0x82000008",
                    "image": "../image.json",
                    "claim": "Validator fixture vtable.",
                    "confidence": "candidate",
                    "evidence": evidence(),
                    "qualification": qualification(),
                    "slots": [
                        {
                            "id": "RVA-SLOT-9001",
                            "offset": "0x0",
                            "target": "RVA-SYM-9002",
                            "claim": "Validator fixture slot.",
                            "confidence": "candidate",
                            "evidence": evidence(),
                            "qualification": qualification(),
                        }
                    ],
                }
            ],
        },
        "relations": {
            "schemaVersion": 1,
            "catalog": "relations",
            "records": [
                {
                    "id": "RVA-REL-9001",
                    "kind": "reads-field",
                    "from": "RVA-SYM-9001",
                    "to": "RVA-FLD-9001",
                    "image": "../image.json",
                    "claim": "Validator fixture relation.",
                    "confidence": "candidate",
                    "evidence": evidence(),
                    "qualification": qualification(),
                }
            ],
        },
    }


class CatalogValidatorNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas, cls.repository_documents = load_contract(REPO)
        cls.documents = sample_documents()

    def reject(self, mutate, expected_message: str):
        documents = copy.deepcopy(self.documents)
        mutate(documents)
        with self.assertRaisesRegex(CatalogValidationError, expected_message):
            validate_catalog_documents(self.schemas, documents)

    def reject_local(self, mutate, expected_message: str):
        documents = copy.deepcopy(self.documents)
        mutate(documents)
        with self.assertRaisesRegex(CatalogValidationError, expected_message):
            validate_local_references(REPO, documents)

    def test_repository_catalogs_are_valid(self):
        validate_catalog_documents(self.schemas, self.repository_documents)
        validate_local_references(REPO, self.repository_documents)

    def test_fixture_is_valid(self):
        validate_catalog_documents(self.schemas, self.documents)
        validate_local_references(REPO, self.documents)

    def test_rejects_malformed_address(self):
        self.reject(
            lambda docs: docs["symbols"]["records"][0].update(
                address="0x8200000a"
            ),
            "does not match",
        )

    def test_rejects_missing_evidence(self):
        self.reject(
            lambda docs: docs["symbols"]["records"][0].pop("evidence"),
            "'evidence' is a required property",
        )

    def test_rejects_duplicate_ids(self):
        def duplicate(docs):
            docs["symbols"]["records"].append(
                copy.deepcopy(docs["symbols"]["records"][0])
            )

        self.reject(duplicate, "duplicate ID RVA-SYM-9001")

    def test_rejects_unknown_confidence(self):
        self.reject(
            lambda docs: docs["symbols"]["records"][0].update(
                confidence="probable"
            ),
            "is not one of",
        )

    def test_rejects_invalid_relation_endpoint(self):
        self.reject(
            lambda docs: docs["relations"]["records"][0].update(
                to="RVA-FLD-9999"
            ),
            "unknown to endpoint RVA-FLD-9999",
        )

    def test_rejects_invalid_vtable_slot_target(self):
        self.reject(
            lambda docs: docs["vtables"]["records"][0]["slots"][0].update(
                target="RVA-SYM-9999"
            ),
            "unknown target RVA-SYM-9999",
        )

    def test_rejects_image_path_escape(self):
        self.reject_local(
            lambda docs: docs["symbols"]["records"][0].update(
                image="../../manifests/image.json"
            ),
            "does not reference manifests/image.json",
        )

    def test_rejects_symlinked_image_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            manifests = repo / "manifests"
            (manifests / "catalogs").mkdir(parents=True)
            try:
                (manifests / "image.json").symlink_to(
                    REPO / "manifests" / "image.json"
                )
            except OSError as exc:
                self.skipTest(f"file symlinks unavailable: {exc}")
            with self.assertRaisesRegex(
                CatalogValidationError, "must be a local regular file"
            ):
                validate_local_references(repo, copy.deepcopy(self.documents))

    def test_rejects_topic_manifest_path_escape(self):
        self.reject_local(
            lambda docs: docs["symbols"]["records"][0].update(
                evidence=[
                    {
                        "kind": "topic-manifest",
                        "locator": "../../README.md#/title",
                    }
                ]
            ),
            "leaves manifests",
        )

    def test_rejects_missing_topic_manifest(self):
        self.reject_local(
            lambda docs: docs["symbols"]["records"][0].update(
                evidence=[
                    {
                        "kind": "topic-manifest",
                        "locator": "../missing-topic.json#/title",
                    }
                ]
            ),
            "evidence is missing",
        )

    def test_rejects_unresolved_json_pointer(self):
        self.reject_local(
            lambda docs: docs["symbols"]["records"][0].update(
                evidence=[
                    {
                        "kind": "topic-manifest",
                        "locator": "../runtime-baseline.json#/doesNotExist",
                    }
                ]
            ),
            "JSON pointer does not resolve",
        )


if __name__ == "__main__":
    unittest.main()
