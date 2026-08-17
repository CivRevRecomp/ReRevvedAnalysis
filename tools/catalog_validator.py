#!/usr/bin/env python3
"""Validate canonical catalogs and their cross-catalog invariants."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


CATALOG_NAMES = ("symbols", "structs", "vtables", "relations")


class CatalogValidationError(ValueError):
    """Raised when a catalog violates a repository-level invariant."""


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def load_contract(repo: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    schemas = {"common": load_json(repo / "schemas" / "common.schema.json")}
    schemas.update(
        {
            name: load_json(repo / "schemas" / f"{name}.schema.json")
            for name in CATALOG_NAMES
        }
    )
    documents = {
        name: load_json(repo / "manifests" / "catalogs" / f"{name}.json")
        for name in CATALOG_NAMES
    }
    return schemas, documents


def _format_path(parts: list[Any]) -> str:
    return "/".join(str(part) for part in parts) or "<root>"


def _record_entities(record: dict[str, Any]):
    yield record
    for child_name in ("fields", "slots"):
        yield from record.get(child_name, [])


def validate_catalog_documents(
    schemas: dict[str, Any], documents: dict[str, Any]
) -> None:
    expected = set(CATALOG_NAMES)
    if set(schemas) != expected | {"common"} or set(documents) != expected:
        raise CatalogValidationError(
            "the four canonical catalogs and common schema are required"
        )

    common_schema = schemas["common"]
    Draft202012Validator.check_schema(common_schema)
    registry = Registry().with_resource(
        common_schema["$id"], Resource.from_contents(common_schema)
    )

    for name in CATALOG_NAMES:
        schema = schemas[name]
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema, registry=registry).iter_errors(
                documents[name]
            ),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            error = errors[0]
            raise CatalogValidationError(
                f"{name}:{_format_path(list(error.absolute_path))}: {error.message}"
            )

    entities: dict[str, str] = {}
    for catalog_name in CATALOG_NAMES:
        for record_index, record in enumerate(documents[catalog_name]["records"]):
            for entity in _record_entities(record):
                entity_id = entity["id"]
                location = f"{catalog_name}/records/{record_index}"
                if entity_id in entities:
                    raise CatalogValidationError(
                        f"duplicate ID {entity_id}: {entities[entity_id]} and {location}"
                    )
                entities[entity_id] = location

    endpoint_ids = {
        entity_id for entity_id in entities if not entity_id.startswith("RVA-REL-")
    }
    for relation in documents["relations"]["records"]:
        for endpoint_name in ("from", "to"):
            endpoint = relation[endpoint_name]
            if endpoint not in endpoint_ids:
                raise CatalogValidationError(
                    f"relation {relation['id']} has unknown {endpoint_name} endpoint "
                    f"{endpoint}"
                )

    for vtable in documents["vtables"]["records"]:
        for slot in vtable["slots"]:
            if slot["target"] not in endpoint_ids:
                raise CatalogValidationError(
                    f"vtable slot {slot['id']} has unknown target {slot['target']}"
                )


def _resolve_json_pointer(document: Any, pointer: str) -> Any:
    if not isinstance(pointer, str):
        raise CatalogValidationError(f"evidence JSON pointer is not a string: {pointer}")
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise CatalogValidationError(f"evidence JSON pointer must start with /: {pointer}")
    current = document
    for encoded_part in pointer[1:].split("/"):
        if re.search(r"~(?![01])", encoded_part):
            raise CatalogValidationError(
                f"evidence JSON pointer has invalid escape: {pointer}"
            )
        part = encoded_part.replace("~1", "/").replace("~0", "~")
        try:
            if isinstance(current, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", part):
                    raise ValueError(part)
                index = int(part)
                current = current[index]
            elif isinstance(current, dict):
                current = current[part]
            else:
                raise TypeError(type(current).__name__)
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise CatalogValidationError(
                f"evidence JSON pointer does not resolve: {pointer}"
            ) from exc
    return current


def validate_local_references(repo: Path, documents: dict[str, Any]) -> None:
    repo = repo.resolve()
    catalog_dir = repo / "manifests" / "catalogs"
    manifests_dir = (repo / "manifests").resolve()
    image_file = repo / "manifests" / "image.json"
    contract_image_path = image_file.resolve()
    if (
        not image_file.is_file()
        or contract_image_path != image_file
        or contract_image_path.parent != manifests_dir
    ):
        raise CatalogValidationError(
            "image contract must be a local regular file: image.json"
        )

    for catalog_name in CATALOG_NAMES:
        for record in documents[catalog_name]["records"]:
            try:
                image_reference = Path(record["image"])
                record_image_path = (catalog_dir / image_reference).resolve()
            except (TypeError, ValueError, OSError) as exc:
                raise CatalogValidationError(
                    f"{record['id']} does not reference a declared image contract"
                ) from exc
            if (
                image_reference.as_posix() != "../image.json"
                or record_image_path != contract_image_path
            ):
                raise CatalogValidationError(
                    f"{record['id']} does not reference manifests/image.json"
                )
            for entity in _record_entities(record):
                for evidence in entity.get("evidence", []):
                    if evidence["kind"] != "topic-manifest":
                        continue
                    try:
                        relative_path, pointer = evidence["locator"].split("#", 1)
                    except (AttributeError, TypeError, ValueError) as exc:
                        raise CatalogValidationError(
                            f"topic-manifest evidence has no JSON pointer: "
                            f"{evidence['locator']}"
                        ) from exc
                    relative_parts = relative_path.replace("\\", "/").split("/")
                    if len(relative_parts) != 2 or relative_parts[0] != "..":
                        raise CatalogValidationError(
                            f"topic-manifest evidence leaves manifests/: {relative_path}"
                        )
                    evidence_path = (catalog_dir / relative_path).resolve()
                    if (
                        evidence_path.parent != manifests_dir
                        or not evidence_path.is_relative_to(manifests_dir)
                    ):
                        raise CatalogValidationError(
                            f"topic-manifest evidence leaves manifests/: {relative_path}"
                        )
                    if not evidence_path.is_file():
                        raise CatalogValidationError(
                            f"topic-manifest evidence is missing: {relative_path}"
                        )
                    _resolve_json_pointer(load_json(evidence_path), pointer)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()

    try:
        schemas, documents = load_contract(repo)
        validate_catalog_documents(schemas, documents)
        validate_local_references(repo, documents)
    except (CatalogValidationError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    entity_count = sum(
        1
        for name in CATALOG_NAMES
        for record in documents[name]["records"]
        for _entity in _record_entities(record)
    )
    print(f"Validated 4 catalog schemas and {entity_count} catalog entities.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
