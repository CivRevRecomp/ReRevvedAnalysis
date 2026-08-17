#!/usr/bin/env python3
"""Match compatible function-fingerprint exports from two program versions.

The matcher deliberately works on JSONL rather than a Ghidra project so that a
comparison can be repeated offline and reviewed as a small deterministic JSON
artifact.  A JSONL export contains one ``recordType=program`` record followed
by ``recordType=function`` records.
"""

from __future__ import annotations

import argparse
import json
import sys
from itertools import chain, islice
from pathlib import Path
from typing import Any, Iterable


FUNCTION_FIELDS = (
    "address",
    "minAddress",
    "maxAddress",
    "name",
    "bodySize",
    "instructionCount",
    "exactHash",
    "shapeHash",
    "mnemonicHash",
    "directCallCount",
    "stringAnchors",
)
PROGRAM_FIELDS = ("source", "fingerprintAlgorithm")
NUMERIC_FIELDS = ("bodySize", "instructionCount", "directCallCount")
HASH_FIELDS = ("exactHash", "shapeHash", "mnemonicHash")
# Heuristic matching never scores or reports more than this many candidates.
MAX_HEURISTIC_CANDIDATES = 256


class InputFormatError(ValueError):
    """Raised when an export is not a valid program/function JSONL stream."""


def _json_line(path: Path, line_number: int, line: str) -> dict[str, Any]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise InputFormatError(f"{path}:{line_number}: invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise InputFormatError(f"{path}:{line_number}: record must be an object")
    return value


def _validate_function(record: dict[str, Any], path: Path, line_number: int) -> None:
    missing = [field for field in FUNCTION_FIELDS if field not in record]
    if missing:
        raise InputFormatError(
            f"{path}:{line_number}: function record missing {', '.join(missing)}"
        )
    for field in NUMERIC_FIELDS:
        value = record[field]
        if isinstance(value, bool) or not isinstance(value, int):
            raise InputFormatError(
                f"{path}:{line_number}: {field} must be a non-negative integer"
            )
        if value < 0:
            raise InputFormatError(
                f"{path}:{line_number}: {field} must be non-negative"
            )
    for field in ("address", "minAddress", "maxAddress", "name") + HASH_FIELDS:
        if not isinstance(record[field], str) or not record[field]:
            raise InputFormatError(
                f"{path}:{line_number}: {field} must be a non-empty string"
            )
    anchors = record["stringAnchors"]
    if not isinstance(anchors, list) or any(
        not isinstance(anchor, str) for anchor in anchors
    ):
        raise InputFormatError(
            f"{path}:{line_number}: stringAnchors must be a list of strings"
        )


def _validate_program(record: dict[str, Any], path: Path, line_number: int) -> None:
    for field in PROGRAM_FIELDS:
        if not isinstance(record.get(field), str) or not record[field]:
            raise InputFormatError(
                f"{path}:{line_number}: program {field} must be a non-empty string"
            )
    function_count = record.get("functionCount")
    if (
        isinstance(function_count, bool)
        or not isinstance(function_count, int)
        or function_count < 0
    ):
        raise InputFormatError(
            f"{path}:{line_number}: program functionCount must be a non-negative integer"
        )


def load_export(path: Path | str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load and validate one JSONL export, returning metadata and functions."""

    path = Path(path)
    metadata: dict[str, Any] | None = None
    functions: list[dict[str, Any]] = []
    addresses: set[str] = set()
    try:
        stream = path.open(encoding="utf-8")
    except OSError as exc:
        raise InputFormatError(f"{path}: cannot read export: {exc}") from exc
    with stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            record = _json_line(path, line_number, line)
            record_type = record.get("recordType")
            if record_type == "program":
                if metadata is not None:
                    raise InputFormatError(
                        f"{path}:{line_number}: duplicate program record"
                    )
                _validate_program(record, path, line_number)
                metadata = record
            elif record_type == "function":
                _validate_function(record, path, line_number)
                address = record["address"]
                if address in addresses:
                    raise InputFormatError(
                        f"{path}:{line_number}: duplicate function address {address}"
                    )
                addresses.add(address)
                functions.append(record)
            else:
                raise InputFormatError(
                    f"{path}:{line_number}: recordType must be program or function"
                )
    if metadata is None:
        raise InputFormatError(f"{path}: missing program record")
    if metadata["functionCount"] != len(functions):
        raise InputFormatError(
            f"{path}: functionCount declares {metadata['functionCount']} but "
            f"the export contains {len(functions)} function records"
        )
    functions.sort(key=_function_sort_key)
    return metadata, functions


def _address_key(address: str) -> tuple[int, str]:
    try:
        return int(address, 0), address
    except (TypeError, ValueError):
        return (sys.maxsize, str(address))


def _function_sort_key(function: dict[str, Any]) -> tuple[Any, ...]:
    return (*_address_key(function["address"]), function["name"])


def _relative_similarity(left: float, right: float) -> float:
    denominator = max(abs(left), abs(right), 1.0)
    return max(0.0, 1.0 - abs(left - right) / denominator)


def _anchor_overlap(source: dict[str, Any], target: dict[str, Any]) -> int:
    return len(set(source["stringAnchors"]) & set(target["stringAnchors"]))


def _heuristic_score(
    source: dict[str, Any], target: dict[str, Any]
) -> tuple[float, list[str]]:
    """Return a heuristic score and human-readable reasons."""

    score = 0.0
    reasons: list[str] = []
    if source["mnemonicHash"] == target["mnemonicHash"]:
        score += 50.0
        reasons.append("matching mnemonicHash")

    body_similarity = _relative_similarity(source["bodySize"], target["bodySize"])
    instruction_similarity = _relative_similarity(
        source["instructionCount"], target["instructionCount"]
    )
    call_similarity = _relative_similarity(
        source["directCallCount"], target["directCallCount"]
    )
    score += 20.0 * body_similarity
    score += 20.0 * instruction_similarity
    score += 10.0 * call_similarity
    if body_similarity >= 0.8 and instruction_similarity >= 0.8:
        reasons.append("bodySize/instructionCount within 20%")
    if body_similarity == 1.0:
        reasons.append("matching bodySize")
    if instruction_similarity == 1.0:
        reasons.append("matching instructionCount")
    if call_similarity == 1.0:
        reasons.append("matching directCallCount")

    shared_anchors = _anchor_overlap(source, target)
    if shared_anchors:
        score += min(shared_anchors, 3) * (10.0 / 3.0)
        reasons.append(f"{shared_anchors} shared string anchor(s)")

    return round(score, 6), reasons


def _candidate_details(
    source: dict[str, Any], targets: Iterable[dict[str, Any]]
) -> list[tuple[dict[str, Any], float, list[str]]]:
    details: list[tuple[dict[str, Any], float, list[str]]] = []
    for target in targets:
        score, reasons = _heuristic_score(source, target)
        if score >= 45.0:
            details.append((target, score, reasons))
    details.sort(key=lambda item: (-item[1], _address_key(item[0]["address"]), item[0]["name"]))
    return details


def _bounded_candidate_pool(
    source: dict[str, Any],
    mnemonic_index: dict[str, dict[int, list[dict[str, Any]]]],
    mnemonic_totals: dict[str, int],
    anchor_index: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Collect indexed heuristic candidates without scanning an unbounded bucket.

    Exact instruction-count postings are preferred.  Nearby instruction counts
    are included only when the complete mnemonic bucket fits the cap.  Anchor
    postings have the same cap; an oversized posting emits a deterministic
    ambiguity sample and is never scored.
    """

    pool: dict[str, dict[str, Any]] = {}
    overflow: dict[str, dict[str, Any]] = {}
    reasons: list[str] = []

    def add_targets(targets: Iterable[dict[str, Any]]) -> bool:
        for target in targets:
            pool[target["address"]] = target
            if len(pool) > MAX_HEURISTIC_CANDIDATES:
                note_overflow(
                    "combined heuristic candidate pool",
                    sorted(pool.values(), key=_function_sort_key),
                )
                return False
        return True

    def note_overflow(label: str, targets: Iterable[dict[str, Any]]) -> None:
        reasons.append(
            f"{label} exceeds cap {MAX_HEURISTIC_CANDIDATES}; candidates were not scored"
        )
        for target in islice(targets, MAX_HEURISTIC_CANDIDATES):
            overflow[target["address"]] = target

    mnemonic_buckets = mnemonic_index.get(source["mnemonicHash"], {})
    exact_count_targets = mnemonic_buckets.get(
        int(source["instructionCount"]), []
    )
    if len(exact_count_targets) > MAX_HEURISTIC_CANDIDATES:
        note_overflow("mnemonicHash/instructionCount bucket", exact_count_targets)
        addresses = sorted(overflow, key=_address_key)
        return [], addresses, reasons
    elif exact_count_targets:
        if not add_targets(exact_count_targets):
            addresses = sorted(overflow, key=_address_key)
            return [], addresses, reasons
        mnemonic_total = mnemonic_totals.get(source["mnemonicHash"], 0)
        if mnemonic_total <= MAX_HEURISTIC_CANDIDATES:
            if not add_targets(chain.from_iterable(mnemonic_buckets.values())):
                addresses = sorted(overflow, key=_address_key)
                return [], addresses, reasons
    else:
        mnemonic_total = mnemonic_totals.get(source["mnemonicHash"], 0)
        mnemonic_targets = chain.from_iterable(mnemonic_buckets.values())
        if mnemonic_total <= MAX_HEURISTIC_CANDIDATES:
            if not add_targets(mnemonic_targets):
                addresses = sorted(overflow, key=_address_key)
                return [], addresses, reasons
        elif mnemonic_total:
            note_overflow("mnemonicHash bucket", mnemonic_targets)
            addresses = sorted(overflow, key=_address_key)
            return [], addresses, reasons

    for anchor in sorted(set(source["stringAnchors"])):
        targets = anchor_index.get(anchor, [])
        if len(targets) > MAX_HEURISTIC_CANDIDATES:
            note_overflow(f"string anchor bucket {anchor}", targets)
            addresses = sorted(overflow, key=_address_key)
            return [], addresses, reasons
        else:
            if not add_targets(targets):
                addresses = sorted(overflow, key=_address_key)
                return [], addresses, reasons

    if reasons:
        addresses = sorted(
            overflow,
            key=lambda address: _address_key(address),
        )[:MAX_HEURISTIC_CANDIDATES]
        return [], addresses, reasons
    return sorted(pool.values(), key=_function_sort_key), [], []


def _result_base(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "sourceAddress": source["address"],
        "sourceName": source["name"],
        "status": "unmatched",
        "confidence": "none",
        "candidateTarget": None,
        "candidateAddress": None,
        "score": None,
        "reasons": [],
        "ambiguity": [],
    }


def _require_compatible_metadata(
    source_metadata: dict[str, Any], target_metadata: dict[str, Any]
) -> None:
    for field in PROGRAM_FIELDS:
        source_value = source_metadata.get(field)
        target_value = target_metadata.get(field)
        if source_value != target_value:
            raise InputFormatError(
                f"incompatible exports: source {field}={source_value!r}, "
                f"target {field}={target_value!r}"
            )


def _reject_target_collisions(matches: list[dict[str, Any]]) -> None:
    claims: dict[str, list[dict[str, Any]]] = {}
    for match in matches:
        address = match["candidateAddress"]
        if address is not None:
            claims.setdefault(address, []).append(match)
    for target, claimants in claims.items():
        if len(claimants) < 2:
            continue
        for match in claimants:
            match.update(
                status="ambiguous",
                confidence="none",
                candidateTarget=None,
                candidateAddress=None,
                score=None,
                reasons=[
                    *match["reasons"],
                    f"target {target} is claimed by multiple source functions",
                ],
                ambiguity=[target],
            )


def match_functions(
    source_metadata: dict[str, Any],
    source_functions: list[dict[str, Any]],
    target_metadata: dict[str, Any],
    target_functions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Match loaded functions and return the deterministic report document."""

    _require_compatible_metadata(source_metadata, target_metadata)

    exact_index: dict[str, list[dict[str, Any]]] = {}
    shape_index: dict[tuple[str, int], list[dict[str, Any]]] = {}
    mnemonic_index: dict[str, dict[int, list[dict[str, Any]]]] = {}
    anchor_index: dict[str, list[dict[str, Any]]] = {}
    for target in target_functions:
        exact_index.setdefault(target["exactHash"], []).append(target)
        shape_index.setdefault(
            (target["shapeHash"], int(target["instructionCount"])), []
        ).append(target)
        mnemonic_index.setdefault(target["mnemonicHash"], {}).setdefault(
            int(target["instructionCount"]), []
        ).append(target)
        for anchor in set(target["stringAnchors"]):
            anchor_index.setdefault(anchor, []).append(target)
    for buckets in mnemonic_index.values():
        for targets in buckets.values():
            targets.sort(key=_function_sort_key)
    mnemonic_totals = {
        mnemonic_hash: sum(len(targets) for targets in buckets.values())
        for mnemonic_hash, buckets in mnemonic_index.items()
    }
    for targets in anchor_index.values():
        targets.sort(key=_function_sort_key)

    matches: list[dict[str, Any]] = []
    for source in sorted(source_functions, key=_function_sort_key):
        result = _result_base(source)
        exact = exact_index.get(source["exactHash"], [])
        if len(exact) == 1:
            target = exact[0]
            result.update(
                status="exact",
                confidence="exact",
                candidateTarget=target["address"],
                candidateAddress=target["address"],
                score=100.0,
                reasons=["unique exactHash match"],
            )
        else:
            strong = shape_index.get(
                (source["shapeHash"], int(source["instructionCount"])), []
            )
            if len(strong) == 1:
                target = strong[0]
                result.update(
                    status="strong",
                    confidence="strong",
                    candidateTarget=target["address"],
                    candidateAddress=target["address"],
                    score=90.0,
                    reasons=["unique shapeHash + instructionCount match"],
                )
            else:
                bounded_targets, overflow, overflow_reasons = _bounded_candidate_pool(
                    source, mnemonic_index, mnemonic_totals, anchor_index
                )
                details: list[tuple[dict[str, Any], float, list[str]]] = []
                if overflow_reasons:
                    result.update(
                        status="ambiguous",
                        confidence="none",
                        reasons=overflow_reasons,
                        ambiguity=overflow,
                    )
                else:
                    details = _candidate_details(source, bounded_targets)
                if not overflow_reasons and details:
                    best_score = details[0][1]
                    tied = [item for item in details if item[1] == best_score]
                    if len(tied) == 1:
                        target, score, reasons = tied[0]
                        result.update(
                            status="candidate",
                            confidence="candidate",
                            candidateTarget=target["address"],
                            candidateAddress=target["address"],
                            score=score,
                            reasons=reasons,
                        )
                    else:
                        result.update(
                            status="ambiguous",
                            confidence="none",
                            score=best_score,
                            reasons=["multiple equally scored bounded candidates"],
                            ambiguity=[item[0]["address"] for item in tied],
                        )
        matches.append(result)

    _reject_target_collisions(matches)
    counts = {"exact": 0, "strong": 0, "candidate": 0, "ambiguous": 0, "unmatched": 0}
    for match in matches:
        counts[match["status"]] += 1

    return {
        "schemaVersion": 1,
        "source": source_metadata,
        "target": target_metadata,
        "summary": {
            "sourceFunctions": len(source_functions),
            "targetFunctions": len(target_functions),
            "exact": counts["exact"],
            "strong": counts["strong"],
            "candidate": counts["candidate"],
            "ambiguous": counts["ambiguous"],
            "unmatched": counts["unmatched"],
            "matched": counts["exact"] + counts["strong"] + counts["candidate"],
        },
        "matches": matches,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Match two compatible offline function-fingerprint JSONL exports.",
        epilog=(
            "Confidence semantics: exact is a unique exactHash match; strong is a "
            "unique shapeHash plus instructionCount match; candidate is a unique "
            "bounded heuristic winner; ties are ambiguous and never selected. "
            f"Heuristic pools are capped at {MAX_HEURISTIC_CANDIDATES}; oversized "
            "pools are reported ambiguous without scoring."
        ),
    )
    parser.add_argument("--source", type=Path, required=True, help="source JSONL export")
    parser.add_argument("--target", type=Path, required=True, help="target JSONL export")
    parser.add_argument("--out", type=Path, required=True, help="output JSON report")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        source_metadata, source_functions = load_export(args.source)
        target_metadata, target_functions = load_export(args.target)
        report = match_functions(
            source_metadata, source_functions, target_metadata, target_functions
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (InputFormatError, OSError, TypeError, ValueError) as exc:
        print(f"match-version-functions.py: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
