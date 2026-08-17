#!/usr/bin/env python3
"""Export deterministic function fingerprints from ReXGlue generated C++."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


FUNCTION_RE = re.compile(r"^DEFINE_REX_FUNC\(sub_([0-9A-Fa-f]{8})\)\s*\{")
INSTRUCTION_RE = re.compile(r"^\s*//\s+([A-Za-z].*)$")
ADDRESS_RE = re.compile(r"0x[0-9A-Fa-f]+")
SPACE_RE = re.compile(r"\s+")


def canonical_instruction(text: str) -> str:
    return SPACE_RE.sub(" ", text.strip()).lower()


def digest(lines: list[str]) -> str:
    payload = "\n".join(lines).encode("ascii")
    return hashlib.sha256(payload).hexdigest().upper()


def chunk_key(path: Path, prefix: str) -> int:
    match = re.fullmatch(re.escape(prefix) + r"_recomp\.(\d+)\.cpp", path.name)
    if not match:
        raise ValueError(f"unexpected generated chunk name: {path.name}")
    return int(match.group(1))


def make_record(address: int, instructions: list[str]) -> dict[str, object]:
    canonical = [canonical_instruction(line) for line in instructions]
    mnemonics = [line.split(" ", 1)[0] for line in canonical]
    shape = [ADDRESS_RE.sub("<addr>", line) for line in canonical]
    direct_calls = sum(mnemonic in {"bl", "bla"} for mnemonic in mnemonics)
    body_size = len(canonical) * 4
    return {
        "recordType": "function",
        "address": f"0x{address:08X}",
        "minAddress": f"0x{address:08X}",
        "maxAddress": f"0x{address + max(body_size - 1, 0):08X}",
        "name": f"sub_{address:08X}",
        "bodySize": body_size,
        "instructionCount": len(canonical),
        "exactHash": digest(canonical),
        "shapeHash": digest(shape),
        "mnemonicHash": digest(mnemonics),
        "directCallCount": direct_calls,
        "stringAnchors": [],
    }


def parse_chunks(generated_dir: Path, prefix: str) -> list[dict[str, object]]:
    chunks = sorted(
        generated_dir.glob(f"{prefix}_recomp.*.cpp"),
        key=lambda path: chunk_key(path, prefix),
    )
    if not chunks:
        raise ValueError(f"no generated chunks found for prefix {prefix}")

    records: list[dict[str, object]] = []
    active_address: int | None = None
    instructions: list[str] = []

    def finish() -> None:
        nonlocal active_address, instructions
        if active_address is not None:
            records.append(make_record(active_address, instructions))
        active_address = None
        instructions = []

    for chunk in chunks:
        with chunk.open("r", encoding="utf-8") as source:
            for line in source:
                function_match = FUNCTION_RE.match(line)
                if function_match:
                    finish()
                    active_address = int(function_match.group(1), 16)
                    continue
                if active_address is None:
                    continue
                instruction_match = INSTRUCTION_RE.match(line)
                if instruction_match:
                    instructions.append(instruction_match.group(1))
        finish()

    records.sort(key=lambda record: int(str(record["address"]), 16))
    addresses = [record["address"] for record in records]
    if len(addresses) != len(set(addresses)):
        raise ValueError("generated chunks contain duplicate function addresses")
    return records


def export(generated_dir: Path, prefix: str, output: Path) -> int:
    records = parse_chunks(generated_dir, prefix)
    program = {
        "recordType": "program",
        "program": prefix,
        "source": "rexglue-generated-cpp",
        "fingerprintAlgorithm": "rexglue-comment-v1",
        "functionCount": len(records),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="ascii", newline="\n") as destination:
        destination.write(json.dumps(program, sort_keys=True, separators=(",", ":")))
        destination.write("\n")
        for record in records:
            destination.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
            destination.write("\n")
    return len(records)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export cross-version fingerprints from ReXGlue generated C++."
    )
    parser.add_argument("--generated-dir", type=Path, required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    count = export(args.generated_dir.resolve(), args.prefix, args.out.resolve())
    print(f"Exported {count} function fingerprints to {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
