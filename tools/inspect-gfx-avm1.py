#!/usr/bin/env python3
"""Inspect matching AVM1 action blocks in an uncompressed retail GFX movie."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any


ACTION_NAMES = {
    0x00: "End",
    0x04: "NextFrame",
    0x05: "PreviousFrame",
    0x06: "Play",
    0x07: "Stop",
    0x08: "ToggleQuality",
    0x09: "StopSounds",
    0x0A: "Add",
    0x0B: "Subtract",
    0x0C: "Multiply",
    0x0D: "Divide",
    0x0E: "Equals",
    0x0F: "Less",
    0x10: "And",
    0x11: "Or",
    0x12: "Not",
    0x13: "StringEquals",
    0x14: "StringLength",
    0x15: "StringExtract",
    0x17: "Pop",
    0x18: "ToInteger",
    0x1C: "GetVariable",
    0x1D: "SetVariable",
    0x20: "SetTarget2",
    0x21: "StringAdd",
    0x22: "GetProperty",
    0x23: "SetProperty",
    0x24: "CloneSprite",
    0x25: "RemoveSprite",
    0x26: "Trace",
    0x27: "StartDrag",
    0x28: "EndDrag",
    0x29: "StringLess",
    0x2A: "Throw",
    0x2B: "CastOp",
    0x2C: "ImplementsOp",
    0x30: "RandomNumber",
    0x31: "MBStringLength",
    0x32: "CharToAscii",
    0x33: "AsciiToChar",
    0x34: "GetTime",
    0x35: "MBStringExtract",
    0x36: "MBCharToAscii",
    0x37: "MBAsciiToChar",
    0x3A: "Delete",
    0x3B: "Delete2",
    0x3C: "DefineLocal",
    0x3D: "CallFunction",
    0x3E: "Return",
    0x3F: "Modulo",
    0x40: "NewObject",
    0x41: "DefineLocal2",
    0x42: "InitArray",
    0x43: "InitObject",
    0x44: "TypeOf",
    0x45: "TargetPath",
    0x46: "Enumerate",
    0x47: "Add2",
    0x48: "Less2",
    0x49: "Equals2",
    0x4A: "ToNumber",
    0x4B: "ToString",
    0x4C: "PushDuplicate",
    0x4D: "StackSwap",
    0x4E: "GetMember",
    0x4F: "SetMember",
    0x50: "Increment",
    0x51: "Decrement",
    0x52: "CallMethod",
    0x53: "NewMethod",
    0x54: "InstanceOf",
    0x55: "Enumerate2",
    0x60: "BitAnd",
    0x61: "BitOr",
    0x62: "BitXor",
    0x63: "BitLShift",
    0x64: "BitRShift",
    0x65: "BitURShift",
    0x66: "StrictEquals",
    0x67: "Greater",
    0x68: "StringGreater",
    0x81: "GotoFrame",
    0x83: "GetURL",
    0x87: "StoreRegister",
    0x88: "ConstantPool",
    0x89: "StrictMode",
    0x8A: "WaitForFrame",
    0x8B: "SetTarget",
    0x8C: "GotoLabel",
    0x8D: "WaitForFrame2",
    0x8E: "DefineFunction2",
    0x8F: "Try",
    0x94: "With",
    0x96: "Push",
    0x99: "Jump",
    0x9A: "GetURL2",
    0x9B: "DefineFunction",
    0x9D: "If",
    0x9E: "Call",
    0x9F: "GotoFrame2",
}


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def cstring(data: bytes, offset: int, end: int) -> tuple[str, int]:
    stop = data.find(b"\0", offset, end)
    if stop < 0:
        raise ValueError(f"unterminated string at 0x{offset:X}")
    return data[offset:stop].decode("latin-1"), stop + 1


def rect_end(data: bytes, offset: int) -> int:
    if offset >= len(data):
        raise ValueError("missing frame RECT")
    bit_count = 5 + (data[offset] >> 3) * 4
    return offset + (bit_count + 7) // 8


def push_values(payload: bytes, pool: list[str]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    pos = 0
    while pos < len(payload):
        kind = payload[pos]
        pos += 1
        item: dict[str, Any] = {"type": kind}
        if kind == 0:
            item["kind"] = "string"
            item["value"], pos = cstring(payload, pos, len(payload))
        elif kind == 1:
            item.update(kind="float", value=struct.unpack_from("<f", payload, pos)[0])
            pos += 4
        elif kind == 2:
            item.update(kind="null", value=None)
        elif kind == 3:
            item.update(kind="undefined", value=None)
        elif kind == 4:
            item.update(kind="register", value=payload[pos])
            pos += 1
        elif kind == 5:
            item.update(kind="boolean", value=bool(payload[pos]))
            pos += 1
        elif kind == 6:
            raw = payload[pos : pos + 8]
            item.update(kind="double", value=struct.unpack("<d", raw[4:8] + raw[0:4])[0])
            pos += 8
        elif kind == 7:
            item.update(kind="integer", value=struct.unpack_from("<i", payload, pos)[0])
            pos += 4
        elif kind == 8:
            index = payload[pos]
            pos += 1
            item.update(kind="constant8", index=index, value=pool[index] if index < len(pool) else None)
        elif kind == 9:
            index = u16(payload, pos)
            pos += 2
            item.update(kind="constant16", index=index, value=pool[index] if index < len(pool) else None)
        else:
            raise ValueError(f"unsupported push type {kind} at payload offset 0x{pos - 1:X}")
        values.append(item)
    return values


def parse_constant_pool(payload: bytes) -> list[str]:
    if len(payload) < 2:
        raise ValueError("truncated constant pool")
    count = u16(payload, 0)
    pos = 2
    values = []
    for _ in range(count):
        value, pos = cstring(payload, pos, len(payload))
        values.append(value)
    if pos != len(payload):
        raise ValueError("constant pool has trailing bytes")
    return values


def parse_function_header(payload: bytes, version: int) -> tuple[dict[str, Any], int]:
    pos = 0
    name, pos = cstring(payload, pos, len(payload))
    parameter_count = u16(payload, pos)
    pos += 2
    result: dict[str, Any] = {"functionName": name}
    if version == 1:
        parameters = []
        for _ in range(parameter_count):
            parameter, pos = cstring(payload, pos, len(payload))
            parameters.append(parameter)
        result["parameters"] = parameters
    else:
        result["registerCount"] = payload[pos]
        pos += 1
        result["flags"] = u16(payload, pos)
        pos += 2
        parameters = []
        for _ in range(parameter_count):
            register = payload[pos]
            pos += 1
            parameter, pos = cstring(payload, pos, len(payload))
            parameters.append({"register": register, "name": parameter})
        result["parameters"] = parameters
    code_size = u16(payload, pos)
    pos += 2
    if pos != len(payload):
        raise ValueError("function header has trailing bytes")
    return result, code_size


def parse_try_header(payload: bytes) -> tuple[dict[str, Any], tuple[int, int, int]]:
    if len(payload) < 7:
        raise ValueError("truncated Try header")
    flags = payload[0]
    sizes = (u16(payload, 1), u16(payload, 3), u16(payload, 5))
    pos = 7
    result: dict[str, Any] = {"flags": flags}
    if flags & 0x04:
        result["catchRegister"] = payload[pos]
        pos += 1
    else:
        result["catchName"], pos = cstring(payload, pos, len(payload))
    if pos != len(payload):
        raise ValueError("Try header has trailing bytes")
    return result, sizes


def decode_operands(opcode: int, payload: bytes, pool: list[str], base: int) -> dict[str, Any]:
    if opcode == 0x88:
        return {"constants": parse_constant_pool(payload)}
    if opcode == 0x96:
        return {"values": push_values(payload, pool)}
    if opcode in (0x99, 0x9D):
        return {"branchOffset": struct.unpack_from("<h", payload, 0)[0]}
    if opcode == 0x87:
        return {"register": payload[0]}
    if opcode == 0x81:
        return {"frame": u16(payload, 0)}
    if opcode in (0x8B, 0x8C):
        value, end = cstring(payload, 0, len(payload))
        if end != len(payload):
            raise ValueError("string operand has trailing bytes")
        return {"value": value}
    if opcode == 0x83:
        url, pos = cstring(payload, 0, len(payload))
        target, pos = cstring(payload, pos, len(payload))
        if pos != len(payload):
            raise ValueError("GetURL has trailing bytes")
        return {"url": url, "target": target}
    if opcode == 0x9A:
        return {"flags": payload[0]}
    if opcode == 0x8A:
        return {"frame": u16(payload, 0), "skipCount": payload[2]}
    if opcode == 0x8D:
        return {"skipCount": payload[0]}
    if opcode in (0x89, 0x9F):
        return {"flags": payload[0]}
    if payload:
        return {"rawHex": payload.hex().upper()}
    return {}


def parse_actions(data: bytes, base: int, inherited_pool: list[str] | None = None) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    pool = list(inherited_pool or [])
    pos = 0
    while pos < len(data):
        start = pos
        opcode = data[pos]
        pos += 1
        length = 0
        if opcode >= 0x80:
            if pos + 2 > len(data):
                raise ValueError(f"truncated action length at 0x{base + start:X}")
            length = u16(data, pos)
            pos += 2
        end = pos + length
        if end > len(data):
            raise ValueError(f"action at 0x{base + start:X} exceeds its block")
        payload = data[pos:end]
        action = {
            "offset": f"0x{base + start:X}",
            "relativeOffset": f"0x{start:X}",
            "opcode": f"0x{opcode:02X}",
            "name": ACTION_NAMES.get(opcode, f"Action_{opcode:02X}"),
        }
        action.update(decode_operands(opcode, payload, pool, base + pos))
        body_end = end
        if opcode in (0x9B, 0x8E):
            function, code_size = parse_function_header(payload, 1 if opcode == 0x9B else 2)
            body_end = end + code_size
            if body_end > len(data):
                raise ValueError(f"function body at 0x{base + end:X} exceeds its block")
            function["body"] = parse_actions(data[end:body_end], base + end, pool.copy())
            action.update(function)
        elif opcode == 0x94:
            if len(payload) != 2:
                raise ValueError("With header must contain only its code size")
            body_end = end + u16(payload, 0)
            if body_end > len(data):
                raise ValueError(f"With body at 0x{base + end:X} exceeds its block")
            action["body"] = parse_actions(data[end:body_end], base + end, pool.copy())
        elif opcode == 0x8F:
            try_header, sizes = parse_try_header(payload)
            action.update(try_header)
            body_end = end + sum(sizes)
            if body_end > len(data):
                raise ValueError(f"Try bodies at 0x{base + end:X} exceed their block")
            cursor = end
            for name, size in zip(("tryBody", "catchBody", "finallyBody"), sizes):
                action[name] = parse_actions(data[cursor : cursor + size], base + cursor, pool.copy()) if size else []
                cursor += size
        actions.append(action)
        if opcode == 0x88:
            pool = action["constants"]
        pos = body_end
        if opcode == 0:
            if pos != len(data) and any(data[pos:]):
                raise ValueError(f"nonzero bytes follow End at 0x{base + start:X}")
            break
    return actions


def strings_in(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, list):
        for item in value:
            found.extend(strings_in(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            if key not in {"offset", "relativeOffset", "opcode", "name", "rawHex"}:
                found.extend(strings_in(item))
    return found


def parse_tag_stream(
    data: bytes,
    start: int,
    end: int,
    path: list[str],
    targets: list[str],
    matches: list[dict[str, Any]],
) -> None:
    pos = start
    tag_index = 0
    while pos + 2 <= end:
        tag_start = pos
        header = u16(data, pos)
        pos += 2
        code = header >> 6
        length = header & 0x3F
        if length == 0x3F:
            if pos + 4 > end:
                raise ValueError(f"truncated long tag at 0x{tag_start:X}")
            length = u32(data, pos)
            pos += 4
        payload_start = pos
        payload_end = pos + length
        if payload_end > end:
            raise ValueError(f"tag {code} at 0x{tag_start:X} exceeds its stream")
        tag_path = path + [f"tag[{tag_index}]/{code}@0x{tag_start:X}"]
        if code in (12, 59):
            action_start = payload_start
            block: dict[str, Any] = {
                "tagType": "DoAction" if code == 12 else "DoInitAction",
                "tagOffset": f"0x{tag_start:X}",
                "tagPath": tag_path,
            }
            if code == 59:
                if length < 2:
                    raise ValueError(f"truncated DoInitAction at 0x{tag_start:X}")
                block["spriteId"] = u16(data, payload_start)
                action_start += 2
            block["actionOffset"] = f"0x{action_start:X}"
            block["actions"] = parse_actions(data[action_start:payload_end], action_start)
            strings = strings_in(block["actions"])
            matched = [target for target in targets if target in strings]
            if matched:
                block["matchedTargets"] = matched
                matches.append(block)
        elif code == 39:
            if length < 4:
                raise ValueError(f"truncated DefineSprite at 0x{tag_start:X}")
            sprite_id = u16(data, payload_start)
            parse_tag_stream(
                data,
                payload_start + 4,
                payload_end,
                tag_path + [f"spriteId={sprite_id}"],
                targets,
                matches,
            )
        pos = payload_end
        tag_index += 1
        if code == 0:
            break


def inspect_movie(path: Path, targets: list[str]) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 12 or data[:3] not in (b"GFX", b"FWS"):
        raise ValueError("expected an uncompressed GFX or FWS movie")
    declared_size = u32(data, 4)
    if declared_size != len(data):
        raise ValueError(f"declared size {declared_size} does not match file size {len(data)}")
    frame_end = rect_end(data, 8)
    tag_start = frame_end + 4
    if tag_start > len(data):
        raise ValueError("truncated movie header")
    matches: list[dict[str, Any]] = []
    parse_tag_stream(data, tag_start, len(data), [path.name], targets, matches)
    return {
        "movie": path.name,
        "signature": data[:3].decode("ascii"),
        "version": data[3],
        "size": len(data),
        "targets": targets,
        "matchingBlocks": matches,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("movie", type=Path)
    parser.add_argument("--target", action="append", required=True, dest="targets")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = inspect_movie(args.movie, args.targets)
    rendered = json.dumps(result, indent=2, sort_keys=False) + "\n"
    if args.out:
        args.out.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
