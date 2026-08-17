#!/usr/bin/env python3
"""List fetch-constant 0 states at draws in a trace-format-v1 GPU trace."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


TRACE_HEADER_SIZE = 48
FETCH_REGISTER_BASE = 0x4800
PM4_DRAW_INDX = 0x22
PM4_DRAW_INDX_2 = 0x36
PM4_SET_CONSTANT = 0x2D
PM4_SET_CONSTANT2 = 0x55
PM4_SET_SHADER_CONSTANTS = 0x56


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def gpu_words(payload: bytes) -> list[int]:
    if len(payload) % 4:
        raise ValueError("GPU packet payload is not dword-aligned")
    return list(struct.unpack(f">{len(payload) // 4}I", payload))


def write_register(fetch: list[int], index: int, value: int) -> None:
    if FETCH_REGISTER_BASE <= index < FETCH_REGISTER_BASE + len(fetch):
        fetch[index - FETCH_REGISTER_BASE] = value


def process_packet(words: list[int], fetch: list[int]) -> int | None:
    if not words:
        return None
    packet = words[0]
    packet_type = packet >> 30
    if packet_type == 0:
        count = ((packet >> 16) & 0x3FFF) + 1
        base = packet & 0x7FFF
        write_one = (packet >> 15) & 1
        for item, value in enumerate(words[1 : 1 + count]):
            write_register(fetch, base if write_one else base + item, value)
        return None
    if packet_type != 3:
        return None

    opcode = (packet >> 8) & 0x7F
    payload = words[1:]
    if opcode == PM4_SET_CONSTANT and payload:
        offset_type = payload[0]
        index = offset_type & 0x7FF
        constant_type = (offset_type >> 16) & 0xFF
        if constant_type == 1:
            for item, value in enumerate(payload[1:]):
                write_register(fetch, FETCH_REGISTER_BASE + index + item, value)
    elif opcode in (PM4_SET_CONSTANT2, PM4_SET_SHADER_CONSTANTS) and payload:
        index = payload[0] & 0xFFFF
        for item, value in enumerate(payload[1:]):
            write_register(fetch, index + item, value)
    return opcode


def describe_fetch(fetch: list[int]) -> dict[str, int]:
    d0, d1, d2, _, _, d5 = fetch
    return {
        "base": ((d1 >> 12) & 0xFFFFF) << 12,
        "pitch": ((d0 >> 22) & 0x1FF) << 5,
        "tiled": (d0 >> 31) & 1,
        "format": d1 & 0x3F,
        "endian": (d1 >> 6) & 3,
        "width": (d2 & 0x1FFF) + 1,
        "height": ((d2 >> 13) & 0x1FFF) + 1,
        "dimension": (d5 >> 9) & 3,
    }


def inspect(data: bytes) -> list[tuple[int, int, list[int]]]:
    if len(data) < TRACE_HEADER_SIZE or read_u32(data, 0) != 1:
        raise ValueError("not a trace-format-v1 file")
    offset = TRACE_HEADER_SIZE
    fetch = [0] * 6
    pending_words: list[int] | None = None
    draws: list[tuple[int, int, list[int]]] = []
    while offset < len(data):
        command_type = read_u32(data, offset)
        if command_type in (0, 2):
            count = read_u32(data, offset + 8)
            offset += 12 + count * 4
        elif command_type in (1, 3, 5):
            offset += 4
            if command_type == 5 and pending_words is not None:
                opcode = process_packet(pending_words, fetch)
                if opcode in (PM4_DRAW_INDX, PM4_DRAW_INDX_2):
                    draws.append((len(draws), offset, fetch.copy()))
                pending_words = None
        elif command_type == 4:
            count = read_u32(data, offset + 8)
            payload_start = offset + 12
            payload_end = payload_start + count * 4
            pending_words = gpu_words(data[payload_start:payload_end])
            offset = payload_end
        elif command_type in (6, 7):
            encoded_length = read_u32(data, offset + 12)
            offset += 20 + encoded_length
        elif command_type == 8:
            encoded_length = read_u32(data, offset + 8)
            offset += 12 + encoded_length
        elif command_type == 9:
            offset += 8
        elif command_type == 10:
            encoded_length = read_u32(data, offset + 20)
            offset += 24 + encoded_length
        elif command_type == 11:
            encoded_length = read_u32(data, offset + 12)
            offset += 16 + encoded_length
        else:
            raise ValueError(f"unknown command type {command_type} at 0x{offset:X}")
        if offset > len(data):
            raise ValueError("trace command extends beyond end of file")
    if offset != len(data):
        raise ValueError("trace parser did not finish at end of file")
    return draws


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("--width", type=int)
    parser.add_argument("--height", type=int)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    data = args.trace.read_bytes()
    draws = inspect(data)
    matches: list[tuple[int, int, list[int]]] = []
    previous: list[int] | None = None
    for draw_index, end_offset, fetch in draws:
        if fetch == previous:
            continue
        previous = fetch
        fields = describe_fetch(fetch)
        if args.width is not None and fields["width"] != args.width:
            continue
        if args.height is not None and fields["height"] != args.height:
            continue
        matches.append((draw_index, end_offset, fetch))
        words = " ".join(f"{word:08X}" for word in fetch)
        print(
            f"draw={draw_index} end=0x{end_offset:X} fetch0={words} "
            f"base={fields['base']:08X} pitch={fields['pitch']} "
            f"tiled={fields['tiled']} format={fields['format']} "
            f"endian={fields['endian']} size={fields['width']}x{fields['height']} "
            f"dimension={fields['dimension']}"
        )
    print(f"draws={len(draws)} distinct_matches={len(matches)}")
    if args.out:
        if not matches:
            raise ValueError("no matching draw to extract")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(data[: matches[0][1]])
        print(f"extracted={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
