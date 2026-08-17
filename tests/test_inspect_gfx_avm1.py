import importlib.util
import struct
import unittest
from pathlib import Path


TOOL_PATH = Path(__file__).parents[1] / "tools" / "inspect-gfx-avm1.py"
SPEC = importlib.util.spec_from_file_location("inspect_gfx_avm1", TOOL_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def long_action(opcode, payload):
    return bytes([opcode]) + struct.pack("<H", len(payload)) + payload


class InspectGfxAvm1Tests(unittest.TestCase):
    def test_constant_pool_push_resolves_string(self):
        pool = long_action(0x88, struct.pack("<H", 2) + b"loadClip\0MovieClipLoader\0")
        push = long_action(0x96, b"\x08\x00\x08\x01")
        actions = MODULE.parse_actions(pool + push + b"\0", 0x100)
        self.assertEqual(actions[1]["values"][0]["value"], "loadClip")
        self.assertEqual(actions[1]["values"][1]["value"], "MovieClipLoader")

    def test_define_function_body_is_decoded(self):
        body = long_action(0x96, b"\x00SetPortrait\0") + b"\0"
        header = b"handler\0" + struct.pack("<H", 0) + struct.pack("<H", len(body))
        actions = MODULE.parse_actions(long_action(0x9B, header) + body + b"\0", 0x200)
        nested = actions[0]["body"][0]
        self.assertEqual(nested["values"][0]["value"], "SetPortrait")
        self.assertEqual(nested["offset"], "0x20F")

    def test_rect_end_uses_declared_bit_width(self):
        self.assertEqual(MODULE.rect_end(bytes([0x08, 0x00]), 0), 2)


if __name__ == "__main__":
    unittest.main()
