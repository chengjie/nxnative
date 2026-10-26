"""Exercise actual AArch64 thunk shapes without any game files."""
import ast
from pathlib import Path
import re
import struct
import unittest

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TOOLS = Path(__file__).resolve().parents[1]
tree = ast.parse((TOOLS / 'patch_nso.py').read_text())
scope = {'re': re}
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef)
    and n.name in ('tail_call', 'tail_call_at_end')], type_ignores=[]), str(TOOLS / 'patch_nso.py'), 'exec'), scope)

# Standard frame, null guard to error block, pointer load, argument move,
# frame restore, tail jump, error call, trap padding.
THUNK = [0xa9bf7bfd, 0x910003fd, 0xb40000a1, 0xf9400812,
         0xaa0103e0, 0xa8c17bfd, 0xd61f0240, 0x94000400, 0]


def decode(words):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return list(md.disasm(struct.pack('<' + 'I' * len(words), *words), 0))


class TailCall(unittest.TestCase):
    def check(self, words, j=6):
        ins = decode(words)
        self.assertEqual(len(ins), len(words))
        return scope['tail_call'](ins, j)

    def test_framed_thunk_with_error_block(self):
        self.assertTrue(self.check(THUNK))
        self.assertTrue(self.check(THUNK[:-1]))

    def test_legacy_terminal_patterns_are_unchanged(self):
        for words in ([0xf9400812, 0xd61f0240],
                      [0xf9400812, 0xb4000081, 0xaa0103e0, 0xd61f0240],
                      [0xaa0103f2, 0xd61f0240]):
            ins = decode(words)
            self.assertEqual(self.check(words, len(words) - 1), scope['tail_call_at_end'](ins, len(ins) - 1))
        self.assertTrue(self.check([0xf9400812, 0xb4000081, 0xaa0103e0, 0xd61f0240], 3))

    def test_clobbers_calls_branches_and_traps_rejected(self):
        for word in (0x52800012, 0xaa0003f2, 0x94000400, 0xd63f0000,
                     0x14000001, 0xb4000020, 0xd65f03c0, 0, 0x910043ff):
            with self.subTest(word=hex(word)):
                words = THUNK.copy(); words[4] = word
                self.assertFalse(self.check(words))

    def test_required_frame_and_guard(self):
        for index, word in ((0, 0xd503201f), (1, 0xd503201f), (2, 0xb4000021),
                            (2, 0xb50000a1), (3, 0xaa0003f2), (5, 0xd503201f),
                            (7, 0xd503201f), (7, 0x97fffffd), (8, 0xaa0003e0)):
            with self.subTest(index=index, word=hex(word)):
                words = THUNK.copy(); words[index] = word
                self.assertFalse(self.check(words))

    def test_decoding_gap_is_rejected(self):
        ins = decode(THUNK)
        del ins[4]
        self.assertFalse(scope['tail_call'](ins, 5))

    def test_unframed_mid_function_pointer_jump_rejected(self):
        self.assertFalse(self.check([0xf9400812, 0xaa0103e0, 0xd61f0240, 0x94000400], 2))


if __name__ == '__main__':
    unittest.main()
