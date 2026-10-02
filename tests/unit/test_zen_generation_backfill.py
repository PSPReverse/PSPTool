# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2026 contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import contextlib
import io
import os
import tempfile
import unittest

from psptool import PSPTool
from psptool.directory import Directory

from .synthetic_rom import build_synthetic_rom


class TestZenGenerationBackfill(unittest.TestCase):
    """Drive the PSP_FW_BOOT_LOADER back-fill path with synthetic ROMs.

    Each test builds an 8 MB ROM whose only PSP_FW_BOOT_LOADER carries a
    chosen version-major byte, parses it through PSPTool, and asserts
    that the resulting directory.zen_generation matches what
    BOOTLOADER_VERSION_TO_ZEN dictates.
    """

    def _parse_synthetic(self, bl_major):
        data = build_synthetic_rom(bl_major)
        with tempfile.NamedTemporaryFile(suffix='.rom', delete=False) as f:
            f.write(data)
            path = f.name
        try:
            with io.StringIO() as stderr_buf, contextlib.redirect_stderr(stderr_buf):
                pt = PSPTool.from_file(path)
                warnings = stderr_buf.getvalue()
            return pt, warnings
        finally:
            os.unlink(path)

    def test_each_known_major_resolves_to_expected_zen(self):
        for bl_major, expected in Directory.BOOTLOADER_VERSION_TO_ZEN.items():
            with self.subTest(f'major=0x{bl_major:02X}'):
                pt, _ = self._parse_synthetic(bl_major)
                gens = [d.zen_generation for r in pt.blob.roms for d in r.directories]
                self.assertEqual(
                    gens, [expected],
                    f'major=0x{bl_major:02X}: expected one directory tagged {expected!r}, got {gens!r}',
                )

    def test_unknown_major_leaves_zen_generation_none_and_warns(self):
        # 0x99 is intentionally not in BOOTLOADER_VERSION_TO_ZEN.
        self.assertNotIn(0x99, Directory.BOOTLOADER_VERSION_TO_ZEN)
        pt, warnings = self._parse_synthetic(0x99)
        gens = [d.zen_generation for r in pt.blob.roms for d in r.directories]
        self.assertEqual(gens, [None])
        self.assertIn('0x99', warnings)
        self.assertIn('not in BOOTLOADER_VERSION_TO_ZEN', warnings)

    def test_back_fill_does_not_overwrite_pre_classified_directories(self):
        # If the directory already has a zen_generation set (would be the
        # case in a combo BIOS where combo_dir classified it), back-fill
        # must not touch it. Verify by mutating the parsed object: pin
        # the directory to a known string, run back-fill again, observe
        # it stays put even though it would otherwise resolve via the
        # 0x0C boot loader.
        pt, _ = self._parse_synthetic(0x0C)
        directory = pt.blob.roms[0].directories[0]
        self.assertEqual(directory.zen_generation, 'Zen 2')

        directory.zen_generation = 'pre-classified'
        pt._backfill_zen_generation_from_bootloader()
        self.assertEqual(directory.zen_generation, 'pre-classified')


if __name__ == '__main__':
    unittest.main()
