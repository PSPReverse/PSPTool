# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2026 contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Synthetic ROMs for layouts seen in Lenovo ThinkPad client firmware.

- A 64 MB flash whose BIOS L2 directory points past 32 MB (Z13 Gen 2),
  and 32 MB ROMs in files of 64 MB that must keep their size.
- 0x48/0x4a entries pointing straight at a $PL2 directory rather than at
  a header holding its offset (L13 Gen 4).
- A BIOS directory entry holding a plain PE image, whose bytes at the
  header's size field are text (L13 Gen 4).
- A 0x4a slot header pointing at an APCB rather than at a $PL2 directory
  (T14 Gen 7 AMD).
- An x86 physical address with entry address mode 0 in a directory with
  address mode 1, as coreboot writes APOB NV entries (StarBook Mk VI AMD).
- An entry left erased (all 0xff), as the KVM_IMAGE slot on Threadripper boards
  (Supermicro M12SWA-TF, H13SRA).
- Two ROMs in one file with different directories at the same ROM offsets
  (Supermicro M12SWA-TF), and ANOTHER_FET entries whose tables look like FETs.
- A second, minimal EFS at 0x1000 next to the one at 0x20000 (AM5).
- SPI settings after the FET's pointers (AM5).
- Slot headers without the leading checksum, with the L2 location at 0xc (Steam Deck).
- An image cut short of what its BIOS entries address (Steam Deck region from a capsule).
"""

import contextlib
import io
import os
import struct
import tempfile
import unittest

from psptool import PSPTool
from psptool.blob import Blob
from psptool.utils import fletcher32

MB = 1024 * 1024
FET_OFFSET = Blob.POSSIBLE_FET_OFFSETS[0]
PSP_DIR_OFFSET = FET_OFFSET + 0x1000
HEADER_FILE_SIZE = 0x100

# Directory additional_info: version bit set, address mode 1 (flash offset)
FLASH_OFFSET_MODE = (1 << 31) | (1 << 24)


def directory(magic: bytes, entries) -> bytes:
    body = struct.pack('<II', len(entries), FLASH_OFFSET_MODE)
    for type_, size, offset in entries:
        body += struct.pack('<BBHIII', type_, 0, 0, size, offset, 0)
    return magic + fletcher32(body) + body


def header_file(rom_size: int = 0) -> bytes:
    header = bytearray(HEADER_FILE_SIZE)
    header[0x62] = 0x0C  # boot loader major in BOOTLOADER_VERSION_TO_ZEN, else PSPTool warns
    header[0x6c:0x70] = struct.pack('<I', rom_size)
    return bytes(header)


def rom(size: int, psp_entries, extra=()) -> bytes:
    blob = bytearray(size)
    blob[FET_OFFSET - 4:FET_OFFSET] = b'\xff' * 4
    blob[FET_OFFSET:FET_OFFSET + 4] = Blob._FIRMWARE_ENTRY_MAGIC
    blob[FET_OFFSET + 4:FET_OFFSET + 8] = struct.pack('<I', PSP_DIR_OFFSET)
    blob[FET_OFFSET + 8:FET_OFFSET + 24] = b'\xff' * 16
    psp_dir = directory(b'$PSP', psp_entries)
    blob[PSP_DIR_OFFSET:PSP_DIR_OFFSET + len(psp_dir)] = psp_dir
    for offset, data in extra:
        blob[offset:offset + len(data)] = data
    return bytes(blob)


def fet(pointers, trailer=b'') -> bytes:
    """A FET with the given pointers (from offset 4), padded to 0x40, then trailer"""
    table = Blob._FIRMWARE_ENTRY_MAGIC + b''.join(struct.pack('<I', p) for p in pointers)
    return table.ljust(0x40, b'\0') + trailer + b'\xff' * 16


def boot_loader(major: int) -> bytes:
    header = bytearray(header_file())
    header[0x62] = major
    return bytes(header)


def place(blob: bytearray, offset: int, data: bytes):
    blob[offset:offset + len(data)] = data


def parse(data: bytes):
    with tempfile.NamedTemporaryFile(suffix='.rom', delete=False) as f:
        f.write(data)
        path = f.name
    try:
        with io.StringIO() as stderr, contextlib.redirect_stderr(stderr):
            pt = PSPTool.from_file(path)
            return pt, stderr.getvalue()
    finally:
        os.unlink(path)


def files(pt):
    return {(f.type, f.get_address()) for f in pt.blob.unique_files()}


class TestRomLayouts(unittest.TestCase):

    def test_64mb_rom_reaches_files_past_32mb(self):
        file_offset = 48 * MB
        data = rom(64 * MB, [(0x01, HEADER_FILE_SIZE, file_offset)],
                   [(file_offset, header_file())])
        pt, warnings = parse(data)
        self.assertIn('ROM size of 64M', warnings)
        self.assertEqual(pt.blob.roms[0].addr_mask, 64 * MB - 1)
        self.assertIn((0x01, file_offset), files(pt))

    def test_32mb_rom_in_64mb_file_keeps_its_size(self):
        file_offset = 16 * MB
        data = rom(64 * MB, [(0x01, HEADER_FILE_SIZE, file_offset)],
                   [(file_offset, header_file())])
        pt, warnings = parse(data)
        self.assertNotIn('ROM size of 64M', warnings)
        self.assertEqual(pt.blob.roms[0].addr_mask, 32 * MB - 1)
        self.assertIn((0x01, file_offset), files(pt))

    def test_32mb_rom_at_offset_in_64mb_file(self):
        rom_offset = 0x320
        file_offset = 16 * MB
        data = bytes(rom_offset) + rom(64 * MB - rom_offset, [(0x01, HEADER_FILE_SIZE, file_offset)],
                                       [(file_offset, header_file())])
        pt, _ = parse(data)
        self.assertEqual(len(pt.blob.roms), 1)
        self.assertEqual(pt.blob.roms[0].addr_mask, 32 * MB - 1)
        self.assertEqual({type_ for type_, _ in files(pt)}, {0x01})

    def test_l2_pointer_straight_at_directory(self):
        l2_offset = FET_OFFSET + 0x4000
        file_offset = FET_OFFSET + 0x5000
        data = rom(8 * MB, [(0x48, 0x400, l2_offset)], [
            (l2_offset, directory(b'$PL2', [(0x01, HEADER_FILE_SIZE, file_offset)])),
            (file_offset, header_file()),
        ])
        pt, _ = parse(data)
        magics = [d.magic for d in pt.blob.roms[0].directories]
        self.assertEqual(magics, [b'$PSP', b'$PL2'])
        self.assertIn((0x01, file_offset), files(pt))

    def test_l2_reached_directly_and_through_ish(self):
        l2_offset = FET_OFFSET + 0x4000
        ish_offset = FET_OFFSET + 0x3000
        file_offset = FET_OFFSET + 0x5000
        ish = bytes(16) + struct.pack('<I', l2_offset) + b'\x00\x01\x0C\xBC'
        data = rom(8 * MB, [(0x48, 0x400, l2_offset), (0x4a, 0x20, ish_offset)], [
            (ish_offset, ish),
            (l2_offset, directory(b'$PL2', [(0x01, HEADER_FILE_SIZE, file_offset)])),
            (file_offset, header_file()),
        ])
        pt, _ = parse(data)
        directories = pt.blob.roms[0].directories
        self.assertEqual([d.magic for d in directories], [b'$PSP', b'$PL2'])
        self.assertEqual(directories[1].zen_generation, 'Zen 3 (PSP ID 0xbc0c0100)')

    def test_header_size_past_rom_skips_file(self):
        bad_offset = FET_OFFSET + 0x4000
        good_offset = FET_OFFSET + 0x5000
        data = rom(8 * MB, [
            (0x01, HEADER_FILE_SIZE, bad_offset),
            (0x73, HEADER_FILE_SIZE, good_offset),
        ], [
            (bad_offset, header_file(rom_size=0x6b20796e)),
            (good_offset, header_file(rom_size=2 * HEADER_FILE_SIZE)),
        ])
        pt, warnings = parse(data)
        self.assertIn('overflows the parent buffer', warnings)
        self.assertEqual(files(pt), {(0x73, good_offset)})
        # A header size past the entry size but inside the ROM still counts
        (good,) = pt.blob.unique_files()
        self.assertEqual(good.buffer_size, 2 * HEADER_FILE_SIZE)

    def test_erased_entry_is_kept_as_plain_file(self):
        offset = FET_OFFSET + 0x4000
        size = 0x2000
        data = rom(8 * MB, [(0x29, size, offset)], [(offset, b'\xff' * size)])
        pt, warnings = parse(data)
        self.assertNotIn('ParseError', warnings)
        (erased,) = pt.blob.unique_files()
        self.assertEqual(type(erased).__name__, 'File')
        self.assertTrue(erased.is_erased)
        self.assertEqual(erased.buffer_size, size)

    def test_two_roms_with_directories_at_same_rom_offsets(self):
        blob = bytearray(32 * MB)
        for rom_start, major in ((0, 0x29), (16 * MB, 0x3D)):
            place(blob, rom_start + FET_OFFSET - 4, b'\xff' * 4 + fet([0, 0, 0, PSP_DIR_OFFSET]))
            place(blob, rom_start + PSP_DIR_OFFSET, directory(b'$PSP', [(0x01, HEADER_FILE_SIZE, 0x30000)]))
            place(blob, rom_start + 0x30000, boot_loader(major))
        pt, _ = parse(bytes(blob))
        self.assertEqual([rom.get_address() for rom in pt.blob.roms], [0, 16 * MB])
        self.assertEqual(files(pt), {(0x01, 0x30000), (0x01, 16 * MB + 0x30000)})
        versions = {f.get_address(): f.get_readable_version() for f in pt.blob.unique_files()}
        self.assertEqual(versions, {0x30000: '0.29.0.0', 16 * MB + 0x30000: '0.3D.0.0'})

    def test_fet_inside_another_fet_entry_is_not_a_rom(self):
        another_fet = FET_OFFSET + 0x20000
        data = rom(8 * MB, [(0x46, 0x1000, another_fet)], [
            # A table addressing a separate image, starting like a FET
            (another_fet, b'\xff' * 4 + fet([0xff000030])),
        ])
        pt, warnings = parse(data)
        self.assertEqual(len(pt.blob.roms), 1)
        self.assertNotIn('unknown ROM alignment', warnings)
        self.assertEqual(files(pt), {(0x46, another_fet)})

    def test_early_fet_at_0x1000_is_parsed_after_main_rom(self):
        blob = bytearray(16 * MB)
        place(blob, FET_OFFSET - 4, b'\xff' * 4 + fet([0, 0, 0, PSP_DIR_OFFSET]))
        place(blob, PSP_DIR_OFFSET, directory(b'$PSP', [(0x01, HEADER_FILE_SIZE, 0x30000)]))
        place(blob, 0x30000, boot_loader(0x29))
        place(blob, 0x1000 - 4, b'\xff' * 4 + fet([0, 0, 0, 0x2000]))
        place(blob, 0x2000, directory(b'$PSP', [(0x01, HEADER_FILE_SIZE, 0x3000)]))
        place(blob, 0x3000, boot_loader(0x2B))
        pt, warnings = parse(bytes(blob))
        self.assertNotIn('unknown ROM alignment', warnings)
        self.assertEqual([rom.fet.get_address() for rom in pt.blob.roms], [FET_OFFSET, 0x1000])
        self.assertEqual(files(pt), {(0x01, 0x30000), (0x01, 0x3000)})

    def test_spi_settings_after_fet_pointers_are_ignored(self):
        data = bytearray(rom(32 * MB, [(0x01, HEADER_FILE_SIZE, FET_OFFSET + 0x4000)],
                             [(FET_OFFSET + 0x4000, header_file())]))
        # SPI read mode, fast speed and friends at 0x40, as on AM5
        place(data, FET_OFFSET, fet([0, 0, 0, PSP_DIR_OFFSET], b'\xff' * 8 + bytes.fromhex('ffffff050055ffff')))
        pt, warnings = parse(bytes(data))
        self.assertNotIn('not found or invalid', warnings)
        self.assertEqual(files(pt), {(0x01, FET_OFFSET + 0x4000)})

    def test_slot_header_without_checksum(self):
        ish = FET_OFFSET + 0x2000
        l2_offset = FET_OFFSET + 0x4000
        file_offset = FET_OFFSET + 0x5000
        # boot priority, update retries, glitch retries, L2 location, erased PSP ID
        slot = struct.pack('<IIII', 2, 3, 0xff, l2_offset) + b'\xff' * 16
        data = rom(8 * MB, [(0x48, 0, ish)], [
            (ish, slot),
            (l2_offset, directory(b'$PL2', [(0x01, HEADER_FILE_SIZE, file_offset)])),
            (file_offset, header_file()),
        ])
        pt, warnings = parse(data)
        self.assertNotIn('Unknown zen_generation_id', warnings)
        self.assertEqual([d.magic for d in pt.blob.roms[0].directories], [b'$PSP', b'$PL2'])
        self.assertIn((0x01, file_offset), files(pt))

    def test_entries_past_end_of_cut_short_image_are_skipped(self):
        size = 16 * MB
        file_offset = FET_OFFSET + 0x5000
        data = rom(size, [(0x01, HEADER_FILE_SIZE, file_offset), (0x62, 0x1000, size + 0x10000)],
                   [(file_offset, header_file())])
        pt, warnings = parse(data)
        self.assertIn('skipping entries outside', warnings)
        self.assertEqual(files(pt), {(0x01, file_offset)})

    def test_slot_header_pointing_at_non_directory_is_skipped(self):
        ish_a = FET_OFFSET + 0x2000
        ish_b = FET_OFFSET + 0x3000
        l2_offset = FET_OFFSET + 0x4000
        apcb_offset = FET_OFFSET + 0x6000
        file_offset = FET_OFFSET + 0x5000
        zen_id = b'\x00\x01\x0C\xBC'
        data = rom(8 * MB, [(0x48, 0x20, ish_a), (0x4a, 0x20, ish_b)], [
            (ish_a, bytes(16) + struct.pack('<I', l2_offset) + zen_id),
            (ish_b, bytes(16) + struct.pack('<I', apcb_offset) + zen_id),
            (l2_offset, directory(b'$PL2', [(0x01, HEADER_FILE_SIZE, file_offset)])),
            (apcb_offset, b'APCB' + bytes(12)),
            (file_offset, header_file()),
        ])
        pt, warnings = parse(data)
        self.assertIn('Unknown directory magic', warnings)
        magics = [d.magic for d in pt.blob.roms[0].directories]
        self.assertEqual(magics, [b'$PSP', b'$PL2'])
        self.assertIn((0x01, file_offset), files(pt))

    def test_physical_address_in_flash_offset_directory(self):
        file_offset = FET_OFFSET + 0x4000
        data = rom(16 * MB, [(0x01, HEADER_FILE_SIZE, 0xFF000000 + file_offset)],
                   [(file_offset, header_file())])
        pt, _ = parse(data)
        self.assertEqual(files(pt), {(0x01, file_offset)})


if __name__ == '__main__':
    unittest.main()
