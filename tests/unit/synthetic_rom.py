# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2026 contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Synthetic ROM builder for unit tests.

Constructs an 8 MB ROM-shaped binary that PSPTool.from_file() can parse
end-to-end: a Firmware Entry Table referencing a single $PSP directory,
which in turn references one PSP_FW_BOOT_LOADER (type 0x01) HeaderFile.
Most of the binary is zero padding; only the small windows that PSPTool
parses are populated.

The boot loader's `version` field is the only knob tests need: setting
the major byte (printed as version[1]) chooses which Zen generation
PSPTool's back-fill assigns. The mapping itself lives in
psptool.directory.Directory.BOOTLOADER_VERSION_TO_ZEN.

This is intentionally NOT a faithful PSP image; checksums on file
contents are zero, no signatures, no AGESA strings. It exercises the
parsing path that drives zen_generation back-fill and nothing more.
"""

import struct

from psptool.blob import Blob
from psptool.utils import fletcher32

ROM_SIZE = 8 * 1024 * 1024
# Smallest FET offset PSPTool will probe — every other constant in this
# module is derived as a small offset above it, so updating the blob's
# offset table doesn't desync the builder.
FET_OFFSET = Blob.POSSIBLE_FET_OFFSETS[0]
PSP_DIR_OFFSET = FET_OFFSET + 0x1000
BL_FILE_OFFSET = FET_OFFSET + 0x2000

FET_MAGIC = Blob._FIRMWARE_ENTRY_MAGIC
PSP_DIR_MAGIC = b'$PSP'

DIRECTORY_HEADER_SIZE = 16
DIRECTORY_ENTRY_SIZE = 16
HEADER_FILE_SIZE = 0x100   # HeaderFile.HEADER_LEN; minimal file body


def _build_psp_directory(entry_offset: int, entry_size: int) -> bytes:
    # Header layout:
    #   [0:4]   magic '$PSP'
    #   [4:8]   fletcher32(body)
    #   [8:12]  entry count
    #   [12:16] additional_info: bit31=version=1, bits 25:24 = address_mode
    #           (1 = flash offset from start of BIOS)
    additional_info = struct.pack('<I', (1 << 31) | (1 << 24))
    count = struct.pack('<I', 1)

    # One DirectoryEntry: type=0x01 PSP_FW_BOOT_LOADER, subprog=0, flags=0,
    # size, offset, rsv0=0
    entry = struct.pack(
        '<BBHIII',
        0x01,         # type
        0x00,         # subprogram
        0x0000,       # flags
        entry_size,   # size
        entry_offset, # offset (raw — directory addr_mode 1 returns this as-is)
        0x00000000,   # rsv0
    )

    body = count + additional_info + entry  # bytes after the checksum field
    checksum = fletcher32(body)
    return PSP_DIR_MAGIC + checksum + body


def _build_header_file(bl_major: int) -> bytes:
    # HeaderFile reads version as header[0x63:0x5f:-1], i.e. bytes at
    # 0x63, 0x62, 0x61, 0x60 in printed order. The major byte that drives
    # zen_generation lives at version[1] = header[0x62].
    header = bytearray(HEADER_FILE_SIZE)
    header[0x60] = 0x00      # version[3] (build, ignored for backfill)
    header[0x61] = 0x00      # version[2] (minor, ignored)
    header[0x62] = bl_major  # version[1] (major — drives backfill)
    header[0x63] = 0x00      # version[0] (printed-form leading zero)
    # rom_size (header[0x6c:0x70]) = 0 means "use buffer_size" in HeaderFile
    # All other fields stay zero: not encrypted, not signed, no checksum bits.
    return bytes(header)


def build_synthetic_rom(bl_major: int) -> bytes:
    """Return an 8 MB ROM blob whose PSP_FW_BOOT_LOADER version major
    byte is `bl_major`. Pass a value from
    Directory.BOOTLOADER_VERSION_TO_ZEN to drive a specific Zen
    generation through the back-fill path.
    """
    blob = bytearray(ROM_SIZE)

    # FET layout. The FET parser walks 4-byte words from FET_OFFSET until
    # it sees 16 bytes of 0xFF. The first word is the FET magic itself
    # (which the parser tries to interpret as a directory pointer and
    # warns about — benign for tests). The next valid pointer points at
    # our $PSP directory.
    blob[FET_OFFSET - 4:FET_OFFSET] = b'\xff\xff\xff\xff'  # required by _find_fets regex
    blob[FET_OFFSET:FET_OFFSET + 4] = FET_MAGIC
    blob[FET_OFFSET + 4:FET_OFFSET + 8] = struct.pack('<I', PSP_DIR_OFFSET)
    blob[FET_OFFSET + 8:FET_OFFSET + 24] = b'\xff' * 16  # FET terminator

    psp_dir = _build_psp_directory(BL_FILE_OFFSET, HEADER_FILE_SIZE)
    blob[PSP_DIR_OFFSET:PSP_DIR_OFFSET + len(psp_dir)] = psp_dir

    bl_header = _build_header_file(bl_major)
    blob[BL_FILE_OFFSET:BL_FILE_OFFSET + len(bl_header)] = bl_header

    return bytes(blob)


if __name__ == '__main__':
    # Smoke check: build a Zen 2 ROM and dump its size and the version
    # bytes for sanity.
    data = build_synthetic_rom(0x0C)
    print(f'len={len(data)} fet[0:4]={data[FET_OFFSET:FET_OFFSET+4].hex()} '
          f'psp_dir[0:4]={data[PSP_DIR_OFFSET:PSP_DIR_OFFSET+4]!r} '
          f'bl_version[60:64]={data[BL_FILE_OFFSET+0x60:BL_FILE_OFFSET+0x64].hex()}')
