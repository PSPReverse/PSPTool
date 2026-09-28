# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2026 contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Synthetic ROMs holding a single 0x50 key store.

Key stores in early ThinkPad T14/X13 Gen 1 AMD releases have no $PS1
magic and signature type 0 next to a 0x200 byte signature.
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

ROM_SIZE = 8 * 1024 * 1024
FET_OFFSET = Blob.POSSIBLE_FET_OFFSETS[0]
PSP_DIR_OFFSET = FET_OFFSET + 0x1000
KEY_STORE_OFFSET = FET_OFFSET + 0x2000
HEADER_FILE_SIZE = 0x100

# Directory additional_info: version bit set, address mode 1 (flash offset)
FLASH_OFFSET_MODE = (1 << 31) | (1 << 24)


def key_store_file(magic: bytes, signature_type: int) -> bytes:
    modulus_size = 0x100
    key = struct.pack('<IIII', 0x50 + modulus_size, 1, 0, 0x10001)
    key += bytes(0x10) + struct.pack('<I', modulus_size * 8)
    key = key.ljust(0x50, b'\0') + bytes(modulus_size)
    key_store = struct.pack('<II', 0x50 + len(key), 1) + b'$KDB'
    key_store = key_store.ljust(0x50, b'\0') + key
    signature_size = 0x200
    header = bytearray(HEADER_FILE_SIZE)
    header[0x10:0x14] = magic
    header[0x14:0x18] = struct.pack('<I', len(key_store))
    header[0x30:0x38] = struct.pack('<II', 1, signature_type)
    header[0x6c:0x70] = struct.pack('<I', HEADER_FILE_SIZE + len(key_store) + signature_size)
    header[0x7c:0x80] = struct.pack('<I', 0x50)
    return bytes(header) + key_store + bytes(signature_size)


def rom(ksf: bytes) -> bytes:
    blob = bytearray(ROM_SIZE)
    blob[FET_OFFSET - 4:FET_OFFSET] = b'\xff' * 4
    blob[FET_OFFSET:FET_OFFSET + 4] = Blob._FIRMWARE_ENTRY_MAGIC
    blob[FET_OFFSET + 4:FET_OFFSET + 8] = struct.pack('<I', PSP_DIR_OFFSET)
    blob[FET_OFFSET + 8:FET_OFFSET + 24] = b'\xff' * 16
    body = struct.pack('<II', 1, FLASH_OFFSET_MODE)
    body += struct.pack('<BBHIII', 0x50, 0, 0, len(ksf), KEY_STORE_OFFSET, 0)
    psp_dir = b'$PSP' + fletcher32(body) + body
    blob[PSP_DIR_OFFSET:PSP_DIR_OFFSET + len(psp_dir)] = psp_dir
    blob[KEY_STORE_OFFSET:KEY_STORE_OFFSET + len(ksf)] = ksf
    return bytes(blob)


def parse(data: bytes):
    with tempfile.NamedTemporaryFile(suffix='.rom', delete=False) as f:
        f.write(data)
        path = f.name
    try:
        with io.StringIO() as stderr, contextlib.redirect_stderr(stderr):
            return PSPTool.from_file(path)
    finally:
        os.unlink(path)


class TestKeyStoreFile(unittest.TestCase):

    def test_key_store_with_signature_type_0(self):
        for magic, signature_type in ((b'$PS1', 2), (bytes(4), 0)):
            with self.subTest(magic=magic, signature_type=signature_type):
                pt = parse(rom(key_store_file(magic, signature_type)))
                (key_store,) = pt.blob.unique_files()
                self.assertEqual(type(key_store).__name__, 'KeyStoreFile')
                self.assertEqual(key_store.signature.buffer_size, 0x200)
                self.assertEqual(len(key_store.key_store.keys), 1)


if __name__ == '__main__':
    unittest.main()
