# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2026 contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""What the SHA-256/384 checksum at 0xd0 of a $PS1 file covers.

- The content of a padded body, with the content size at 0x70 (MPIO_FW on Zen 4/5
  client firmware) or without it (SEC_GASKET on Zen 2/3 client firmware).
- A compressed body as stored (AMF_FW2, MFD_MPM_WLAN_FW on Zen 3+ to Zen 5 laptops).
"""

import hashlib
import os
import struct
import unittest
import zlib

from .signed_rom import align, file_of_type, header, parse, rom, root_key, sign


def checksummed_file(hdr: bytearray, stored: bytes, checksummed: bytes, content_size: int = 0) -> bytes:
    hdr[0x58:0x5c] = struct.pack('>I', 1)  # sha256 checksum
    hdr[0x70:0x74] = struct.pack('<I', content_size)
    hdr[0xd0:0xf0] = hashlib.sha256(checksummed).digest()
    return bytes(hdr) + stored + sign(bytes(hdr) + stored)


class TestChecksums(unittest.TestCase):

    def test_checksum_over_content_of_padded_body(self):
        content = os.urandom(0x2ca7) + b'\x01'
        for content_size, padding_size in ((len(content), 0x2), (0, 0x8)):
            with self.subTest(content_size=content_size):
                body = content + bytes(padding_size)
                data = checksummed_file(header(len(body)), body, content, content_size)
                pt, _ = parse(rom([(0x00, root_key(), None), (0x24, data, None)]))
                file = file_of_type(pt, 0x24)
                self.assertTrue(file.verify_sha256())
                self.assertTrue(file.signed_entity.is_verified())

    def test_checksum_over_compressed_body_as_stored(self):
        payload = bytes(range(256)) * 64
        compressed = zlib.compress(payload)
        stored = align(compressed)
        data = checksummed_file(header(len(stored), True, len(payload), len(compressed)), stored, stored)
        pt, _ = parse(rom([(0x00, root_key(), None), (0x88, data, None)]))
        file = file_of_type(pt, 0x88)
        self.assertTrue(file.verify_sha256())
        self.assertEqual(file.get_decrypted_decompressed_body(), payload)

    def test_checksum_mismatch_is_still_reported(self):
        body = os.urandom(0x400)
        data = bytearray(checksummed_file(header(len(body)), body, body))
        data[0xd0] ^= 1
        pt, _ = parse(rom([(0x00, root_key(), None), (0x24, bytes(data), None)]))
        self.assertFalse(file_of_type(pt, 0x24).verify_sha256(print_warning=False))


if __name__ == '__main__':
    unittest.main()
