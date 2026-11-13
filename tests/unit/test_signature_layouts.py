# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2026 contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Where the signature is and what it covers.

The signature follows the body as stored, which is all of these layouts:
- Compressed bodies signed as stored (Zen 3 and later) or decompressed (Zen 1/2).
- A signed index of sub-modules that follow the signature: (id, offset) pairs on
  Zen 4/5 (ABL0, 0x76), with a SHA-384 per module on Zen 6 (ABL0, ABL7, 0x76, 0xb5).
- Padding up to a larger entry after the signature (Zen 5 boot loader).
- A header size that leaves out the signature (Zen 6).
- Signature type 0 next to a 0x200 byte signature (Zen 2 PMU firmware).
"""

import hashlib
import os
import struct
import unittest
import zlib

from cryptography.hazmat.primitives.asymmetric import rsa

from .signed_rom import HEADER_LEN, SIGNATURE_LEN, align, file_of_type, header, parse, rom, root_key, sign


def compressed_file(payload: bytes, signed_as_stored: bool) -> (bytes, bytes):
    """Returns the file and the bytes its signature covers"""
    compressed = zlib.compress(payload)
    stored = align(compressed)
    hdr = bytes(header(len(stored) if signed_as_stored else len(payload), True, len(payload), len(compressed)))
    signed = hdr + (stored if signed_as_stored else payload)
    return hdr + stored + sign(signed), signed


def indexed_file(modules, version: int) -> bytes:
    index_len = 0x10 + 0x40 * len(modules) if version == 2 else 8 * (len(modules) + 2)
    offset = HEADER_LEN + index_len + SIGNATURE_LEN
    entries = b''
    for i, module in enumerate(modules):
        if version == 2:
            entries += struct.pack('<4I', 0x3e01 + i, offset, len(module), 0) + hashlib.sha384(module).digest()
        else:
            entries += struct.pack('<II', 0x10 + i, offset)
        offset += len(module)
    if version == 2:
        index = struct.pack('<4I', 2, 0, offset - HEADER_LEN - index_len - SIGNATURE_LEN, len(modules)) + entries
    else:
        index = entries.ljust(index_len, b'\0')  # padded with zero entries, like on Zen 5
    hdr = bytes(header(len(index)))
    return hdr + index + sign(hdr + index) + b''.join(modules)


class TestSignatureLayouts(unittest.TestCase):

    def assertVerified(self, file):
        self.assertTrue(file.signed_entity.is_verified(), f'{file} does not verify')

    def test_compressed_body_signed_as_stored_or_decompressed(self):
        payload = bytes(range(256)) * 64
        for signed_as_stored in (True, False):
            with self.subTest(signed_as_stored=signed_as_stored):
                data, signed = compressed_file(payload, signed_as_stored)
                pt, _ = parse(rom([(0x00, root_key(), None), (0x08, data, None)]))
                file = file_of_type(pt, 0x08)
                self.assertVerified(file)
                self.assertEqual(file.signs_stored_body, signed_as_stored)
                # Resigning signs get_signed_bytes(), so it must keep the layout that verified
                self.assertEqual(file.get_signed_bytes(), signed)
                self.assertEqual(file.get_decrypted_decompressed_body(), payload)

    def test_module_index(self):
        modules = [os.urandom(0x123), os.urandom(0x40), os.urandom(0x200)]
        for version in (1, 2):
            with self.subTest(version=version):
                data = indexed_file(modules, version)
                pt, _ = parse(rom([(0x00, root_key(), None), (0x30, data, None)]))
                file = file_of_type(pt, 0x30)
                self.assertVerified(file)
                self.assertEqual(file.signature.buffer_offset, HEADER_LEN + file.size_signed)
                self.assertEqual(len(file.body), file.size_signed)
                self.assertEqual(file.buffer_size, len(data))
                self.assertEqual([len(m) for m in modules], [size for _, _, size, _ in file.module_index.modules])
                self.assertEqual(file.module_index.has_digests, version == 2)
                self.assertTrue(file.module_index.verify(file))

    def test_module_index_detects_modified_module(self):
        data = bytearray(indexed_file([os.urandom(0x100), os.urandom(0x100)], 2))
        data[-1] ^= 1
        pt, _ = parse(rom([(0x00, root_key(), None), (0x30, bytes(data), None)]))
        file = file_of_type(pt, 0x30)
        self.assertVerified(file)  # the index itself is untouched
        self.assertFalse(file.module_index.verify(file))

    def test_padding_after_signature_is_trimmed(self):
        body = os.urandom(0x400)
        hdr = bytes(header(len(body)))
        data = hdr + body + sign(hdr + body)
        pt, _ = parse(rom([(0x00, root_key(), None), (0x01, data, 0x8000)]))
        file = file_of_type(pt, 0x01)
        self.assertEqual(file.buffer_size, len(data))
        self.assertVerified(file)

    def test_header_size_without_signature(self):
        body = os.urandom(0x400)
        hdr = bytes(header(len(body), rom_size=HEADER_LEN + len(body)))
        data = hdr + body + sign(hdr + body)
        pt, _ = parse(rom([(0x00, root_key(), None), (0x02, data, None)]))
        file = file_of_type(pt, 0x02)
        self.assertEqual(file.buffer_size, len(data))
        self.assertVerified(file)

    def test_signature_type_0_with_rsa4096_signature(self):
        private_key = rsa.generate_private_key(public_exponent=0x10001, key_size=4096)
        payload = bytes(range(256)) * 32
        stored = align(zlib.compress(payload))
        hdr = bytes(header(len(payload), True, len(payload), len(zlib.compress(payload)),
                           rom_size=HEADER_LEN + len(stored) + 0x200))
        data = hdr + stored + sign(hdr + payload, private_key)
        pt, _ = parse(rom([(0x00, root_key(private_key), None), (0x64, data, None)]))
        file = file_of_type(pt, 0x64)
        self.assertEqual(file.signature.len, 0x200)
        self.assertVerified(file)
        self.assertFalse(file.signs_stored_body)


if __name__ == '__main__':
    unittest.main()
