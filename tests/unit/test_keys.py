# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2026 contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Keys and how they are found.

- LMS public keys after the AMD root key and in key stores (Zen 6).
- $PS1 key stores in former pubkey entry types (0xad on Zen 6).
- A signed key with an all-zero certifying ID, signed by the root key (SEC_DBG key on
  Mendocino).
- Keys embedded at unaligned offsets in boot loaders, certified by other embedded keys
  (the SMU, SEC_GASKET and DEBUG_UNLOCK keys of Zen 2), or after the signature of the
  file they sign (MP2_FW on Zen 2/3 client firmware).
"""

import os
import struct
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa

from psptool.key_store_file import KeyStoreFile
from psptool.pubkey_file import InlinePubkeyFile, PubkeyFile

from .signed_rom import (HEADER_LEN, PRIVATE_KEY, ROOT_KEY_ID, align, file_of_type, header, parse, pubkey, rom,
                         root_key, sign)

# u32 lms_type (LMS_SHA256_M32_H20), u32 lmots_type (LMOTS_SHA256_N32_W8), I, T[1]
LMS_PUBLIC_KEY = struct.pack('>II', 0x08, 0x04) + bytes(range(16)) + bytes(range(0x40, 0x60))


def lms_record(key_id: bytes) -> bytes:
    record = bytearray(0x38)
    record[0x0:0x4] = struct.pack('<I', 1)
    record[0x4:0x14] = key_id
    record[0x34:0x36] = struct.pack('<H', 0x70)
    return bytes(record) + LMS_PUBLIC_KEY


def signed_file(signer: bytes = ROOT_KEY_ID, private_key=PRIVATE_KEY, body: bytes = None) -> bytes:
    body = body or os.urandom(0x200)
    hdr = bytes(header(len(body), signer=signer))
    return hdr + body + sign(hdr + body, private_key)


class TestKeys(unittest.TestCase):

    def assertVerified(self, file):
        self.assertTrue(file.signed_entity.is_verified(), f'{file} does not verify')

    def test_lms_keys_after_root_key(self):
        ark = root_key() + b''.join(lms_record(bytes([i]) * 0x10) for i in range(4))
        pt, _ = parse(rom([(0x00, ark, None), (0x02, signed_file(), None)]))
        key = file_of_type(pt, 0x00)
        self.assertIsInstance(key, PubkeyFile)
        self.assertFalse(key.is_signed)
        self.assertEqual(len(key.lms_keys), 4)
        self.assertEqual(key.lms_keys[0][1].get_readable_type(), 'LMS_SHA256_M32_H20/LMOTS_SHA256_N32_W8')
        self.assertVerified(file_of_type(pt, 0x02))

    def test_key_store_with_lms_key_in_key_store_and_pubkey_types(self):
        rsa_key = struct.pack('<IIII', 0x150, 1, 0x26, 0x10001) + bytes(range(0x20, 0x30))
        rsa_key += struct.pack('<I', 2048)
        rsa_key = rsa_key.ljust(0x50, b'\0') + PRIVATE_KEY.public_key().public_numbers().n.to_bytes(0x100, 'little')
        lms_key = struct.pack('<IIII', 0x90, 1, 0x26, 0) + bytes(range(0x30, 0x40))
        lms_key += struct.pack('<II', len(LMS_PUBLIC_KEY), 3)
        lms_key = lms_key.ljust(0x50, b'\0') + LMS_PUBLIC_KEY.ljust(0x40, b'\0')
        kdb = struct.pack('<II', 0x50 + len(rsa_key) + len(lms_key), 1) + b'$KDB'
        kdb = kdb.ljust(0x50, b'\0') + rsa_key + lms_key
        hdr = header(len(kdb), rom_size=HEADER_LEN + len(kdb) + 0x100)
        hdr[0x7c:0x80] = struct.pack('<I', 0x50)
        key_store = bytes(hdr) + kdb + sign(bytes(hdr) + kdb)

        for type_ in (0x50, 0xad):
            with self.subTest(type=type_):
                pt, _ = parse(rom([(0x00, root_key(), None), (type_, key_store, None)]))
                file = file_of_type(pt, type_)
                self.assertIsInstance(file, KeyStoreFile)
                self.assertVerified(file)
                rsa_entry, lms_entry = file.key_store.keys
                self.assertFalse(rsa_entry.is_lms)
                self.assertTrue(lms_entry.is_lms)
                self.assertEqual(lms_entry.lms_key.root, LMS_PUBLIC_KEY[24:])

    def test_signed_key_without_certifying_id_is_signed_by_root_key(self):
        key = rsa.generate_private_key(public_exponent=0x10001, key_size=2048)
        debug_key = pubkey(bytes([0xd1]) * 0x10, key, bytes(0x10), PRIVATE_KEY)
        pt, _ = parse(rom([(0x00, root_key(), None), (0x09, debug_key, None)]))
        file = file_of_type(pt, 0x09)
        self.assertVerified(file)
        self.assertEqual(file.get_readable_signed_by(), file_of_type(pt, 0x00).get_readable_magic())

    def test_chain_of_unaligned_inline_keys(self):
        k1, k2 = (rsa.generate_private_key(public_exponent=0x10001, key_size=2048) for _ in range(2))
        k1_id, k2_id = bytes([0xa1]) * 0x10, bytes([0xa2]) * 0x10
        # The boot loader embeds K1 (certified by the root key) and K2 (certified by K1),
        # at unaligned offsets
        body = align(b'\x01' * 0x2e + pubkey(k1_id, k1, ROOT_KEY_ID, PRIVATE_KEY) +
                     b'\x02' * 0x16 + pubkey(k2_id, k2, k1_id, k1))
        pt, warnings = parse(rom([(0x00, root_key(), None), (0x01, signed_file(body=body), None),
                                  (0x08, signed_file(k2_id, k2), None)]))
        self.assertNotIn('Could not parse inline key', warnings)
        boot_loader = file_of_type(pt, 0x01)
        inline_keys = sorted(boot_loader.inline_keys, key=lambda k: k.get_address())
        self.assertEqual([k.key_id.get_bytes() for k in inline_keys], [k1_id, k2_id])
        self.assertTrue(all(isinstance(k, InlinePubkeyFile) for k in inline_keys))
        self.assertEqual(inline_keys[0].get_address(), boot_loader.get_address() + HEADER_LEN + 0x2e)
        for key in inline_keys:
            self.assertVerified(key)
        self.assertVerified(file_of_type(pt, 0x08))

    def test_signing_key_after_signature(self):
        key = rsa.generate_private_key(public_exponent=0x10001, key_size=2048)
        key_id = bytes([0xb1]) * 0x10
        body = os.urandom(0x1db1)
        mp2 = signed_file(key_id, key, body) + pubkey(key_id, key, ROOT_KEY_ID, PRIVATE_KEY)
        pt, _ = parse(rom([(0x00, root_key(), None), (0x25, mp2, None)]))
        file = file_of_type(pt, 0x25)
        self.assertEqual(file.buffer_size, len(mp2))
        self.assertEqual(file.signature.buffer_offset, HEADER_LEN + len(body))
        (inline_key,) = file.inline_keys
        self.assertVerified(inline_key)
        self.assertVerified(file)


if __name__ == '__main__':
    unittest.main()
