# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2026 contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Builder for synthetic ROMs with signed files.

An 8 MB ROM with a FET, one $PSP directory and the given files, signed with an RSA-2048
root key (the layouts under test do not depend on the key size). The root key is listed
as AMD_PUBLIC_KEY by passing root_key() as one of the files.
"""

import contextlib
import io
import os
import struct
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from psptool import PSPTool
from psptool.blob import Blob
from psptool.utils import fletcher32

ROM_SIZE = 8 * 1024 * 1024
FET_OFFSET = Blob.POSSIBLE_FET_OFFSETS[0]
PSP_DIR_OFFSET = FET_OFFSET + 0x1000
FILES_OFFSET = FET_OFFSET + 0x2000
HEADER_LEN = 0x100
SIGNATURE_LEN = 0x100

# Directory additional_info: version bit set, address mode 1 (flash offset)
FLASH_OFFSET_MODE = (1 << 31) | (1 << 24)

ROOT_KEY_ID = bytes(range(0x10, 0x20))
PRIVATE_KEY = rsa.generate_private_key(public_exponent=0x10001, key_size=2048)


def sign(data: bytes, private_key=PRIVATE_KEY) -> bytes:
    if private_key.key_size == 2048:
        return private_key.sign(data, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256())
    return private_key.sign(data, padding.PSS(padding.MGF1(hashes.SHA384()), 48), hashes.SHA384())


def pubkey(key_id: bytes, private_key, certifying_id: bytes = bytes(0x10), certifying_key=None) -> bytes:
    """A pubkey file, signed with a reversed (little endian) signature if certifying_key is given"""
    bits = private_key.key_size
    header = bytearray(0x40)
    header[0x0:0x4] = struct.pack('<I', 1)
    header[0x4:0x14] = key_id
    header[0x14:0x24] = certifying_id
    header[0x38:0x40] = struct.pack('<II', bits, bits)
    key = bytes(header) + (0x10001).to_bytes(bits // 8, 'little') + \
        private_key.public_key().public_numbers().n.to_bytes(bits // 8, 'little')
    if certifying_key is not None:
        key += sign(key, certifying_key)[::-1]
    return key


def root_key(private_key=PRIVATE_KEY) -> bytes:
    """AMD_PUBLIC_KEY (type 0x00), unsigned"""
    return pubkey(ROOT_KEY_ID, private_key)


def header(size_signed: int, compressed: bool = False, uncompressed_size: int = 0, zlib_size: int = 0,
           rom_size: int = 0, signer: bytes = ROOT_KEY_ID) -> bytearray:
    hdr = bytearray(HEADER_LEN)
    hdr[0x10:0x14] = b'$PS1'
    hdr[0x14:0x18] = struct.pack('<I', size_signed)
    hdr[0x30:0x38] = struct.pack('<II', 1, 0)  # signed, signature type 0 (0x100 bytes)
    hdr[0x38:0x48] = signer
    hdr[0x48:0x4c] = struct.pack('<I', int(compressed))
    hdr[0x50:0x58] = struct.pack('<II', uncompressed_size, zlib_size)
    hdr[0x62] = 0x0C  # boot loader major in BOOTLOADER_VERSION_TO_ZEN, else PSPTool warns
    hdr[0x6c:0x70] = struct.pack('<I', rom_size)
    return hdr


def align(data: bytes, alignment: int = 0x10) -> bytes:
    return data + bytes(-len(data) % alignment)


def rom(entries) -> bytes:
    """entries: (type, file bytes, entry size or None), placed one after another and
    padded with 0xff up to the entry size"""
    blob = bytearray(ROM_SIZE)
    blob[FET_OFFSET - 4:FET_OFFSET] = b'\xff' * 4
    blob[FET_OFFSET:FET_OFFSET + 4] = Blob._FIRMWARE_ENTRY_MAGIC
    blob[FET_OFFSET + 4:FET_OFFSET + 8] = struct.pack('<I', PSP_DIR_OFFSET)
    blob[FET_OFFSET + 8:FET_OFFSET + 24] = b'\xff' * 16

    body = struct.pack('<II', len(entries), FLASH_OFFSET_MODE)
    offset = FILES_OFFSET
    for type_, data, entry_size in entries:
        entry_size = entry_size or len(data)
        body += struct.pack('<BBHIII', type_, 0, 0, entry_size, offset, 0)
        blob[offset:offset + entry_size] = data.ljust(entry_size, b'\xff')
        offset += (entry_size + 0xfff) & ~0xfff
    psp_dir = b'$PSP' + fletcher32(body) + body
    blob[PSP_DIR_OFFSET:PSP_DIR_OFFSET + len(psp_dir)] = psp_dir
    return bytes(blob)


def parse(data: bytes):
    with tempfile.NamedTemporaryFile(suffix='.rom', delete=False) as f:
        f.write(data)
        path = f.name
    try:
        with io.StringIO() as stderr, contextlib.redirect_stderr(stderr):
            return PSPTool.from_file(path), stderr.getvalue()
    finally:
        os.unlink(path)


def file_of_type(pt, type_):
    (file,) = [f for f in pt.blob.unique_files() if f.type == type_]
    return file
