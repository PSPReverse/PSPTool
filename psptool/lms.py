# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""LMS (RFC 8554 / NIST SP 800-208) public keys, as found in Zen 6 PSP images.

Zen 6 images carry LMS public keys next to the RSA-4096 ones: appended to the
AMD root key (AMD_PUBLIC_KEY, type 0x00) and as entries of type 3 inside
$KDB key stores. psptool parses and lists them but cannot verify LMS
signatures.
"""

# RFC 8554 section 8.1 and NIST SP 800-208 section 4
LMS_TYPES = {
    0x05: 'LMS_SHA256_M32_H5',  0x06: 'LMS_SHA256_M32_H10', 0x07: 'LMS_SHA256_M32_H15',
    0x08: 'LMS_SHA256_M32_H20', 0x09: 'LMS_SHA256_M32_H25',
    0x0A: 'LMS_SHA256_M24_H5',  0x0B: 'LMS_SHA256_M24_H10', 0x0C: 'LMS_SHA256_M24_H15',
    0x0D: 'LMS_SHA256_M24_H20', 0x0E: 'LMS_SHA256_M24_H25',
    0x0F: 'LMS_SHAKE_M32_H5',   0x10: 'LMS_SHAKE_M32_H10',  0x11: 'LMS_SHAKE_M32_H15',
    0x12: 'LMS_SHAKE_M32_H20',  0x13: 'LMS_SHAKE_M32_H25',
    0x14: 'LMS_SHAKE_M24_H5',   0x15: 'LMS_SHAKE_M24_H10',  0x16: 'LMS_SHAKE_M24_H15',
    0x17: 'LMS_SHAKE_M24_H20',  0x18: 'LMS_SHAKE_M24_H25',
}
LMOTS_TYPES = {
    0x01: 'LMOTS_SHA256_N32_W1', 0x02: 'LMOTS_SHA256_N32_W2',
    0x03: 'LMOTS_SHA256_N32_W4', 0x04: 'LMOTS_SHA256_N32_W8',
    0x05: 'LMOTS_SHA256_N24_W1', 0x06: 'LMOTS_SHA256_N24_W2',
    0x07: 'LMOTS_SHA256_N24_W4', 0x08: 'LMOTS_SHA256_N24_W8',
    0x09: 'LMOTS_SHAKE_N32_W1',  0x0A: 'LMOTS_SHAKE_N32_W2',
    0x0B: 'LMOTS_SHAKE_N32_W4',  0x0C: 'LMOTS_SHAKE_N32_W8',
    0x0D: 'LMOTS_SHAKE_N24_W1',  0x0E: 'LMOTS_SHAKE_N24_W2',
    0x0F: 'LMOTS_SHAKE_N24_W4',  0x10: 'LMOTS_SHAKE_N24_W8',
}


def _hash_len(lms_type: int) -> int:
    # M24 parameter sets: 0x0A-0x0E and 0x14-0x18
    return 24 if lms_type in range(0x0A, 0x0F) or lms_type in range(0x14, 0x19) else 32


class LmsPublicKey:
    """u32 lms_type || u32 lmots_type || I[16] || T[1][m], all big endian"""

    def __init__(self, data: bytes):
        self.lms_type = int.from_bytes(data[0:4], 'big')
        self.lmots_type = int.from_bytes(data[4:8], 'big')
        if self.lms_type not in LMS_TYPES or self.lmots_type not in LMOTS_TYPES:
            raise ValueError(f'Not an LMS public key ({self.lms_type=:#x}, {self.lmots_type=:#x})')
        self.size = 8 + 16 + _hash_len(self.lms_type)
        if len(data) < self.size:
            raise ValueError(f'LMS public key truncated (0x{len(data):x} < 0x{self.size:x})')
        self.identifier = data[8:24]
        self.root = data[24:self.size]

    @staticmethod
    def looks_like(data: bytes) -> bool:
        try:
            LmsPublicKey(data)
            return True
        except ValueError:
            return False

    def get_readable_type(self) -> str:
        return f'{LMS_TYPES[self.lms_type]}/{LMOTS_TYPES[self.lmots_type]}'

    def __repr__(self) -> str:
        return f'LmsPublicKey({self.get_readable_type()}, I={self.identifier.hex()})'
