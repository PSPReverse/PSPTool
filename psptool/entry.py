# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2019 Christian Werling, Robert Buhren
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import string
import struct

from .utils import NestedBuffer
from .utils import shannon
from .utils import chunker
from .utils import zlib_decompress

from binascii import hexlify
from base64 import b64encode
from math import ceil
from hashlib import md5

from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class Entry(NestedBuffer):
    ENTRY_ALIGNMENT = 0x100

    DIRECTORY_ENTRY_TYPES = {
        0x00: 'AMD_PUBLIC_KEY',
        0x01: 'PSP_FW_BOOT_LOADER',
        0x02: 'PSP_FW_TRUSTED_OS',
        0x03: 'PSP_FW_RECOVERY_BOOT_LOADER',
        0x04: 'PSP_NV_DATA',
        0x05: 'BIOS_PUBLIC_KEY',
        0x06: 'BIOS_RTM_FIRMWARE',
        0x07: 'BIOS_RTM_SIGNATURE',
        0x08: 'SMU_OFFCHIP_FW',
        0x09: 'SEC_DBG_PUBLIC_KEY',
        0x0A: 'OEM_PSP_FW_PUBLIC_KEY',
        0x0B: 'SOFT_FUSE_CHAIN_01',
        0x0C: 'PSP_BOOT_TIME_TRUSTLETS',
        0x0D: 'PSP_BOOT_TIME_TRUSTLETS_KEY',
        0x10: 'PSP_AGESA_RESUME_FW',
        0x12: 'SMU_OFF_CHIP_FW_2',
        0x13: 'DEBUG_UNLOCK',
        0x1A: 'PSP_S3_NV_DATA',
        0x21: 'WRAPPED_IKEK',
        0x22: 'TOKEN_UNLOCK',
        0x24: 'SEC_GASKET',
        0x25: 'MP2_FW',
        0x28: 'DRIVER_ENTRIES',
        0x2D: 'S0I3_DRIVER',
        0x30: 'ABL0',
        0x31: 'ABL1',
        0x32: 'ABL2',
        0x33: 'ABL3',
        0x34: 'ABL4',
        0x35: 'ABL5',
        0x36: 'ABL6',
        0x37: 'ABL7',
        0x3A: 'FW_PSP_WHITELIST',
        # 0x40: 'FW_L2_PTR',
        0x41: 'FW_IMC',
        0x42: 'FW_GEC',
        0x43: 'FW_XHCI',
        0x44: 'FW_INVALID',
        0x5f: 'FW_PSP_SMUSCS',
        0x60: 'FW_IMC',
        0x61: 'FW_GEC',
        0x62: 'FW_XHCI',
        0x63: 'FW_INVALID',
        0x108: 'PSP_SMU_FN_FIRMWARE',
        0x118: 'PSP_SMU_FN_FIRMWARE2',

        # Entry types named by us
        #   Custom names are denoted by a leading '!'
        0x14: '!PSP_MCLF_TRUSTLETS',  # very similiar to ~PspTrustlets.bin~ in coreboot blobs
        0x38: '!PSP_ENCRYPTED_NV_DATA',
        0x40: '!PL2_SECONDARY_DIRECTORY',
        0x70: '!BL2_SECONDARY_DIRECTORY',
        0x15f: '!FW_PSP_SMUSCS_2',  # seems to be a secondary FW_PSP_SMUSCS (see above)
        0x112: '!SMU_OFF_CHIP_FW_3',  # seems to tbe a tertiary SMU image (see above)
        0x39: '!SEV_APP',
        0x30062: '!UEFI-IMAGE'

    }

    class ParseError(Exception):
        pass

    @classmethod
    def from_fields(cls, parent_directory, parent_buffer, type_, size, offset):
        if type_ in [0x0B, 0x30062, 0x40, 0x70]:  # i.e. SOFT_FUSE_CHAIN_01, UEFI-IMAGE or secondary dir links
            size = 0

        try:
            # Option 1: it's a PubkeyEntry
            new_entry = PubkeyEntry(parent_directory, parent_buffer, type_, size, buffer_offset=offset)
        except (cls.ParseError, AssertionError):
            try:
                # Option 2: it's a HeaderEntry (most common)
                new_entry = HeaderEntry(parent_directory, parent_buffer, type_, size, buffer_offset=offset)
            except (cls.ParseError, AssertionError):
                # Option 3: it's a plain Entry
                new_entry = Entry(parent_directory, parent_buffer, type_, size, buffer_offset=offset)

        return new_entry

    def __init__(self, parent_directory, parent_buffer, type_, buffer_size, buffer_offset: int):
        super().__init__(parent_buffer, buffer_size, buffer_offset=buffer_offset)

        self.blob = parent_buffer
        self.type = type_
        self.references = [parent_directory]

        self.compressed = False
        self.signed = False
        self.encrypted = False

        try:
            self._parse()
        except (struct.error, AssertionError):
            raise Entry.ParseError()

    def __repr__(self):
        return f'{self.__class__.__name__}(type={hex(self.type)}, address={hex(self.get_address())}, ' \
               f'size={hex(self.buffer_size)}, len(references)={len(self.references)})'

    def __eq__(self, other):
        return self.type == other.type and self.get_address() == other.get_address() and \
              self.buffer_size == other.buffer_size

    def __hash__(self):
        return hash((self.type, self.get_address(), self.buffer_size))

    def __lt__(self, other):
        return self.get_address() < other.get_address()

    def _parse(self):
        pass

    def get_readable_type(self):
        if self.type in self.DIRECTORY_ENTRY_TYPES:
            return f'{self.DIRECTORY_ENTRY_TYPES[self.type]}~{hex(self.type)}'
        else:
            return hex(self.type)

    def get_readable_version(self):
        return ''

    def get_readable_magic(self):
        return ''

    def get_readable_signed_by(self):
        return ''

    def shannon_entropy(self):
        return shannon(self[:])

    def md5(self):
        m = md5()
        m.update(self.get_bytes())
        return m.hexdigest()

    def move_buffer(self, new_address, size):
        current_address = self.get_address()
        move_offset = new_address - current_address
        self.buffer_offset += move_offset
        self.buffer_size = int(ceil(size / self.ENTRY_ALIGNMENT)) * self.ENTRY_ALIGNMENT

        # update all directories' headers that point to this entry
        for directory in self.references:
            directory.update_entry_fields(self, self.type, self.buffer_size, self.buffer_offset)


class PubkeyEntry(Entry):
    def _parse(self):
        """ SEV spec B.1 """

        pubexp_size = struct.unpack('<I', self[0x38:0x3c])[0] // 8
        modulus_size = signature_size = struct.unpack('<I', self[0x3c:0x40])[0] // 8
        pubexp_start = 0x40
        modulus_start = pubexp_start + pubexp_size

        # Byte order of the numbers is inverted over their entire length
        # Assumption: Only the most significant 4 bytes of pubexp are relevant and can be converted to int

        # todo: use NestedBuffers instead of saving by value
        self.pubexp = self[pubexp_start:modulus_start][::-1][-4:]
        self.modulus = self[modulus_start:modulus_start + modulus_size][::-1]

        self.version = struct.unpack('<I', self[0x0:0x4])[0]
        self.key_id = hexlify(self[0x4:0x14])
        self.certifying_id = hexlify(self[0x14:0x24])
        self.key_usage = struct.unpack('<I', self[0x24:0x28])[0]

        expected_size = 0x40 + pubexp_size + modulus_size + signature_size

        # Option 1: it's a regular Pubkey (with a trailing signature)
        if len(self) == expected_size:
            self.signature = self[modulus_start + modulus_size:]
        # Option 2: it's the AMD Root Signing Key (without a trailing signature)
        elif len(self) == expected_size - signature_size:
            self.signature = None
        else:
            raise Entry.ParseError()

    def get_readable_magic(self):
        # use this to show the first four characters of the key ID
        return str(self.key_id[:4], encoding='ascii').upper()

    def get_der_encoded(self):
        if struct.unpack('>I', self.pubexp)[0] != 65537:
            raise NotImplementedError('Only an exponent of 65537 is supported.')

        if len(self.modulus) == 0x100:
            der_encoding = b'\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01' \
                           b'\x0F\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00' + self.modulus + b'\x02\x03\x01\x00\x01'
        elif len(self.modulus) == 0x200:
            der_encoding = b'\x30\x82\x02\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x02' \
                           b'\x0F\x00\x30\x82\x02\x0A\x02\x82\x02\x01\x00' + self.modulus + b'\x02\x03\x01\x00\x01'
        else:
            return None

        return der_encoding

    def get_pem_encoded(self):
        return b'-----BEGIN PUBLIC KEY-----\n' + \
               b'\n'.join(chunker(b64encode(self.get_der_encoded()), 64)) + \
               b'\n-----END PUBLIC KEY-----\n'


class HeaderEntry(Entry):
    def _parse(self):
        self.header = NestedBuffer(self, 0x100)

        # todo: use NestedBuffers instead of saving by value
        self.magic = self.header[0x10:0x14]
        self.size_signed = struct.unpack('<I', self.header[0x14:0x18])[0]
        self.encrypted = struct.unpack('<I', self.header[0x18:0x1c])[0] == 1
        self.signed = struct.unpack('<I', self.header[0x30:0x34])[0] == 1
        self.signature_fingerprint = hexlify(self.header[0x38:0x48])
        self.compressed = struct.unpack('<I', self.header[0x48:0x4c])[0] == 1
        self.size_full = struct.unpack('<I', self.header[0x50:0x54])[0]
        self.version = self.header[0x63:0x5f:-1]
        self.unknown = struct.unpack('<I', self.header[0x68:0x6c])[0]
        self.size_packed = struct.unpack('<I', self.header[0x6c:0x70])[0]

        self.unknown_fingerprint1 = hexlify(self.header[0x20:0x30])
        self.unknown_bool = struct.unpack('<I', self.header[0x7c:0x80])[0]
        self.unknown_fingerprint2 = hexlify(self.header[0x80:0x90])

        assert(self.size_packed <= self.buffer_size)
        assert(self.compressed in [0, 1])
        assert(self.encrypted in [0, 1])
        assert(self.get_readable_version() not in ['0.0.0.0', 'FF.FF.FF.FF'])

        # update buffer size with more precise size_packed
        self.buffer_size = self.size_packed

        # Note: This is a heuristic and it would be better to find out by looking at the signing key's modulus size.
        # However, this might not have been parsed at this point.
        signature_size = 0x100                            # Assume a default signature size of 0x100,
        if self.size_packed - self.size_signed == 0x300:  # unless the size_signed and size_packed indicate a 0x200 sig.
            signature_size = 0x200

        self.body = NestedBuffer(self, len(self) - 0x100 - signature_size, 0x100)
        self.signature = NestedBuffer(self, 0x100, len(self) - signature_size)

    def get_readable_version(self):
        return '.'.join([hex(b)[2:].upper() for b in self.version])

    def get_readable_magic(self):
        # if self.magic == b'\x01\x00\x00\x00':
            # actually twice as long, but SMURULESMURULES is kinda redundant
            # readable_magic= self[0x0:0x4]
        if self.magic == b'\x05\x00\x00\x00':
            readable_magic = b'0x05'
        else:
            readable_magic = self.magic

        try:
            # Try to encode the id as ascii
            readable_magic = str(readable_magic, encoding='ascii')
            # and remove unprintable chars
            readable_magic = ''.join(s for s in readable_magic if s in string.printable)
        except UnicodeDecodeError:
            return ''

        return readable_magic

    def get_readable_signed_by(self):
        return str(self.signature_fingerprint, encoding='ascii').upper()[:4]

    def get_decompressed(self) -> bytes:
        return self.header.get_bytes() + self.get_decompressed_body()

    def get_decompressed_body(self) -> bytes:
        if not self.compressed:
            return self.body.get_bytes()
        else:
            return zlib_decompress(self.body.get_bytes())

    def shannon_entropy(self):
        return shannon(self.body[:])

    def md5(self):
        m = md5()
        m.update(self.body.get_bytes())
        return m.hexdigest()

    def verify_signature(self):
        if self.buffer_size == 0:
            return False

        try:
            pubkey: PubkeyEntry = self.blob.pubkeys[self.signature_fingerprint]
        except KeyError:
            self.blob.psptool.print_warning(f'Corresponding public key ({self.signature_fingerprint[:4]}) not found. '
                                            f'Signature verification failed.')
            return False

        signature_size = len(pubkey.modulus)

        if signature_size != 0x100:
            self.blob.psptool.print_warning('Signatures of other key length than 2048 bit are unsupported.')
            return False

        signed_data = self.header.get_bytes() + self.get_decompressed_body()
        signature = self.get_bytes(offset=self.buffer_size - signature_size, size=signature_size)

        pubkey_der_encoded = pubkey.get_der_encoded()
        crypto_pubkey = load_der_public_key(pubkey_der_encoded, backend=default_backend())

        try:
            crypto_pubkey.verify(
                signature,
                signed_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False

        return True
