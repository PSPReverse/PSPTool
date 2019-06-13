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

from binascii import hexlify


class Entry(NestedBuffer):
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
        0x09: 'AMD_SEC_DBG_PUBLIC_KEY',
        0x0A: 'OEM_PSP_FW_PUBLIC_KEY',
        0x0B: 'AMD_SOFT_FUSE_CHAIN_01',
        0x0C: 'PSP_BOOT_TIME_TRUSTLETS',
        0x0D: 'PSP_BOOT_TIME_TRUSTLETS_KEY',
        0x10: 'PSP_AGESA_RESUME_FW',
        0x12: 'SMU_OFF_CHIP_FW_2',
        0x1A: 'PSP_S3_NV_DATA',
        0x5f: 'FW_PSP_SMUSCS',
        0x60: 'FW_IMC',
        0x61: 'FW_GEC',
        0x62: 'FW_XHCI',
        0x63: 'FW_INVALID',
        0x108: 'PSP_SMU_FN_FIRMWARE',
        0x118: 'PSP_SMU_FN_FIRMWARE2',

        # Entry types named by us
        #   Custom names are denoted by a leading '!' and comments by '~'
        0x14: '!PSP_MCLF_TRUSTLETS',  # very similiar to ~PspTrustlets.bin~ in coreboot blobs
        0x31: '0x31~ABL_ARM_CODE~',  # a _lot_ of strings and also some ARM code
        0x38: '!PSP_ENCRYPTED_NV_DATA',
        0x40: '!PL2_SECONDARY_DIRECTORY',
        0x70: '!BL2_SECONDARY_DIRECTORY',
        0x15f: '!FW_PSP_SMUSCS_2',  # seems to be a secondary FW_PSP_SMUSCS (see above)
        0x112: '!SMU_OFF_CHIP_FW_3',  # seems to tbe a tertiary SMU image (see above)
        0x39: '!SEV_APP',
        0x30062: '0x30062~UEFI-IMAGE~'

    }

    class ParseError(Exception):
        pass

    @classmethod
    def from_fields(cls, parent_directory, parent_buffer, type_, size, offset):
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

        self.type = type_
        self.references = [parent_directory]

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
            return self.DIRECTORY_ENTRY_TYPES[self.type]
        else:
            return ''

    def get_readable_version(self):
        return ''

    def get_readable_magic(self):
        return ''

    def get_readable_signed_by(self):
        return ''

    def shannon_entropy(self):
        return shannon(self[:])

    def move_buffer(self, new_address, size):
        current_address = self.get_address()
        move_offset = new_address - current_address
        self.buffer_offset += move_offset
        self.buffer_size = size

        # update all directories' header that point to this entry
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


class HeaderEntry(Entry):
    def _parse(self):
        self.header = NestedBuffer(self, 0x100)

        # todo: use NestedBuffers instead of saving by value
        self.magic = self.header[0x10:0x14]
        self.size_signed = struct.unpack('<I', self.header[0x14:0x18])[0]
        self.encrypted = struct.unpack('<I', self.header[0x18:0x1c])[0]
        self.signature_fingerprint = hexlify(self.header[0x38:0x48])
        self.compressed = struct.unpack('<I', self.header[0x48:0x4c])[0]
        self.size_full = struct.unpack('<I', self.header[0x50:0x54])[0]
        self.version = self.header[0x63:0x5f:-1]
        self.unknown = struct.unpack('<I', self.header[0x68:0x6c])[0]
        self.size_packed = struct.unpack('<I', self.header[0x6c:0x70])[0]

        self.unknown_fingerprint1 = hexlify(self.header[0x20:0x30])
        self.unknown_bool = struct.unpack('<I', self.header[0x7c:0x80])[0]
        self.unknown_fingerprint2 = hexlify(self.header[0x80:0x90])

        assert(self.compressed in [0, 1])
        assert(self.encrypted in [0, 1])

        # update buffer size with more precise size_packed
        self.buffer_size = self.size_packed

        self.body = NestedBuffer(self, len(self) - 0x200, 0x100)
        self.signature = NestedBuffer(self, 0x100, len(self) - 0x100)

    def get_readable_version(self):
        return '.'.join([hex(b)[2:].upper() for b in self.version])

    def get_readable_magic(self):
        if self.magic == b'\x01\x00\x00\x00':
            # actually twice as long, but SMURULESMURULES is kinda redundant
            readable_magic= self[0x0:0x4]
        elif self.magic == b'\x05\x00\x00\x00':
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
        if self.signature_fingerprint in self.parent_buffer.pubkeys:
            pubkey_entry = self.parent_buffer.pubkeys[self.signature_fingerprint]

            return pubkey_entry.get_readable_type()

    def shannon_entropy(self):
        return shannon(self.body[:])
