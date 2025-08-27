# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2021 Christian Werling, Robert Buhren, Hans Niklas Jacob
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
import struct

from .utils import NestedBuffer
from .utils import shannon
from .utils import zlib_find_header
from .entry import BiosDirectoryEntry

from enum import Enum

from math import ceil
from hashlib import md5

from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from .directory import Directory
    from .entry import DirectoryEntry

SECONDARY_DIRECTORY_ENTRY_TYPES = [0x40, 0x49, 0x70]
TERTIARY_DIRECTORY_ENTRY_TYPES = [0x48, 0x4a]

class File(NestedBuffer):
    # all files by offset
    # todo: what if we have multi-ROM? then two ROMs share this singleton!
    files_by_offset: Dict[int, 'File'] = {}

    @classmethod
    def create_file_if_not_exists(cls, directory: 'Directory', entry: 'DirectoryEntry'):
        if entry.file_offset() in cls.files_by_offset:
            existing_file = cls.files_by_offset[entry.file_offset()]
            existing_file.references.append(directory)
            return existing_file
        else:
            file = cls.from_entry(directory, directory.parent_buffer, entry, directory.rom, directory.psptool)
            if file is not None:
                cls.files_by_offset[entry.file_offset()] = file
                return file
        pass

    ENTRY_ALIGNMENT = 0x10

    UNWRAPPED_IKEK_ZEN_PLUS = b'\x4c\x77\x63\x65\x32\xfe\x4c\x6f\xd6\xb9\xd6\xd7\xb5\x1e\xde\x59'
    HASH_IKEK_ZEN_PLUS = b'\xe2\x84\xda\xe0\x6e\x58\x01\x04\xfa\x6e\x8e\x6b\x58\x68\x8a\x0c'

    UNWRAPPED_IKEK_ZEN = b'\x49\x1e\x40\x1a\x40\x1e\xc1\xb2\x28\x46\x00\xf0\x99\xfd\xe8\x68'
    HASH_IKEK_ZEN = b'\x47\x23\xa8\x52\x03\x38\xbd\x2e\xac\x5f\xae\x9c\x2c\xb5\x92\x5b'

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
        0x20: 'HARDWARE_IP_CONFIG',
        0x21: 'WRAPPED_IKEK',
        0x22: 'TOKEN_UNLOCK',
        0x24: 'SEC_GASKET',
        0x25: 'MP2_FW',
        0x26: 'MP2_FW_2',
        0x27: 'USER_MODE_UNIT_TEST',
        0x28: 'DRIVER_ENTRIES',
        0x29: 'KVM_IMAGE',
        0x2A: 'MP5_FW',
        0x2D: 'S0I3_DRIVER',
        0x30: 'ABL0',
        0x31: 'ABL1',
        0x32: 'ABL2',
        0x33: 'ABL3',
        0x34: 'ABL4',
        0x35: 'ABL5',
        0x36: 'ABL6',
        0x37: 'ABL7',
        0x38: 'SEV_DATA',
        0x39: 'SEV_CODE',
        0x3A: 'FW_PSP_WHITELIST',
        0x3C: 'VBIOS_PRELOAD',
        # 0x40: 'FW_L2_PTR',
        0x41: 'FW_IMC',
        0x42: 'FW_GEC',
        # 0x43: 'FW_XHCI',
        0x44: 'FW_INVALID',
        0x45: 'TOS_SECURITY_POLICY',
        0x47: 'DRTM_TA',
        0x51: 'TOS_PUBLIC_KEY',
        0x54: 'PSP_NVRAM',
        0x55: 'BL_ROLLBACK_SPL',
        0x5a: 'MSMU_BINARY_0',
        0x5c: 'WMOS',
        0x71: 'DMCUB_INS',
        0x46: 'ANOTHER_FET',
        0x50: 'KEY_DATABASE',
        0x5f: 'FW_PSP_SMUSCS',
        0x60: 'APCB',
        0x61: 'APOB',
        0x62: 'FW_XHCI',
        0x63: 'APOB_NV_COPY',
        0x64: 'PMU_CODE',
        0x65: 'PMU_DATA',
        0x66: 'MICROCODE_PATCH',
        0x67: 'CORE_MCE_DATA',
        0x68: 'APCB_COPY',
        0x69: 'EARLY_VGA_IMAGE',
        0x6A: 'MP2_FW_CFG',
        0x73: 'PSP_FW_BOOT_LOADER',
        0x80: 'OEM_System_Trusted_Application',
        0x81: 'OEM_System_TA_Signing_key',
        0x108: 'PSP_SMU_FN_FIRMWARE',
        0x118: 'PSP_SMU_FN_FIRMWARE2',

        # Entry types named by us
        #   Custom names are denoted by a leading '!'
        0x14: '!PSP_MCLF_TRUSTLETS',  # very similiar to ~PspTrustlets.bin~ in coreboot blobs
        0x40: '!PL2_SECONDARY_DIRECTORY',
        0x43: '!KEY_UNKNOWN_1',
        0x4e: '!KEY_UNKNOWN_2',
        0x70: '!BL2_SECONDARY_DIRECTORY',
        0x15f: '!FW_PSP_SMUSCS_2',  # seems to be a secondary FW_PSP_SMUSCS (see above)
        0x112: '!SMU_OFF_CHIP_FW_3',  # seems to tbe a tertiary SMU image (see above)
        0xdead: '!KEY_NOT_IN_DIR'

    }
    PUBKEY_ENTRY_TYPES = [0x0, 0x9, 0xa, 0x5, 0xd, 0x43, 0x4e, 0xdead]

    # Types known to have no PSP HDR
    # TODO: Find a better way to identify those entries
    NO_HDR_ENTRY_TYPES = [0x4, 0xb, 0x21, 0x40, 0x48, 0x49, 0x4a, 0x70, 0x6, 0x61, 0x60, 0x68, 0x5f,
                          0x1a, 0x22, 0x63, 0x67, 0x66, 0x6d, 0x62, 0x61, 0x7, 0x38, 0x46, 0x54, 0x8d,
                          0x69 ]

    NO_SIZE_ENTRY_TYPES = [0xb]
    KEY_STORE_TYPES = [0x50, 0x51]

    class ParseError(Exception):
        pass

    @classmethod
    def from_entry(cls, parent_directory, parent_buffer, entry, blob, psptool):
        if entry.type in cls.NO_SIZE_ENTRY_TYPES:
            entry.size = 0

        assert entry.file_offset() < len(parent_directory.rom), "File offset overflows ROM bounds!"
        file_args = [parent_directory, parent_buffer, entry.file_offset(), entry, blob, psptool]

        from .pubkey_file import PubkeyFile
        from .key_store_file import KeyStoreFile
        from .header_file import HeaderFile

        try:
            if entry.type in cls.PUBKEY_ENTRY_TYPES:
                return PubkeyFile(*file_args)
            elif entry.type in File.KEY_STORE_TYPES:
                return KeyStoreFile(*file_args)
            elif entry.type not in cls.NO_HDR_ENTRY_TYPES + SECONDARY_DIRECTORY_ENTRY_TYPES:
                return HeaderFile(*file_args)
            else:
                return cls(*file_args)
        except File.ParseError as e:
            psptool.ph.print_warning(f"ParseError from {entry}: \n  {e}")
            return None

    def __init__(self, parent_directory, parent_buffer, offset, entry, blob, psptool):
        self.blob = blob
        self.psptool = psptool
        self.entry = entry
        self.type = entry.type

        if type(entry) == BiosDirectoryEntry:
            self.compressed = (self.entry.type_flags >> 3) & 1
        else:
            self.compressed = False

        if parent_buffer.buffer_size >= offset + entry.size:
            try:
                super().__init__(parent_buffer, entry.size, buffer_offset=offset)
            except AssertionError as e:
                raise File.ParseError(e)
        else:
            if self.compressed:
                zlib_hdr = zlib_find_header(self.blob[offset:])
                if zlib_hdr != -1:
                    zlib_size = int.from_bytes(
                        self.blob.get_bytes(offset + 0x14, 4),
                        'little'
                    )
                    super().__init__(parent_buffer, zlib_hdr + zlib_size, buffer_offset=offset)
                    self.size_uncompressed = entry.size
                else:
                    self.psptool.ph.print_warning("Entry compressed but no zlib header found")
                    raise File.ParseError()
                    return
            else:
                self.psptool.ph.print_warning("Entry size exceed parent buffer bounds")
                raise File.ParseError()
                return

        self.encrypted = False
        self.is_legacy = False
        self.size_uncompressed = 0

        if parent_directory is not None:
            self.references = [parent_directory]
        self.parent_directory = parent_directory

        self._parse()

    @property
    def is_signed(self) -> bool:
        return False

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
        if self.type == 0x62:
            return "BIOS"
        if self.type in self.DIRECTORY_ENTRY_TYPES:
            return f'{self.DIRECTORY_ENTRY_TYPES[self.type]}~{hex(self.type)}'
        else:
            return hex(self.type)

    def get_readable_destination_address(self):
        return hex(self.entry.destination)

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


class BiosFile(File):
    pass
