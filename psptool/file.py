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

    @classmethod
    def create_file_if_not_exists(cls, directory: 'Directory', entry: 'DirectoryEntry'):
        # APOBs do not have location nor size, so can be easily mistaken as duplicated
        # in multi-ROM files. There should be only one APOB per BIOS directory anyways.
        if type(entry) == BiosDirectoryEntry and entry.type == 0x61:
            file = cls.from_entry(directory, directory.parent_buffer, entry, directory.rom, directory.psptool)
            if file is not None:
                return file
        elif entry.file_offset() in directory.psptool.files_by_offset:
            existing_file = directory.psptool.files_by_offset[entry.file_offset()]
            existing_file.references.append(directory)
            return existing_file
        else:
            file = cls.from_entry(directory, directory.parent_buffer, entry, directory.rom, directory.psptool)
            if file is not None:
                directory.psptool.files_by_offset[entry.file_offset()] = file
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
        0x15: 'TEE_IP_KEY_MGR_DRIVER',
        0x1A: 'PSP_S3_NV_DATA_OR_SEV_DRIVER',
        0x1B: 'TEE_BOOT_DRIVER',
        0x1C: 'TEE_SOC_DRIVER',
        0x1D: 'TEE_FBG_DRIVER',
        0x1F: 'TEE_INTERFACE_DRIVER',
        0x20: 'HARDWARE_IP_CONFIG',
        0x21: 'WRAPPED_IKEK',
        0x22: 'TOKEN_UNLOCK',
        0x23: 'PSP_DIAG_BL',
        0x24: 'SEC_GASKET',
        0x25: 'MP2_FW',
        0x26: 'MP2_FW_2',
        0x27: 'USER_MODE_UNIT_TEST',
        0x28: 'DRIVER_ENTRIES',
        0x29: 'KVM_IMAGE',
        0x2A: 'MP5_FW',
        0x2B: 'EMBEDDED_FW_STRUCTURE',
        0x2C: 'TEE_WRITE_ONCE_NVRAM',
        0x2D: 'S0I3_DRIVER',
        0x2E: 'PREMIUM_CHIPSET_MP0_DXIO_FW',
        0x2F: 'PREMIUM_CHIPSET_MP1_FW',
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
        0x3D: 'WLAN_UMAC',
        0x3E: 'WLAN_IMAC',
        0x3F: 'WLAN_BT',
        0x40: 'PSP_FW_L2_PTR',
        0x41: 'FW_IMC',
        0x42: 'FW_GEC_OR_DXIO_PHY_SRAM_FW',
        0x43: 'DXIO_PHY_SRAM_FW_PUBKEY',
        0x44: 'FW_XHCI',
        0x45: 'TOS_SECURITY_POLICY',
        0x46: 'ANOTHER_FET',
        0x47: 'DRTM_TA',
        0x48: 'PSP_FW_L2A_PTR',
        0x49: 'BIOS_L2AB_PTR',
        0x4a: 'PSP_FW_L2B_PTR',
        0x4b: 'RESERVED',
        0x4c: 'PREMIUM_CHIPSET_SEC_POLICY',
        0x4d: 'PREMIUM_CHIPSET_DEBUG_UNLOCK',
        0x4e: 'PMU_PUBKEY',
        0x4f: 'UMC_FW',
        0x50: 'BL_PUBLIC_KEY',
        0x51: 'TOS_PUBLIC_KEY',
        0x52: 'OEM_PSP_BL_USER_APP',
        0x53: 'OEM_PSP_BL_USER_APP_KEY',
        0x54: 'PSP_NVRAM',
        0x55: 'BL_ROLLBACK_SPL',
        0x56: 'TOS_ROLLBACK_SPL',
        0x57: 'PSP_BL_CVIP_TABLE',
        0x58: 'DMCU_ERAM',
        0x59: 'DMCU_ISR',
        0x5a: 'MSMU_BINARY_0',
        0x5b: 'MSMU_BINARY_1',
        0x5c: 'WMOS',
        0x5d: 'MPIO_FW',
        0x5e: 'DF_TOPOLOGY',
        0x5f: 'FW_PSP_SMUSCS_OR_TPMLITE',
        0x64: 'TEE_RAS_DRIVER',
        0x65: 'TEE_RAS_TRUSTED_APP',
        0x67: 'TEE_FHP_DRIVER_FW',
        0x68: 'TEE_SPDM_DRIVER_FW',
        0x69: 'TEE_DPE_DRIVER_FW',
        0x6a: 'TEE_PRE_MEM_DRIVER_FW',
        0x6b: 'TEE_MP_RAS_DRIVER_FW',
        0x6c: 'TEE_POST_MEM_DRIVER_FW',
        0x70: 'BIOS_L2_PTR',
        0x71: 'PSP_DMCUB_CODE',
        0x72: 'PSP_DMCUB_DATA',
        0x73: 'PSP_FW_BOOT_LOADER',
        0x74: 'PSP_PLATFORM_DRIVER',
        0x75: 'FW_SOFT_FUSING_BINARY',
        0x76: 'REGISTER_INIT_BIN',
        0x80: 'OEM_SYS_TA',
        0x81: 'OEM_SYS_TA_SIGNING_KEY',
        0x82: 'IKEK_OEM',
        0x84: 'TKEK_OEM',
        0x85: 'AMF_FW1',
        0x86: 'AMF_FW2',
        0x87: 'MFD_MPM_FACTORY',
        0x88: 'MFD_MPM_WLAN_FW',
        0x89: 'MPM_DRIVER',
        0x8A: 'USB4_PHY_FW',
        0x8B: 'FIPS_CERTIFICATION_MODULE',
        0x8C: 'MPDMA_TF_FW',
        0x8D: 'IKEK_TA',
        0x8E: 'SEC_FW_DATA_RECORDER',
        0x8F: 'OFFCHIP_USB4_FW',
        0x90: 'CCX_CORE_INIT_AND_PM',
        0x91: 'GMI3_PHY_FW',
        0x92: 'MPDMA_MPDACC_TIERED_MEMORY_PAGE_MIGRATION_FW',
        0x93: 'PROM21_FW',
        0x94: 'LSDMA_FW',
        0x95: 'C20_PHY_FW',
        0x96: 'NPU_FW',
        0x97: 'AMD_SFFS_PUBKEY',
        0x98: 'CPU_FEAT_CONFIG_TBL',
        0x99: 'PMF_BINARY',
        0x9A: 'REDUCED_MSMU_SIZE',
        0x9B: 'GFX_IMU_LX7_CODE',
        0x9C: 'GFX_IMU_LX7_DATA',
        0x9D: 'FW_ROM_OR_FIPS_SRAM',
        0x9E: 'SFDR_DATA',
        0x9F: 'REG_ACCESS_WHITELIST',
        0xA0: 'CPU_S3_IMAGE',
        0xA2: 'UZSC_RESET_WORKAROUND',
        0xA3: 'USB_NATIVE_DP',
        0xA4: 'USB_TYPEC_DP',
        0xA5: 'USB_SS_FW',
        0xA6: 'USB4',
        0xA7: 'OFFCHIP_XHCI_SATA_PCIE',
        0xAA: 'ASP_LIBSEC',
        0xAB: 'ART_FMC_IMG',
        0xAC: 'ART_RUNTIME_FW',
        0xAD: 'ART_KEY_DATABASE',
        0xAE: 'SEC_ASP_LIBROM_OVERLAY_FW',
        0xB0: 'MPM_CONTEXT',
    }

    # Entry types which overlap the type value with PSP directory, but are present only in BIOS directory
    BIOS_DIRECTORY_ENTRY_TYPES = {
        0x60: 'APCB',
        0x61: 'APOB',
        0x62: 'BIOS',
        0x63: 'APOB_NV_COPY',
        0x64: 'PMU_CODE',
        0x65: 'PMU_DATA',
        0x66: 'MICROCODE_PATCH',
        0x67: 'CORE_MCE_DATA',
        0x68: 'APCB_COPY',
        0x69: 'EARLY_VGA_IMAGE',
        0x6B: 'COREBOOT_VBOOT_CONTEXT',
        0x6D: 'ROM_ARMOR_BIOS_NVSTORE',
        0x6E: 'DEBUG_UNIT',
        0x6F: 'OEM_LOGO_IMAGE',
        0x77: 'DDRPHY_PCU_FW',
        0x7B: 'MPRAS_TRUSTRED_APP_IMG',
        0x7C: 'OC_SWEET_SPOT_PROFILE',
    }

    PUBKEY_ENTRY_TYPES = [0x0, 0x9, 0xa, 0x5, 0xd, 0x43, 0x4e, 0x53, 0x81, 0x97, 0xad ]

    # Types known to have no PSP HDR
    # TODO: Find a better way to identify those entries
    NO_HDR_ENTRY_TYPES = [0x4, 0xb, 0x21, 0x40, 0x48, 0x49, 0x4a, 0x70, 0x6, 0x61, 0x60, 0x68, 0x5f,
                          0x1a, 0x22, 0x63, 0x67, 0x66, 0x6d, 0x62, 0x61, 0x7, 0x38, 0x46, 0x54,
                          0x82, 0x84, 0x8d, 0x69, 0x7c, 0x98 ]

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
        from .microcode_file import MicrocodeFile

        try:
            if entry.type in cls.PUBKEY_ENTRY_TYPES:
                return PubkeyFile(*file_args)
            elif entry.type in File.KEY_STORE_TYPES:
                return KeyStoreFile(*file_args)
            elif entry.type not in cls.NO_HDR_ENTRY_TYPES + SECONDARY_DIRECTORY_ENTRY_TYPES:
                return HeaderFile(*file_args)
            elif type(entry) == BiosDirectoryEntry and entry.type == 0x66:
                return MicrocodeFile(*file_args)
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
            self.compressed = (self.entry.flags >> 3) & 1
        else:
            self.compressed = False

        # For entries without size, create buffer of directory entry size
        # at offset in directory
        if self.type in self.NO_SIZE_ENTRY_TYPES:
            dir_start = parent_directory.buffer_offset + parent_directory.HEADER_SIZE
            try:
                super().__init__(parent_buffer, entry.ENTRY_SIZE, dir_start + entry.entry_offset)
            except AssertionError as e:
                raise File.ParseError(e)
        # Some images break the rule of placing components on 16MB boundary.
        # Use entry.offset to get real offset in flash, not masked to 16MB to
        # detect entries that would overflow parent buffer. Because of this
        # the compressed entries cannot be uncompressed.
        elif parent_buffer.buffer_size >= entry.file_offset() + entry.size:
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
        if type(self.entry) == BiosDirectoryEntry:
            if self.type == 0x62:
                return "BIOS"
            if self.type == 0x61:
                return "APOB"
            if self.type in self.BIOS_DIRECTORY_ENTRY_TYPES:
                return f'{self.BIOS_DIRECTORY_ENTRY_TYPES[self.type]}~{hex(self.type)}'
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
    def __init__(self, parent_directory, parent_buffer, offset, entry, blob, psptool):
        super().__init__(parent_directory, parent_buffer, offset, entry, blob, psptool)
        self.destination = self.entry.destination

    def get_address(self) -> int:
        if self.get_readable_type() == "APOB":
            return 0
        elif isinstance(self.parent_buffer, NestedBuffer):
            return self.buffer_offset + self.parent_buffer.get_address()
        else:
            return self.buffer_offset

    def __repr__(self):
        return super().__repr__()[:-1] + f', destination={hex(self.destination)})'

    def get_readable_destination_address(self):
        return hex(self.destination)
