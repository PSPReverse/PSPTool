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

from typing import TYPE_CHECKING
from enum import IntEnum
if TYPE_CHECKING:
    from directory import Directory

from .utils import NestedBuffer

class AddressMode(IntEnum):
    PHYSICAL = 0                # x86 Physical address
    REL_BIOS = 1                # Offset from start of the BIOS (flash offset) most common on modern systems
    REL_DIR = 2                 # Offset from start of directory header
    REL_SLOT = 3                # Offset from start of partition

class DirectoryEntry(NestedBuffer):
    ENTRY_SIZE = 4 * 4

    def __init__(self, parent_directory: 'Directory', entry_offset):
        super().__init__(parent_directory.body, self.ENTRY_SIZE, entry_offset)
        self.parent_directory = parent_directory
        self.entry_offset = entry_offset

    def __repr__(self):
        return f'{self.__class__.__name__}({self.type=:#x}, {self.flags=:#x}, {self.size=:#x}, ' \
               f'{self.offset=:#x}, {self.entry_offset=:#x}, {self.rsv0=:#x})'

    def file_offset(self):
        # Special case soft fuse chain, no offset or size
        if self.type == 0xb:
            dir_start = self.parent_directory.buffer_offset + self.parent_directory.HEADER_SIZE
            return dir_start + self.entry_offset

        addr_mode = self.parent_directory.address_mode
        # If directory address mode is relative to dir or slot, the
        # entry address mode must be taken into account, otherwise ignored.
        if addr_mode == AddressMode.REL_DIR or addr_mode == AddressMode.REL_SLOT:
            addr_mode = self.address_mode
        # coreboot's amdfwtool writes APOB NV entries on older SoCs as an x86
        # physical address in a directory with relative-to-bios mode. No
        # flash offset reaches 0xff000000.
        elif addr_mode == AddressMode.REL_BIOS and self.address_mode == AddressMode.PHYSICAL and self.offset >= 0xFF000000:
            addr_mode = AddressMode.PHYSICAL

        if addr_mode == AddressMode.PHYSICAL:
            # x86 physical address, should be in range 0xff000000 - 0xffffffff
            # But some images use flash offset in x86 physical address mode.
            # If ROM is bigger than 16MB and the entry address is in the
            # 0xff000000 - 0xffffffff range, we have to override the mask for
            # physical address.
            rom_size = self.parent_directory.rom.addr_mask + 1
            if self.offset > 0xFF000000 and rom_size > 16 * 1024 * 1024:
                return self.offset & 0x00FFFFFF
            else:
                return self.offset & self.parent_directory.rom.addr_mask
        elif addr_mode == AddressMode.REL_BIOS:
            return self.offset
        elif addr_mode == AddressMode.REL_DIR:
            return self.parent_directory.buffer_offset + self.offset
        elif addr_mode == AddressMode.REL_SLOT:
            # TODO: How to calculate the offset from slot? Is this correct?
            return self.parent_directory.buffer_offset + self.offset

    @property
    def type(self):
        return struct.unpack('<B', self[0:1])[0]

    @type.setter
    def type(self, value):
        self.set_bytes(0, struct.pack('<B', value))

    @property
    def subprogram(self):
        return struct.unpack('<B', self[1:2])[0]

    @subprogram.setter
    def subprogram(self, value):
        self.set_bytes(1, struct.pack('<B', value))

    @property
    def flags(self):
        return struct.unpack('<H', self[2:4])[0]

    @flags.setter
    def flags(self, value):
        self.set_bytes(2, struct.pack('<H', value))

    @property
    def instance(self):
        return (self.flags >> 3) & 0xF

    @instance.setter
    def instance(self, value):
       self.flags = self.flags | ((value & 0xF) << 3)

    @property
    def size(self):
        return struct.unpack('<I', self[4:8])[0]

    @size.setter
    def size(self, value):
        self.set_bytes(4, struct.pack('<I', value))

    @property
    def offset(self):
        return struct.unpack('<I', self[8:12])[0]

    @offset.setter
    def offset(self, value):
        self.set_bytes(8, struct.pack('<I', value))

    @property
    def rsv0(self):
        return struct.unpack('<I', self[12:16])[0]

    @rsv0.setter
    def rsv0(self, value):
        self.set_bytes(12, struct.pack('<I', value))

    @property
    def address_mode(self) -> AddressMode:
        return AddressMode((self.rsv0 >> 30) & 3)

class BiosDirectoryEntry(DirectoryEntry):
    ENTRY_SIZE = 4 * 6

    def __repr__(self):
        return super().__repr__()[:-1] + f', {self.destination=:#x})'

    @property
    def destination(self):
        return struct.unpack('<Q', self[16:24])[0]

    @destination.setter
    def destination(self, value):
        self.set_bytes(16, struct.pack('<Q', value))

    @property
    def region_type(self):
        return struct.unpack('<B', self[1:2])[0]

    @region_type.setter
    def region_type(self, value):
        self.set_bytes(1, struct.pack('<B', value))

    @property
    def flags(self):
        return struct.unpack('<H', self[2:4])[0]

    @flags.setter
    def flags(self, value):
        self.set_bytes(2, struct.pack('<H', value))

    @property
    def subprogram(self):
        return (self.flags >> 8) & 0x7

    @subprogram.setter
    def subprogram(self, value):
       self.flags = self.flags | ((value & 0x7) << 8)

    @property
    def instance(self):
        return (self.flags >> 4) & 0xF

    @instance.setter
    def instance(self, value):
       self.flags = self.flags | ((value & 0xF) << 4)
