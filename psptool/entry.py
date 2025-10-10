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
if TYPE_CHECKING:
    from directory import Directory

from .utils import NestedBuffer


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
        if self.rsv0 & (1 << 31):  # Zen 4 + 5
            return self.parent_directory.buffer_offset + self.offset
        else:  # old style
            return self.offset & self.parent_directory.rom.addr_mask
    
    @property
    def type(self):
        return struct.unpack('<B', self[0:1])[0]

    @type.setter
    def type(self, value):
        self.set_bytes(0, 1, struct.pack('<B', value))

    @property
    def subprogram(self):
        return struct.unpack('<B', self[1:2])[0]

    @subprogram.setter
    def subprogram(self, value):
        self.set_bytes(1, 1, struct.pack('<B', value))

    @property
    def flags(self):
        return struct.unpack('<H', self[2:4])[0]

    @flags.setter
    def flags(self, value):
        self.set_bytes(2, 2, struct.pack('<H', value))

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
        self.set_bytes(4, 4, struct.pack('<I', value))

    @property
    def offset(self):
        return struct.unpack('<I', self[8:12])[0]

    @offset.setter
    def offset(self, value):
        self.set_bytes(8, 4, struct.pack('<I', value))

    @property
    def rsv0(self):
        return struct.unpack('<I', self[12:16])[0]

    @rsv0.setter
    def rsv0(self, value):
        self.set_bytes(12, 4, struct.pack('<I', value))


class BiosDirectoryEntry(DirectoryEntry):
    ENTRY_SIZE = 4 * 6

    def __repr__(self):
        return super().__repr__()[:-1] + f', {self.destination=:#x})'

    @property
    def destination(self):
        return struct.unpack('<Q', self[16:24])[0]

    @destination.setter
    def destination(self, value):
        self.set_bytes(16, 8, struct.pack('<Q', value))

    @property
    def region_type(self):
        return struct.unpack('<B', self[1:2])[0]

    @region_type.setter
    def region_type(self, value):
        self.set_bytes(1, 1, struct.pack('<B', value))

    @property
    def flags(self):
        return struct.unpack('<H', self[2:4])[0]

    @flags.setter
    def flags(self, value):
        self.set_bytes(2, 2, struct.pack('<H', value))

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
