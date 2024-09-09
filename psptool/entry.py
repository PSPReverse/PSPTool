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


class DirectoryEntry:
    ENTRY_SIZE = 4 * 4

    def __init__(self, entry_bytes, parent_directory: 'Directory'):
        assert len(entry_bytes) == self.ENTRY_SIZE

        self.type = struct.unpack('<H', entry_bytes[0:2])[0]
        self.type_flags = struct.unpack('<H', entry_bytes[2:4])[0]
        self.size = struct.unpack('<I', entry_bytes[4:8])[0]
        self.offset = struct.unpack('<I', entry_bytes[8:12])[0]
        self.rsv0 = struct.unpack('<I', entry_bytes[12:16])[0]

        self.parent_directory = parent_directory

    def __repr__(self):
        return f'{self.__class__.__name__}({self.type=:#x}, {self.type_flags=:#x}, {self.size=:#x}, ' \
               f'{self.offset=:#x}, {self.rsv0=:#x})'

    def file_offset(self):
        if self.rsv0 & (1 << 31):  # Zen 4 + 5
            return self.parent_directory.buffer_offset + self.offset
        else:  # old style
            return self.offset & self.parent_directory.rom.addr_mask


class BiosDirectoryEntry(DirectoryEntry):
    ENTRY_SIZE = 4 * 6

    def __init__(self, entry_bytes, parent_directory: 'Directory'):
        super().__init__(entry_bytes, parent_directory)
        self.destination = struct.unpack('<Q', entry_bytes[0x10:0x18])[0]

    def __repr__(self):
        return super().__repr__()[:-1] + f', {self.destination=:#x})'
