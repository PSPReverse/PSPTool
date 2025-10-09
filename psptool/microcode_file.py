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

from binascii import hexlify

from .file import BiosFile, File
from .header_file import HeaderFile

class MicrocodeFile(BiosFile):
    def __init__(self, parent_directory, parent_buffer, offset, entry, blob, psptool):
        super().__init__(parent_directory, parent_buffer, offset, entry, blob, psptool)

        # Sometime microcode files can be wrapped in a PSP blob header
        try:
            self.header = HeaderFile(parent_directory, parent_buffer, offset, entry, blob, psptool)
            self.body = self.header.get_decrypted_decompressed_body()
            self.date = struct.unpack('<I', self.body[0:4])[0]
            self.patch_level = struct.unpack('<I', self.body[4:8])[0]
        except File.ParseError as e:
            self.header = None
            self.date = struct.unpack('<I', self[0:4])[0]
            self.patch_level = struct.unpack('<I', self[4:8])[0]

        self.year = (self.date & 0xf) + (self.date >> 4 & 0xf) * 10
        self.year += ((self.date >> 8) & 0xf) * 100 + (self.date >> 12 & 0xf) * 1000
        self.month = (self.date >> 16 & 0xf) + ((self.date >> 20) & 0xf) * 10
        self.day = (self.date >> 24 & 0xf) + ((self.date >> 28) & 0xf) * 10

    def get_readable_version(self):
        if self.header is not None:
            return self.header.get_readable_version()

        return f'{hex(self.patch_level)}'
    
    def get_readable_magic(self):
        if self.header is not None:
            return self.header.get_readable_magic()

        return super().get_readable_magic()

    def get_readable_date(self):
        return '%.2d/%.2d/%.4d' % (self.day, self.month, self.year)

    def __repr__(self):
        return super().__repr__()[:-1] + self.get_readable_version() + self.get_readable_date()
