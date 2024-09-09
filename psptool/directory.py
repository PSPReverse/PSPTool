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

from .entry import DirectoryEntry, BiosDirectoryEntry
from .utils import NestedBuffer, fletcher32
from .file import File, BiosFile, SECONDARY_DIRECTORY_ENTRY_TYPES, TERTIARY_DIRECTORY_ENTRY_TYPES

from typing import List


class Directory(NestedBuffer):
    DIRECTORY_MAGICS = [b'$PSP', b'$PL2']
    HEADER_SIZE = 4 * 4

    ENTRY_CLASS = DirectoryEntry
    ENTRY_SIZE = DirectoryEntry.ENTRY_SIZE
    FILE_CLASS = File

    # all directories by offset in rom
    # todo: what if we have multi-ROM? then two ROMs share this singleton!
    directories_by_offset = {}

    class ParseError(Exception):
        pass

    @classmethod
    def bios_directory_class(cls):
        return BiosDirectory

    @classmethod
    def create_directories_if_not_exist(cls, offset, fet) -> List['Directory']:
        # Recursively return or create and return found directories
        if offset in cls.directories_by_offset:
            return [cls.directories_by_offset[offset]]
        else:
            # 1. Create the immediate directory in front of us
            created_directories = []
            directory = cls.from_offset(fet, offset)
            cls.directories_by_offset[offset] = directory
            created_directories.append(directory)

            # 2. Recursively add secondary directories referenced by the just created directory, if applicable
            for secondary_directory_offset in directory.secondary_directory_offsets:
                secondary_directories = cls.create_directories_if_not_exist(secondary_directory_offset, fet)
                created_directories += secondary_directories

            # 3. Recursively add tertiary directories (double references introduced in Zen 4), if applicable
            for tertiary_directory_offset in directory.tertiary_directory_offsets:
                directory_body = fet.rom.get_bytes(tertiary_directory_offset + 16, 8)
                actual_tertiary_offset = int.from_bytes(directory_body[:4], 'little')
                # Resolve one more indirection
                tertiary_directories = cls.create_directories_if_not_exist(actual_tertiary_offset, fet)
                created_directories += tertiary_directories

            return created_directories

    @classmethod
    def from_offset(cls, fet, rom_offset):
        rom_offset &= fet.rom.addr_mask
        magic = fet.rom.get_bytes(rom_offset, 4)

        if magic in cls.DIRECTORY_MAGICS:
            return cls(fet.rom, rom_offset, fet.psptool)
        elif magic in BiosDirectory.DIRECTORY_MAGICS:
            return cls.bios_directory_class()(fet.rom, rom_offset, fet.psptool)
        else:
            raise Directory.ParseError

    def __init__(self, parent_rom, offset: int, psptool, zen_generation=None):
        # todo: incorporate zen generation from combo dirs
        self.rom = parent_rom
        self.buffer_offset = offset
        self.psptool = psptool
        self.zen_generation = zen_generation
        self.bios_directory_type = BiosDirectory

        # a directory must parse itself before it knows its size and can initialize its buffer
        self._count = int.from_bytes(self.rom[self.buffer_offset + 8: self.buffer_offset + 12], 'little')
        self.magic = self.rom.get_bytes(self.buffer_offset, 4)
        assert self.magic in self.DIRECTORY_MAGICS
        self.reserved = self.rom.get_bytes(self.buffer_offset + 12, 4)
        self.header = NestedBuffer(self, self.HEADER_SIZE)
        self.body = NestedBuffer(self, self.ENTRY_SIZE * self.count, buffer_offset=self.HEADER_SIZE)
        self.buffer_size = len(self.header) + len(self.body)
        self.checksum = NestedBuffer(self, 4, 4)

        # now initialize the buffer
        super().__init__(self.rom, self.buffer_size, buffer_offset=self.buffer_offset)

        self.entries: List[DirectoryEntry] = []
        self.files: List[File] = []

        # parse entries
        for entry_bytes in self.body.get_chunks(self.ENTRY_SIZE):
            self.entries.append(self.ENTRY_CLASS(entry_bytes, self))

        # create/link files
        for entry in self.entries:
            file = self.FILE_CLASS.create_file_if_not_exists(self, entry)
            if file is not None:
                self.files.append(file)

        # check entries for a link to a secondary directory (i.e. a continuation of this directory)
        self.secondary_directory_offsets = []
        self.tertiary_directory_offsets = []

        for entry in self.entries:
            if entry.type in SECONDARY_DIRECTORY_ENTRY_TYPES:
                self.secondary_directory_offsets.append(entry.file_offset())
            elif entry.type in TERTIARY_DIRECTORY_ENTRY_TYPES:
                self.tertiary_directory_offsets.append(entry.file_offset())

        self.verify_checksum()

    def __repr__(self):
        return f'{self.__class__.__name__}(address={hex(self.get_address())}, magic={self.magic}, count={self.count})'

    @property
    def count(self):
        return self._count

    @count.setter
    def count(self, value):
        self._count = value

        # update binary representation
        self.header[8:12] = struct.pack('<I', self.count)
        self.update_checksum()

    @property
    def address_mode(self):
        rsvd = struct.unpack('=L', self.reserved)[0]
        return (rsvd & 0x60000000) >> 29 if rsvd != 0 else None
    # todo: do we need to still consider the address_mode somewhere?
    #   at the moment we seem to be running fine by checking entry.rsv0 & (1 << 30) to figure out if we need
    #   directory-relative or absolute addressing

    def verify_checksum(self):
        data = self[0x8:]
        checksum = self.checksum.get_bytes()
        calculated_checksum = fletcher32(data)
        if checksum == calculated_checksum:
            return
        self.psptool.ph.print_warning(f"Could not verify fletcher checksum for directory {self}")

    def update_checksum(self):
        data = self[0x8:]  # checksum is calculated from after the checksum field in the header
        self.checksum.set_bytes(0, 4, fletcher32(data))

    def update_entry_fields(self, entry: File, type_, size, offset):
        entry_index = None
        for index, my_entry in enumerate(self.entries):
            if my_entry.type == entry.type:
                entry_index = index
                break

        assert(entry_index is not None)

        # apparently this masking is still needed for the PSP to parse stuff correctly
        offset |= 0xFF000000

        # update type, size, offset (rsv0 (nor rsv1 nor rsv2 in $BHD/$BLD directories))
        self.body.set_bytes(self._entry_size * entry_index + 0, 2, struct.pack('<H', type_))
        # todo: allow updating the address_mode which consists of two bytes right here
        self.body.set_bytes(self._entry_size * entry_index + 4, 4, struct.pack('<I', size))
        self.body.set_bytes(self._entry_size * entry_index + 8, 4, struct.pack('<I', offset))

        self.update_checksum()


class BiosDirectory(Directory):
    DIRECTORY_MAGICS = [b'$BHD', b'$BL2']

    ENTRY_CLASS = BiosDirectoryEntry
    ENTRY_SIZE = BiosDirectoryEntry.ENTRY_SIZE
    FILE_CLASS = BiosFile
