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

from .utils import NestedBuffer, chunker, fletcher32
from .entry import Entry, BIOS_ENTRY_TYPES

from typing import List


class Directory(NestedBuffer):
    ENTRY_FIELDS = [
        'type',
        'size',
        'offset',
        'rsv0',
        'rsv1',
        'rsv2'
    ]

    _HEADER_SIZES = {
        b'$PSP': 4 * 4,
        b'$PL2': 4 * 4,
        b'$BHD': 4 * 4,
        b'$BL2': 4 * 4
    }

    _ENTRY_SIZES = {
        b'$PSP': 4 * 4,
        b'$PL2': 4 * 4,
        b'$BHD': 4 * 6,
        b'$BL2': 4 * 6
    }

    _ENTRY_TYPES_SECONDARY_DIR = [0x40, 0x70]
    _ENTRY_TYPES_PUBKEY = [0x0, 0x9, 0xa, 0x5, 0xd]

    def __init__(self, parent_rom, rom_address: int, type_: str, psptool):
        self.rom = parent_rom

        # The offset of this directory as specified in the FET
        self.buffer_offset = rom_address

        self.psptool = psptool
        self.checksum = None
        self._count = None

        # a directory must parse itself before it knows its size and can initialize its buffer
        self._parse_header()

        super().__init__(self.rom, self.buffer_size, buffer_offset=self.buffer_offset)

        self.type = type_
        self.entries: List[Entry] = []

        self._entry_size = self._ENTRY_SIZES[self.magic]

        self._parse_entries()

        # check entries for a link to a secondary directory (i.e. a continuation of this directory)
        self.secondary_directory_address = None
        for entry in self.entries:
            if entry.type in self._ENTRY_TYPES_SECONDARY_DIR:
                # print_warning(f"Secondary dir at 0x{entry.buffer_offset:x}")
                self.secondary_directory_address = entry.buffer_offset

        self.verify_checksum()

    def __repr__(self):
        return f'Directory(address={hex(self.get_address())}, type={self.type}, magic={self.magic}, count={self.count})'

    @property
    def count(self):
        return self._count

    @count.setter
    def count(self, value):
        self._count = value

        # update binary representation
        self.header[8:12] = struct.pack('<I', self.count)
        self.update_checksum()

    def _parse_header(self):
        # ugly to do this manually, but we do not know our size yet
        self._count = int.from_bytes(
            self.rom[self.buffer_offset + 8: self.buffer_offset + 12],
            'little'
        )
        self.magic = self.rom.get_bytes(self.buffer_offset, 4)

        self.header = NestedBuffer(
            self,
            self._HEADER_SIZES[self.magic]
        )
        self.body = NestedBuffer(
            self,
            self._ENTRY_SIZES[self.magic] * self._count,
            buffer_offset=self._HEADER_SIZES[self.magic]
        )

        self.buffer_size = len(self.header) + len(self.body)
        self.checksum = NestedBuffer(self, 4, 4)

    def _parse_entries(self):
        self.entries = []

        for entry_bytes in self.body.get_chunks(self._entry_size):
            entry_fields = {}
            for key, word in zip(self.ENTRY_FIELDS, chunker(entry_bytes, 4)):
                entry_fields[key] = struct.unpack('<I', word)[0]

            entry_fields['offset'] &= self.rom.addr_mask
            destination = None

            if entry_fields['type'] in BIOS_ENTRY_TYPES:
                destination = struct.unpack('<Q', entry_bytes[0x10:0x18])[0]

            try:
                entry = Entry.from_fields(self, self.parent_buffer,
                                          entry_fields['type'],
                                          entry_fields['size'],
                                          entry_fields['offset'],
                                          self.rom,
                                          self.psptool,
                                          destination=destination)
            except:
                self.psptool.ph.print_warning(f"Entry of {self} at {hex(entry_fields['offset'])} cannot be parsed")
                continue

            for existing_entry in self.rom.unique_entries:
                if entry == existing_entry:
                    existing_entry.references.append(self)

            self.entries.append(entry)
            self.rom.unique_entries.add(entry)

    def verify_checksum(self):
        data = self[0x8:]
        checksum = self.checksum.get_bytes()
        calculated_checksum = fletcher32(data)
        if checksum == calculated_checksum:
            return
        self.psptool.ph.print_warning(f"Could not verify checksum for directory {self}")

    def update_checksum(self):
        data = self[0x8:]  # checksum is calculated from after the checksum field in the header
        self.checksum.set_bytes(0, 4, fletcher32(data))

    def update_entry_fields(self, entry: Entry, type_, size, offset):
        entry_index = None
        for index, my_entry in enumerate(self.entries):
            if my_entry.type == entry.type:
                entry_index = index
                break

        assert(entry_index is not None)

        # apparently this masking is still needed for the PSP to parse stuff correctly
        offset |= 0xFF000000

        # update type, size, offset (but not rsv0 (nor rsv1 nor rsv2 in $BHD/$BLD directories))
        entry_bytes = b''.join([struct.pack('<I', value) for value in [type_, size, offset]])

        self.body.set_bytes(
            self._entry_size * entry_index,
            len(entry_bytes),
            entry_bytes
        )

        self.update_checksum()
