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

from .utils import NestedBuffer
from .directory import Directory

from typing import List


class Fet(NestedBuffer):
    def __init__(self, parent_buffer, fet_offset: int, agesa_version, psptool):

        # The nested buffer that represents the whole binary
        self.blob = parent_buffer
        self.psptool = psptool

        self.fet_offset = fet_offset

        self.agesa_version = agesa_version
        self.directories: List[Directory] = []

        self._determine_size()
        self._determine_rom()

        super().__init__(parent_buffer, len(parent_buffer), buffer_offset=self.blob_offset)

        # TODO: Don't assume this offset
        self.fet = NestedBuffer(self, self.fet_size, buffer_offset=0x20000)

        self._parse_entry_table()

    def __repr__(self):
        return f'Fet(len(directories)={len(self.directories)})'

    def _determine_size(self):
        size = 0
        step_size = 4
        end_sequence = 2 * b'\xff\xff\xff\xff'

        while self.blob[
              (self.fet_offset + size)
              :(self.fet_offset + size + len(end_sequence))
              ] != end_sequence:
            size += step_size

        self.fet_size = size

    def _determine_rom(self):
        self.mask = 0x00FFFFFF
        self.blob_offset = self.fet_offset - 0x20000  # TODO don't assume this offset

    def _create_dir(self, addr, magic):
        if magic == b'$PSP':
            type_ = "PSP"
        elif magic == b'$BHD':
            type_ = "BIOS"
        else:
            # TODO: Better warning
            # print_warning("Weird PSP Combo directory. Please report this")
            return
        dir_ = Directory(self, addr, type_, self.blob, self.psptool)
        self.directories.append(dir_)
        if dir_.secondary_directory_address is not None:
            self.directories.append(
                Directory(self, dir_.secondary_directory_address, 'secondary', self.blob, self.psptool)
            )

    def _parse_entry_table(self):
        entries = self.fet.get_chunks(4, 4)
        for _index, entry in enumerate(entries):
            addr = int.from_bytes(entry, 'little')
            # TODO: Why is 0xFFFFFFFe a possible value here?
            if addr in [0x0, 0xFFFFFFFF, 0xFFFFFFFe]:
                continue
            addr &= self.mask
            try:
                dir_magic = self[addr:addr + 4]
            except:
                print(f"FET entry 0x{addr:x} not found or invalid, skipping ...")
                continue
            if dir_magic == b'2PSP':
                combo_addresses = self._parse_combo_dir(addr)
                for addr in combo_addresses:
                    dir_magic = self[addr:addr + 4]
                    self._create_dir(addr, dir_magic)
            else:
                self._create_dir(addr, dir_magic)

    def _parse_combo_dir(self, dir_addr):
        addresses = []
        nr_entries = int.from_bytes(self[dir_addr + 8: dir_addr + 0xc],
                                    'little')
        combo_dir = self[dir_addr: dir_addr + 16 * (nr_entries + 2)]

        # Combo dir entries seem to begin at offset 0x20, make sure we don't
        # miss directories that don't adhere to that rule
        assert(combo_dir[0x10:0x20] == (b'\x00' * 16))

        for i in range(2, nr_entries+2):
            entry = combo_dir[i * 16 + 0x8: i * 16 + 0xc]
            entry_addr = int.from_bytes(entry, 'little')
            if entry_addr in [0, 0xFFFFFFFF]:
                continue
            entry_addr &= self.mask
            # entry_addr += self.blob_offset
            addresses.append(entry_addr)

        return addresses
