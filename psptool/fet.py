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


ZEN_GENERATION_IDS = {'Zen 1': [b'\x00\x09\xBC', b'\x00\x0A\xBC'],
                      'Zen 2': [b'\x05\x0B\xBC', b'\x01\x0A\xBC'],
                      'Zen 3': [b'\x01\x0C\xBC', b'\x00\x0C\xBC']}


class EmptyFet(Exception):
    pass


class Fet(NestedBuffer):
    def __init__(self, parent_rom, fet_offset: int, psptool):

        self.rom = parent_rom
        self.psptool = psptool
        self.directories: List[Directory] = []

        super().__init__(
            self.rom,
            self._determine_size(fet_offset),
            buffer_offset=fet_offset
        )

        self._parse_entry_table()

    def __repr__(self):
        return f'Fet(len(directories)={len(self.directories)})'

    def _determine_size(self, fet_offset):
        size = 0
        step_size = 4
        end_sequence = 4 * b'\xff\xff\xff\xff'

        while self.rom[
              (fet_offset + size)
              :(fet_offset + size + len(end_sequence))
              ] != end_sequence:
            size += step_size

        if size <= 0:
            raise EmptyFet()
        return size

    def _parse_entry_table(self):
        entries = self.get_chunks(4, 4)
        for _index, entry in enumerate(entries):
            rom_addr = int.from_bytes(entry, 'little')
            # TODO: Why is 0xFFFFFFFe a possible value here?
            if rom_addr in [0x0, 0xFFFFFFFF, 0xFFFFFFFe]:
                continue
            rom_addr &= self.rom.addr_mask
            try:
                dir_magic = self.rom[rom_addr:rom_addr + 4]
            except:
                self.psptool.ph.print_warning(f"FET entry 0x{rom_addr:x} not found or invalid, skipping ...")
                continue
            if dir_magic == b'2PSP' or dir_magic == b'2BHD':
                combo_results = self._parse_combo_dir(rom_addr)
                for result in combo_results:
                    combo_offset = result[0]
                    combo_zen_gen = result[1]
                    dir_magic = self.rom[combo_offset:combo_offset + 4]
                    dirs = Directory.create_directories_if_not_exist(combo_offset, self, combo_zen_gen)
                    for dir_ in dirs:
                        if dir_ not in self.directories:
                            self.directories.append(dir_)
            elif dir_magic == b'$PSP' or dir_magic == b'$BHD':
                dirs = Directory.create_directories_if_not_exist(rom_addr, self)
                for dir_ in dirs:
                    if dir_ not in self.directories:
                        self.directories.append(dir_)

    def _parse_combo_dir(self, dir_addr):
        results = []
        no_of_entries = int.from_bytes(self.rom[dir_addr + 8: dir_addr + 0xc], 'little')
        combo_dir = self.rom[dir_addr: dir_addr + 16 * (no_of_entries + 2)]

        # Combo dir entries seem to begin at offset 0x20, make sure we don't
        # miss directories that don't adhere to that rule
        assert(combo_dir[0x10:0x20] == (b'\x00' * 16))

        for i in range(2, no_of_entries+2):
            entry = combo_dir[i * 16 + 0x8: i * 16 + 0xc]
            entry_addr = int.from_bytes(entry, 'little')
            if entry_addr in [0, 0xFFFFFFFF]:
                continue
            entry_addr &= self.rom.addr_mask
            # entry_addr += self.blob_offset
            zen_generation_id = combo_dir[i*16+5:i*16+8]
            zen_generation = 'unknown'
            for possible_zen_generation in ZEN_GENERATION_IDS:
                if zen_generation_id in ZEN_GENERATION_IDS[possible_zen_generation]:
                    zen_generation = possible_zen_generation
            if zen_generation == 'unknown':
                self.psptool.ph.print_warning(f"Unknown {zen_generation_id=}")

            results.append((entry_addr, zen_generation))

        return results
