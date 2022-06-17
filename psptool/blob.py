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

import re
import binascii

from typing import List

from .fet import EmptyFet
from .rom import Rom
from .utils import NestedBuffer, RangeDict
from .entry import Entry, PubkeyEntry


class Blob(NestedBuffer):
    _FIRMWARE_ENTRY_MAGIC = b'\xAA\x55\xAA\x55'
    _FIRMWARE_ENTRY_TABLE_BASE_ADDRESS = 0x20000

    class NoFirmwareEntryTableError(Exception):
        pass

    def __init__(self, buffer: bytearray, size: int, psptool):
        super().__init__(buffer, size)

        self.psptool = psptool
        self.roms: List[Rom] = []

        potential_fet_offsets = [
            # as seen by a PSPTrace Zen 1 boot
            0x020000,
            0xfa0000,
            0xf20000,
            0xe20000,
            0xc20000,
            0x820000,
        ]

        rom_size = 0x1000000
        if self.buffer_size < rom_size:
            self.psptool.ph.print_warning("Input  file < 16M, will assume 8M ROM ...")
            rom_size = 0x800000

        # For each FET, we try to create a 16MB ROM starting at `FET - offset`
        for fet_location in self._find_fets():
            fet_parsed = False
            for fet_offset in potential_fet_offsets:
                if fet_location < fet_offset:
                    # would lead to Blob underflow
                    continue
                if fet_location - fet_offset + rom_size > self.buffer_size:
                    # would lead to Blob overflow
                    continue
                try:
                    rom_offset = fet_location - fet_offset  # e.g. 0x20800 - 0x20000 = 0x0800
                    potential_rom = Rom(self, rom_size, rom_offset, fet_offset, psptool)
                    self.roms.append(potential_rom)
                    fet_parsed = True
                    break  # found correct fet_offset!
                except EmptyFet:
                    self.psptool.ph.print_warning(f"Empty FET at offset {hex(fet_offset)}, trying next offset")
                    continue
            if not fet_parsed:
                self.psptool.ph.print_warning(f"Skipping FET at {hex(fet_location)} due to unknown ROM alignment")

        self._construct_range_dict()

    def __repr__(self):
        return f'Blob({self.roms=})'

    def _construct_range_dict(self):
        all_entries = self.unique_entries()

        # create RangeDict in order to find entries, directories and fets for a given address
        directories = [directory for rom in self.roms for directory in rom.directories]
        self.range_dict = RangeDict({
            **{
                range(entry.get_address(),
                      entry.get_address() + entry.buffer_size):  # key is start and end address of the entry
                entry
                for entry in all_entries if entry.buffer_size != 0xffffffff  # value is its type
            }, **{
                range(directory.get_address(), directory.get_address() + len(directory)):
                    directory
                for directory in directories
            }, **{
                range(rom.fet.get_address(), rom.fet.get_address() + len(rom.fet)):
                    rom.fet
                for rom in self.roms
            }
        })

    def unique_entries(self) -> set:
        directories = [directory for rom in self.roms for directory in rom.directories]
        directory_entries = [directory.entries for directory in directories]
        # flatten list of lists
        all_entries = [entry for sublist in directory_entries for entry in sublist]
        # filter duplicates through set
        unique_entries = set(all_entries)
        return unique_entries

    def _find_fets(self):
        # AA55AA55 is to unspecific, so we require a word of padding before (to be tested)
        for m in re.finditer(b'\xff\xff\xff\xff' + self._FIRMWARE_ENTRY_MAGIC, self.get_buffer()):
            fet_offset = m.start() + 4
            yield fet_offset

    def _find_inline_pubkeys(self, fp):

        """ Try to find a pubkey anywhere in the blob.
        The pubkey is identified by its fingerprint. If found, the pubkey is
        added to the list of pubkeys of the blob """
        found_pubkeys = []

        m = re.finditer(re.escape(binascii.a2b_hex(fp)), self.get_bytes())
        for index in m:
            start = index.start() - 4
            if int.from_bytes(self[start:start + 4], 'little') == 1:
                # Maybe a pubkey. Determine its size:
                pub_exp_size = int.from_bytes(self[start + 0x38: start + 0x3c],
                                              'little')
                if pub_exp_size == 2048:
                    size = 0x240
                elif pub_exp_size == 4096:
                    size = 0x440
                else:
                    continue

                key_id = self[start + 0x04: start + 0x14]
                cert_id = self[start + 0x14: start + 0x24]

                if key_id != cert_id and cert_id != b'\0' * 0x10:
                    if pub_exp_size == 2048:
                        size += 0x100
                    else:
                        size += 0x200

                try:
                    entry = PubkeyEntry(self, self, 0xdead, size, start, self, self.psptool)
                    # todo: use from_fields factory instead of PubkeyEntry init
                    # entry = Entry.from_fields(self, self.parent_buffer,
                    #                           0xdead,
                    #                           size,
                    #                           start,
                    #                           self,
                    #                           self.psptool)
                    assert isinstance(entry, PubkeyEntry)
                    entry.is_inline = True
                    entry.parent_entry = self.range_dict[entry.get_address()]
                    if type(entry.parent_entry) == PubkeyEntry:
                        break
                    entry.parent_entry.inline_keys.add(entry)
                    found_pubkeys.append(entry)
                except Entry.ParseError as e:
                    self.psptool.ph.print_warning(f"_find_pubkey: Entry parse error at 0x{start:x}")
                    self.psptool.ph.print_warning(f'{e}')
                except Exception as e:
                    self.psptool.ph.print_warning(f"_find_pubkey: Error couldn't convert key at: 0x{start:x}")
                    self.psptool.ph.print_warning(f'{e}')

        return found_pubkeys

    def find_inline_pubkey_entries(self, ids):
        found_pkes = []
        for key_id in ids:
            found_pkes += self._find_inline_pubkeys(key_id)
        return found_pkes

    def get_entries_by_type(self, type_) -> List[Entry]:
        entries = []

        for rom in self.roms:
            for _dir in rom.directories:
                for entry in _dir.entries:
                    if entry.type == type_:
                        entries.append(entry)

        return entries
