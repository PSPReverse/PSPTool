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
from .file import File
from .pubkey_file import PubkeyFile, InlinePubkeyFile


class Blob(NestedBuffer):
    _FIRMWARE_ENTRY_MAGIC = b'\xAA\x55\xAA\x55'
    # All structures per Rom must be in 16MB windows
    _MAX_PAGE_SIZE = 16 * 1024 * 1024
    class NoFirmwareEntryTableError(Exception):
        pass

    def __init__(self, buffer: bytearray, size: int, psptool):
        super().__init__(buffer, size)

        self.psptool = psptool
        self.roms: List[Rom] = []

        possible_fet_offsets = [
            # as seen by a PSPTrace Zen 1 boot
            0x020000,
            0xfa0000,
            0xf20000,
            0xe20000,
            0xc20000,
            0x820000,
        ]

        possible_rom_sizes = [32, 16, 8]
        _rom_size = max(value for value in possible_rom_sizes if value * 1024 * 1024 <= self.buffer_size)
        rom_size = _rom_size * 1024 * 1024
        self.psptool.ph.print_warning(f"Input  file is {self.buffer_size:#x}, will assume ROM size of {_rom_size}M")

        # For each FET, we try to create a 16MB ROM starting at `FET - offset`
        for fet_location in self._find_fets():
            fet_parsed = False
            for fet_offset in possible_fet_offsets:
                if fet_location < fet_offset:
                    # would lead to Blob underflow
                    continue
                rom_page = int(fet_location / self._MAX_PAGE_SIZE)
                if fet_location - fet_offset + rom_size - rom_page * self._MAX_PAGE_SIZE > self.buffer_size:
                    # would lead to Blob overflow
                    continue
                try:
                    rom_offset = fet_location - fet_offset  # e.g. 0x20800 - 0x20000 = 0x0800
                    potential_rom = Rom(self, min(rom_size, self._MAX_PAGE_SIZE), rom_offset, fet_offset, psptool)
                    self.roms.append(potential_rom)
                    fet_parsed = True
                    break  # found correct fet_offset!
                except EmptyFet:
                    self.psptool.ph.print_warning(f"Empty FET at offset {hex(fet_offset)}, trying next offset")
                    continue
            if not fet_parsed:
                self.psptool.ph.print_warning(f"Skipping FET at {hex(fet_location)} due to unknown ROM alignment")

        if len(self.roms) == 0:
            self.psptool.ph.print_warning("Could not find any Firmware Entry Table!")

        self._construct_range_dict()

    def __repr__(self):
        return f'Blob({self.roms=})'

    def _construct_range_dict(self):
        all_files = self.unique_files()

        # create RangeDict in order to find entries, directories and fets for a given address
        directories = [directory for rom in self.roms for directory in rom.directories]
        self.range_dict = RangeDict({
            **{
                range(file.get_address(),
                      file.get_address() + file.buffer_size):  # key is start and end address of the file
                file
                for file in all_files if file.buffer_size != 0xffffffff  # value is its type
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

    def unique_files(self) -> set:
        directories = [directory for rom in self.roms for directory in rom.directories]
        directory_files = [directory.files for directory in directories]
        # flatten list of lists
        all_files = [file for sublist in directory_files for file in sublist]
        # filter duplicates through set
        unique_files = set(all_files)
        return unique_files

    def _find_fets(self):
        # AA55AA55 is to unspecific, so we require a word of padding before (to be tested)
        for m in re.finditer(b'\xff\xff\xff\xff' + self._FIRMWARE_ENTRY_MAGIC, self.get_buffer()):
            fet_offset = m.start() + 4
            yield fet_offset
        for m in re.finditer(b'\x00\x00\x00\x00' + self._FIRMWARE_ENTRY_MAGIC, self.get_buffer()):
            fet_offset = m.start() + 4
            yield fet_offset

    def _find_inline_pubkeys(self, fp):

        """ Try to find a pubkey in any of the found files.
        The pubkey is identified by its fingerprint. If found, the pubkey is
        added to the list of pubkeys of the blob """
        found_pubkeys = []

        for file in self.unique_files():
            if type(file) == PubkeyFile:
                continue  # Pubkeys don't have inline keys but will only produce false positives
            m = re.finditer(re.escape(binascii.a2b_hex(fp)), file.get_bytes())
            for index in m:
                start_offset = index.start() - 4
                if int.from_bytes(self[start_offset:start_offset + 4], 'little') in PubkeyFile.KNOWN_VERSIONS:
                    # Maybe a pubkey. Determine its size:
                    pub_exp_size = int.from_bytes(self[start_offset + 0x38: start_offset + 0x3c],
                                                  'little')
                    if pub_exp_size == 2048:
                        size = 0x240
                    elif pub_exp_size == 4096:
                        size = 0x440
                    else:
                        continue

                    key_id = self[start_offset + 0x04: start_offset + 0x14]
                    cert_id = self[start_offset + 0x14: start_offset + 0x24]

                    if key_id != cert_id and cert_id != b'\0' * 0x10:
                        if pub_exp_size == 2048:
                            size += 0x100
                        else:
                            size += 0x200

                    try:
                        file = InlinePubkeyFile(file, start_offset, size, self, self.psptool)
                        assert isinstance(file, PubkeyFile)
                        file.inline_keys.add(file)
                        found_pubkeys.append(file)
                    except File.ParseError as e:
                        self.psptool.ph.print_warning(f"_find_pubkey: File parse error at 0x{start_offset:x}")
                        self.psptool.ph.print_warning(f'{e}')

        return found_pubkeys

    def find_inline_pubkey_entries(self, ids):
        found_pkes = []
        for key_id in ids:
            found_pkes += self._find_inline_pubkeys(key_id)
        return found_pkes

    def get_entries_by_type(self, type_) -> List[File]:
        entries = []

        for rom in self.roms:
            for _dir in rom.directories:
                for entry in _dir.entries:
                    if entry.type == type_:
                        entries.append(entry)

        return entries
