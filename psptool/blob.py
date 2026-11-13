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
import struct
import binascii

from typing import List

from .fet import EmptyFet
from .rom import Rom
from .utils import NestedBuffer, RangeDict
from .file import File
from .pubkey_file import PubkeyFile, InlinePubkeyFile, UnknownPubkeyFileVersion


class Blob(NestedBuffer):
    _FIRMWARE_ENTRY_MAGIC = b'\xAA\x55\xAA\x55'
    # All structures per Rom must be in 16MB windows
    _MAX_PAGE_SIZE = 16 * 1024 * 1024
    # Assumed only when a file entry points past the ROM size taken from the
    # input size, so a 32 MB ROM inside a bigger file keeps its size
    _BIG_ROM_SIZE = 64 * 1024 * 1024

    # ROM-relative offsets at which a FET may legitimately appear, in the
    # try-order used by the parser (the loop breaks on first successful
    # FET parse, so order is observable). As seen by a PSPTrace Zen 1
    # boot. The first entry is the canonical position for compact images
    # and is what the synthetic-fixture builder targets via [0].
    POSSIBLE_FET_OFFSETS = (
        0x020000,
        0xfa0000,
        0xf20000,
        0xe20000,
        0xc20000,
        0x820000,
        0x120000,
        # A second, minimal EFS with its own boot loader on AM5. Only taken at the start
        # of a 16MB page, see EARLY_FET_OFFSET.
        0x001000,
    )
    EARLY_FET_OFFSET = 0x001000

    # Directory entry type of a FET for a separate image
    ANOTHER_FET_TYPE = 0x46

    class NoFirmwareEntryTableError(Exception):
        pass

    def __init__(self, buffer: bytearray, size: int, psptool):
        super().__init__(buffer, size)

        self.psptool = psptool
        self.roms: List[Rom] = []

        possible_rom_sizes = [32, 16, 8]
        _rom_size = max(value for value in possible_rom_sizes if value * 1024 * 1024 <= self.buffer_size)
        rom_size = _rom_size * 1024 * 1024
        self.psptool.ph.print_warning(f"Input  file is {self.buffer_size:#x}, will assume ROM size of {_rom_size}M")

        # Early FETs go last, so that ROM 0 (the default of -X and -R) stays the main ROM
        fet_locations = sorted(self._find_fets(),
                               key=lambda location: location % self._MAX_PAGE_SIZE == self.EARLY_FET_OFFSET)

        # For each FET, we try to create a ROM starting at `FET - offset`
        for fet_location in fet_locations:
            another_fet = self._another_fet_at(fet_location)
            if another_fet is not None:
                # Its table addresses a separate image, not a ROM in this file
                self.psptool.ph.print_info(f"Not parsing FET at {hex(fet_location)} inside {another_fet}")
                continue
            fet_parsed = False
            for fet_offset in self.POSSIBLE_FET_OFFSETS:
                if fet_location < fet_offset:
                    # would lead to Blob underflow
                    continue
                if fet_offset == self.EARLY_FET_OFFSET and (fet_location - fet_offset) % self._MAX_PAGE_SIZE:
                    # Too short an offset to tell a ROM start from data that looks like a FET
                    continue
                rom_page = int(fet_location / self._MAX_PAGE_SIZE)
                if fet_location - fet_offset + rom_size - rom_page * self._MAX_PAGE_SIZE > self.buffer_size:
                    # would lead to Blob overflow
                    continue
                try:
                    rom_offset = fet_location - fet_offset  # e.g. 0x20800 - 0x20000 = 0x0800
                    # W/A for images with single ROMs that have entries crossing 16MB boundary
                    if rom_page == 0:
                        potential_rom = self._create_first_page_rom(rom_size, rom_offset, fet_offset)
                    else:
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

    def _another_fet_at(self, address: int):
        """The ANOTHER_FET entry of a parsed ROM holding this address, if any. Other entries
        are not checked, as their sizes can overstate what they hold."""
        for rom in self.roms:
            for directory in rom.directories:
                for file in directory.files:
                    if file.type == self.ANOTHER_FET_TYPE and \
                            file.get_address() <= address < file.get_address() + file.buffer_size:
                        return file
        return None

    def _create_first_page_rom(self, rom_size, rom_offset, fet_offset):
        psptool = self.psptool
        directories = dict(psptool.directories_by_offset)
        files = dict(psptool.files_by_offset)
        references = {file: len(file.references) for file in files.values()}
        try:
            return Rom(self, rom_size, rom_offset, fet_offset, psptool)
        except AssertionError as e:
            if 'overflows ROM bounds' not in str(e):
                raise

        # Drop what the failed attempt registered before parsing again
        psptool.directories_by_offset = directories
        psptool.files_by_offset = files
        for file, count in references.items():
            del file.references[count:]
        if rom_offset + self._BIG_ROM_SIZE > self.buffer_size:
            # The input is shorter than what its entries address, e.g. a region carved out of
            # a capsule: keep what is there
            psptool.ph.print_warning(f"File offset past the end of the input, skipping entries outside "
                                     f"its {rom_size >> 20}M")
            return Rom(self, rom_size, rom_offset, fet_offset, psptool, cut_short=True)
        psptool.ph.print_warning(f"File offset past {rom_size >> 20}M, will assume ROM size of "
                                 f"{self._BIG_ROM_SIZE >> 20}M")
        return Rom(self, self._BIG_ROM_SIZE, rom_offset, fet_offset, psptool)

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

    def find_inline_pubkey_entries(self, ids) -> List[InlinePubkeyFile]:
        """ Find public keys with the given key ids (hex strings) embedded in files with a
        header, such as the keys in Zen 2 boot loaders that sign SMU, SEC_GASKET and
        DEBUG_UNLOCK. A key is recognized by its version before the key id and its key
        sizes, at any alignment. Found keys are added to the inline_keys of their file. """
        if not ids:
            return []
        pattern = re.compile(b'|'.join(re.escape(binascii.a2b_hex(key_id)) for key_id in sorted(ids)))

        found_pubkeys = []
        for file in sorted(self.unique_files()):
            if isinstance(file, PubkeyFile) or not hasattr(file, 'inline_keys'):
                continue
            data = file.get_bytes()
            for match in pattern.finditer(data):
                inline_key = self._inline_pubkey_at(file, data, match.start() - 4)
                if inline_key is not None:
                    file.inline_keys.add(inline_key)
                    found_pubkeys.append(inline_key)

        return found_pubkeys

    def _inline_pubkey_at(self, file: File, data: bytes, start: int):
        if start < 0 or start + PubkeyFile.HEADER_LEN > len(data):
            return None
        version, = struct.unpack_from('<I', data, start)
        pubexp_bits, modulus_bits = struct.unpack_from('<II', data, start + 0x38)
        if version not in PubkeyFile.KNOWN_VERSIONS or pubexp_bits != modulus_bits or pubexp_bits not in (2048, 4096):
            return None

        size = PubkeyFile.HEADER_LEN + 2 * (pubexp_bits >> 3)
        key_id = data[start + 0x04:start + 0x14]
        certifying_id = data[start + 0x14:start + 0x24]
        if certifying_id not in (key_id, bytes(0x10)):
            # Signed key; assume the certifying key has the same size
            size += pubexp_bits >> 3
        if start + size > len(data):
            return None

        try:
            return InlinePubkeyFile(file, start, size, self, self.psptool)
        except (File.ParseError, UnknownPubkeyFileVersion, AssertionError) as e:
            self.psptool.ph.print_warning(f"Could not parse inline key at 0x{file.get_address() + start:x}: {e}")
            return None

    def get_files_by_type(self, type_) -> List[File]:
        all_files = self.unique_files()
        return list(filter(lambda f: f.type == type_, all_files))
