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

from .utils import NestedBuffer, RangeDict
from .entry import Entry, PubkeyEntry
from .fet import Fet


class Blob(NestedBuffer):
    _FIRMWARE_ENTRY_MAGIC = b'\xAA\x55\xAA\x55'
    _FIRMWARE_ENTRY_TABLE_BASE_ADDRESS = 0x20000

    class NoFirmwareEntryTableError(Exception):
        pass

    def __init__(self, buffer: bytearray, size: int, psptool):
        super().__init__(buffer, size)

        self.psptool = psptool
        self.raw_blob = buffer

        self.pubkeys = {}
        self.fets: List[Fet] = []
        self.unique_entries = set()

        self.dual_rom = False
        self._parse_agesa_version()

        self._find_entry_table()
        self._construct_range_dict()

    def __repr__(self):
        return f'Blob(agesa_version={self.agesa_version})'

    def _parse_agesa_version(self):
        # from https://www.amd.com/system/files/TechDocs/44065_Arch2008.pdf

        # todo: use NestedBuffers instead of saving by value

        m = re.compile(b"AGESA!..\x00.*?\x00")
        res = m.findall(self.get_buffer())

        # We are only interested in different agesa versions
        res = set(res)
        res = list(res)

        # Some Images contain actually two ROM images. I.e. one for Naples and 
        # one for Rome. Both will contain a valid FET which needs to be parsed.
        if len(res) == 2:
            self.dual_rom = True
            self.agesa_version = str(re.sub(b'\x00', b' ', res[0]).strip().decode("ascii"))
            self.agesa_version_second = str(re.sub(b'\x00', b' ', res[1]).strip().decode("ascii"))
        elif len(res) == 1:
            self.agesa_version = str(re.sub(b'\x00', b' ', res[0]).strip().decode("ascii"))
        else:
            self.agesa_version = str("UNKNOWN")

    def _find_entry_table(self):
        # AA55AA55 is to unspecific, so we require a word of padding before (to be tested)
        # TODO: Use better regex to find FET
        m = re.search(b'\xff\xff\xff\xff' + self._FIRMWARE_ENTRY_MAGIC, self.get_buffer())
        if m is None:
            raise self.NoFirmwareEntryTableError
        fet_offset = m.start() + 4
        self.fets.append(Fet(self, fet_offset, self.agesa_version, self.psptool))
        if self.dual_rom:
            if self[fet_offset + 0x1000000:fet_offset + 0x1000004] == self._FIRMWARE_ENTRY_MAGIC:
                self.fets.append(Fet(self, fet_offset + 0x1000000, self.agesa_version_second, self.psptool))
            else:
                self.psptool.ph.print_warning(f"Found two AGESA versions strings, but only one firmware entry table")

    def _construct_range_dict(self):
        all_entries = self.all_entries()

        # create RangeDict in order to find entries, directories and fets for a given address
        directories = [directory for fet in self.fets for directory in fet.directories]
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
                range(fet.get_address(), fet.get_address() + len(fet)):
                    fet
                for fet in self.fets
            }
        })

    def all_entries(self):
        directories = [directory for fet in self.fets for directory in fet.directories]
        directory_entries = [directory.entries for directory in directories]
        # flatten list of lists
        all_entries = [entry for sublist in directory_entries for entry in sublist]
        return all_entries

    def _find_inline_pubkeys(self, fp):
        """ Try to find a pubkey anywhere in the blob.
        The pubkey is identified by its fingerprint. If found, the pubkey is
        added to the list of pubkeys of the blob """
        found_pubkeys = []

        m = re.finditer(re.escape(binascii.a2b_hex(fp)), self.raw_blob)
        for index in m:
            start = index.start() - 4
            if int.from_bytes(self.raw_blob[start:start + 4], 'little') == 1:
                # Maybe a pubkey. Determine its size:
                pub_exp_size = int.from_bytes(self.raw_blob[start + 0x38: start + 0x3c],
                                              'little')
                if pub_exp_size == 2048:
                    size = 0x240
                elif pub_exp_size == 4096:
                    size = 0x440
                else:
                    continue

                key_id = self.raw_blob[start + 0x04: start + 0x14]
                cert_id = self.raw_blob[start + 0x14: start + 0x24]

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

        for fet in self.fets:
            for _dir in fet.directories:
                for entry in _dir.entries:
                    if entry.type == type_:
                        entries.append(entry)

        return entries
