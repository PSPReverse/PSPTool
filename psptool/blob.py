# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2019 Christian Werling, Robert Buhren
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

from typing import List, Set

from .utils import NestedBuffer, chunker, print_warning
from .firmware import Firmware
from .directory import Directory
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
        self.fets = []
        self.unique_entries = set()

        self._parse_agesa_version()

        self._find_entry_table()

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
            self.agesa_version = str(re.sub(b'\x00',b' ',res[0]).strip().decode("ascii"))
            self.agesa_version_second = str(re.sub(b'\x00',b' ',res[1]).strip().decode("ascii"))
        elif len(res) == 1:
            self.agesa_version = str(re.sub(b'\x00',b' ',res[0]).strip().decode("ascii"))
            self.dual_rom = False
        else:
            self.agesa_version = str("UNKNOWN")



    def _find_entry_table(self):
        # AA55AA55 is to unspecific, so we require a word of padding before (to be tested)
        # TODO: Use better regex to find FET
        m = re.search(b'\xff\xff\xff\xff' + self._FIRMWARE_ENTRY_MAGIC, self.get_buffer())
        if m is None:
            raise self.NoFirmwareEntryTableError
        fet_offset = m.start() + 4
        self.fets.append(Fet(self, fet_offset, self.agesa_version))
        if self.dual_rom:
            if self[fet_offset + 0x1000000:fet_offset + 0x1000004] == self._FIRMWARE_ENTRY_MAGIC:
                self.fets.append(Fet(self, fet_offset + 0x1000000, self.agesa_version_second))
            else:
                print_warning(f"Found two AGESA versions strings, but only one firmware entry table")


    def find_pubkey(self,fp):
        """ Try to find a pubkey anywhere in the blob.
        The pubkey is identified by it's fingerprint. If found, the pubkey is
        added to the list of pubkeys of the blob """
        m = re.finditer(re.escape(fp), self.raw_blob)
        for index in m:
            start = index.start() - 4
            if int.from_bytes(self.raw_blob[start:start+4], 'little') == 1:
                # Maybe a pubkey. Determine it's size:
                pub_exp_size = int.from_bytes(self.raw_blob[start + 0x38: start + 0x3c],
                                              'little')
                if pub_exp_size == 2048:
                    size = 0x240
                elif pub_exp_size == 4096:
                    size = 0x440
                else:
                    continue
                try:
                    entry = PubkeyEntry(self,self, '99', size, start, self)
                    self.pubkeys[entry.key_id] = entry
                except Entry.ParseError:
                    print(f"_find_pubkey: Entry parse error at 0x{start:x}")
                except:
                    print_warning(f"Error couldn't convert key at: {start:x}")

    def get_entries_by_type(self, type_) -> List[Entry]:
        entries = []

        for fet in self.fets:
            for dir in fet.directories:
                for entry in dir:
                    if entry.type == type:
                        entries.append(entry)

        return entries

