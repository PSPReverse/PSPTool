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

from typing import List

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
        self.directories: List[Directory] = []
        self.firmwares: List[Firmware] = []
        self.raw_blob = buffer

        self.unique_entries = set()
        self.pubkeys = {}

        self._parse_agesa_version()

        self._find_entry_table()

        # todo: info members:
        #  self.range = (min, max)

    def __repr__(self):
        return f'Blob(agesa_version={self.agesa_version}, len(firmwares)={len(self.firmwares)}, ' \
               f'len(directories)={len(self.directories)})'

    def _parse_agesa_version(self):
        # from https://www.amd.com/system/files/TechDocs/44065_Arch2008.pdf

        # todo: use NestedBuffers instead of saving by value
        start = self.get_buffer().find(b'AGESA!')
        version_string = self[start:start + 36]

        agesa_magic = version_string[0:8]
        component_name = version_string[9:16]
        version = version_string[16:]

        try:
            self.agesa_version = str(b''.join([agesa_magic, b' ', component_name, version]), 'ascii').rstrip('\x00')
        except:
            self.agesa_version = "UNKNOWN"

    def _find_entry_table(self):
        # AA55AA55 is to unspecific, so we require a word of padding before (to be tested)
        m = re.search(b'\xff\xff\xff\xff' + self._FIRMWARE_ENTRY_MAGIC, self.get_buffer())
        if m is None:
            raise self.NoFirmwareEntryTableError
        fet_offset = m.start() + 4
        self.fet = Fet(self, fet_offset)

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

        for entry in self.unique_entries:
            if entry.type == type_:
                entries.append(entry)

        return entries
