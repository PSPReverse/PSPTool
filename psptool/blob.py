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
from .entry import Entry


class Blob(NestedBuffer):
    _FIRMWARE_ENTRY_MAGIC = b'\xAA\x55\xAA\x55'
    _FIRMWARE_ENTRY_TABLE_BASE_ADDRESS = 0x20000

    _FIRMWARE_ENTRY_TYPES = [  # typedef struct _FIRMWARE_ENTRY_TABLE {
        # 'signature', UINT32  Signature;    ///< Signature should be 0x55AA55AAul
        'IMC',       # UINT32  ImcRomBase;   ///< Base Address for Imc Firmware
        'GMC',       # UINT32  GecRomBase;   ///< Base Address for Gmc Firmware
        'XHCI',      # UINT32  XHCRomBase;   ///< Base Address for XHCI Firmware
        'PSP_DIR',   # UINT32  PspDirBase;   ///< Base Address for PSP directory
        'PSP_NEW',   # UINT32  NewPspDirBase;///< Base Address of PSP directory from program start from ST
        'BHD',       # UINT32  BhdDirBase;   ///< Base Address for BHD directory
    ]

    class NoFirmwareEntryTableError(Exception):
        pass

    def __init__(self, buffer: bytearray, size: int, psptool):
        super().__init__(buffer, size)

        self.psptool = psptool
        self.directories: List[Directory] = []
        self.firmwares: List[Firmware] = []

        self.unique_entries = set()
        self.pubkeys = {}

        self._parse_agesa_version()

        self._find_entry_table()
        self._parse_entry_table()

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

        self.agesa_version = str(b''.join([agesa_magic, b' ', component_name, version]), 'ascii').rstrip('\x00')

    def _find_entry_table(self):
        # AA55AA55 is to unspecific, so we require a word of padding before (to be tested)
        m = re.search(b'\xff\xff\xff\xff' + self._FIRMWARE_ENTRY_MAGIC, self.get_buffer())
        if m is None:
            raise self.NoFirmwareEntryTableError
        fet_offset = m.start() + 4

        # Find out its size by determining an FF-word as termination
        fet_size = 0
        while fet_offset <= len(self.get_buffer()) - 4:
            if self[(fet_offset + fet_size):(fet_offset + fet_size + 4)] != b'\xff\xff\xff\xff':
                fet_size += 4
            else:
                break

        # Normally, the FET is found at offset 0x20000 in the ROM file
        # If the actual offset is bigger because of e.g. additional ROM headers, shift our NestedBuffer accordingly
        rom_offset = fet_offset - self._FIRMWARE_ENTRY_TABLE_BASE_ADDRESS
        self.buffer_offset = rom_offset

        # Now the FET can be found at its usual static offset of 0x20000 in shifted NestedBuffer
        self.firmware_entry_table = NestedBuffer(self, fet_size, self._FIRMWARE_ENTRY_TABLE_BASE_ADDRESS)

    def _parse_entry_table(self) -> (List[Firmware], List[Directory]):
        entries = chunker(self.firmware_entry_table[4:], 4)

        for index, entry in enumerate(entries):
            firmware_type = self._FIRMWARE_ENTRY_TYPES[index] if index < len(self._FIRMWARE_ENTRY_TYPES) else 'unknown'
            address = struct.unpack('<I', entry)[0] & 0x00FFFFFF

            # assumption: offset == 0 is an invalid entry
            if address not in [0x0, 0xfffffe]:
                directory = self[address:address + 16 * 8]
                magic = directory[:4]

                # either this entry points to a PSP directory directly
                if magic in [b'$PSP', b'$BHD']:
                    directory = Directory(self, address, firmware_type)
                    self.directories.append(directory)

                    # if this Directory points to a secondary directory: add it, too
                    if directory.secondary_directory_address is not None:
                        secondary_directory = Directory(self, directory.secondary_directory_address, 'secondary')
                        self.directories.append(secondary_directory)

                # or this entry points to a combo-directory (i.e. two directories)
                elif magic == b'2PSP':
                    psp_dir_one_addr = struct.unpack('<I', directory[10*4:10*4+4])[0] & 0x00FFFFFF
                    psp_dir_two_addr = struct.unpack('<I', directory[14*4:14*4+4])[0] & 0x00FFFFFF

                    for address in [psp_dir_one_addr, psp_dir_two_addr]:
                        try:
                            directory = Directory(self, address, firmware_type)
                            self.directories.append(directory)
                        except:
                            print_warning(f'Unable to parse directory at {hex(address)}.')
                            continue

                        # if this Directory points to a secondary directory: add it, too
                        if directory.secondary_directory_address is not None:
                            secondary_directory = Directory(self, directory.secondary_directory_address, 'secondary')
                            self.directories.append(secondary_directory)

                # or this entry is unparsable and thus a firmware
                else:
                    firmware = Firmware(self, address, firmware_type, magic)
                    self.firmwares.append(firmware)

    def get_entries_by_type(self, type_) -> List[Entry]:
        entries = []

        for entry in self.unique_entries:
            if entry.type == type_:
                entries.append(entry)

        return entries
