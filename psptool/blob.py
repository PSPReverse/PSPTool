import re
import struct

from typing import List

from .utils import print_error_and_exit, chunker
from .firmware import Firmware
from .directory import Directory


class Blob:
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

    def __init__(self, rom_bytes: bytes):
        self.bytes = rom_bytes
        firmwares, directories = self._parse_entry_table()

        self.firmwares = firmwares
        self.directories = directories

        # todo: info members:
        #  self.range = (min, max)

    def _parse_entry_table(self) -> (List[Firmware], List[Directory]):
        # AA55AA55 is to unspecific, so we require a word of padding before (to be tested)
        m = re.search(b'\xff\xff\xff\xff' + self._FIRMWARE_ENTRY_MAGIC, self.bytes)

        if m is None:
            print_error_and_exit('Could not find any Firmware Entry Table!')

        offset = m.start() + 4
        size = 0

        # Find out size by determining an FF-word as termination
        while offset <= len(self.bytes) - 4:
            if self.bytes[(offset + size):(offset + size + 4)] != b'\xff\xff\xff\xff':
                size += 4
            else:
                break

        self.firmware_entry_table = self.bytes[offset:offset + size]
        entries = chunker(self.firmware_entry_table[4:], 4)

        # If the binary contains additional headers, shift those away by assuming the FET to be at 0x20000
        bios_rom_offset = offset - self._FIRMWARE_ENTRY_TABLE_BASE_ADDRESS

        if bios_rom_offset != 0:
            print('Found Firmware Entry Table at 0x%x instead of 0x%x. All addresses will lack an offset of 0x%x.' %
                  (offset, self._FIRMWARE_ENTRY_TABLE_BASE_ADDRESS, bios_rom_offset))
            self.bytes = self.bytes[bios_rom_offset:]

        firmwares = []
        directories = []

        for index, entry in enumerate(entries):
            firmware_type = self._FIRMWARE_ENTRY_TYPES[index] if index < len(self._FIRMWARE_ENTRY_TYPES) else 'unknown'
            address = struct.unpack('<I', entry)[0] & 0x00FFFFFF

            # assumption: address == 0 is an invalid entry
            if address != 0:
                directory = self.bytes[address:address + 16 * 8]
                magic = directory[:4]

                # either this entry points to a PSP directory directly
                if magic in [b'$PSP', b'$BHD']:
                    directory = Directory(self, address, firmware_type)
                    directories.append(directory)

                # or this entry points to a combo-directory (i.e. two directories)
                elif magic == b'2PSP':
                    psp_dir_one_addr = struct.unpack('<I', directory[10*4:10*4+4])[0] & 0x00FFFFFF
                    psp_dir_two_addr = struct.unpack('<I', directory[14*4:14*4+4])[0] & 0x00FFFFFF

                    for address in [psp_dir_one_addr, psp_dir_two_addr]:
                        directory = Directory(self, address, firmware_type)
                        directories.append(directory)

                # or this entry is unparsable and thus a firmware
                else:
                    firmware = Firmware(self, firmware_type, address, magic)
                    firmwares.append(firmware)

        return firmwares, directories
