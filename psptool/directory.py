import struct

from typing import List

from entry import Entry
from utils import chunker


class Directory:
    ENTRY_FIELDS = ['type', 'size', 'address', 'rsv0', 'rsv1', 'rsv2']

    _HEADER_SIZES = {
        b'$PSP': 4 * 4,
        b'$PL2': 4 * 4,
        b'$BHD': 4 * 4,
        b'$BL2': 4 * 4
    }

    _ENTRY_SIZES = {
        b'$PSP': 4 * 4,
        b'$PL2': 4 * 4,
        b'$BHD': 4 * 6,
        b'$BL2': 4 * 6
    }

    _ENTRY_TYPES_SECONDARY_DIR = [0x40, 0x70]

    def __init__(self, parent_blob, address: int, type_: str):
        self.blob = parent_blob
        self.address = address
        self.type = type_

        self.entries: List[Entry] = []

        self._parse_header()
        self._parse_entries()

        # check entries for a link to a secondary directory (i.e. a continuation of this directory)
        self.secondary_directory_address = None
        for entry in self.entries:
            if entry.type in self._ENTRY_TYPES_SECONDARY_DIR:
                self.secondary_directory_address = entry.address

        # todo: delete duplicates depending on their __repr__
        # self._unique_entries: set = set()

    def __repr__(self):
        return f'Directory(address={hex(self.address)}, type={self.type}, count={self.count})'

    def _parse_header(self):
        self.count = struct.unpack('<I', self.blob.get_bytes_at(self.address + 8, 4))[0]
        self.magic = self.blob.get_bytes_at(self.address, 4)
        self._header_size = self._HEADER_SIZES[self.magic]
        self._entry_size = self._ENTRY_SIZES[self.magic]
        self.size = self._header_size + (self._entry_size * self.count)

    def _parse_entries(self):
        for entry_bytes in chunker(self.get_bytes()[self._header_size:], self._entry_size):
            # Iterate over the entry_bytes fields
            entry_fields = {}
            for key, word in zip(self.ENTRY_FIELDS, chunker(entry_bytes, 4)):
                entry_fields[key] = struct.unpack('<I', word)[0]

            # addresses are all starting at 0xff000000, but we just want everything from there
            entry_fields['address'] &= 0x00FFFFFF

            entry = Entry(self, entry_fields['type'], entry_fields['size'], entry_fields['address'])
            self.entries.append(entry)

    def get_bytes(self) -> bytes:
        return self.blob.bytes[self.address:self.address + self.size]

    def get_bytes_at(self, offset, size) -> bytes:
        return self.get_bytes()[offset:offset + size]

    def set_bytes(self, offset, bytes_):
        self.blob.set_bytes(self.address + offset, bytes_)
