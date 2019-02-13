import struct
import utils

from typing import List
from entry import Entry


class Directory(utils.NestedBuffer):
    ENTRY_FIELDS = ['type', 'size', 'offset', 'rsv0', 'rsv1', 'rsv2']

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

    def __init__(self, parent_buffer: utils.NestedBuffer, buffer_offset: int, type_: str):
        self.parent_buffer = parent_buffer
        self.buffer_offset = buffer_offset

        # a directory must parse itself before it knows its size and can initialize its buffer
        self._parse_header()

        super().__init__(self.parent_buffer, self.buffer_size, buffer_offset=self.buffer_offset)

        self.type = type_
        self.entries: List[Entry] = []

        self._entry_size = self._ENTRY_SIZES[self.magic]
        self._parse_entries()

        # check entries for a link to a secondary directory (i.e. a continuation of this directory)
        self.secondary_directory_address = None
        for entry in self.entries:
            if entry.type in self._ENTRY_TYPES_SECONDARY_DIR:
                self.secondary_directory_address = entry.buffer_offset

        # todo: delete duplicates depending on their __repr__/__eq__
        # self._unique_entries: set = set()

    def __repr__(self):
        return f'Directory(address={hex(self.get_address())}, type={self.type}, count={self.count})'

    def _parse_header(self):
        # ugly to do this manually, but we do not know our size yet
        self.count = struct.unpack('<I', self.parent_buffer.get_bytes(self.buffer_offset + 8, 4))[0]
        self.magic = self.parent_buffer.get_bytes(self.buffer_offset, 4)

        if self.magic == b'\xff\xff\xff\xff':
            pass

        self.header = utils.NestedBuffer(self, self._HEADER_SIZES[self.magic])
        self.body = utils.NestedBuffer(self, self._ENTRY_SIZES[self.magic] * self.count,
                                       buffer_offset=self._HEADER_SIZES[self.magic])

        self.buffer_size = self.header.buffer_size + self.body.buffer_size

    def _parse_entries(self):
        for entry_bytes in self.body.get_chunks(self._entry_size):
            entry_fields = {}
            for key, word in zip(self.ENTRY_FIELDS, utils.chunker(entry_bytes, 4)):
                entry_fields[key] = struct.unpack('<I', word)[0]

            # addresses are all starting at 0xff000000, but we just want everything from there
            entry_fields['offset'] &= 0x00FFFFFF

            entry = Entry(self.parent_buffer, entry_fields['type'], entry_fields['size'], entry_fields['offset'])
            self.entries.append(entry)
