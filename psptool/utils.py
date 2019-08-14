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

import sys
import argparse
import math
import zlib
import struct


class ObligingArgumentParser(argparse.ArgumentParser):
    """ Display the full help message whenever there is something wrong with the arguments.
        (from https://groups.google.com/d/msg/argparse-users/LazV_tEQvQw/xJhBOm1qS5IJ) """
    def error(self, message):
        sys.stderr.write('Error: %s\n' % message)
        self.print_help()
        sys.exit(2)


class NestedBuffer:
    def __init__(self, parent_buffer, buffer_size: int, buffer_offset: int = 0):
        self.parent_buffer = parent_buffer
        self.buffer_size = buffer_size
        self.buffer_offset = buffer_offset
        assert(self.buffer_size <= self.buffer_offset + self.buffer_size)

    def __len__(self):
        return self.buffer_size

    def __getitem__(self, item):
        if isinstance(item, slice):
            new_slice = self._offset_slice(item)
            return self.parent_buffer[new_slice]
        else:
            assert(isinstance(item, int))
            return self.parent_buffer[item]

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            new_slice = self._offset_slice(key)
            self.parent_buffer[new_slice] = value
        else:
            assert(isinstance(key, int))
            self.parent_buffer[self.buffer_offset + key] = value

    def _offset_slice(self, old_slice):
        if old_slice.start is None:
            start = self.buffer_offset
        else:
            assert (old_slice.start <= self.buffer_size)
            if old_slice.start < 0:
                start = self.buffer_offset + old_slice.start % self.buffer_size
            else:
                start = self.buffer_offset + old_slice.start
        if old_slice.stop is None:
            stop = self.buffer_offset + self.buffer_size
        else:
            assert (old_slice.stop <= self.buffer_size)
            if old_slice.stop < 0:
                stop = self.buffer_offset + old_slice.stop % self.buffer_size
            else:
                stop = self.buffer_offset + old_slice.stop

        new_slice = slice(start, stop, old_slice.step)
        return new_slice

    def get_address(self) -> int:
        if isinstance(self.parent_buffer, NestedBuffer):
            return self.buffer_offset + self.parent_buffer.get_address()
        else:
            return self.buffer_offset

    def get_buffer(self):
        return self.parent_buffer

    def get_bytes(self, offset: int = 0x0, size: int = None) -> bytes:
        size = self.buffer_size if size is None else size
        return bytes(self[offset:offset + size])

    def set_bytes(self, address: int, size: int, value):
        self[address:address + size] = value

    def get_chunks(self, size: int, offset: int = 0):
        return chunker(self[offset:], size)


def print_error_and_exit(arg0, *nargs, **kwargs):
    """ Wrapper function to print errors to stderr, so we don't interfere with e.g. extraction output. """
    arg0 = 'Error: ' + arg0 + '\n'
    sys.stderr.write(arg0, *nargs, **kwargs)
    sys.exit(1)


def print_warning(arg0, *nargs, **kwargs):
    """ Wrapper function to print warnings to stderr, so we don't interfere with e.g. extraction output. """
    arg0 = 'Warning: ' + arg0 + '\n'
    sys.stderr.write(arg0, *nargs, **kwargs)


def print_info(arg0, *nargs, **kwargs):
    """ Wrapper function to print info to stderr, so we don't interfere with e.g. extraction output. """
    arg0 = 'Info: ' + arg0 + '\n'
    sys.stderr.write(arg0, *nargs, **kwargs)


def chunker(seq, size):
    """ Utility function to chunk seq into a list of size sized sequences. """
    return (seq[pos:pos + size] for pos in range(0, len(seq), size))


def rstrip_padding(bytestring):
    """ Takes a bytestring and strips trailing 0xFFFFFFFF dwords. """
    i = 0
    while bytestring[-(4+i):len(bytestring)-i] == b'\xff\xff\xff\xff':
        i += 4
    return bytestring[:len(bytestring)-i]


def shannon(s):
    """ Performs a Shannon entropy analysis on a given block of s.
    from: https://github.com/ReFirmLabs/binwalk """

    entropy = 0

    if s:
        length = len(s)

        seen = dict((x, 0) for x in range(0, 256))
        for byte in s:
            seen[byte] += 1

        for x in range(0, 256):
            p_x = float(seen[x]) / length
            if p_x > 0:
                entropy -= p_x * math.log(p_x, 2)

    return entropy / 8


# The order is important here, as 78da is the most common magic and others might produce false positives
ZLIB_TYPES = {
    b'\x78\xda': 'Zlib compressed data, best compression',
    b'\x78\x9c': 'Zlib compressed data, default compression',
    b'\x78\x5e': 'Zlib compressed data, compressed',
    b'\x78\x01': 'Zlib header, no compression'
}


def zlib_find_header(s):
    """ Checks s for any zlib magic bytes and returns the offset (or -1). """

    # Only check the first 0x500 bytes, as the rest is too unlikely to be valid
    s = s[:0x500]

    for zlib_magic in ZLIB_TYPES.keys():
        # Check the most common location at 0x100 first to avoid false positives and save time
        if s[0x100:0x102] == zlib_magic:
            return 0x100

        zlib_start = s.find(zlib_magic)

        if zlib_start != -1:
            return zlib_start

    return -1


def zlib_decompress(s):
    """ Checks s for the first appearance of a zlib header and returns the uncompressed start of s as well as the
    decompressed section. If no zlib header is found, s is returned as is. """

    zlib_start = zlib_find_header(s)

    if zlib_start != -1:
        uncompressed = s[:zlib_start]
        compressed = s[zlib_start:]
        decompressed = zlib.decompress(compressed)

        return uncompressed + decompressed

    return s


def fletcher32(s):
    c0 = 0xFFFF
    c1 = 0xFFFF

    for index, byte_pair in enumerate(chunker(s, 2)):  # fletcher is calculated over 16bit words, i.e. 2 bytes
        byte_pair_int = struct.unpack('<H', byte_pair)[0]

        c0 += byte_pair_int
        c1 += c0

        if index % 360 == 0:
            c0 = (c0 & 0xFFFF) + (c0 >> 16)
            c1 = (c1 & 0xFFFF) + (c1 >> 16)

    c0 = (c0 & 0xFFFF) + (c0 >> 16)
    c1 = (c1 & 0xFFFF) + (c1 >> 16)

    checksum = (c1 << 16) | c0
    return struct.pack('<I', checksum)
