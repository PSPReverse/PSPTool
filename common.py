#!/usr/bin/env python3

import argparse
import sys
import psptool
import math
import zlib


class ObligingArgumentParser(argparse.ArgumentParser):
    """ Display the full help message whenever there is something wrong with the arguments.
        (from https://groups.google.com/d/msg/argparse-users/LazV_tEQvQw/xJhBOm1qS5IJ) """
    def error(self, message):
        sys.stderr.write('Error: %s\n' % message)
        self.print_help()
        sys.exit(2)


"""
General utility functions
"""


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


def get_arch_for_type(type_, romfile):
    if type_ == 0x30062:  # UEFI_IMAGE
        return None

    # use psptool to correlate addresses to firmware directory entries
    with open(romfile, 'rb') as f:
        psptool.file_content = f.read()

    directories = psptool.find_directories()
    directory_entries = [psptool.find_directory_entries(directory) for directory in directories]

    # flatten list of lists
    all_entries = [entry for sublist in directory_entries for entry in sublist]

    for entry in all_entries:
        if entry['type'] == type_:
            start = entry['address']
            size = entry.get('s_packed') or entry['size']
            end = start + size

            compressed = True if entry.get('compressed') else False
            if compressed:
                data_decompressed = psptool.zlib_decompress(psptool.rstrip_padding(psptool.file_content[start:end - 0x100]))
                data = data_decompressed[:entry['s_signed'] + 0x100]
            else:
                data = psptool.file_content[start:end - 0x100]

            return find_arch(data)

    return None


def find_arch(data):
    if len(data) > 1024 * 1024:  # 1M
        psptool.print_warning('Skipping arch detection. Size > 1M!')
        return None

    import cpu_rec.cpu_rec as cpu_rec

    return cpu_rec.main_with_data(data)
