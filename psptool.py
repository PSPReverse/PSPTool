#!/usr/bin/env python3

import struct
import re
import subprocess
import tempfile
import string
import os

from hashlib import md5
from base64 import b64encode
from binascii import hexlify
from prettytable import PrettyTable
from argparse import RawTextHelpFormatter

from common import *


"""
PSP related utility functions
"""


def parse_amd_pubkey(s):
    """ Checks whether the given binary string represents a valid AMD Signing Key according to SEV spec B.1. If
    so, returns a pubkey dict containing all parsed fields. """

    try:
        pubexp_size = struct.unpack('<I', s[0x38:0x3c])[0] // 8
        modulus_size = signature_size = struct.unpack('<I', s[0x3c:0x40])[0] // 8

        pubexp_start = 0x40
        modulus_start = pubexp_start + pubexp_size

        # Byte order of the numbers is inverted over their entire length
        # Assumption: Only the most significant 4 bytes of pubexp are relevant and can be converted to int
        pubexp = s[pubexp_start:modulus_start][::-1][-4:]
        modulus = s[modulus_start:modulus_start + modulus_size][::-1]

        pubkey = {
            'version': struct.unpack('<I', s[0x0:0x4])[0],
            'key_id': hexlify(s[0x4:0x14]),
            'certifying_id': hexlify(s[0x14:0x24]),
            'key_usage': struct.unpack('<I', s[0x24:0x28])[0],
            'pubexp_size': pubexp_size,
            'modulus_size': modulus_size,
            'pubexp': pubexp,
            'modulus': modulus
        }

    except struct.error:
        return {}

    expected_size = 0x40 + pubexp_size + modulus_size + signature_size

    if len(s) == expected_size:
        pubkey['signature'] = s[modulus_start + modulus_size:]
        return pubkey

    elif len(s) == expected_size - signature_size:  # The AMD Root Signing Key is missing a trailing signature
        return pubkey

    else:
        return {}


def extract_amd_pubkey(s):
    """ Takes a raw AMD Signing Key according to SEV spec B.1 as a binary string and returns modulus and exponent. """
    pubexp_size = struct.unpack('<I', s[0x38:0x3c])[0] // 8
    modulus_size = struct.unpack('<I', s[0x3c:0x40])[0] // 8

    pubexp_start = 0x40
    modulus_start = pubexp_start + pubexp_size

    # Byte order of the numbers is inverted over their entire length
    # Assumption: Only the most significant 4 bytes of pubexp are relevant and can be converted to int
    pubexp = s[pubexp_start:modulus_start][::-1][-4:]
    modulus = s[modulus_start:modulus_start + modulus_size][::-1]

    return pubexp, modulus


"""
PSP finding, parsing, extracting functions based on reverse-engineering and coreboot sources
"""

FIRMWARE_ENTRY_TABLE_BASE_ADDRESS = 0x20000

FIRMWARE_ENTRY_MAGIC = b'\xAA\x55\xAA\x55'

FIRMWARE_ENTRY_TYPES = [  # typedef struct _FIRMWARE_ENTRY_TABLE {
            # 'signature',      # UINT32  Signature;    ///< Signature should be 0x55AA55AAul
            'IMC',              # UINT32  ImcRomBase;   ///< Base Address for Imc Firmware
            'GMC',              # UINT32  GecRomBase;   ///< Base Address for Gmc Firmware
            'XHCI',             # UINT32  XHCRomBase;   ///< Base Address for XHCI Firmware
            'PSP_DIR',          # UINT32  PspDirBase;   ///< Base Address for PSP directory
            'PSP_NEW',          # UINT32  NewPspDirBase;///< Base Address of PSP directory from program start from ST
            'BHD',              # UINT32  BhdDirBase;   ///< Base Address for BHD directory
]

PARSABLE_DIRECTORY_MAGIC = [b'$PSP', b'$BHD', b'$PL2', b'$BL2']

DIRECTORY_HEADER_SIZES = {
    b'$PSP': 4 * 4,
    b'$PL2': 4 * 4,
    b'$BHD': 4 * 4,
    b'$BL2': 4 * 4
}

DIRECTORY_ENTRY_SIZES = {
    b'$PSP': 4 * 4,
    b'$PL2': 4 * 4,
    b'$BHD': 4 * 6,
    b'$BL2': 4 * 6
}

DIRECTORY_ENTRY_FIELDS = ['type', 'size', 'address', 'rsv0', 'rsv1', 'rsv2']

# from https://github.com/coreboot/coreboot/blob/master/...
#  .../src/vendorcode/amd/pi/00670F00/Proc/Psp/PspBaseLib/PspDirectory.h
#  .../util/amdfwtool/amdfwtool.c

DIRECTORY_ENTRY_TYPES = {  # enum _PSP_DIRECTORY_ENTRY_TYPE {
    0x00:   'AMD_PUBLIC_KEY',               # PSP entry pointer to AMD public key
    0x01:   'PSP_FW_BOOT_LOADER',           # PSP entry points to PSP boot loader in SPI space
    0x02:   'PSP_FW_TRUSTED_OS',            # PSP entry points to PSP Firmware region in SPI space
    0x03:   'PSP_FW_RECOVERY_BOOT_LOADER',  # PSP entry point to PSP recovery region.
    0x04:   'PSP_NV_DATA',                  # PSP entry points to PSP data region in SPI space
    0x05:   'BIOS_PUBLIC_KEY',              # PSP entry points to BIOS public key stored in SPI space
    0x06:   'BIOS_RTM_FIRMWARE',            # PSP entry points to BIOS RTM code (PEI volume) in SPI space
    0x07:   'BIOS_RTM_SIGNATURE',           # PSP entry points to signed BIOS RTM hash stored  in SPI space
    0x08:   'SMU_OFFCHIP_FW',               # PSP entry points to SMU image
    0x09:   'AMD_SEC_DBG_PUBLIC_KEY',       # PSP entry pointer to Secure Unlock Public key
    0x0A:   'OEM_PSP_FW_PUBLIC_KEY',        # PSP entry pointer to an optional public part of the OEM PSP Firmware
                                            #  Signing Key Token
    0x0B:   'AMD_SOFT_FUSE_CHAIN_01',       # PSP entry pointer to 64bit PSP Soft Fuse Chain
    0x0C:   'PSP_BOOT_TIME_TRUSTLETS',      # PSP entry points to boot-loaded trustlet binaries
    0x0D:   'PSP_BOOT_TIME_TRUSTLETS_KEY',  # PSP entry points to key of the boot-loaded trustlet binaries
    0x10:   'PSP_AGESA_RESUME_FW',          # PSP Entry points to PSP Agesa-Resume-Firmware
    0x12:   'SMU_OFF_CHIP_FW_2',            # PSP entry points to secondary SMU image
    0x1A:   'PSP_S3_NV_DATA',               # PSP entry pointer to S3 Data Blob
    0x5f:   'FW_PSP_SMUSCS',                # Software Configuration Settings Data Block
    0x60:   'FW_IMC',
    0x61:   'FW_GEC',
    0x62:   'FW_XHCI',
    0x63:   'FW_INVALID',
    0x108:  'PSP_SMU_FN_FIRMWARE',
    0x118:  'PSP_SMU_FN_FIRMWARE2',

    # Entry types named by us – Titles denoted by a leading '!' and comments by '~'
    0x14:   '!PSP_MCLF_TRUSTLETS',          # very similiar to ~PspTrustlets.bin~ in coreboot blobs
    0x31:   '0x31~ABL_ARM_CODE~',           # a _lot_ of strings and also some ARM code
    0x38:   '!PSP_ENCRYPTED_NV_DATA',
    0x40:   '!PL2_SECONDARY_DIRECTORY',
    0x70:   '!BL2_SECONDARY_DIRECTORY',
    0x15f:  '!FW_PSP_SMUSCS_2',             # seems to be a secondary FW_PSP_SMUSCS (see above)
    0x112:  '!SMU_OFF_CHIP_FW_3',           # seems to tbe a tertiary SMU image (see above)
    0x39:   '!SEV_APP',
    0x30062: '0x30062~UEFI-IMAGE~'

}

DIRECTORY_ENTRY_TYPES_SECONDARY_DIR = [0x40, 0x70]  # see entry types above


class PSPTool:
    def __init__(self, file, verbose=False):
        self.file = file
        self._verbose = verbose

        self._print_info = print_info if self._verbose else None

        self._md5sums = set()
        self._pubkeys = {}
        self._accessed_entries = {}

        with open(self.file, 'rb') as f:
            self._file_content = f.read()

        if len(self._file_content) != 0x1000000:
            print_warning('Input file of unknown size. Expected size is 0x1000000 bytes (or 16MB).\n\n')

        self.agesa_version = self._parse_agesa_version()
        self._firmwares = self._parse_firmwares()
        self._directories = self._parse_directories(self._firmwares)

    def _parse_agesa_version(self):
        # from https://www.amd.com/system/files/TechDocs/44065_Arch2008.pdf
        start = self._file_content.find(b'AGESA!')
        version_string = self._file_content[start:start + 36]

        agesa_magic = version_string[0:8]
        component_name = version_string[9:16]
        version = version_string[16:29]

        return str(b''.join([agesa_magic, b' ', component_name, version]), 'ascii')

    def _parse_firmwares(self):
        """ Takes a _file_content and returns found _firmwares from the Firmware Entry Table (FET) as a list of
        dictionaries. """

        # AA55AA55 is to unspecific, so we require a word of padding before (to be tested)
        m = re.search(b'\xff\xff\xff\xff' + FIRMWARE_ENTRY_MAGIC, self._file_content)

        if m is None:
            print_error_and_exit('Could not find any Firmware Entry Table!')

        offset = m.start() + 4
        size = 0

        # Find out size by determining an FF-word as termination
        while offset <= len(self._file_content) - 4:
            if self._file_content[(offset + size):(offset + size + 4)] != b'\xff\xff\xff\xff':
                size += 4
            else:
                break

        firmware_entry_table = self._file_content[offset:offset + size]
        entries = chunker(firmware_entry_table[4:], 4)

        # If the input file contains additional headers, shift those away by assuming the FET to be at 0x20000
        bios_rom_offset = offset - FIRMWARE_ENTRY_TABLE_BASE_ADDRESS

        if bios_rom_offset != 0:
            print('Found Firmware Entry Table at 0x%x instead of 0x%x. All addresses will lack an offset of 0x%x.' %
                  (offset, FIRMWARE_ENTRY_TABLE_BASE_ADDRESS, bios_rom_offset))
            self._file_content = self._file_content[bios_rom_offset:]

        firmwares = []

        for index, entry in enumerate(entries):
            type_ = FIRMWARE_ENTRY_TYPES[index] if index < len(FIRMWARE_ENTRY_TYPES) else 'unknown'
            address = struct.unpack('<I', entry)[0] & 0x00FFFFFF

            # address=0 seams to be an invalid entry
            if address != 0:
                directory = self._file_content[address:address + 16 * 8]
                magic = directory[:4]

                # If this is a PSP combo directory
                if magic == b'2PSP':
                    psp_dir_one_addr = struct.unpack('<I', directory[10*4:10*4+4])[0] & 0x00FFFFFF
                    psp_dir_two_addr = struct.unpack('<I', directory[14*4:14*4+4])[0] & 0x00FFFFFF

                    for address in [psp_dir_one_addr, psp_dir_two_addr]:
                        magic = self._file_content[address:address + 4]
                        firmwares.append({
                            'address': address,
                            'magic': magic,
                            'type': type_
                        })
                elif magic != b'\xff\xff\xff\xff':
                    firmwares.append({
                        'address': address,
                        'magic': magic,
                        'type': type_
                    })

        return firmwares

    def _parse_directories(self, firmwares):
        """" Returns found PSP firmware _directories as a list of dictionaries. Each firmware will be one directory, but
        some of them have secondary _directories. """

        directories = []

        for firmware in firmwares:
            magic = firmware['magic']
            address = firmware['address']
            type_ = firmware['type']

            if magic in [b'$PSP', b'$BHD']:
                directory = self._parse_directory(address)
                directory['type'] = type_

                directories.append(directory)

                if directory['secondary']:
                    directory = self._parse_directory(directory['secondary'])
                    directory['magic'] = magic
                    directory['type'] = 'SECONDARY'

                    directories.append(directory)

            elif magic == b'_PT_':
                directories.append({
                    'address': address,
                    'size': 0x8c,
                    'magic': magic,
                    'type': type_,
                    'secondary': False,
                    'content': self._file_content[address:address + 0x8c]
                })

            else:
                directories.append({
                    'address': address,
                    'magic': magic,
                    'type': type_,
                    'secondary': False
                })

        return directories

    def _parse_directory(self, address):
        count_offset = address + 8
        count = struct.unpack('<I', self._file_content[count_offset:count_offset + 4])[0]
        magic = self._file_content[address:address + 4]

        size = DIRECTORY_HEADER_SIZES[magic] + (DIRECTORY_ENTRY_SIZES[magic] * count)
        termination_bytes = self._file_content[(address + size):(address + size + 4)]

        # Assertion that we assumed the right directory size
        if termination_bytes != b'\xff\xff\xff\xff':
            return None

        directory = {
            'address': address,
            'size': size,
            'count': count,
            'magic': magic,
            'content': self._file_content[address:address + size],
            'secondary': None
        }

        directory['entries'] = self._parse_directory_entries(directory)

        # Check if the directory points to a secondary directory in one of its entries
        for entry in directory['entries']:
            if entry['type'] in DIRECTORY_ENTRY_TYPES_SECONDARY_DIR:
                directory['secondary'] = entry['address']

        return directory

    def _parse_directory_entries(self, directory):
        header_size = DIRECTORY_HEADER_SIZES[directory['magic']]
        entry_size = DIRECTORY_ENTRY_SIZES[directory['magic']]

        entries = []

        # Iterate over directory entries
        for index, entry in enumerate(chunker(directory['content'][header_size:], entry_size)):
            entry_dict = {}

            # Iterate over the entry fields
            for key, word in zip(DIRECTORY_ENTRY_FIELDS, chunker(entry, 4)):
                entry_dict[key] = struct.unpack('<I', word)[0]

                # addresses are all starting at 0xff000000, but we just want everything from there
                if key == 'address':
                    entry_dict['address'] &= 0x00FFFFFF

            start = entry_dict['address']
            end = start + entry_dict['size']
            entry_content = rstrip_padding(self._file_content[start:end])

            entry_dict['content'] = entry_content

            # entry: merge in keys and values from a potential entry_header
            if entry_dict['type'] not in DIRECTORY_ENTRY_TYPES_SECONDARY_DIR:
                entry_header = self._parse_entry_header(entry_dict)
                entry_dict = {**entry_dict, **entry_header}

            # add md5 and duplicate info for entries with a valid size
            if 0 < entry_dict['size'] < 0x100000:
                md5sum = md5(entry_content).hexdigest()[:8]
                entry_dict['is_duplicate'] = True if md5sum in self._md5sums else False
                self._md5sums.add(md5sum)
            else:
                md5sum = 'n/a'
                entry_dict['is_duplicate'] = False

            entry_dict['md5sum'] = md5sum

            entries.append(entry_dict)

        return entries

    def _parse_entry_header(self, entry):
        entry_content = entry['content']
        pubkey = parse_amd_pubkey(entry_content)

        if pubkey or entry_content[0xfc:0x100] != b'\x00\x00\x00\x00':
            return {}
        else:
            entry_content = entry_content[:0x100]

        header = {
            'id': entry_content[0x10:0x14],
            's_signed': struct.unpack('<I', entry_content[0x14:0x18])[0],
            # 'h_type': struct.unpack('<I', entry_content[0x30:0x34])[0],  # always 0x01
            'sig_fp': hexlify(entry_content[0x38:0x48]),
            'compressed': struct.unpack('<I', entry_content[0x48:0x4c])[0],
            's_full': struct.unpack('<I', entry_content[0x50:0x54])[0],
            'version': '.'.join([hex(b)[2:].upper() for b in entry_content[0x63:0x5f:-1]]),
            'unknown': struct.unpack('<I', entry_content[0x68:0x6c])[0],
            's_packed': struct.unpack('<I', entry_content[0x6c:0x70])[0],
        }

        if header['id'] == b'\x01\x00\x00\x00':
            # actually twice as long, but SMURULESMURULES is kinda redundant
            header['id'] = entry_content[0x0:0x4]
        elif header['id'] == b'\x05\x00\x00\x00':
            header['id'] = b'0x05'

        try:
            # Try to encode the id as ascii
            header['id'] = str(header['id'], encoding='ascii')
            # and remove unprintable chars
            header['id'] = ''.join(s for s in header['id'] if s in string.printable)
            # If no printable chars are left, remove
            if header['id'] == '':
                del header['id']
        except UnicodeDecodeError:
            del header['id']

        return header

    def _verify_signature(self, entry):
        """ Verifies the signature of a given entry using the corresponding pubkey """

        if entry['type'] in ['AMD_PUBLIC_KEY', 'OEM_PSP_FW_PUBLIC_KEY', 'BIOS_PUBLIC_KEY', 'AMD_SEC_DBG_PUBLIC_KEY']:
            # todo: check signatures of secondary keys, too
            return False

        pubkey = self._pubkeys[entry['sig_fp']]

        if pubkey is None:
            print_warning('Could not find pubkey for entry.')
            return False

        start = entry['address']
        size = entry.get('s_packed') or entry['size']
        end = start + size
        sig = self._file_content[start - 0x100:end]

        compressed = True if entry.get('compressed') else False

        if compressed:
            data_decompressed = zlib_decompress(rstrip_padding(self._file_content[start:end - 0x100]))
            data = data_decompressed[:entry['s_signed'] + 0x100]
        else:
            data = self._file_content[start:end - 0x100]

        (fd_sig, sig_fname) = tempfile.mkstemp()
        (fd_data, data_fname) = tempfile.mkstemp()

        pubkey_tmp = tempfile.mktemp()
        self.extract_entry(pubkey['directory'], pubkey['entry'], pubkey_tmp, False, False, True)

        try:
            sig_file = os.fdopen(fd_sig, "wb")
            sig_file.write(sig)
            sig_file.close()

            data_file = os.fdopen(fd_data, "wb")
            data_file.write(data)
            data_file.close()

            try:
                subprocess.check_output(["openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-signature",
                                         sig_fname, "-verify", pubkey_tmp + ".pem", data_fname])

                return True
            except subprocess.CalledProcessError:
                return False
        finally:
            os.remove(sig_fname)
            os.remove(data_fname)
            os.remove(pubkey_tmp + ".pem")

    def extract_entry(self, directory_index, entry_index, outfile=None, no_duplicates=False, decompress=False,
                      to_pem_key=False):
        entry = self._directories[directory_index]['entries'][entry_index]
        entry_content = entry['content']

        if no_duplicates and entry['is_duplicate']:
            return

        if decompress:
            compressed = True if entry.get('compressed') else False
            if compressed:
                entry_content = zlib_decompress(entry_content)
            else:
                self._print_info('No zlib compression detected. Extracting raw entry instead.')

        if to_pem_key:
            pubkey = parse_amd_pubkey(entry_content)
            if pubkey:
                if struct.unpack('>I', pubkey['pubexp'])[0] != 65537:
                    print_error_and_exit('Only an exponent of 65537 is supported so far.')

                der_encoding = b'\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82' \
                               b'\x01\x0F\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00' + pubkey['modulus'] + b'\x02\x03' \
                                                                                                         b'\x01\x00\x01'

                pem_format = b'-----BEGIN PUBLIC KEY-----\n' + \
                             b'\n'.join(chunker(b64encode(der_encoding), 64)) + \
                             b'\n-----END PUBLIC KEY-----\n'

                if outfile is not None:
                    outfile += '.pem'

                entry_content = pem_format
            else:
                self._print_info('No AMD Signing Key detected. Extracting raw entry instead.')

        if outfile is not None:
            with open(outfile, 'wb') as f:
                f.write(entry_content)
        else:
            sys.stdout.buffer.write(entry_content)

    def extract_directory(self, directory_index, outdir=None, no_duplicates=False, decompress=False, to_pem_key=False):
        """
        Extracts a PSP directory to an output directory. If parsable by PSPTool, each entry will be saved as an
        individual file. Otherwise the directory will be extracted as one blob.

        :param directory_index:     Directory index as enumerated and displayed by PSPTool
        :param outdir:              Output directory (default: ./)
        :param no_duplicates:       Whether duplicates should be extracted only once
        :param decompress:          Whether compressed entries should be unpacked
        :param to_pem_key:          Whether cryptographic keys should be converted to PEM format
        """

        outdir = outdir or './'  # todo: give an option to return the extracted directory as binary string
        directory = self._directories[directory_index]

        # If this is a parsable directory, extract all entries individually
        if directory['magic'] in PARSABLE_DIRECTORY_MAGIC:
            for index, entry in enumerate(directory['entries']):
                if entry['type'] in DIRECTORY_ENTRY_TYPES:
                    name = DIRECTORY_ENTRY_TYPES[entry['type']]
                else:
                    name = hex(entry['type'])

                outfile = outdir + '/d%.2d_e%.2d_%s' % (directory_index, index, name)

                if 'version' in entry:
                    outfile += '_v%s' % entry['version']

                    self.extract_entry(directory_index, index, outfile=outfile, no_duplicates=no_duplicates,
                                       decompress=decompress, to_pem_key=to_pem_key)

        # If this is an unparsable directory, extract the directory as is
        else:
            all_directories = self._directories
            directory_start = directory['address']

            # Find out this directory's bounds by taking the following directory's bounds or EOF
            if directory_index < len(all_directories) - 1:
                if all_directories[directory_index + 1]['address'] > directory_start:
                    print_warning('Extracting unparsable directory %d as is.' % directory_index)
                    directory_end = all_directories[directory_index + 1]['address']
                else:
                    print_warning('Assuming EOF for the bounds of directory %d.' % directory_index)
                    directory_end = len(self._file_content)

            directory_content = self._file_content[directory_start:directory_end]

            outfile = outdir + '/d%.2d_%s_%s' % (directory_index, directory['type'], hex(directory_start))

            with open(outfile, 'wb') as f:
                f.write(directory_content)

    def extract_all_directories(self, outdir=None, no_duplicates=False, decompress=False, to_pem_key=False):
        outdir = outdir or './'

        if not os.path.isdir(outdir):
            print_error_and_exit('Specified output directory (-o) is not a directory.')

        for directory_index in range(len(self._directories)):
            self.extract_directory(directory_index, outdir, decompress, no_duplicates, to_pem_key)

    def replace_entry(self, directory_index, entry_index, subfile, outfile):
        # todo: when used as Python module, this should change the actual _directories/entries
        # todo: handle file sizes and padding stuff
        entry = self._directories[directory_index]['entries'][entry_index]

        if subfile is not None:
            with open(subfile, 'rb') as f:
                subfile_content = f.read()
        else:
            subfile_content = sys.stdin.buffer.read()

        if len(subfile_content) != entry['size']:
            print_error_and_exit('input of exactly 0x%x bytes needed.' % entry['size'])

        start = entry['address']
        end = start + entry['size']
        new_file_content = self._file_content[:start] + subfile_content + self._file_content[end:]

        if outfile is not None:
            with open(outfile, 'wb') as f:
                f.write(new_file_content)
        else:
            sys.stdout.buffer.write(new_file_content)

    def print_directory_entries(self, directory_index, no_duplicates=False, display_entry_header=False,
                                display_arch=False, csvfile=None):
        directory = self._directories[directory_index]

        if directory['magic'] not in PARSABLE_DIRECTORY_MAGIC:
            print_warning('Parsing of %s not supported.' % directory['magic'])
            return

        # Table head
        basic_fields = [' ', 'Entry', 'Address', 'Size', 'Type (Magic)', 'Version', 'Signed by', 'Info']
        verbose_fields = ['MD5', 'Entropy']
        entry_header_fields = ['identifier', 'compressed', 'size_full', 'size_signed', 'size_packed', 'unknown',
                               'sig_fp']
        all_fields = basic_fields + verbose_fields + entry_header_fields

        # Corresponding dict keys of entry dict
        all_keys = ['', 'index', 'address', 'size', 'type', 'version', 'signed_by', 'info', 'md5sum', 'entropy', 'id',
                    'compressed', 's_full', 's_signed', 's_packed', 'unknown',  'sig_fp']

        t = PrettyTable(all_fields)
        t.align = 'r'
        t.align['Type (Magic)'] = 'l'

        for index, entry in enumerate(directory['entries']):
            entry = {'index': str(index), 'info': [], 'signed_by': '', **entry}

            # When an SPI trace file is provided, hide unused entry or display additional info
            if csvfile:
                if entry['type'] not in self._accessed_entries:
                    continue
                else:
                    accessed_entry = self._accessed_entries[entry['type']]
                    entry['info'].append('accessed(%.2d)' % accessed_entry['position'])

            # Translate known entry types into strings
            if entry['type'] in DIRECTORY_ENTRY_TYPES:
                entry['type'] = DIRECTORY_ENTRY_TYPES[entry['type']]
            else:
                entry['type'] = hex(entry['type'])

            # Incorporate string identifier into type field
            if 'id' in entry:
                entry['type'] += ' (%s)' % entry['id']

            # Check if this is an AMD signing key
            # todo: extract!
            pubkey = parse_amd_pubkey(entry['content'])

            if pubkey:
                entry['sig_fp'] = pubkey['certifying_id']
                entry['id'] = pubkey['key_id']
                entry['info'].append('pubkey')

                if self._verbose:
                    entry['info'].append('key_version:%i' % pubkey['version'])
                    entry['info'].append('key_usage:%i' % pubkey['key_usage'])

                if pubkey['key_id'] not in self._pubkeys:
                    self._pubkeys[pubkey['key_id']] = {
                        'directory': directory_index,
                        'entry': index,
                        'type': entry['type']
                    }

            # Display info about signing
            if 'sig_fp' in entry and entry['sig_fp'] != '' and entry['sig_fp'] in self._pubkeys:
                signed_by = self._pubkeys[entry['sig_fp']]
                entry['signed_by'] = signed_by['type']

                if self._verify_signature(entry):
                    entry['signed_by'] += '\n[verified]'
                else:
                    entry['signed_by'] += '\n[not verified]'

            # The following operations might be to expensive or impossible on bad entry sizes
            if not (0 < entry['size'] < 0x100000):
                entry['entropy'] = 'n/a'
            else:
                if entry['is_duplicate']:
                    if no_duplicates:
                        continue
                    else:
                        entry['info'].append('duplicate')

                # Entropy calculation for detection of encrypted entries
                entry['entropy'] = round(shannon(entry['content']), 2)

                # Zlib compression detection
                zlib_header = zlib_find_header(entry['content'])

                # When entropy is high and the entry uncompressed, we assume that it's encrypted
                if 'compressed' in entry and entry['compressed'] == 1:
                        entry['info'].append('compressed') if not self._verbose else entry['info'].append('zlib@0x%x' %
                                                                                                          zlib_header)
                elif entry['entropy'] >= 0.9:
                    entry['info'].append('encrypted?')

                # Architecture detection
                if display_arch:
                    data = entry['content']

                    if entry.get('compressed'):
                        data = zlib_decompress(entry['content'])  # [:-0x100]

                    arch = find_arch(data)
                    if arch is not None:
                        entry['info'].append('arch=%s' % arch)

            # Line up all values according to all_keys (remember: dicts are not ordered!)
            entry_row_values = []
            for key in all_keys:
                try:
                    value = entry[key]
                except KeyError:
                    value = ''

                if isinstance(value, bytes) and len(value) == 32:   # truncate hex-fingerprints to 4 uppercase chars
                    value = value[:8].upper()

                if isinstance(value, int):                          # convert numbers to hex
                    entry_row_values.append(hex(value))
                elif isinstance(value, bytes):                      # convert bytes to string
                    try:
                        entry_row_values.append(str(value, 'ascii'))
                    except UnicodeDecodeError:
                        entry_row_values.append(value)
                elif isinstance(value, list):                       # convert lists (e.g. 'info') to string
                    entry_row_values.append('\n'.join(entry['info']))
                else:
                    entry_row_values.append(value)

            t.add_row(entry_row_values)

        # See which fields are actually demanded (depending on -v and -i)
        fields = basic_fields

        if display_entry_header:
            fields += entry_header_fields
        if self._verbose:
            fields += verbose_fields

        print(t.get_string(fields=fields))

    def print_all_directory_entries(self, no_duplicates=False, display_entry_header=False, display_arch=False,
                                    csvfile=None):
        if csvfile:
            data = get_database(csvfile, self.file)

            position = 0
            accessed_entries = {}

            for start_time, values in sorted(data['read_accesses'].items()):
                if values['type'] not in accessed_entries:
                    accessed_entries[values['type']] = values
                    accessed_entries[values['type']]['position'] = position
                    position += 1

        for directory_index, directory in enumerate(self._directories):
            t = PrettyTable(['Directory', 'Addr', 'Type', 'Magic', 'Secondary Directory'])

            dir_magic = directory['magic'].decode('utf-8', 'backslashreplace')
            dir_secondary = hex(directory['secondary']) if directory['secondary'] else '--'

            t.add_row([directory_index, hex(directory['address']), directory['type'], dir_magic, dir_secondary])

            print(t)

            self.print_directory_entries(directory_index, no_duplicates=no_duplicates,
                                         display_entry_header=display_entry_header, display_arch=display_arch,
                                         csvfile=csvfile)

            print('\n')


def main():
    parser = ObligingArgumentParser(description='Parse, display, extract and manipulate PSP firmware inside BIOS ROMs, '
                                                'UEFI volumes and so on.\n',
                                    formatter_class=RawTextHelpFormatter, add_help=False)

    parser.add_argument('file', help='Binary file to be parsed for PSP firmware _directories')

    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit.\n\n')

    # These arguments are explained implicitly through other arguments and are therefore hidden from the help
    parser.add_argument('-v', '--verbose', help=argparse.SUPPRESS, action='store_true')
    parser.add_argument('-n', '--no-duplicates', help=argparse.SUPPRESS, action='store_true')
    parser.add_argument('-d', '--directory-index', help=argparse.SUPPRESS, type=int)
    parser.add_argument('-e', '--entry-index', help=argparse.SUPPRESS, type=int)
    parser.add_argument('-o', '--outfile', help=argparse.SUPPRESS)
    parser.add_argument('-s', '--subfile', help=argparse.SUPPRESS)
    parser.add_argument('-u', '--decompress', help=argparse.SUPPRESS, action='store_true')
    parser.add_argument('-k', '--pem-key', help=argparse.SUPPRESS, action='store_true')
    parser.add_argument('-i', '--entry-header', help=argparse.SUPPRESS, action='store_true')
    parser.add_argument('-a', '--detect-arch', help=argparse.SUPPRESS, action='store_true')
    parser.add_argument('-t', '--csvfile', help=argparse.SUPPRESS)

    # These are the main options
    action = parser.add_mutually_exclusive_group(required=False)

    action.add_argument('-E', '--entries', help='\n'.join([
        'Default: Parse and display PSP firmware entries.',
        '[-d idx] [-n] [-i] [-v]',
        '',
        '-d idx:     specifies directory_index (default: all _directories)',
        '-n:         hide duplicate entries from listings',
        '-i:         display additional entry header info',
        '-a:         display entry architecture (powered by cpu_rec)',
        '-v:         display even more info (AGESA Version, Entropy, MD5)',
        '-t csvfile: only display entries found in the given SPI trace',
        '            (see psptrace for details)',
        '']), action='store_true')

    action.add_argument('-X', '--extract-entry', help='\n'.join([
        'Extract one or more PSP firmware entries.',
        '[-d idx [-e idx]] [-n] [-u] [-k] [-v] [-o outfile]',
        '',
        '-d idx:  specifies directory_index (default: all _directories)',
        '-e idx:  specifies entry_index (default: all entries)',
        '-n:      skip duplicate entries',
        '-u:      uncompress compressed entries',
        '-k:      convert _pubkeys into PEM format',
        '-v:      increase output verbosity',
        '-o file: specifies outfile/outdir (default: stdout/$PWD)',
        '']), action='store_true')

    action.add_argument('-R', '--replace-entry', help='\n'.join([
        'Replace a raw PSP firmware entry and export new ROM file.',
        '-d idx -e idx [-s subfile] [-o outfile]',
        '',
        '-d idx:  specifies directory_index',
        '-e idx:  specifies entry_index',
        '-s file: specifies subfile (default: stdin)',
        '-o file: specifies outfile (default: stdout)',
        '']), action='store_true')

    args = parser.parse_args()
    pt = PSPTool(args.file, verbose=args.verbose)

    if args.verbose:
        print(pt.agesa_version)

    # Now follows an ugly but necessary argument dependency checking
    if args.extract_entry:
        if args.directory_index is not None:
            if args.entry_index is not None:
                pt.extract_entry(args.directory_index, args.entry_index, outfile=args.outfile,
                                 no_duplicates=args.no_duplicates, decompress=args.decompress, to_pem_key=args.pem_key)
            else:
                pt.extract_directory(args.directory_index, outdir=args.outdir, no_duplicates=args.no_duplicates,
                                     decompress=args.decompress, to_pem_key=args.pem_key)
        else:
            if args.entry_index is None:
                pt.extract_all_directories(outdir=args.outfile, no_duplicates=args.no_duplicates,
                                           decompress=args.decompress, to_pem_key=args.pem_key)
            else:
                parser.print_help(sys.stderr)

    elif args.replace_entry:
        if args.directory_index is not None and args.entry_index is not None:
            pt.replace_entry(args.directory_index, args.entry_index, args.subfile, args.outfile)
        else:
            parser.print_help(sys.stderr)

    else:  # args.entries is the default behaviour
        if args.directory_index is not None:
            pt.print_directory_entries(args.directory_index, no_duplicates=args.no_duplicates,
                                       display_entry_header=args.entry_header, display_arch=args.detect_arch,
                                       csvfile=args.csvfile)
        else:
            pt.print_all_directory_entries(no_duplicates=args.no_duplicates, display_entry_header=args.entry_header,
                                           display_arch=args.detect_arch, csvfile=args.csvfile)


if __name__ == '__main__':
    main()
