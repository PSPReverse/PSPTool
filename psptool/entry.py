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

import string
import struct
import traceback

from .utils import NestedBuffer
from .utils import shannon
from .utils import chunker
from .utils import zlib_decompress, zlib_compress
from .utils import decrypt
from .utils import print_warning
from .utils import round_to_int

from IPython import embed

from enum import Enum

from binascii import hexlify
from base64 import b64encode
from math import ceil
from hashlib import md5

import sys
import zlib
import re

from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class Entry(NestedBuffer):
    ENTRY_ALIGNMENT = 0x100

    UNWRAPPED_IKEK_ZEN_PLUS = b'\x4c\x77\x63\x65\x32\xfe\x4c\x6f\xd6\xb9\xd6\xd7\xb5\x1e\xde\x59'
    HASH_IKEK_ZEN_PLUS = b'\xe2\x84\xda\xe0\x6e\x58\x01\x04\xfa\x6e\x8e\x6b\x58\x68\x8a\x0c'

    UNWRAPPED_IKEK_ZEN = b'\x49\x1e\x40\x1a\x40\x1e\xc1\xb2\x28\x46\x00\xf0\x99\xfd\xe8\x68'
    HASH_IKEK_ZEN = b'\x47\x23\xa8\x52\x03\x38\xbd\x2e\xac\x5f\xae\x9c\x2c\xb5\x92\x5b'

    DIRECTORY_ENTRY_TYPES = {
        0x00: 'AMD_PUBLIC_KEY',
        0x01: 'PSP_FW_BOOT_LOADER',
        0x02: 'PSP_FW_TRUSTED_OS',
        0x03: 'PSP_FW_RECOVERY_BOOT_LOADER',
        0x04: 'PSP_NV_DATA',
        0x05: 'BIOS_PUBLIC_KEY',
        0x06: 'BIOS_RTM_FIRMWARE',
        0x07: 'BIOS_RTM_SIGNATURE',
        0x08: 'SMU_OFFCHIP_FW',
        0x09: 'SEC_DBG_PUBLIC_KEY',
        0x0A: 'OEM_PSP_FW_PUBLIC_KEY',
        0x0B: 'SOFT_FUSE_CHAIN_01',
        0x0C: 'PSP_BOOT_TIME_TRUSTLETS',
        0x0D: 'PSP_BOOT_TIME_TRUSTLETS_KEY',
        0x10: 'PSP_AGESA_RESUME_FW',
        0x12: 'SMU_OFF_CHIP_FW_2',
        0x13: 'DEBUG_UNLOCK',
        0x1A: 'PSP_S3_NV_DATA',
        0x21: 'WRAPPED_IKEK',
        0x22: 'TOKEN_UNLOCK',
        0x24: 'SEC_GASKET',
        0x25: 'MP2_FW',
        0x28: 'DRIVER_ENTRIES',
        0x2D: 'S0I3_DRIVER',
        0x30: 'ABL0',
        0x31: 'ABL1',
        0x32: 'ABL2',
        0x33: 'ABL3',
        0x34: 'ABL4',
        0x35: 'ABL5',
        0x36: 'ABL6',
        0x37: 'ABL7',
        0x3A: 'FW_PSP_WHITELIST',
        # 0x40: 'FW_L2_PTR',
        0x41: 'FW_IMC',
        0x42: 'FW_GEC',
        0x43: 'FW_XHCI',
        0x44: 'FW_INVALID',
        0x5f: 'FW_PSP_SMUSCS',
        0x60: 'FW_IMC',
        0x61: 'FW_GEC',
        0x62: 'FW_XHCI',
        0x63: 'FW_INVALID',
        0x108: 'PSP_SMU_FN_FIRMWARE',
        0x118: 'PSP_SMU_FN_FIRMWARE2',

        # Entry types named by us
        #   Custom names are denoted by a leading '!'
        0x14: '!PSP_MCLF_TRUSTLETS',  # very similiar to ~PspTrustlets.bin~ in coreboot blobs
        0x38: '!PSP_ENCRYPTED_NV_DATA',
        0x40: '!PL2_SECONDARY_DIRECTORY',
        0x70: '!BL2_SECONDARY_DIRECTORY',
        0x15f: '!FW_PSP_SMUSCS_2',  # seems to be a secondary FW_PSP_SMUSCS (see above)
        0x112: '!SMU_OFF_CHIP_FW_3',  # seems to tbe a tertiary SMU image (see above)
        0x39: '!SEV_APP',
        0x30062: '!UEFI-IMAGE'

    }

    class Type(Enum):
        NO_HDR_ENTRY = 1
        PUBKEY = 2
        NORMAL = 3

    class ParseError(Exception):
        pass

    class TypeError(Exception):
        pass

    @classmethod
    def from_fields(cls, parent_directory, parent_buffer, type_, size, offset, blob):
        # Try to parse these ID's as a key entry
        PUBKEY_ENTRY_TYPES = [ 0x0, 0x9, 0xa, 0x5, 0xd]

        # Types known to have no PSP HDR
        # TODO: Find a better way to identify those entries
        NO_HDR_ENTRY_TYPES = [ 0x4, 0xb, 0x21, 0x40, 0x70, 0x30062, 0x6, 0x61, 0x60,
                               0x68, 0x100060, 0x100068, 0x5f, 0x15f, 0x1a, 0x22, 0x63,
                               0x67 , 0x66, 0x100066, 0x200066, 0x300066, 0x10062,
                               0x400066, 0x500066, 0x800068, 0x61, 0x200060, 0x300060,
                               0x300068, 0x400068, 0x500068, 0x400060, 0x500060, 0x200068,
                               0x7, 0x38]
        NO_SIZE_ENTRY_TYPES = [ 0xb]

        new_entry = None

        if type_ in NO_SIZE_ENTRY_TYPES:
            size = 0

        if type_ in NO_HDR_ENTRY_TYPES:
            # Option 1: it's a plain Entry
            try:
                new_entry = Entry(parent_directory, parent_buffer, type_, size, buffer_offset=offset, blob=blob)
            except:
                print_warning(f"Couldn't parse plain entry: 0x{type_:x}")

        elif type_ in PUBKEY_ENTRY_TYPES:
            # Option 2: it's a PubkeyEntry

            try:
                new_entry = PubkeyEntry(parent_directory, parent_buffer, type_, size, buffer_offset=offset, blob=blob)
            except:
                print_warning(f"Couldn't parse pubkey entry 0x{type_:x}")
        else:
            # Option 3: it's a HeaderEntry (most common)
            if size == 0:
                # If the size in the directory is zero, set the size to hdr len
                size = HeaderEntry.HEADER_LEN
            new_entry = HeaderEntry(parent_directory, parent_buffer, type_, size, buffer_offset=offset, blob=blob)
            if size == 0:
                print_warning(f"Entry with zero size. Type: {type_}. Dir: 0x{offset:x}")

        return new_entry

    @classmethod
    def from_blob(cls, binary, id, type, compressed, signed, hdr=None, address=None, private_key=None):
        if type == Entry.Type.PUBKEY:
            print_warning(f"from_blob is not implemented for pubkeys")
            pass
        elif type == Entry.Type.NO_HDR_ENTRY:
            print_warning(f"from_blob is not implemented for non-header objects")
            pass
        elif type == Entry.Type.NORMAL:
            size = round_to_int(len(binary),0x10)
            if compressed:
                rom_data = zlib_compress(binary)
                zlib_size = len(rom_data)
                padded_size = round_to_int(zlib_size, 0x10)
            else:
                rom_data = binary
                zlib_size = 0
                padded_size = round_to_int(len(rom_data),0x10)

            if signed:
                if private_key != None:
                    private_key = load_pem_private_key(private_key,password=None,backend=default_backend())
                    sig_len = private_key.key_size // 8
                else:
                    # We reserve 0x200 for the signature, just in case we use a 4096 bit key.
                    sig_len = 0x200
                total_size = padded_size + sig_len
            else:
                total_size = padded_size

            # Add 0x100 for the header
            total_size += 0x100

            if compressed:
                padding_size = padded_size - zlib_size
                total_size += padding_size
                blob = NestedBuffer(bytearray(total_size), total_size)
                blob[0x100:0x100 + zlib_size] = rom_data
                blob[0x100 + zlib_size:0x100 + padded_size] = padding_size * b'\xff'
            else:
                padding_size = padded_size - len(rom_data)
                total_size += padding_size
                blob = NestedBuffer(bytearray(total_size), total_size)
                blob[0x100:0x100 + len(rom_data)] = rom_data
                blob[0x100 + len(rom_data):0x100 + padded_size] = padded_size * b'\xff'


            # Set compressed bit
            if compressed:
                blob[0x48:0x4c] = (1).to_bytes(4, 'little')
            # Set size
            blob[0x14:0x18] = (size).to_bytes(4, 'little')
            # Set rom_size
            blob[0x6c:0x70] = (total_size).to_bytes(4, 'little')
            if compressed:
                # Set zlib_size
                blob[0x54:0x58] = (zlib_size).to_bytes(4, 'little')


            entry = HeaderEntry(None, blob, id, total_size, 0x0, blob)

            if signed and private_key != None:
                entry.sign(private_key)
                entry[-0x200:] = entry.signature
            # if signed:
            #     sig = private_key.sign(

            return entry


        else:
            raise Entry.TypeError()


    def __init__(self, parent_directory, parent_buffer, type_, buffer_size, buffer_offset: int, blob):
        super().__init__(parent_buffer, buffer_size, buffer_offset=buffer_offset)

        # TODO: Fix to reference of FET
        self.blob = blob
        self.type = type_
        self.references = [parent_directory]
        self.parent_directory = parent_directory


        self.compressed = False
        self.signed = False
        self.encrypted = False
        self.is_legacy = False


        try:
            self._parse()
        except (struct.error, AssertionError):
            print_warning(f"Couldn't parse entry at: 0x{self.get_address():x}. Type: {self.get_readable_type()}. Size 0x{len(self):x}")
            raise Entry.ParseError()

    def __repr__(self):
        return f'{self.__class__.__name__}(type={hex(self.type)}, address={hex(self.get_address())}, ' \
               f'size={hex(self.buffer_size)}, len(references)={len(self.references)})'

    def __eq__(self, other):
        return self.type == other.type and self.get_address() == other.get_address() and \
              self.buffer_size == other.buffer_size

    def __hash__(self):
        return hash((self.type, self.get_address(), self.buffer_size))

    def __lt__(self, other):
        return self.get_address() < other.get_address()

    def _parse(self):
        pass

    def get_readable_type(self):
        if self.type in self.DIRECTORY_ENTRY_TYPES:
            return f'{self.DIRECTORY_ENTRY_TYPES[self.type]}~{hex(self.type)}'
        else:
            return hex(self.type)

    def get_readable_version(self):
        return ''

    def get_readable_magic(self):
        return ''

    def get_readable_signed_by(self):
        return ''

    def shannon_entropy(self):
        return shannon(self[:])

    def md5(self):
        m = md5()
        m.update(self.get_bytes())
        return m.hexdigest()

    def move_buffer(self, new_address, size):
        current_address = self.get_address()
        move_offset = new_address - current_address
        self.buffer_offset += move_offset
        self.buffer_size = int(ceil(size / self.ENTRY_ALIGNMENT)) * self.ENTRY_ALIGNMENT

        # update all directories' headers that point to this entry
        for directory in self.references:
            directory.update_entry_fields(self, self.type, self.buffer_size, self.buffer_offset)


class PubkeyEntry(Entry):
    def _parse(self):
        """ SEV spec B.1 """

        pubexp_size = struct.unpack('<I', self[0x38:0x3c])[0] // 8
        modulus_size = signature_size = struct.unpack('<I', self[0x3c:0x40])[0] // 8
        pubexp_start = 0x40
        modulus_start = pubexp_start + pubexp_size

        # Byte order of the numbers is inverted over their entire length
        # Assumption: Only the most significant 4 bytes of pubexp are relevant and can be converted to int

        # todo: use NestedBuffers instead of saving by value
        self.pubexp = self[pubexp_start:modulus_start][::-1][-4:]
        self.modulus = self[modulus_start:modulus_start + modulus_size][::-1]

        self.version = struct.unpack('<I', self[0x0:0x4])[0]
        self.key_id = hexlify(self[0x4:0x14])
        self.certifying_id = hexlify(self[0x14:0x24])
        self.key_usage = struct.unpack('<I', self[0x24:0x28])[0]

        expected_size = 0x40 + pubexp_size + modulus_size + signature_size

        # Option 1: it's a regular Pubkey (with a trailing signature)
        if len(self) == expected_size:
            self.signature = self[modulus_start + modulus_size:]
        # Option 2: it's the AMD Root Signing Key (without a trailing signature)
        elif len(self) == expected_size - signature_size:
            self.signature = None
        else:
            raise Entry.ParseError()

    def get_readable_magic(self):
        # use this to show the first four characters of the key ID
        return str(self.key_id[:4], encoding='ascii').upper()

    def get_der_encoded(self):
        if struct.unpack('>I', self.pubexp)[0] != 65537:
            raise NotImplementedError('Only an exponent of 65537 is supported.')

        if len(self.modulus) == 0x100:
            der_encoding = b'\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01' \
                           b'\x0F\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00' + self.modulus + b'\x02\x03\x01\x00\x01'
        elif len(self.modulus) == 0x200:
            der_encoding = b'\x30\x82\x02\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x02' \
                           b'\x0F\x00\x30\x82\x02\x0A\x02\x82\x02\x01\x00' + self.modulus + b'\x02\x03\x01\x00\x01'
        else:
            return None

        return der_encoding

    def get_pem_encoded(self):
        return b'-----BEGIN PUBLIC KEY-----\n' + \
               b'\n'.join(chunker(b64encode(self.get_der_encoded()), 64)) + \
               b'\n-----END PUBLIC KEY-----\n'


class HeaderEntry(Entry):


    HEADER_LEN = 0x100

    def _parse(self):
        self.header = NestedBuffer(self, HeaderEntry.HEADER_LEN)

        # todo: use NestedBuffers instead of saving by value
        self.magic = self.header[0x10:0x14]
        self.size_signed = struct.unpack('<I', self.header[0x14:0x18])[0]
        self.encrypted = struct.unpack('<I', self.header[0x18:0x1c])[0] == 1
        self.signed = struct.unpack('<I', self.header[0x30:0x34])[0] == 1
        self.signature_fingerprint = hexlify(self.header[0x38:0x48])
        self.compressed = struct.unpack('<I', self.header[0x48:0x4c])[0] == 1
        self.size_uncompressed = struct.unpack('<I', self.header[0x50:0x54])[0]
        self.version = self.header[0x63:0x5f:-1]
        self.load_addr = struct.unpack('<I', self.header[0x68:0x6c])[0]
        self.rom_size = struct.unpack('<I', self.header[0x6c:0x70])[0]
        self.zlib_size = struct.unpack('<I', self.header[0x54:0x58])[0]

        self.iv = hexlify(self.header[0x20:0x30])
        self.unknown_bool = struct.unpack('<I', self.header[0x7c:0x80])[0]
        self.wrapped_key = hexlify(self.header[0x80:0x90])


        # TODO: Take care of headers with only 0xfff...

        # TODO if zlib_size == 0 try size_signed


        assert(self.compressed in [0, 1])
        assert(self.encrypted in [0, 1])

        if self.signed:
            self._parse_signature()
        else:
            self.signature_len = 0

        self.header_len = 0x100

        if self.rom_size == 0 or (self.compressed and self.zlib_size == 0):
            # Try to parse as legacy header
            self._parse_legacy_hdr()
        else:
            self._parse_hdr()
        return

    def _parse_signature(self):
        if self.signature_fingerprint != hexlify(16 * b'\x00'):
            try:
                self.pubkey = self.blob.pubkeys[self.signature_fingerprint]
                self.signature_len = len(self.pubkey.modulus)
            except KeyError:
                # Key not found yet, try to find it anywhere in the blob
                self.blob.find_pubkey(self[0x38:0x48])
                try:
                    self.pubkey = self.blob.pubkeys[self.signature_fingerprint]
                except KeyError:
                    print_warning(f"Couldn't find corresponding key in blob for entry at: 0x{self.get_address():x}. Type: {self.get_readable_type()}")
                    self.signature_len = 0x0
                    self.signed = False
                    return
            self.signature_len = len(self.pubkey.modulus)
        else:
            print_warning("ERROR: Signed but no key id present")




    def _parse_legacy_hdr(self):

        self.buffer_size = self.size_signed + self.header_len

        if self.compressed:
            self.zlib_size = self.size_signed

        if self.signed and not self.compressed:
            # The signature can be found in the last 'signature_len' bytes of the entry
            self.signature = NestedBuffer(self,self.signature_len, len(self) - self.signature_len)
        else:
            #TODO create nested buffer with uncompressed signature
            # raw_bytes = zlib.decompress(self[0x100:])
            self.signature = None


        self.body = NestedBuffer(self, len(self) - self.size_signed - self.header_len, self.header_len)
        self.is_legacy = True

    def _parse_hdr(self):
        if self.rom_size == 0:
            #TODO throw exception
            self.buffer_size = self.size_signed + self.header_len
            print_warning("ERROR. rom size is zero")
        else:
            self.buffer_size = self.rom_size

        if self.signed:
            buf_start = self.get_address()
            sig_start = self.get_address() + self.rom_size - self.signature_len
            # print_warning(f"Signature at: 0x{buf_start:x} sig_start: 0x{sig_start:x}")
            self.signature = NestedBuffer(self, self.signature_len, sig_start - buf_start)


        if self.compressed:
            if self.zlib_size == 0:
                # Todo throw exception
                print_warning(f"ERROR: Weird entry. Address 0x{self.get_address():x}")

        # Get IV and wrapped KEY from entry header
        if self.encrypted:
            self.iv = self.header[0x20:0x30]
            self.key = self.header[0x80:0x90]
            assert(self.iv != (b'\x00' * 16))
            assert(self.key != (b'\x00' * 16))

        self.body = NestedBuffer(self, len(self) - self.header_len - self.signature_len, self.header_len)
        self.is_legacy = False


    def get_readable_version(self):
        return '.'.join([hex(b)[2:].upper() for b in self.version])

    def get_ikek_md5sum(self) -> bytes:
        ikek = self.parent_buffer.get_entries_by_type(0x21)[0]
        m = md5()
        m.update(ikek.get_bytes())
        return m.digest()

    def get_readable_magic(self):
        # if self.magic == b'\x01\x00\x00\x00':
            # actually twice as long, but SMURULESMURULES is kinda redundant
            # readable_magic= self[0x0:0x4]
        if self.magic == b'\x05\x00\x00\x00':
            readable_magic = b'0x05'
        else:
            readable_magic = self.magic

        try:
            # Try to encode the id as ascii
            readable_magic = str(readable_magic, encoding='ascii')
            # and remove unprintable chars
            readable_magic = ''.join(s for s in readable_magic if s in string.printable)
        except UnicodeDecodeError:
            return ''

        return readable_magic

    def get_readable_signed_by(self):
        return str(self.signature_fingerprint, encoding='ascii').upper()[:4]

    def get_decompressed(self) -> bytes:
        return self.header.get_bytes() + self.get_decompressed_body()

    def get_decompressed_body(self) -> bytes:
        if not self.compressed:
            return self.body.get_bytes()
        else:
            try:
                return zlib_decompress(self.body.get_bytes()[:self.zlib_size])
            except:
                print_warning(f"ZLIB decompression faild on entry {self.get_readable_type()}")
                return self.body.get_bytes()

    def get_decrypted(self) -> bytes:
        return self.header.get_bytes() + self.get_decrypted_body()

    def get_decrypted_body(self) -> bytes:
        if not self.encrypted:
            return self.body.get_bytes()
        else:
            unwrapped_ikek = self.get_unwrapped_ikek()
            assert(unwrapped_ikek != None)
            return decrypt(self.body.get_bytes(), self.key, unwrapped_ikek, self.iv)

    def get_unwrapped_ikek(self) -> bytes:
        #TODO: Find out how to identify the correct IKEK.
        #      For now assume that the zen+ IKEK is correct.

        # if self.get_ikek_md5sum() == self.HASH_IKEK_ZEN:
        #     return self.UNWRAPPED_IKEK_ZEN
        # if self.get_ikek_md5sum() == self.HASH_IKEK_ZEN_PLUS:
        #     return self.UNWRAPPED_IKEK_ZEN_PLUS
        # else:
        #     return None

        return self.UNWRAPPED_IKEK_ZEN_PLUS



    def shannon_entropy(self):
        return shannon(self.body[:])

    def md5(self):
        m = md5()
        try:
            m.update(self.body.get_bytes())
        except:
            print(f"Get bytes failed at entry: 0x{self.get_address():x} type: {self.get_readable_type()} size: 0x{self.buffer_size:x}")
        return m.hexdigest()

    def sign(self,private_key):
        if self.compressed:
            signed_data = self.get_decompressed()[:self.size_signed + self.header_len]
        elif self.encrypted:
            print_warning(f'Signing encrypted entries is not supported yet')
            return False
        else:
            signed_data = self[:self.size_signed + self.header_len]


        if private_key.key_size == 2048 :
            hash = hashes.SHA256()
            salt_length = 32
        elif private_key.key_size == 4096:
            hash = hashes.SHA384()
            salt_length = 48
        else:
            print_warning(f"Unknown key_size: {private_key.key_size}")
            return False

        try:
            signature = private_key.sign(
              signed_data,
              padding.PSS(
                  mgf=padding.MGF1(hash),
                  salt_length=salt_length
              ),
              hash
            )
        except:
            print_warning("Signing exception")
            return False

        # Special fingerprint, denote that this entry was resigned with a custom key
        self.signature_fingerprint = hexlify(4 * b'\xDE\xAD\xBE\xEF')
        self.signature = signature
        return True

    def verify_signature(self):
        # Note: This does not work if an entry was compressed AND encrypted.
        # However, we have not yet seen such entry.

        # Only verify signature if we actually have a signature
        if self.signature == None:
            return False

        if self.compressed:
            signed_data = self.get_decompressed()[:self.size_signed + self.header_len]
        elif self.encrypted:
            signed_data = self.get_decrypted()[:self.size_signed + self.header_len]
        else:
            signed_data = self.get_bytes()[:self.size_signed + self.header_len]

        try:
            pubkey_der_encoded = self.pubkey.get_der_encoded()
        except AttributeError:
            print_warning(f"Entry {self.get_readable_type()} is signed, but corresponding pubkey was not found ({self.get_readable_signed_by()})")
            return False

        crypto_pubkey = load_der_public_key(pubkey_der_encoded, backend=default_backend())


        if len(self.signature) == 0x100:
            hash = hashes.SHA256()
            salt_len = 32
        elif len(self.signature) == 0x200:
            hash = hashes.SHA384()
            salt_len = 48
        else:
            print_warning("Weird signature len")
            return False

        try:
            crypto_pubkey.verify(
                self.signature.get_bytes(),
                signed_data,
                padding.PSS(
                    mgf=padding.MGF1(hash),
                    salt_length=salt_len
                ),
                hash
            )
        except InvalidSignature:
            return False

        return True
