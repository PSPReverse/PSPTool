# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2021 Christian Werling, Robert Buhren, Hans Niklas Jacob
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

from .utils import NestedBuffer
from .utils import shannon
from .utils import zlib_decompress, zlib_compress
from .utils import decrypt
from .utils import round_to_int
from .crypto import KeyId, Signature, ReversedSignature, PrivateKey

from enum import Enum

from binascii import hexlify
from math import ceil
from hashlib import md5, sha256

BIOS_ENTRY_TYPES = [0x10062, 0x30062]


class Entry(NestedBuffer):
    ENTRY_ALIGNMENT = 0x10

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
        # 0x43: 'FW_XHCI',
        0x44: 'FW_INVALID',
        0x46: 'ANOTHER_FET',
        0x50: 'KEY_DATABASE',
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
        0x43: '!KEY_UNKNOWN_1',
        0x4e: '!KEY_UNKNOWN_2',
        0x70: '!BL2_SECONDARY_DIRECTORY',
        0x15f: '!FW_PSP_SMUSCS_2',  # seems to be a secondary FW_PSP_SMUSCS (see above)
        0x112: '!SMU_OFF_CHIP_FW_3',  # seems to tbe a tertiary SMU image (see above)
        0x39: '!SEV_APP',
        0x10062: '!UEFI-IMAGE',
        0x30062: '!UEFI-IMAGE',
        0xdead: '!KEY_NOT_IN_DIR'

    }

    KEY_STORE_TYPES = [0x50, 0x51]

    class Type(Enum):
        NO_HDR_ENTRY = 1
        PUBKEY = 2
        NORMAL = 3

    class ParseError(Exception):
        pass

    class TypeError(Exception):
        pass

    @classmethod
    def from_fields(cls, parent_directory, parent_buffer, type_, size, offset, blob, psptool, destination: int = None):
        # Try to parse these ID's as a key entry
        # todo: consolidate these constants with Directory._ENTRY_TYPES_PUBKEY
        PUBKEY_ENTRY_TYPES = [0x0, 0x9, 0xa, 0x5, 0xd, 0x43, 0x4e, 0xdead]

        # Types known to have no PSP HDR
        # TODO: Find a better way to identify those entries
        NO_HDR_ENTRY_TYPES = [0x4, 0xb, 0x21, 0x40, 0x70, 0x30062, 0x6, 0x61, 0x60,
                              0x68, 0x100060, 0x100068, 0x5f, 0x15f, 0x1a, 0x22, 0x63,
                              0x67, 0x66, 0x100066, 0x200066, 0x300066, 0x10062,
                              0x400066, 0x500066, 0x800068, 0x61, 0x200060, 0x300060,
                              0x300068, 0x400068, 0x500068, 0x400060, 0x500060, 0x200068,
                              0x7, 0x38, 0x46, 0x54, 0x600060, 0x700060, 0x600068, 0x700068]

        NO_SIZE_ENTRY_TYPES = [0xb]

        size &= 0x00ffffff

        new_entry = None

        if type_ in NO_SIZE_ENTRY_TYPES:
            size = 0

        if type_ in NO_HDR_ENTRY_TYPES:
            # Option 1: it's a plain Entry
            try:
                new_entry = Entry(
                    parent_directory,
                    parent_buffer,
                    type_,
                    size,
                    offset,
                    blob,
                    psptool,
                    destination=destination,
                )
            except:
                psptool.ph.print_warning(f"Couldn't parse plain entry: 0x{type_:x}")

        elif type_ in PUBKEY_ENTRY_TYPES:
            # Option 2: it's a PubkeyEntry
            try:
                new_entry = PubkeyEntry(parent_directory, parent_buffer, type_, size, offset, blob, psptool)
            except Exception as e:
                new_entry = Entry(
                    parent_directory,
                    parent_buffer,
                    type_,
                    size,
                    offset,
                    blob,
                    psptool,
                    destination=destination,
                )
                psptool.ph.print_warning(f"{e.__class__.__name__} for {new_entry}")

        elif type_ in Entry.KEY_STORE_TYPES:
            # Option 2: it's a KeyStoreEntry
            try:
                new_entry = KeyStoreEntry(parent_directory, parent_buffer, type_, size, offset, blob, psptool)
            except:
                new_entry = Entry(
                    parent_directory,
                    parent_buffer,
                    type_,
                    size,
                    offset,
                    blob,
                    psptool,
                    destination=destination,
                )

        if new_entry is None:
            # Option 3: it's a HeaderEntry (most common)
            if size == 0:
                # If the size in the directory is zero, set the size to hdr len
                size = HeaderEntry.HEADER_LEN
            try:
                new_entry = HeaderEntry(parent_directory, parent_buffer, type_, size, offset, blob, psptool)
                if size == 0:
                    psptool.ph.print_warning(f"Entry with zero size. Type: {type_}. Dir: 0x{offset:x}")
            except:
                new_entry = Entry(
                    parent_directory,
                    parent_buffer,
                    type_,
                    size,
                    offset,
                    blob,
                    psptool,
                    destination=destination,
                )

        return new_entry

    @classmethod
    def from_blob(cls, binary, id_, type_, compressed, signed, psptool, private_key: PrivateKey=None):
        if type_ == Entry.Type.PUBKEY:
            psptool.ph.print_warning(f"from_blob is not implemented for pubkeys")
            pass
        elif type_ == Entry.Type.NO_HDR_ENTRY:
            psptool.ph.print_warning(f"from_blob is not implemented for non-header objects")
            pass
        elif type_ == Entry.Type.NORMAL:
            size = round_to_int(len(binary), 0x10)
            if compressed:
                rom_data = zlib_compress(binary)
                zlib_size = len(rom_data)
                padded_size = round_to_int(zlib_size, 0x10)
            else:
                rom_data = binary
                zlib_size = 0
                padded_size = round_to_int(len(rom_data), 0x10)

            if signed:
                assert private_key is not None
                total_size = padded_size + private_key.key_type.signature_size
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
            blob[0x14:0x18] = size.to_bytes(4, 'little')
            # Set rom_size
            blob[0x6c:0x70] = total_size.to_bytes(4, 'little')
            if compressed:
                # Set zlib_size
                blob[0x54:0x58] = zlib_size.to_bytes(4, 'little')

            entry = HeaderEntry(None, blob, id_, total_size, 0x0, blob, psptool)

            if signed:
                entry.signature[:] = private_key.sign(entry.get_signed_bytes())

            return entry
        else:
            raise Entry.TypeError()

    def __init__(self, parent_directory, parent_buffer, type_, buffer_size, buffer_offset: int, blob, psptool,
                 destination: int = None):
        super().__init__(parent_buffer, buffer_size, buffer_offset=buffer_offset)

        # TODO: Fix to reference of FET
        self.blob = blob
        self.psptool = psptool
        self.type = type_
        self.destination = destination
        # todo: deduplicate Entry objects pointing to the same address (in `from_fields`?)
        self.references = [parent_directory] if parent_directory is not None else []
        self.parent_directory = parent_directory

        self.compressed = False
        self.encrypted = False
        self.is_legacy = False
        self.sha256_verified = False

        try:
            self._parse()
        except (struct.error, AssertionError):
            self.psptool.ph.print_warning(f"Couldn't parse entry at: 0x{self.get_address():x}. "
                                          f"Type: {self.get_readable_type()}. Size 0x{len(self):x}")
            raise Entry.ParseError()

    @property
    def signed(self) -> bool:
        return False

    @property
    def has_sha256_checksum(self) -> bool:
        return False

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
        if self.type in BIOS_ENTRY_TYPES:
            return "BIOS"
        if self.type in self.DIRECTORY_ENTRY_TYPES:
            return f'{self.DIRECTORY_ENTRY_TYPES[self.type]}~{hex(self.type)}'
        else:
            return hex(self.type)

    def get_readable_destination_address(self):
        return hex(self.destination)

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


class KeyStoreEntry(Entry):

    def _parse(self):

        # Will be set by the CertificateTree created after the blob
        self.signed_entity = None

        self.header = KeyStoreEntryHeader(self)

        key_store_start = self.header.buffer_size
        key_store_size = self.header.body_size
        self.key_store = KeyStore(self, key_store_size, buffer_offset=key_store_start)

        signature_start = key_store_start + key_store_size
        signature_size = self.header.signature_size
        assert signature_size in {0x100, 0x200}
        self.signature = Signature(self, signature_size, signature_start)
        #self.signature = ReversedSignature(self, signature_size, signature_start)

        if self.header.has_sha256_checksum:
            self.sha256_verified = self.verify_sha256()

        assert signature_start + signature_size == self.buffer_size

    def get_signed_bytes(self):
        return self.header.get_bytes() + self.key_store.get_bytes()

    def get_readable_version(self):
        return '1'

    def get_readable_magic(self):
        return f'{self.header.magic}'[2:-1]

    def get_readable_signed_by(self):
        return self.header.certifying_id.magic

    @property
    def signed(self):
        return True

    @property
    def _sha256_checksum_flag_2(self):
        nb = NestedBuffer(self, 0x4, 0x58)
        return struct.unpack(">I", nb.get_bytes())[0]

    @property
    def has_sha256_checksum(self) -> bool:
        return self.header.has_sha256_checksum

    def verify_sha256(self, print_warning=True) -> bool:
        if self.header.sha256_checksum.get_bytes() == sha256(self.key_store.get_bytes()).digest():
            return True
        if print_warning:
            self.psptool.ph.print_warning(f"Could not verify sha256 checksum for {self}")
        return False

    def update_sha256(self):
        self.header.sha256_checksum[:] = sha256(self.key_store.get_bytes()).digest()
        self.verify_sha256()


class KeyStoreEntryHeader(NestedBuffer):

    HEADER_SIZE = 0x100

    def __init__(self, entry):
        super().__init__(entry, self.HEADER_SIZE)

        self._magic = NestedBuffer(self, 0x4, buffer_offset=0x10)
        assert self.magic in {b'$PS1', 4*b'\0'}

        self._body_size = NestedBuffer(self, 0x4, buffer_offset=0x14)
        self._packed_size = NestedBuffer(self, 0x4, buffer_offset=0x6c)
        assert self.signature_size in {0x100, 0x200}

        self.certifying_id = KeyId(self, 0x10, buffer_offset=0x38)

        self._unknown_constant_1 = NestedBuffer(self, 0x4, buffer_offset=0x30)
        self._unknown_constant_2 = NestedBuffer(self, 0x4, buffer_offset=0x34)
        assert self.unknown_constants == (b'\1\0\0\0', b'\2\0\0\0')

        self._keystore_type = NestedBuffer(self, 0x4, buffer_offset=0x7c)
        assert self.keystore_type in Entry.KEY_STORE_TYPES or self.keystore_type == 0


        self._sha256_checksum_flag_1 = NestedBuffer(self, 0x4, buffer_offset=0x4c)
        self._sha256_checksum_flag_2 = NestedBuffer(self, 0x4, buffer_offset=0x58)

        self.sha256_checksum = None
        if self.has_sha256_checksum:
            self.sha256_checksum = NestedBuffer(self, 0x20, buffer_offset=0xd0)

        zero_ranges = {
            (0x00, 0x10),
            (0x18, 0x18),
            (0x48, 0x04),
            (0x50, 0x08),
            (0x5c, 0x10),
            (0x70, 0x0c),
            (0x80, 0x50),
            (0xf0, 0x10),
        }
        for (start, length) in zero_ranges:
            assert self.get_bytes(start, length) == b'\0' * length

    @property
    def magic(self) -> bytes:
        return self._magic.get_bytes()

    @magic.setter
    def magic(self, value: bytes):
        self._magic[:] = value

    @property
    def body_size(self) -> int:
        return int.from_bytes(self._body_size.get_bytes(), 'little')

    @property
    def packed_size(self) -> int:
        return int.from_bytes(self._packed_size.get_bytes(), 'little')

    @property
    def keystore_type(self) -> int:
        return int.from_bytes(self._keystore_type.get_bytes(), 'little')

    @property
    def signature_size(self) -> int:
        return self.packed_size - self.HEADER_SIZE - self.body_size

    @property
    def unknown_constants(self) -> (bytes, bytes, bytes):
        return (
                self._unknown_constant_1.get_bytes(),
                self._unknown_constant_2.get_bytes(),
                )

    @property
    def sha256_checksum_flag_1(self) -> int:
        return int.from_bytes(self._sha256_checksum_flag_1.get_bytes(), 'little')

    @property
    def sha256_checksum_flag_2(self) -> int:
        return int.from_bytes(self._sha256_checksum_flag_2.get_bytes(), 'big')

    @property
    def has_sha256_checksum(self) -> bool:
        # assert self.sha256_checksum_flag_1 == self.sha256_checksum_flag_2
        assert self.sha256_checksum_flag_1 in {0, 1}
        return self.sha256_checksum_flag_1 == 1


class KeyStore(NestedBuffer):

    HEADER_SIZE = 0x50

    def __init__(self, parent_buffer, buffer_size: int, buffer_offset: int = 0):
        super().__init__(parent_buffer, buffer_size, buffer_offset)

        # parse header
        self.header = NestedBuffer(self, self.HEADER_SIZE)

        self._size = NestedBuffer(self.header, 0x4, buffer_offset=0)
        assert self.size == self.buffer_size

        self._unknown_flag = NestedBuffer(self.header, 0x4, buffer_offset=0x4)
        assert self.unknown_flag

        self.magic = NestedBuffer(self.header, 0x4, buffer_offset=0x8)
        assert self.magic.get_bytes() == b'$KDB'

        assert self.header.get_bytes(0xc, 0x44) == b'\0' * 0x44

        # parse body
        body_start = self.header.buffer_size
        body_size = self.buffer_size - body_start
        assert body_size > 0
        self.body = NestedBuffer(self, body_size, buffer_offset=body_start)

        next_key_start = 0
        self.keys = []
        while next_key_start < body_size:
            key = KeyStoreKey(self.body, next_key_start)
            self.keys.append(key)
            next_key_start += key.size

    @property
    def size(self) -> int:
        return int.from_bytes(self._size.get_bytes(), 'little')

    @property
    def unknown_flag(self) -> bool:
        value = int.from_bytes(self._unknown_flag.get_bytes(), 'little')
        assert value in {0,1}
        return value == 1


class KeyStoreKey(NestedBuffer):

    HEADER_SIZE = 0x50

    def __init__(self, body: NestedBuffer, offset: int):

        # Will be set by the CertificateTree created after the blob
        self.pubkey_entity = None

        # init self
        size = int.from_bytes(body.get_bytes(offset, 0x4), 'little')
        super().__init__(body, size, buffer_offset=offset)

        # init header
        self.header = NestedBuffer(body, self.HEADER_SIZE, buffer_offset=offset)

        # init crypto_material (body)
        body_start = offset + self.HEADER_SIZE
        body_size = size - self.HEADER_SIZE
        assert body_size > 0
        self.crypto_material = NestedBuffer(body, body_size, buffer_offset=body_start)

        # init header fields
        self._size = NestedBuffer(self.header, 0x4, buffer_offset=0)
        assert self.size == self.buffer_size

        self._unknown_flag = NestedBuffer(self.header, 0x4, buffer_offset=0x4)
        assert self.unknown_flag

        self._unknown_id = NestedBuffer(self.header, 0x4, buffer_offset=0x8)
        assert self.unknown_id < 0x100

        self._rsa_exponent = NestedBuffer(self.header, 0x4, buffer_offset=0xc)
        assert self.rsa_exponent == 0x10001

        self.key_id = KeyId(self.header, 0x10, buffer_offset=0x10)

        self._key_size = NestedBuffer(self.header, 0x4, buffer_offset=0x20)
        assert self.key_size == self.crypto_material.buffer_size << 3

        assert self.header.get_bytes(0x24, 0x2c) == b'\0' * 0x2c

    @property
    def size(self) -> int:
        return int.from_bytes(self._size.get_bytes(), 'little')

    @property
    def unknown_flag(self) -> bool:
        value = int.from_bytes(self._unknown_flag.get_bytes(), 'little')
        assert value in {0,1}
        return value == 1

    @property
    def unknown_id(self) -> int:
        return int.from_bytes(self._unknown_id.get_bytes(), 'little')

    @property
    def rsa_exponent(self) -> int:
        return int.from_bytes(self._rsa_exponent.get_bytes(), 'little')

    @property
    def key_size(self) -> int:
        return int.from_bytes(self._key_size.get_bytes(), 'little')


class UnknownPubkeyEntryVersion(Exception):
    pass


class PubkeyEntry(Entry):

    HEADER_LEN = 0x40

    def _parse(self):
        """ SEV spec B.1 """

        # Will be set by the CertificateTree created after the blob
        self.signed_entity = None
        self.pubkey_entity = None

        # Will be set by blob.find_inline_pubkeys
        self.is_inline = False
        self.parent_entry = None

        # misc info
        self._version = NestedBuffer(self, 4)
        if self.version != 1:
            raise UnknownPubkeyEntryVersion
        self._key_usage = NestedBuffer(self, 4, 0x24)

        # key ids
        self.key_id = KeyId(self, 0x10, 0x4)
        self.certifying_id = KeyId(self, 0x10, 0x14)

        # crypto material
        self._pubexp_bits = NestedBuffer(self, 4, 0x38)
        self._modulus_bits = NestedBuffer(self, 4, 0x3c)
        assert self.pubexp_bits == self.modulus_bits
        assert self.pubexp_bits in {2048, 4096}

        self.crypto_material = NestedBuffer(self, self.pubexp_size + self.modulus_size, self.HEADER_LEN)
        self._pubexp = NestedBuffer(self.crypto_material, self.pubexp_size)
        self._modulus = NestedBuffer(self.crypto_material, self.modulus_size, self.pubexp_size)
        assert self.pubexp == 0x10001

        # signature
        if self.signed:
            assert self.signature_size in {0x100, 0x200}
            signature_start = self.HEADER_LEN + self.pubexp_size + self.modulus_size
            self.signature = ReversedSignature(self, self.signature_size, signature_start)

    @property
    def version(self) -> int:
        return int.from_bytes(self._version.get_bytes(), 'little')

    @property
    def key_usage(self) -> int:
        return int.from_bytes(self._key_usage.get_bytes(), 'little')

    @property
    def pubexp_bits(self) -> int:
        return int.from_bytes(self._pubexp_bits.get_bytes(), 'little')

    @property
    def modulus_bits(self) -> int:
        return int.from_bytes(self._modulus_bits.get_bytes(), 'little')

    @property
    def pubexp_size(self) -> int:
        assert self.pubexp_bits & 0x3 == 0
        return self.pubexp_bits >> 3

    @property
    def modulus_size(self) -> int:
        assert self.modulus_bits & 0x3 == 0
        return self.modulus_bits >> 3

    @property
    def signature_size(self) -> int:
        return self.buffer_size - self.HEADER_LEN - self.pubexp_size - self.modulus_size

    @property
    def signed(self) -> bool:
        return self.signature_size != 0

    @property
    def pubexp(self) -> int:
        return int.from_bytes(self._pubexp.get_bytes(), 'little')

    @property
    def modulus(self) -> int:
        return int.from_bytes(self._modulus.get_bytes(), 'little')

    def get_signed_bytes(self):
        return self.get_bytes(0, self.buffer_size - self.signature_size)

    def get_readable_signed_by(self):
        if self.signed:
            return self.certifying_id.magic

    def get_readable_magic(self):
        return self.key_id.magic

    def get_readable_version(self):
        return str(self.version)


class HeaderEntry(Entry):

    HEADER_LEN = 0x100

    def _parse(self):
        self.header = NestedBuffer(self, HeaderEntry.HEADER_LEN)

        # Will be set by the CertificateTree created after the blob
        self.signed_entity = None

        # Will be set by blob._find_inline_pubkeys
        self.inline_keys = set()

        # todo: use NestedBuffers instead of saving by value
        self.magic = self.header[0x10:0x14]
        self.size_signed = struct.unpack('<I', self.header[0x14:0x18])[0]
        self.encrypted = struct.unpack('<I', self.header[0x18:0x1c])[0] == 1
        self._signed = NestedBuffer(self, 4, 0x30)
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

        self._sha256_checksum = NestedBuffer(self, 0x20, 0xd0)
        if self.has_sha256_checksum:
            self.sha256_verified = self.verify_sha256()

        return

    def _parse_signature(self):
        if self.signature_fingerprint != hexlify(16 * b'\x00'):

            body_size = self.size_signed
            if self.compressed:
                body_size = self.zlib_size

            self.signature_len = self.rom_size - 0x100 - body_size
            if self.signature_len < 0:
                self.signature_len = 0

            # Round to 0x100, 0x200, etc.
            self.signature_len >>= 8
            self.signature_len <<= 8

            if self.signature_len > 0x200:

                # this is a best-effort guess made for e.g. PSP_FW_TRUSTED_OS~0x2
                self.signature_len = 0x100

            if self.signature_len % 0x100 > 0x10:
                # self.psptool.ph.print_warning(f"Signature size of 0x{self.signature_len:x} seems odd!")
                pass

            if self.signature_len not in {0x100, 0x200}:
                # self.psptool.ph.print_warning(f"Signature size of 0x{self.signature_len:x} seems odd!")
                # self.psptool.ph.print_warning(f"signe_sz=0x{self.size_signed:x}")
                # self.psptool.ph.print_warning(f"rom_sz=0x{self.rom_size:x}")
                # self.psptool.ph.print_warning(f"zlib_sz=0x{self.zlib_size:x}")
                pass

            # self.psptool.ph.print_warning(f"Couldn't find corresponding key in blob for entry at: 0x{self.get_address():x}. Type: "
                              # f"{self.get_readable_type()}")
        else:
            self.psptool.ph.print_warning("ERROR: Signed but no key id present")

    def _parse_legacy_hdr(self):
        self.buffer_size = self.size_signed + self.header_len + self.signature_len
        self.buffer_size &= 0x00ffffff

        if self.compressed:
            self.zlib_size = self.size_signed

        if self.signed:
            self.signature = NestedBuffer(self, self.signature_len, self.buffer_size - self.signature_len)

        self.body = NestedBuffer(self, len(self) - self.header_len, self.header_len)

        self.is_legacy = True

    def _parse_hdr(self):
        if self.rom_size == 0:
            # TODO throw exception
            self.buffer_size = self.size_signed + self.header_len
            self.psptool.ph.print_warning("ERROR. rom size is zero")
        else:
            self.buffer_size = self.rom_size

        if self.signed:
            buf_start = self.get_address()
            sig_start = self.get_address() + self.rom_size - self.signature_len
            # self.psptool.ph.print_warning(f"Signature at: 0x{buf_start:x} sig_start: 0x{sig_start:x}")
            self.signature = NestedBuffer(self, self.signature_len, sig_start - buf_start)

        if self.compressed:
            if self.zlib_size == 0:
                # Todo throw exception
                self.psptool.ph.print_warning(f"ERROR: Weird entry. Address 0x{self.get_address():x}")

        # Get IV and wrapped KEY from entry header
        if self.encrypted:
            self.iv = self.header[0x20:0x30]
            self.key = self.header[0x80:0x90]
            assert(self.iv != (b'\x00' * 16))
            assert(self.key != (b'\x00' * 16))

        self.body = NestedBuffer(self, len(self) - self.header_len - self.signature_len, self.header_len)
        self.is_legacy = False

    @property
    def signed(self) -> bool:
        signed = int.from_bytes(self._signed.get_bytes(), 'little')
        assert signed in {0, 1, 0xffff0000}, f'did not expect signed to be 0x{signed:x}'
        return signed != 0

    # @property
    # def _sha256_checksum_flag_1(self):
    #     nb = NestedBuffer(self, 0x4, 0x4c)
    #     return struct.unpack(">I", nb.get_bytes())[0]
    #
    # @_sha256_checksum_flag_1.setter
    # def _sha256_checksum_flag_1(self, value):
    #     nb = NestedBuffer(self, 0x4, 0x4c)
    #     nb[:] = value

    @property
    def _sha256_checksum_flag_2(self):
        nb = NestedBuffer(self, 0x4, 0x58)
        return struct.unpack(">I", nb.get_bytes())[0]

    @property
    def has_sha256_checksum(self) -> bool:
        return self._sha256_checksum_flag_2 == 1

    def verify_sha256(self, print_warning=True) -> bool:
        if self._sha256_checksum.get_bytes() == sha256(self.get_decompressed_body()).digest():
            return True
        if print_warning:
            self.psptool.ph.print_warning(f"Could not verify sha256 checksum for {self}")
        return False

    def update_sha256(self):
        self._sha256_checksum[:] = sha256(self.get_decompressed_body()).digest()
        self.verify_sha256()

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

    def get_signed_bytes(self) -> bytes:
        if self.compressed:
            full_decompressed = self.header.get_bytes() + self.get_decompressed_body()
            # Truncate to actually signed portion
            return full_decompressed[:self.header_len + self.size_signed]
        elif self.encrypted:
            return self.get_decrypted()[:self.size_signed + self.header_len]
        else:
            return self.get_bytes()[:self.size_signed + self.header_len]

    def get_decompressed_body(self) -> bytes:
        if not self.compressed:
            return self.body.get_bytes()
        else:
            try:
                return zlib_decompress(self.body.get_bytes()[:self.zlib_size])
            except:
                self.psptool.ph.print_warning(f"ZLIB decompression failed on entry {self.get_readable_type()}")
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
        # TODO: Find out how to identify the correct IKEK.
        #       For now assume that the zen+ IKEK is correct.

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
            self.psptool.ph.print_warning(f"Get bytes failed at entry: 0x{self.get_address():x} type: {self.get_readable_type()} size: 0x{self.buffer_size:x}")
        return m.hexdigest()

