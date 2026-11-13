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
from binascii import hexlify
from hashlib import md5, sha256, sha384
from enum import Enum

from .utils import NestedBuffer, zlib_decompress, decrypt, shannon
from .file import File

class SignatureType(Enum):
    NONE = (None, 0x0)
    SHA256 = (0, 0x100)
    SHA384 = (2, 0x200)

    def __init__(self, type: int, len: int):
        self.type = type
        self.len = len

    @property
    def is_signed(self) -> bool:
        return self is not SignatureType.NONE

    @classmethod
    def from_header(cls, signed: NestedBuffer, type: int) -> "SignatureType":
        signed = int.from_bytes(signed.get_bytes(), 'little')
        if signed not in {0, 1, 0xffff0000}:
            raise File.ParseError(f'Did not expect signed to be 0x{signed:x}')
        if signed == 0:
            return SignatureType.NONE
        for st in cls:
            if st.type == type:
                return st
        raise File.ParseError(f"Unknown signature type 0x{type:x}")

    @classmethod
    def from_len(cls, len: int) -> "SignatureType":
        for st in cls:
            if st.is_signed and st.len == len:
                return st
        return None

class Signature(NestedBuffer):
    def __init__(self, file: 'HeaderFile', type: SignatureType, offset: int = None):
        self.type = type
        if offset is None:
            offset = file.rom_size - type.len
        super().__init__(file, type.len, offset)

    @property
    def len(self) -> int:
        return self.type.len


class ModuleIndex:
    """Signed index of the sub-modules that follow the signature of e.g. ABL0, ABL7 and
    0x76 on Zen 4 and later. Version 1 lists (u32 id, u32 offset) pairs, padded with
    zeros, of separately signed sub-modules. Version 2 has a 0x10 byte header (u32 version,
    u32, u32 size, u32 count) and 0x40 byte entries (u32 id, u32 offset, u32 size, u32,
    SHA-384) of sub-modules that are not signed themselves. Offsets are within the file.
    """

    def __init__(self, version: int, modules: list):
        self.version = version
        self.modules = modules  # (id, offset, size, SHA-384 digest or None)

    def __len__(self):
        return len(self.modules)

    @classmethod
    def from_file(cls, file: 'HeaderFile'):
        if file.compressed or file.encrypted:
            return None
        index = file.body.get_bytes()
        first_module = file.signature.buffer_offset + file.signature.len
        return cls._parse_v2(file, index, first_module) or cls._parse_v1(file, index, first_module)

    @classmethod
    def _parse_v2(cls, file, index, first_module):
        if len(index) < 0x10:
            return None
        version, _, _, count = struct.unpack_from('<4I', index)
        if version != 2 or count == 0 or 0x10 + 0x40 * count != len(index):
            return None
        modules = []
        for module_id, offset, size, _, digest in struct.iter_unpack('<4I48s', index[0x10:]):
            if offset + size > len(file):
                return None
            modules.append((module_id, offset, size, digest))
        return cls(2, modules) if modules[0][1] == first_module else None

    @classmethod
    def _parse_v1(cls, file, index, first_module):
        if len(index) % 8 or not index:
            return None
        pairs = list(struct.iter_unpack('<II', index))
        while pairs and pairs[-1] == (0, 0):
            pairs.pop()
        offsets = [offset for _, offset in pairs]
        if not pairs or offsets[0] != first_module or offsets[-1] >= len(file) or \
                any(a >= b for a, b in zip(offsets, offsets[1:])):
            return None
        ends = offsets[1:] + [len(file)]
        return cls(1, [(module_id, offset, end - offset, None) for (module_id, offset), end in zip(pairs, ends)])

    @property
    def has_digests(self) -> bool:
        return any(digest is not None for *_, digest in self.modules)

    def verify(self, file: 'HeaderFile') -> bool:
        return all(sha384(file.get_bytes(offset, size)).digest() == digest
                   for _, offset, size, digest in self.modules if digest is not None)


class HeaderFile(File):

    HEADER_LEN = 0x100

    # Set once the signature verified over the body as stored, see get_signed_bytes
    signs_stored_body = False
    # Set once a checksum matched, see _checksum_candidates
    _checksum_view = None

    def _parse(self):
        if self.buffer_size < 0x100:  # give those with a entry size of 0 (!?) a chance to get their header parsed
            self.buffer_size = 0x100
        self.header = NestedBuffer(self, HeaderFile.HEADER_LEN)

        # Will be set by the CertificateTree created after the blob
        self.signed_entity = None

        # Will be set by blob._find_inline_pubkeys
        self.inline_keys = set()

        # todo: use NestedBuffers instead of saving by value
        self.magic = self.header[0x10:0x14]
        self.size_signed = struct.unpack('<I', self.header[0x14:0x18])[0]
        self.encrypted = struct.unpack('<I', self.header[0x18:0x1c])[0] == 1
        self._sha256_checksum = NestedBuffer(self, 0x20, 0xd0)
        self._sha384_checksum = NestedBuffer(self, 0x30, 0xd0)
        # signed, signature_type = struct.unpack('<II', self.header[0x30:0x38])
        signed = NestedBuffer(self, 4, 0x30)
        signature_type = struct.unpack('<I', self.header[0x34:0x38])[0]
        self.signature_fingerprint = hexlify(self.header[0x38:0x48])
        self.compressed = struct.unpack('<I', self.header[0x48:0x4c])[0] == 1
        self.unknown_field_2 = struct.unpack('<I', self.header[0x4c:0x50])[0]
        self.size_uncompressed = struct.unpack('<I', self.header[0x50:0x54])[0]
        self.zlib_size = struct.unpack('<I', self.header[0x54:0x58])[0]
        self.bitfield = struct.unpack('>I', self.header[0x58:0x5c])[0]
        self.version = self.header[0x63:0x5f:-1]
        self.load_addr = struct.unpack('<I', self.header[0x68:0x6c])[0]
        self.rom_size = struct.unpack('<I', self.header[0x6c:0x70])[0]
        self.unknown_field_3 = struct.unpack('<I', self.header[0x7c:0x80])[0]

        self.has_sha256_checksum = self.bitfield & 0b01
        self.has_sha384_checksum = self.bitfield & 0b10

        if self.has_sha256_checksum and self.has_sha384_checksum:
            raise File.ParseError('File should not have both sha256 and sha384 checksum bits set!')

        if self.buffer_offset + self.rom_size > self.parent_buffer.buffer_size:
            raise File.ParseError(f'Header size 0x{self.rom_size:x} overflows the parent buffer, '
                                  f'likely not a PSP header')

        entry_size = self.buffer_size
        size_from_header = self.rom_size != 0
        if self.rom_size == 0:
            self.rom_size = self.buffer_size
        elif self.rom_size > self.buffer_size:
            self.buffer_size = self.rom_size

        # self.iv = hexlify(self.header[0x20:0x30])
        # self.wrapped_key = hexlify(self.header[0x80:0x90])

        # TODO: Take care of headers with only 0xfff...

        signature_type = SignatureType.from_header(signed, signature_type)
        signature_offset = None
        if signature_type.is_signed:
            signature_type, signature_offset = self._find_signature(signature_type, entry_size, size_from_header)
        self.signature = Signature(self, signature_type, signature_offset)
        self.signature_follows_body = signature_offset is not None

        self._parse_hdr()

        self.module_index = None
        if self.signature_follows_body and self.signature.buffer_offset + self.signature.len < len(self):
            self.module_index = ModuleIndex.from_file(self)

        return

    def stored_body_size(self):
        """The size of the body as stored: compressed, or encrypted with AES padding"""
        if self.compressed:
            return (self.zlib_size + 0xf) & ~0xf if self.zlib_size else None
        if self.encrypted:
            return (self.size_signed + 0xf) & ~0xf
        return self.size_signed

    def _find_signature(self, signature_type: SignatureType, entry_size: int, size_from_header: bool):
        """The signature follows the body as stored (with size_signed the uncompressed size
        for some compressed files). The header size can leave it out (Zen 6) or exceed the
        entry (some compressed Zen 6 files), and the file can be followed by sub-modules,
        by the key that signs it, or by padding up to the entry size. Returns the signature
        type and offset, or the offset None for one at the end of the file."""
        stored_size = self.stored_body_size()
        if stored_size is None:
            return signature_type, None
        offset = len(self.header) + stored_size
        if offset + signature_type.len > self.buffer_size:
            return signature_type, None

        # Zen 2 PMU firmware states signature type 0 next to a 0x200 byte signature
        trailing_size = self.rom_size - offset
        if trailing_size != signature_type.len and SignatureType.from_len(trailing_size):
            signature_type = SignatureType.from_len(trailing_size)

        file_end = offset + signature_type.len
        if self.rom_size < file_end:
            self.rom_size = file_end
        elif size_from_header and self.rom_size > entry_size >= file_end:
            self.rom_size = entry_size
        elif not size_from_header and self.rom_size > file_end:
            padding = self.get_bytes(file_end, self.rom_size - file_end)
            if padding in (b'\xff' * len(padding), bytes(len(padding))):
                self.rom_size = file_end
        return signature_type, offset

    def _parse_hdr(self):
        # Get IV and wrapped KEY from file header
        if self.encrypted:
            self.iv = self.header[0x20:0x30]
            self.key = self.header[0x80:0x90]
            assert(self.iv != (b'\x00' * 16))
            assert(self.key != (b'\x00' * 16))

        assert 0 < self.rom_size <= self.buffer_size
        self.buffer_size = self.rom_size
        if self.is_signed and self.signature_follows_body:
            body_size = self.signature.buffer_offset - len(self.header)
        else:
            body_size = len(self) - len(self.header) - self.signature.len
        self.body = NestedBuffer(self, body_size, len(self.header))
        self.is_legacy = False

    def get_checksummed_bytes(self):
        return self.get_decrypted_decompressed_body()

    def _checksum_candidates(self):
        """The views of the body a checksum can cover, as (over the stored body, size): the
        decrypted and decompressed body, its content without padding, with the content size
        at 0x70 (newer files) or without it (older ones), or the body as stored (some
        compressed files on laptops)"""
        data = self.get_checksummed_bytes()
        yield (False, None), data
        if not self.compressed:
            content_size = struct.unpack('<I', self.header[0x70:0x74])[0]
            if 0 < content_size < len(data):
                yield (False, content_size), data[:content_size]
            if len(data) % 0x10 == 0:
                for padding_size in range(1, 0x10):
                    if data[-padding_size] != 0:
                        break
                    yield (False, len(data) - padding_size), data[:-padding_size]
        if self.can_sign_stored_body:
            yield (True, None), self.body.get_bytes()

    def _get_checksummed_view(self) -> bytes:
        stored, size = self._checksum_view or (False, None)
        data = self.body.get_bytes() if stored else self.get_checksummed_bytes()
        return data[:size]

    def _verify_checksum(self, checksum: NestedBuffer, hash_function, print_warning: bool) -> bool:
        expected = checksum.get_bytes()
        if self._checksum_view is not None:
            candidates = [(self._checksum_view, self._get_checksummed_view())]
        else:
            candidates = self._checksum_candidates()
        for view, data in candidates:
            if hash_function(data).digest() == expected:
                self._checksum_view = view
                return True
        if print_warning:
            self.psptool.ph.print_warning(f"Could not verify {hash_function().name} checksum for {self}")
        return False

    def verify_sha256(self, print_warning=True) -> bool:
        return self._verify_checksum(self._sha256_checksum, sha256, print_warning)

    def update_sha256(self):
        self._sha256_checksum[:] = sha256(self._get_checksummed_view()).digest()
        self.verify_sha256()

    def verify_sha384(self, print_warning=True) -> bool:
        return self._verify_checksum(self._sha384_checksum, sha384, print_warning)

    @property
    def is_signed(self) -> bool:
        return self.signature.type.is_signed

    def get_readable_version(self):
        return '.'.join([hex(b)[2:].upper() for b in self.version])

    def get_ikek_md5sum(self) -> bytes:
        ikek = self.parent_buffer.get_files_by_type(0x21)[0]
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
        return self.signed_entity.certifying_id.magic

    def get_signed_bytes(self) -> bytes:
        if self.signs_stored_body:
            return self.get_stored_signed_bytes()
        file_bytes = self.header.get_bytes() + self.get_decrypted_decompressed_body()
        return file_bytes[:len(self.header) + self.size_signed]

    @property
    def can_sign_stored_body(self) -> bool:
        """Whether the body as stored differs from the decrypted, decompressed one"""
        return bool(self.encrypted or self.compressed)

    def get_stored_signed_bytes(self) -> bytes:
        """Newer generations (seen from Zen 3 on) sign encrypted and compressed bodies as
        stored, older ones decrypted and decompressed. SignedEntity tries both."""
        return self.header.get_bytes() + self.body.get_bytes()

    def get_decrypted_decompressed_body(self) -> bytes:
        output = self.get_decrypted_body()

        if self.compressed:
            try:
                return zlib_decompress(output[:self.zlib_size])
            except:
                self.psptool.ph.print_warning(f"ZLIB decompression failed on file {self.get_readable_type()}")
        return output

    def to_decrypted_file_bytes(self) -> bytes:
        """Returns the bytes of the same file, just with the encryption removed"""
        header = bytearray(self.header.get_bytes())
        header[0x18:0x1c] = bytes(4)
        header[0x20:0x30] = bytes(0x10)
        signature = self.signature.get_bytes() if self.is_signed else b''
        return bytes(header) + self.get_decrypted_body() + signature

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
            self.psptool.ph.print_warning(f"Get bytes failed at file: 0x{self.get_address():x} type: {self.get_readable_type()} size: 0x{self.buffer_size:x}")
        return m.hexdigest()
