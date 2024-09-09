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

from .utils import NestedBuffer, zlib_decompress, decrypt, shannon
from .file import File


class HeaderFile(File):

    HEADER_LEN = 0x100

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
        self._signed = NestedBuffer(self, 4, 0x30)
        self.signature_type = struct.unpack('<I', self.header[0x34:0x38])[0]
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

        if self.rom_size == 0:
            self.rom_size = self.buffer_size
        elif self.rom_size > self.buffer_size:
            self.buffer_size = self.rom_size

        # self.iv = hexlify(self.header[0x20:0x30])
        # self.wrapped_key = hexlify(self.header[0x80:0x90])

        # TODO: Take care of headers with only 0xfff...
        # TODO if zlib_size == 0 try size_signed

        if self.is_signed:
            if self.signature_type == 0x0:
                self.signature_len = 0x100
            elif self.signature_type == 0x2:
                self.signature_len = 0x200
            self.signature = NestedBuffer(self, self.signature_len, self.rom_size - self.signature_len)
        else:
            self.signature_len = 0

        self._parse_hdr()

        return

    def _parse_hdr(self):
        # Get IV and wrapped KEY from file header
        if self.encrypted:
            self.iv = self.header[0x20:0x30]
            self.key = self.header[0x80:0x90]
            assert(self.iv != (b'\x00' * 16))
            assert(self.key != (b'\x00' * 16))

        assert 0 < self.rom_size <= self.buffer_size
        self.buffer_size = self.rom_size
        self.body = NestedBuffer(self, len(self) - len(self.header) - self.signature_len, len(self.header))
        self.is_legacy = False

    def get_checksummed_bytes(self):
        return self.get_decrypted_decompressed_body()

    def verify_sha256(self, print_warning=True) -> bool:
        if self._sha256_checksum.get_bytes() == sha256(self.get_checksummed_bytes()).digest():
            return True
        if print_warning:
            self.psptool.ph.print_warning(f"Could not verify sha256 checksum for {self}")
        return False

    def update_sha256(self):
        self._sha256_checksum[:] = sha256(self.get_checksummed_bytes()).digest()
        self.verify_sha256()

    def verify_sha384(self, print_warning=True) -> bool:
        if self._sha384_checksum.get_bytes() == sha384(self.get_checksummed_bytes()).digest():
            return True
        if print_warning:
            self.psptool.ph.print_warning(f"Could not verify sha384 checksum for {self}")
        return False

    @property
    def is_signed(self) -> bool:
        signed = int.from_bytes(self._signed.get_bytes(), 'little')
        if signed not in {0, 1, 0xffff0000}:
            raise self.ParseError(f'Did not expect signed to be 0x{signed:x}')
        return signed != 0

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
        return self.signed_entity.certifying_id.magic

    def get_signed_bytes(self) -> bytes:
        file_bytes = self.header.get_bytes() + self.get_decrypted_decompressed_body()
        return file_bytes[:len(self.header) + self.size_signed]

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