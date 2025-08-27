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

from .crypto import Signature, KeyId
from .file import File
from .header_file import HeaderFile
from .utils import NestedBuffer


class KeyStoreFile(HeaderFile):

    def get_checksummed_bytes(self):
        return self.key_store.get_bytes()

    def _parse(self):
        super()._parse()

        # Will be set by the CertificateTree created after the blob
        self.signed_entity = None

        self.header = KeyStoreFileHeader(self)

        key_store_start = self.header.buffer_size
        key_store_size = self.header.body_size

        if self.compressed:
            self.key_store = KeyStore(bytearray(self.get_decrypted_decompressed_body()), self.size_uncompressed, buffer_offset=0)
        else:
            self.key_store = KeyStore(self, key_store_size, buffer_offset=key_store_start)

        signature_start = key_store_start + key_store_size
        signature_size = self.header.signature_size
        assert signature_size in {0x100, 0x200}
        self.signature = Signature(self, signature_size, signature_start)
        #self.signature = ReversedSignature(self, signature_size, signature_start)

    def get_signed_bytes(self):
        return self.header.get_bytes() + self.key_store.get_bytes()

    def get_readable_version(self):
        return '1'

    def get_readable_magic(self):
        return f'{self.header.magic}'[2:-1]

    def get_readable_signed_by(self):
        return self.header.certifying_id.magic

    @property
    def is_signed(self):
        return True


class KeyStoreFileHeader(NestedBuffer):

    HEADER_SIZE = 0x100

    def __init__(self, file):
        super().__init__(file, self.HEADER_SIZE)

        self._magic = NestedBuffer(self, 0x4, buffer_offset=0x10)
        assert self.magic in {b'$PS1', 4*b'\0'}

        self._body_size = NestedBuffer(self, 0x4, buffer_offset=0x14)
        # todo: work around the 0x6c size here, because this field doesn't exist in Zen 5
        self._packed_size = NestedBuffer(self, 0x4, buffer_offset=0x6c)
        assert self.signature_size in {0x100, 0x200}

        self.certifying_id = KeyId(self, 0x10, buffer_offset=0x38)

        self._unknown_constant_1 = NestedBuffer(self, 0x4, buffer_offset=0x30)
        self._unknown_constant_2 = NestedBuffer(self, 0x4, buffer_offset=0x34)
        assert self.unknown_constants == (b'\1\0\0\0', b'\2\0\0\0')

        self._keystore_type = NestedBuffer(self, 0x4, buffer_offset=0x7c)
        assert self.keystore_type in File.KEY_STORE_TYPES or self.keystore_type == 0

        # Based on KeyStore entries seen in: Lenovo X13 and Lenovo Ideapad 5 Pro 16ACH6
        # zero_ranges = {
        #     (0x18, 0x18),
        #     (0x48, 0x04),
        #     #(0x50, 0x08),
        #     #(0x5c, 0x04),
        #     #(0x64, 0x08),
        #     #(0x70, 0x0c),
        #     #(0x80, 0x50),
        #     #(0xf0, 0x10),
        # }
        # for (start, length) in zero_ranges:
        #     assert self.get_bytes(start, length) == b'\0' * length

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
        if self.packed_size:
            return self.packed_size - self.HEADER_SIZE - self.body_size
        else:
            return self.parent_buffer.buffer_size - self.body_size - self.HEADER_SIZE

    @property
    def unknown_constants(self) -> (bytes, bytes, bytes):
        return (
                self._unknown_constant_1.get_bytes(),
                self._unknown_constant_2.get_bytes(),
                )


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

        # todo: version maybe?
        assert self.header.get_bytes(0x24, 0x2c) in [
            b'\0' * 0x2b + b'\0',
            b'\0' * 0x2b + b'\1',
            b'\0' * 0x2b + b'\2',

        ]

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