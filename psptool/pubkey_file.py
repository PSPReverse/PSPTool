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

from .crypto import KeyId, ReversedSignature
from .file import File
from .utils import NestedBuffer


class UnknownPubkeyFileVersion(Exception):
    pass


class PubkeyFile(File):

    HEADER_LEN = 0x40
    KNOWN_VERSIONS = {1, 2}

    def _parse(self):
        """ SEV spec B.1 """

        # Will be set by the CertificateTree created after the blob
        self.signed_entity = None
        self.pubkey_entity = None

        # misc info
        self._version = NestedBuffer(self, 4)
        if self.version not in self.KNOWN_VERSIONS:
            raise UnknownPubkeyFileVersion
        self._key_usage = NestedBuffer(self, 4, 0x24)

        # key ids
        self.key_id = KeyId(self, 0x10, 0x4)
        self.certifying_id = KeyId(self, 0x10, 0x14)

        # security features
        self._security_features = NestedBuffer(self, 2, 0x2A)

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
        if self.is_signed:
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
    def is_signed(self) -> bool:
        return self.signature_size != 0

    @property
    def pubexp(self) -> int:
        return int.from_bytes(self._pubexp.get_bytes(), 'little')

    @property
    def modulus(self) -> int:
        return int.from_bytes(self._modulus.get_bytes(), 'little')

    @property
    def security_features(self) -> int:
        return int.from_bytes(self._security_features.get_bytes(), 'little')

    def get_signed_bytes(self):
        return self.get_bytes(0, self.buffer_size - self.signature_size)

    def get_readable_signed_by(self):
        if self.is_signed:
            return self.certifying_id.magic

    def get_readable_magic(self):
        return self.key_id.magic

    def get_readable_version(self):
        return str(self.version)

    def get_readable_key_usage(self):
        if self.key_usage == 0:
            return 'AMD_CODE_SIGN'
        if self.key_usage == 1:
            return 'BIOS_CODE_SIGN'
        if self.key_usage == 2:
            return 'AMD_AND_BIOS_CODE_SIGN'
        if self.key_usage == 8:
            return 'PLATFORM_SECURE_BOOT'
        return f'unknown_key_usage({self.key_usage})'

    def get_readable_security_features(self):
        features = []
        if self.security_features & 0b001:
            features.append('DISABLE_BIOS_KEY_ANTI_ROLLBACK')
        if self.security_features & 0b010:
            features.append('DISABLE_AMD_BIOS_KEY_USE')
        if self.security_features & 0b100:
            features.append('DISABLE_SECURE_DEBUG_UNLOCK')
        return ', '.join(features)


class InlinePubkeyFile(PubkeyFile):
    def __init__(self, parent_file: NestedBuffer, offset: int, size: int, blob, psptool):
        # InlinePubkeys don't have a parent directory, so we take None
        super().__init__(None, parent_file, offset, None, size, blob, psptool)
        self.parent_file = parent_file
