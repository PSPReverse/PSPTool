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

from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Abstract classes


class KeyType(ABC):

    @property
    @abstractmethod
    def signature_size(self) -> int:
        pass

    @abstractmethod
    def load_private_key(self, filename: str, password: str = None):
        pass

    @abstractmethod
    def make_public_key(self, crypto_material: bytes):
        pass


class PublicKey(ABC):

    @property
    @abstractmethod
    def key_type(self) -> KeyType:
        pass

    @abstractmethod
    def verify_blob(self, blob: bytes, signature: bytes) -> bool:
        pass

    @abstractmethod
    def get_crypto_material(self, size: int) -> bytes:
        pass


class PrivateKey(ABC):

    @property
    @abstractmethod
    def key_type(self) -> KeyType:
        pass

    @abstractmethod
    def sign_blob(self, blob: bytes) -> bytes:
        pass

    @abstractmethod
    def get_public_key(self) -> PublicKey:
        pass


# Global KeyType Registry

_key_types = dict()


def get_key_type(name: str) -> KeyType:
    try:
        return _key_types[name]
    except KeyError:
        raise Exception(f'There is no KeyType with the name "{name}"!')


def add_key_type(name: str, key_type: KeyType):
    if _key_types.get(name):
        raise Exception(f'There is already a KeyType with the name "{name}"!')
    _key_types[name] = key_type


# KeyType Implementations


class RsaKeyType(KeyType):

    def __init__(self, key_size: int):
        self.key_size = key_size
        if key_size == 2048:
            self.hash_algorithm = hashes.SHA256()
            self.salt_length = 32
        elif self.key_size == 4096:
            self.hash_algorithm = hashes.SHA384()
            self.salt_length = 48
        else:
            raise Exception(f'Unknown rsa key length: {key_size}!')

    @property
    def signature_size(self) -> int:
        return self.key_size >> 3

    def padding(self):
        return padding.PSS(
            mgf=padding.MGF1(self.hash_algorithm),
            salt_length=self.salt_length
        )

    def load_private_key(self, filename: str, password: str = None):
        return RsaPrivateKey.from_file(self, filename, password)

    def make_public_key(self, crypto_material: bytes) -> PublicKey:
        return RsaPublicKey.from_crypto_material(self, crypto_material)


add_key_type("rsa2048", RsaKeyType(2048))
add_key_type("rsa4096", RsaKeyType(4096))


class RsaPrivateKey(PrivateKey):

    def __init__(self, key_type: RsaKeyType, private_key):
        assert private_key.key_size == key_type.key_size, f'Key has the wrong size: {private_key.key_size} != ' \
                                                          f'{key_type.key_size}'
        self._key_type = key_type
        self.private_key = private_key

    @staticmethod
    def from_file(key_type: RsaKeyType, filename: str, password: str = None) -> PrivateKey:
        with open(filename, 'rb') as f:
            return RsaPrivateKey(key_type, load_pem_private_key(f.read(), password=password))

    @property
    def key_type(self) -> KeyType:
        return self._key_type

    def sign_blob(self, blob: bytes) -> bytes:
        return self.private_key.sign(
            blob,
            self._key_type.padding(),
            self._key_type.hash_algorithm
        )

    def get_public_key(self) -> PublicKey:
        return RsaPublicKey(self._key_type, self.private_key.public_key())


class RsaPublicKey(PublicKey):

    def __init__(self, key_type: RsaKeyType, public_key):
        assert public_key.key_size == key_type.key_size, f'Key has the wrong size: {public_key.key_size} != ' \
                                                         f'{key_type.key_size}'
        self.public_key = public_key
        self._key_type = key_type

    @classmethod
    def from_crypto_material(cls, key_type: RsaKeyType, crypto_material: bytes) -> PublicKey:
        key_size_bytes = key_type.key_size >> 3

        if len(crypto_material) == 2 * key_size_bytes:
            pubexp = int.from_bytes(crypto_material[:key_size_bytes], 'little')
            assert pubexp == 65537, f'The public exponent should always be 65537 (0x10001) not {pubexp} ({hex(pubexp)})'
            modulus = int.from_bytes(crypto_material[key_size_bytes:], 'little')
        elif len(crypto_material) == key_size_bytes:
            pubexp = 0x10001
            modulus = int.from_bytes(crypto_material, 'little')
        else:
            raise Exception(f'Crypto material has unknown size: {len(crypto_material)}!')

        return RsaPublicKey(key_type, rsa.RSAPublicNumbers(pubexp, modulus).public_key())

    @property
    def key_type(self) -> KeyType:
        return self._key_type

    # Raises an exception if the signature is not valid
    def verify_blob(self, blob: bytes, signature: bytes):
        try:
            self.public_key.verify(
                signature,
                blob,
                self._key_type.padding(),
                self._key_type.hash_algorithm
            )
        except InvalidSignature:
            return False
        return True

    def get_crypto_material(self, size: int) -> bytes:
        key_size_bytes = self._key_type.key_size >> 3
        numbers = self.public_key.public_numbers()

        modulus = numbers.n.to_bytes(key_size_bytes, 'little')

        if size == key_size_bytes:
            return modulus
        elif size == 2 * key_size_bytes:
            pubexp = numbers.e.to_bytes(key_size_bytes, 'little')
            return pubexp + modulus
        else:
            raise Exception(f'Unknown crypto_material size (0x{size:x}), expected 0x{key_size_bytes:x} or 0x{2*key_size_bytes:x}!')


# Helper Functions

def load_private_key(filename: str, password: str = None) -> PrivateKey:
    try:
        with open(filename, 'rb') as f:
            private_key = load_pem_private_key(f.read(), password=password)
    except:
        raise Exception(f'Could not load private key from {filename}!')

    if private_key.key_size == 2048:
        return RsaPrivateKey(get_key_type("rsa2048"), private_key)
    if private_key.key_size == 4096:
        return RsaPrivateKey(get_key_type("rsa4096"), private_key)

    raise Exception(f'Cannot figure out KeyType for {private_key}!')
