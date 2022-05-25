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

from binascii import hexlify
from os import listdir, mkdir, path

from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, BestAvailableEncryption, NoEncryption
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .utils import NestedBuffer


# Abstract classes
class WithSignatureSize(ABC):

    # abstract static property
    def __init_subclass__(cls):
        cls.signature_size = cls._signature_size()

    @classmethod
    @abstractmethod
    def _signature_size(cls) -> int:
        pass


class PublicKey(WithSignatureSize):

    # abstract static property
    def __init_subclass__(cls):
        super().__init_subclass__()

    # to/from crypto material
    @classmethod
    @abstractmethod
    def from_crypto_material(cls, crypto_material: bytes):
        pass

    @abstractmethod
    def get_crypto_material(self, size: int) -> bytes:
        pass

    # core functionality
    @abstractmethod
    def verify_blob(self, blob: bytes, signature: bytes) -> bool:
        pass


class PrivateKey(WithSignatureSize):

    # abstract static property
    def __init_subclass__(cls):
        super().__init_subclass__()
        cls.PublicKey = cls._PublicKey()

    @staticmethod
    @abstractmethod
    def _PublicKey() -> PublicKey:
        pass

    # generate out of thin air
    @classmethod
    @abstractmethod
    def generate_new(cls):
        pass

    # to/from file
    @classmethod
    @abstractmethod
    def load_from_file(cls, filename: str, password: str = None):
        pass

    @abstractmethod
    def save_to_file(self, filename: str, password: str = None):
        pass

    # core functionality
    @abstractmethod
    def get_public_key(self) -> PublicKey:
        pass

    @abstractmethod
    def sign_blob(self, blob: bytes) -> bytes:
        pass



class KeyType:

    _key_types = dict()

    @staticmethod
    def from_name(name: str):
        return KeyType._key_types[name]

    def __init__(self, name: str, public_key_cls, private_key_cls):

        if KeyType._key_types.get(name):
            raise Exception(f'There is already a KeyType with the name "{name}"!')

        self.name = name

        assert issubclass(public_key_cls, PublicKey)
        assert issubclass(private_key_cls, PrivateKey)
        assert private_key_cls.signature_size == public_key_cls.signature_size

        self.signature_size = private_key_cls.signature_size
        self.PublicKey = public_key_cls
        self.PrivateKey = private_key_cls

        KeyType._key_types[name] = self


    def load_private_key(self, filename: str, password: str = None) -> PrivateKey:
        return self.PrivateKey.load_from_file(filename, password=password)

    def generate_private_key(self) -> PrivateKey:
        return self.PrivateKey.generate_new()

    def make_public_key(self, crypto_material: bytes) -> PublicKey:
        return self.PublicKey.from_crypto_material(crypto_material)


def _create_parent_dirname(dirname):
    dirname = path.dirname(dirname)
    if not path.exists(dirname):
        _create_parent_dirname(dirname)
        mkdir(dirname)

def create_parent_dir(filestub):
    _create_parent_dirname(path.realpath(filestub))


class PrivateKeyDict:

    def __init__(self, keys = dict()):
        self.keys = keys

    def __getitem__(self, name: str) -> PrivateKey:
        if not self.keys.get(name):
            self.keys[name] = KeyType.from_name(name).generate_private_key()
        return self.keys[name]

    def save_to_files(self, filestub: str, password: str = None):
        create_parent_dir(filestub)
        for (name, key) in self.keys.items():
            key.save_to_file(filestub + '.' + name, password=password)

    @staticmethod
    def read_from_files(filestub: str, password: str = None):
        create_parent_dir(filestub)
        dirname = path.dirname(filestub)
        filestub = path.relpath(filestub, start=dirname)
        keys = dict()
        for filename in listdir(dirname):
            if filename.startswith(filestub):
                name = filename.rsplit('.')[-1]
                keys[name] = KeyType.from_name(name).load_private_key(dirname + '/' + filename, password=password)
        return PrivateKeyDict(keys)


# Key Implementations


class RsaKey(WithSignatureSize):

    # abstract static property
    def __init_subclass__(cls):
        super().__init_subclass__()
        cls.key_bits = None
        if cls.signature_size:
            cls.key_bits = cls.signature_size << 3
            if cls.key_bits == 2048:
                cls.hash_algorithm = hashes.SHA256()
                cls.salt_length = 32
            elif cls.key_bits == 4096:
                cls.hash_algorithm = hashes.SHA384()
                cls.salt_length = 48
            else:
                raise Exception(f'Unknown rsa key size: {cls.key_bits} bits!')

    @classmethod
    def padding(cls):
        return padding.PSS(
            mgf=padding.MGF1(cls.hash_algorithm),
            salt_length=cls.salt_length
        )


class RsaPublicKey(PublicKey, RsaKey):

    def __init__(self, public_key):
        super().__init__()
        assert public_key.key_size == self.key_bits, f'Key has the wrong size: \
                expected {self.key_bits} but got {public_key.key_size}!'
        self._public_key = public_key

    # to/from crypto material
    @classmethod
    #override
    def from_crypto_material(cls, crypto_material: bytes) -> PublicKey:
        if len(crypto_material) == 2 * cls.signature_size:
            pubexp = int.from_bytes(crypto_material[:cls.signature_size], 'little')
            assert pubexp == 65537, f'The public exponent should always be 65537 \
                    (0x10001) not {pubexp} (0x{pubexp:x})!'
            modulus = int.from_bytes(crypto_material[cls.signature_size:], 'little')
        elif len(crypto_material) == cls.signature_size:
            pubexp = 0x10001
            modulus = int.from_bytes(crypto_material, 'little')
        else:
            raise Exception(f'Crypto material has unknown size: 0x{len(crypto_material):x}!')

        return cls(rsa.RSAPublicNumbers(pubexp, modulus).public_key())

    #override
    def get_crypto_material(self, size: int) -> bytes:
        numbers = self._public_key.public_numbers()
        modulus = numbers.n.to_bytes(self.signature_size, 'little')

        if size == self.signature_size:
            return modulus
        elif size == 2 * self.signature_size:
            pubexp = numbers.e.to_bytes(self.signature_size, 'little')
            return pubexp + modulus
        else:
            raise Exception(f'Unknown crypto_material size: 0x{size:x} \
                    (expected 0x{self.signature_size:x} or 0x{2*self.signature_size:x})!')

    # core functionality
    #override
    def verify_blob(self, blob: bytes, signature: bytes) -> bool:
        pass
        try:
            self._public_key.verify(
                signature,
                blob,
                self.padding(),
                self.hash_algorithm
            )
        except InvalidSignature:
            return False
        return True


class RsaPrivateKey(PrivateKey, RsaKey):

    def __init__(self, private_key):
        super().__init__()
        assert private_key.key_size == self.key_bits, f'Key has the wrong size: \
                expected {self.key_bits} but got {private_key.key_size}!'
        self._private_key = private_key

    # generate out of thin air
    @classmethod
    #override
    def generate_new(cls) -> PrivateKey:
        return cls(rsa.generate_private_key(public_exponent=0x10001,key_size=cls.key_bits))

    # to/from file
    @classmethod
    #override
    def load_from_file(cls, filename: str, password: str = None) -> PrivateKey:
        if password:
            password = password.encode()
        with open(filename, 'rb') as f:
            return cls(load_pem_private_key(f.read(), password=password))

    #override
    def save_to_file(self, filename: str, password: str = None):
        encryption = NoEncryption()
        if password:
            encryption=BestAvailableEncryption(password.encode())
        with open(filename, 'wb+') as f:
            f.write(self._private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))

    # core functionality
    #override
    def get_public_key(self) -> PublicKey:
        return self.PublicKey(self._private_key.public_key())

    #override
    def sign_blob(self, blob: bytes) -> bytes:
        return self._private_key.sign(
            blob,
            self.padding(),
            self.hash_algorithm
        )


class Rsa2048PublicKey(RsaPublicKey):

    def __init__(self, public_key):
        super().__init__(public_key)

    @classmethod
    #override
    def _signature_size(cls) -> int:
        return 0x100

class Rsa2048PrivateKey(RsaPrivateKey):

    def __init__(self, private_key):
        super().__init__(private_key)

    @staticmethod
    #override
    def _PublicKey() -> PublicKey:
        return Rsa2048PublicKey

    @classmethod
    #override
    def _signature_size(cls) -> int:
        return 0x100


rsa2048_key_type = KeyType("rsa2048", Rsa2048PublicKey, Rsa2048PrivateKey)


class Rsa4096PublicKey(RsaPublicKey):

    def __init__(self, public_key):
        super().__init__(public_key)

    @classmethod
    #override
    def _signature_size(cls) -> int:
        return 0x200

class Rsa4096PrivateKey(RsaPrivateKey):

    def __init__(self, private_key):
        super().__init__(private_key)

    @staticmethod
    #override
    def _PublicKey() -> PublicKey:
        return Rsa4096PublicKey

    @classmethod
    #override
    def _signature_size(cls) -> int:
        return 0x200

rsa4096_key_type = KeyType("rsa4096", Rsa4096PublicKey, Rsa4096PrivateKey)


class KeyId(NestedBuffer):

    @property
    def magic(self) -> str:
        return hexlify(self.get_bytes(0, 2)).upper().decode('ascii')

    def as_string(self) -> str:
        return hexlify(self.get_bytes()).upper().decode('ascii')

    def __repr__(self):
        return f'KeyId({self.as_string()})'


class Signature(NestedBuffer):
    @classmethod
    def from_nested_buffer(cls, nb):
        return Signature(nb.parent_buffer, nb.buffer_size, buffer_offset=nb.buffer_offset)


class ReversedSignature(Signature):
    def __getitem__(self, item):
        if isinstance(item, slice):
            new_slice = self._offset_slice(item)
            return self.parent_buffer[new_slice]
        else:
            assert (isinstance(item, int))
            assert item >= 0, "Negative index not supported for ReversedSignature"
            return self.parent_buffer[self.buffer_offset + self.buffer_size - item - 1]

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            new_slice = self._offset_slice(key)
            self.parent_buffer[new_slice] = value
        else:
            assert (isinstance(key, int))
            self.parent_buffer[self.buffer_offset + self.buffer_size - key - 1] = value

    def _offset_slice(self, item):
        return slice(
            self.buffer_offset + self.buffer_size - (item.start or 0) - 1,
            self.buffer_offset + self.buffer_size - (item.stop or self.buffer_size) - 1,
            -1
        )