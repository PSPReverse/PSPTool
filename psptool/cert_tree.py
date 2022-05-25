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

from .entry import HeaderEntry, PubkeyEntry, KeyStoreEntry, KeyStoreKey
from .utils import NestedBuffer, RangeDict
from .crypto import PublicKey, PrivateKey, KeyType, PrivateKeyDict, KeyId, Signature

from . import errors

# Tree Types


class SignedEntity:
    def __init__(self, entry, certifying_id: KeyId, signature: Signature, psptool):
        self.psptool = psptool
        self.entry = entry
        self.certifying_id = certifying_id
        self.signature = signature

        # will be filled by CertificateTree
        self.certifying_keys = None
        self.contained_keys = set()

    def get_address(self):
        return self.entry.get_address()

    def get_length(self):
        return self.entry.buffer_size

    def get_range(self):
        start = self.get_address()
        return range(start, start + self.get_length())

    def __repr__(self) -> str:
        return f'SignedEntity(@{self.get_address():x}:{self.get_length():x})'

    @staticmethod
    def _from_pubkey_entry(pke, psptool):
        if pke.signed:
            return SignedEntity(pke, pke.certifying_id, pke.signature, psptool)
        return None

    @staticmethod
    def _from_header_entry(he: HeaderEntry, psptool):
        if not he.signed:
            return None

        signature = Signature.from_nested_buffer(he.signature)
        certifying_id = KeyId(he, 0x10, buffer_offset=0x38)

        return SignedEntity(he, certifying_id, signature, psptool)

    @classmethod
    def _from_key_store_entry(cls, kse: KeyStoreEntry, psptool):
        return SignedEntity(kse, kse.header.certifying_id, kse.signature, psptool)

    def is_verified(self):
        return self.verify_with_tree()

    def is_verified_by(self, pubkey):
        return self.verify_with_pubkey(pubkey.get_public_key())

    def verify_with_tree(self):
        if not self.certifying_keys:  # works for None or set()
            raise errors.NoCertifyingKey(self)

        verified_once = False
        failed_once = False
        for pubkey in self.certifying_keys:
            if self.verify_with_pubkey(pubkey.get_public_key()):
                verified_once = True
            else:
                failed_once = True

        if not verified_once:
            return False
        # todo: use this in strict mode (fails e.g. for H12SSW9.719)
        # if failed_once:
        #     raise errors.SignatureInconsistent(self, pubkey)
        return True

    def verify_with_pubkey(self, pubkey: PublicKey) -> bool:
        return pubkey.verify_blob(self.entry.get_signed_bytes(), self.signature.get_bytes())

    # resigns this entry only
    def resign_only(self, privkey: PrivateKey):
        print(f'Resigning {self} ({self.entry})')
        if self.entry.has_sha256_checksum:
            print(f'    Checking sha256 checksum of {self.entry}')
            if self.entry.verify_sha256(print_warning=False):
                print(f'        sha256 still valid!')
            else:
                print(f'        Need to rehash')
                self.entry.update_sha256()
                print(f'        Done')
        assert self.signature.buffer_size == privkey.signature_size
        signature = privkey.sign_blob(self.entry.get_signed_bytes())
        assert len(signature) == self.signature.buffer_size, f'Could not resign {self} with {privkey}: ' \
                                                             f'The new signature has the wrong length ' \
                                                             f'{len(signature)} != {self.signature.buffer_size}'
        self.signature.set_bytes(0, len(signature), signature)

    def resign_and_replace(self, privkeys: PrivateKeyDict = None, recursive: bool = False):
        # this resigns self (multiple times!)
        for pk in self.certifying_keys:
            pk.replace_and_resign(privkeys, recursive=recursive)


class PublicKeyEntity:
    def __init__(self, key_type: KeyType, key_id: KeyId, crypto_material: NestedBuffer, psptool):
        self.psptool = psptool
        self.key_type = key_type
        self.key_id = key_id
        self._crypto_material = crypto_material

        # will be filled by CertificateTree
        self.wrapping_entities = None
        self.certified_entities = None

        # for lazy loading
        self._public_key = None

    def get_address(self):
        return self.key_id.get_address()

    def get_magic(self):
        return self.key_id.as_string()[:4]

    def __repr__(self) -> str:
        return f'PubkeyEntity({self.get_magic()}, @{self.get_address():x})'

    def is_same(self, other) -> bool:
        if self.key_id[:] != other.key_id[:]:
            return False
        if self.key_type != other.key_type:
            return False
        if self._crypto_material[:] != other._crypto_material[:]:
            return False
        # TODO: we don't need this
        assert self.certified_entities == other.certified_entities
        return True

    @classmethod
    def _from_pubkey_entry(cls, pke: PubkeyEntry, psptool):
        if pke.modulus_size == 0x100:
            key_type = KeyType.from_name('rsa2048')
        elif pke.modulus_size == 0x200:
            key_type = KeyType.from_name('rsa4096')
        else:
            raise Exception(f'Unknown PubkeyEntry modulus size ({hex(pke.modulus_size)}) for {pke}')

        return PublicKeyEntity(key_type, pke.key_id, pke.crypto_material, psptool)

    @classmethod
    def _from_key_store_key(cls, ksk: KeyStoreKey, psptool):

        if ksk.key_size == 2048:
            key_type = KeyType.from_name('rsa2048')
        elif ksk.key_size == 4096:
            key_type = KeyType.from_name('rsa4096')
        else:
            raise Exception(f'Unknown key_size ({ksk.key_size:x}) for {ksk}')

        return PublicKeyEntity(key_type, ksk.key_id, ksk.crypto_material, psptool)

    def is_root(self) -> bool:
        return not self.get_certifying_keys() or self in self.get_certifying_keys()

    def get_certifying_ids(self):
        return set(entity.certifying_id
            for entity in self.wrapping_entities
        )

    def get_certifying_keys(self):
        return set(key
            for entity in self.wrapping_entities
                for key in entity.certifying_keys
        )

    def get_certified_keys(self):
        return set(key
            for entity in self.certified_entities
                for key in entity.contained_keys
        )

    def _make_public_key(self) -> PublicKey:
        try:
            return self.key_type.make_public_key(self._crypto_material.get_bytes())
        except:
            raise Exception(f'Cannot create crypto key for {self}.')

    def get_public_key(self) -> PublicKey:
        if not self._public_key:
            self._public_key = self._make_public_key()
        return self._public_key

    def replace_crypto_material(self, crypto_material: bytes):
        assert len(crypto_material) == self._crypto_material.buffer_size, f'Crypto material has wrong size: {len(crypto_material)} != {self._crypto_material.buffer_size}'
        self._public_key = None
        self._crypto_material.set_bytes(0, len(crypto_material), crypto_material)

    def replace_only(self, pubkey: PublicKey):
        print(f'Replacing {self}')
        assert self.key_type.signature_size == pubkey.signature_size
        size = self._crypto_material.buffer_size
        self.replace_crypto_material(pubkey.get_crypto_material(size))
        assert pubkey._public_key.public_numbers() == self.get_public_key()._public_key.public_numbers()

    def replace_and_resign(self, privkeys: PrivateKeyDict = None, recursive: bool = False):

        # get key
        if privkeys is None:
            privkeys = PrivateKeyDict()
        privkey = privkeys[self.key_type.name]
        assert self.key_type.signature_size == privkey.signature_size

        # resign children
        for se in self.certified_entities:
            se.resign_only(privkey)

        # replace self
        self.replace_only(privkey.get_public_key())

        # check crypto
        for se in self.certified_entities:
            assert se.is_verified_by(self), f'Resigning {se} with {self} failed!'

        # continue
        if recursive:
            if len(self.wrapping_entities) > 1:
                self.psptool.ph.print_warning(f'Resigning could be in wrong order for {self.wrapping_entities}!')

            for se in self.wrapping_entities:
                se.resign_and_replace(privkeys=privkeys, recursive=True)


class CertificateTree:
    def __init__(self, psptool):
        self.psptool = psptool
        # key_ids we have seen
        self.ids = set()
        # pubkeys by key id
        self.pubkeys = dict()
        # pubkeys by certifying_id address
        self.pubkeys_address = dict()
        # signed entities by certifying id
        self.signed_entities = dict()
        # signed entities by body address range
        self.signed_ranges = RangeDict()
        # signed entities where the verification failed
        self.verification_failed = set()

    def add_signed_entity(self, signed_entity: SignedEntity):
        address_range = signed_entity.get_range()

        # check if we already have this one
        if self.signed_ranges.get(address_range):
            raise errors.NonUniqueSignedEntity(self.signed_ranges[address_range], signed_entity)

        # add range->signed_entity dict
        self.signed_ranges[address_range] = signed_entity

        # update knowns key ids
        cert_id = signed_entity.certifying_id.as_string()
        self.ids.add(cert_id)

        # add key_id->signed_entity dict
        if not self.signed_entities.get(cert_id):
            self.signed_entities[cert_id] = set()
        self.signed_entities[cert_id].add(signed_entity)

        # update contained/wrapping edges
        for (address, pubkey) in self.pubkeys_address.items():
            if address in address_range:
                signed_entity.contained_keys.add(pubkey)
                pubkey.wrapping_entities.add(signed_entity)

        # update certifying edges
        certifying_keys = self.pubkeys.get(cert_id, set())
        assert signed_entity.certifying_keys is None
        signed_entity.certifying_keys = certifying_keys
        # update certified edges
        for pubkey in certifying_keys:
            pubkey.certified_entities.add(signed_entity)

    def add_pubkey_entity(self, pubkey: PublicKeyEntity):
        start_address = pubkey.get_address()

        # check if we already have this one
        if self.pubkeys_address.get(start_address):
            raise errors.NonUniquePublicKeyEntity(self.pubkeys_address[start_address], pubkey)

        # add address->pubkeys dict
        self.pubkeys_address[start_address] = pubkey

        # update known key ids
        key_id = pubkey.key_id.as_string()
        self.ids.add(key_id)

        # add key_id->pubkeys dict
        if not self.pubkeys.get(key_id):
            self.pubkeys[key_id] = set()
        self.pubkeys[key_id].add(pubkey)

        # update contained/wrapping edges
        assert pubkey.wrapping_entities is None
        pubkey.wrapping_entities = set()
        for (r, signed_entity) in self.signed_ranges.items():
            if start_address in r:
                pubkey.wrapping_entities.add(signed_entity)
                signed_entity.contained_keys.add(pubkey)

        # update certified edges
        assert pubkey.certified_entities is None
        pubkey.certified_entities = self.signed_entities.get(key_id, set())
        # update certifying edges
        for signed_entity in pubkey.certified_entities:
            signed_entity.certifying_keys.add(pubkey)

    def add_header_entry(self, header_entry) -> SignedEntity:
        signed_entity = SignedEntity._from_header_entry(header_entry, self.psptool)
        if signed_entity:
            try:
                self.add_signed_entity(signed_entity)
            except errors.NonUniqueSignedEntity as e:
                signed_entity = e.existing
            header_entry.signed_entity = signed_entity
            return signed_entity
        return None

    def add_pubkey_entry(self, pubkey_entry: PubkeyEntry) -> (PublicKeyEntity, SignedEntity):
        signed_entity = SignedEntity._from_pubkey_entry(pubkey_entry, self.psptool)
        if signed_entity:
            try:
                self.add_signed_entity(signed_entity)
            except errors.NonUniqueSignedEntity as e:
                signed_entity = e.existing
            pubkey_entry.signed_entity = signed_entity

        pubkey = PublicKeyEntity._from_pubkey_entry(pubkey_entry, self.psptool)
        if pubkey:
            try:
                self.add_pubkey_entity(pubkey)
            except errors.NonUniquePublicKeyEntity as e:
                pubkey = e.existing
            pubkey_entry.pubkey_entity = pubkey

        return pubkey, signed_entity

    def add_key_store_entry(self, key_store_entry: KeyStoreEntry):
        signed_entity = SignedEntity._from_key_store_entry(key_store_entry, self.psptool)
        if signed_entity:
            try:
                self.add_signed_entity(signed_entity)
            except errors.NonUniqueSignedEntity as e:
                signed_entity = e.existing
            key_store_entry.signed_entity = signed_entity

        for key_store_key in key_store_entry.key_store.keys:
            pubkey = PublicKeyEntity._from_key_store_key(key_store_key, self.psptool)
            try:
                self.add_pubkey_entity(pubkey)
            except errors.NonUniquePublicKeyEntity as e:
                pubkey = e.existing
            key_store_key.pubkey_entity = pubkey

    @staticmethod
    def from_blob(blob, psptool):
        ct = CertificateTree(psptool)

        for rom in blob.roms:
            for dr in rom.directories:
                for entry in dr.entries:
                    if type(entry) == PubkeyEntry:
                        ct.add_pubkey_entry(entry)
                    if type(entry) == HeaderEntry:
                        ct.add_header_entry(entry)
                    if type(entry) == KeyStoreEntry:
                        ct.add_key_store_entry(entry)

        # Add unlisted/inline keys as found by additional blob parsing efforts
        ids_to_find = ct.ids
        while ids_to_find:
            for pubkey in blob.find_inline_pubkey_entries(ids_to_find):
                ct.add_pubkey_entry(pubkey)
            ids_to_find = ct.ids.difference(ids_to_find)

        return ct

    def unique_pubkeys(self, key_id):
        unique_keys = list()
        for key in self.pubkeys[key_id]:
            inserted = False
            for uk in unique_keys:
                if key.is_same(uk[0]):
                    inserted = True
                    uk.append(key)
                    break
            if not inserted:
                unique_keys.append([key])
        return unique_keys

    def _print_key_tree_line(self, keys, indent):
        keys=list(keys)
        print(indent + f' +-{keys[0]}')
        keys=keys[1:]
        for key in keys:
            print(indent + f' | {key}')

    def _print_signed_entity_tree_line(self, signed_entity, verified, indent):
        print(indent + f' +-{signed_entity} (verified={verified})')

    def print_key_tree(self, root=None, indent='', stack=list()):
        seen_addresses = set()
        if not root:
            print(indent + 'AMD')
            for key_id in self.pubkeys.keys():
                for (keys) in self.unique_pubkeys(key_id):
                    key = keys[0]
                    if key.is_root() and key not in stack:
                        seen_addresses.update(set(map(lambda k: k.get_address(), keys)))
                        self._print_key_tree_line(keys, indent)
                        seen_addresses.update(self.print_key_tree(key, indent+' |', stack+[key]))
            #print("Seen:")
            #print(', '.join(map(hex,seen_addresses)))
            #print("Not seen:")
            #print(', '.join(map(hex,set(self.pubkeys_address) - seen_addresses)))
            assert seen_addresses == set(self.pubkeys_address.keys())
        else:
            for signed_entity in root.certified_entities:
                verified = signed_entity.is_verified_by(root)
                if not verified:
                    self.verification_failed.add(signed_entity)
                self._print_signed_entity_tree_line(signed_entity, verified, indent)
                for key in signed_entity.contained_keys:
                    if key in stack:
                        continue
                    key_id = key.key_id.as_string()
                    for keys in self.unique_pubkeys(key_id):
                        seen_addresses.update(set(map(lambda k: k.get_address(), keys)))
                        self._print_key_tree_line(keys, indent + ' |')
                    seen_addresses.update(self.print_key_tree(key, indent+' | |', stack+[key]))

        return seen_addresses
