from .entry import HeaderEntry, PubkeyEntry, KeyStoreEntry, KeyStoreKey
from .utils import NestedBuffer, RangeDict
from .crypto import KeyType, PublicKey, PrivateKey, get_key_type
from .types import Signature, KeyId, ReversedSignature
from . import errors

# Tree Types

class SignedEntity:
    def __init__(self, entry, certifying_id: KeyId, signature: Signature):
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

    @classmethod
    def _from_pubkey_entry(cls, pke):
        if not pke.signed:
            return None

        signature_start = pke.buffer_size - pke.signature_len
        certifying_id = KeyId(pke, 0x10, buffer_offset=0x14)
        signature = ReversedSignature(pke, pke.signature_len, buffer_offset=signature_start)

        return SignedEntity(pke, certifying_id, signature)

    @classmethod
    def _from_header_entry(cls, he: HeaderEntry):
        if not he.signed:
            return None

        signature = Signature.from_nested_buffer(he.signature)
        certifying_id = KeyId(he, 0x10, buffer_offset=0x38)

        return SignedEntity(he, certifying_id, signature)

    @classmethod
    def _from_key_store_entry(cls, kse: KeyStoreEntry):
        return SignedEntity(kse, kse.header.certifying_id, kse.signature)

    def is_verified(self):
        return self.verify_with_tree()

    def is_verified_by(self, pubkey):
        return self.verify_with_pubkey(pubkey.get_public_key())

    def verify_with_tree(self):
        if not self.certifying_keys:  # works for None or set()
            raise errors.NoCertifyingKey(self)
        for key in self.certifying_keys:
            if not self.verify_with_pubkey(key.get_public_key()):
                return False
        return True

    def verify_with_pubkey(self, pubkey: PublicKey) -> bool:
        return pubkey.verify_blob(self.entry.get_signed_bytes(), self.signature.get_bytes())

    # resigns this entry only
    def resign_only(self, privkey: PrivateKey):
        signature = privkey.sign_blob(self.entry.get_bytes())
        assert len(signature) == self.signature.buffer_size, f'Could not resign {self} with {privkey}: The new signature has the wrong length {len(signature)} != {self.signature.buffer_size}'
        self.signature.set_bytes(0, len(signature), signature)


class PublicKeyEntity:
    def __init__(self, key_type: KeyType, key_id: KeyId, crypto_material: NestedBuffer):
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
    def _from_pubkey_entry(cls, pke: PubkeyEntry):
        body_len = pke.buffer_size
        if pke.signed:
            body_len -= pke.signature_len

        if body_len == 0x240:
            key_type = get_key_type('rsa2048')
        elif body_len == 0x440:
            key_type = get_key_type('rsa4096')
        else:
            raise Exception(f'Unknown PubkeyEntry body length ({hex(body_len)}) for {pke}')

        key_id = KeyId(pke, 0x10, buffer_offset=0x4)
        crypto_material = NestedBuffer(pke, body_len - 0x40, buffer_offset=0x40)

        return PublicKeyEntity(key_type, key_id, crypto_material)

    @classmethod
    def _from_key_store_key(cls, ksk: KeyStoreKey):

        if ksk.key_size == 2048:
            key_type = get_key_type('rsa2048')
        elif ksk.key_size == 4096:
            key_type = get_key_type('rsa4096')
        else:
            raise Exception(f'Unknown key_size ({ksk.key_size:x}) for {ksk}')

        return PublicKeyEntity(key_type, ksk.key_id, ksk.crypto_material)

    def is_root(self) -> bool:
        # TODO this is probably wrong
        assert self not in self.get_certifying_keys()
        return not self.get_certifying_keys()

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
        self.replace_crypto_material(pubkey.get_crypto_material())


class CertificateTree:
    def __init__(self):
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
        signed_entity = SignedEntity._from_header_entry(header_entry)
        if signed_entity:
            try:
                self.add_signed_entity(signed_entity)
            except errors.NonUniqueSignedEntity as e:
                signed_entity = e.existing
            header_entry.signed_entity = signed_entity
            return signed_entity
        return None

    def add_pubkey_entry(self, pubkey_entry: PubkeyEntry) -> (PublicKeyEntity, SignedEntity):
        signed_entity = SignedEntity._from_pubkey_entry(pubkey_entry)
        if signed_entity:
            try:
                self.add_signed_entity(signed_entity)
            except errors.NonUniqueSignedEntity as e:
                signed_entity = e.existing
            pubkey_entry.signed_entity = signed_entity

        pubkey = PublicKeyEntity._from_pubkey_entry(pubkey_entry)
        if pubkey:
            try:
                self.add_pubkey_entity(pubkey)
            except errors.NonUniquePublicKeyEntity as e:
                pubkey = e.existing
            pubkey_entry.pubkey_entity = pubkey

        return pubkey, signed_entity

    def add_key_store_entry(self, key_store_entry: KeyStoreEntry):
        signed_entity = SignedEntity._from_key_store_entry(key_store_entry)
        if signed_entity:
            try:
                self.add_signed_entity(signed_entity)
            except errors.NonUniqueSignedEntity as e:
                signed_entity = e.existing
            key_store_entry.signed_entity = signed_entity

        for key_store_key in key_store_entry.key_store.keys:
            pubkey = PublicKeyEntity._from_key_store_key(key_store_key)
            try:
                self.add_pubkey_entity(pubkey)
            except errors.NonUniquePublicKeyEntity as e:
                pubkey = e.existing
            key_store_key.pubkey_entity = pubkey

    @staticmethod
    def from_blob(blob):
        ct = CertificateTree()

        for fet in blob.fets:
            for dr in fet.directories:
                for entry in dr.entries:
                    if type(entry) == PubkeyEntry:
                        ct.add_pubkey_entry(entry)
                    if type(entry) == HeaderEntry:
                        res=ct.add_header_entry(entry)
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

    def print_key_tree(self, root=None, indent=''):
        seen_addresses = set()
        if not root:
            print(indent + 'AMD')
            for key_id in self.pubkeys.keys():
                for (keys) in self.unique_pubkeys(key_id):
                    key = keys[0]
                    if key.is_root():
                        seen_addresses.update(set(map(lambda k: k.get_address(), keys)))
                        self._print_key_tree_line(keys, indent)
                        seen_addresses.update(self.print_key_tree(key, indent+' |'))
            print("Seen:")
            print(', '.join(map(hex,seen_addresses)))
            print("Not seen:")
            print(', '.join(map(hex,set(self.pubkeys_address) - seen_addresses)))
            assert seen_addresses == set(self.pubkeys_address.keys())
        else:
            for signed_entity in root.certified_entities:
                verified = signed_entity.is_verified_by(root)
                if not verified:
                    self.verification_failed.add(signed_entity)
                self._print_signed_entity_tree_line(signed_entity, verified, indent)
                for key in signed_entity.contained_keys:
                    key_id = key.key_id.as_string()
                    for keys in self.unique_pubkeys(key_id):
                        seen_addresses.update(set(map(lambda k: k.get_address(), keys)))
                        self._print_key_tree_line(keys, indent + ' |')
                    seen_addresses.update(self.print_key_tree(key, indent+' | |'))

        return seen_addresses
