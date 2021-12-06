from binascii import hexlify
from .entry import HeaderEntry, PubkeyEntry
from .utils import NestedBuffer, RangeDict
from .crypto import KeyType, PublicKey, PrivateKey
from . import crypto

# Errors


class NoCertifyingKey(Exception):
    def __init__(self, signed_entity):
        self.signed_entity = signed_entity

    def __str__(self):
        key_id = self.signed_entity.certifying_key
        return f'There is no key with id {key_id.as_string()}, so {self.signed_entity} could not be verified!'


class SignatureInvalid(Exception):
    def __init__(self, signed_entity, pubkey: PublicKey):
        self.signed_entity = signed_entity
        self.pubkey = pubkey

    def __str__(self):
        return f'Signature for {self.signed_entity} is not signed by {self.pubkey}!'


class NonUniqueSignedEntity(Exception):
    def __init__(self, existing, new):
        self.existing = existing
        self.new = new

    def __str__(self):
        start = self.existing.body.get_address()
        end = start + self.existing.body.buffer_size
        return f'There was anlready a SignedEntity at {hex(start)}:{hex(end)} (existing={self.existing}, new={self.new})!'


class NonUniquePublicKeyEntity(Exception):
    def __init__(self, existing, new):
        self.existing = existing
        self.new = new

    def __str__(self):
        start = self.existing.key_id.get_address()
        return f'There was anlready a PublicKeyEntity with key_id at {hex(start)} (existing={self.existing}, new={self.new})!'

# Tree Types


class KeyId(NestedBuffer):
    def as_string(self) -> str:
        return hexlify(self.get_bytes())

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


class SignedEntity:
    def __init__(self, entry, certifying_id: KeyId, signature: Signature):
        self.entry = entry
        self.certifying_id = certifying_id
        self.signature = signature

        # will be filled by CertificateTree
        self.certifying_keys = None
        self.contained_keys = set()

    @classmethod
    def _from_pubkey_entry(cls, pke):
        if not pke.signed:
            return None

        signature_start = pke.buffer_size - pke.signature_len
        body = NestedBuffer(pke, signature_start)
        certifying_id = KeyId(body, 0x10, buffer_offset=0x14)
        signature = ReversedSignature(pke, pke.signature_len, buffer_offset=signature_start)

        return SignedEntity(pke, certifying_id, signature)

    @classmethod
    def _from_header_entry(cls, he):
        if not he.signed or not he.signature:
            return None

        signature = Signature.from_nested_buffer(he.signature)
        certifying_id = KeyId(he, 0x10, buffer_offset=0x38)

        return SignedEntity(he, certifying_id, signature)

    def is_verified(self):
        try:
            self.verify_with_tree()
        except:
            return False
        return True

    def verify_with_tree(self):
        if not self.certifying_keys:  # works for None or set()
            raise NoCertifyingKey(self)
        for key in self.certifying_keys:
            self.verify_with_pubkey(key.get_public_key())

    def verify_with_pubkey(self, pubkey: PublicKey):
        try:
            res = pubkey.verify_blob(self.entry.get_signed_bytes(), self.signature.get_bytes())
            if res is not None and not res:
                raise None
        except:
            raise SignatureInvalid(self, pubkey)

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
        self.wrapping_entity = None
        self.certified_entities = None

        # for lazy loading
        self._public_key = None

    @classmethod
    def _from_pubkey_entry(cls, pke):
        body_len = pke.buffer_size
        if pke.signed:
            body_len -= pke.signature_len

        if body_len == 0x240:
            key_type = crypto.get_key_type('rsa2048')
        elif body_len == 0x440:
            key_type = crypto.get_key_type('rsa4096')
        else:
            raise Exception(f'Unknown PubkeyEntry body length ({hex(body_len)}) for {pke}')

        key_id = KeyId(pke, 0x10, buffer_offset=0x4)
        crypto_material = NestedBuffer(pke, body_len - 0x40, buffer_offset=0x40)

        return PublicKeyEntity(key_type, key_id, crypto_material)

    def get_certifying_id(self) -> KeyId:
        if self.wrapping_entity:
            return self.wrapping_entity.certifying_id
        return None

    def get_certifying_keys(self):
        if self.wrapping_entity:
            return self.wrapping_entity.certified_by_keys
        return set()

    def get_certified_keys(self):
        set(key
            for entity in self.certified_entities
                for key in entity.contained_keys
        )

    def _make_public_key(self) -> PublicKey:
        return self.key_type.make_public_key(self._crypto_material.get_bytes())

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

    def add_signed_entity(self, signed_entity: SignedEntity):
        start_address = signed_entity.entry.get_address()
        address_range = range(start_address, start_address + signed_entity.entry.buffer_size)

        # check if we already have this one
        if self.signed_ranges.get(address_range):
            raise NonUniqueSignedEntity(self.signed_ranges[address_range], signed_entity)

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
                assert pubkey.wrapping_entity is None, f'A pubkey is wrapped in multiple signed entities!'
                self.wrapping_entity = signed_entity

        # update certifying edges
        certifying_keys = self.pubkeys.get(cert_id, set())
        assert signed_entity.certifying_keys is None
        signed_entity.certifying_keys = certifying_keys
        # update certified edges
        for pubkey in certifying_keys:
            pubkey.certified_entities.add(signed_entity)

    def add_pubkey_entity(self, pubkey: PublicKeyEntity):
        start_address = pubkey.key_id.get_address()

        # check if we already have this one
        if self.pubkeys_address.get(start_address):
            raise NonUniquePublicKeyEntity(self.pubkeys_address[start_address], pubkey)

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
        assert pubkey.wrapping_entity is None
        # None instead of KeyError for RangeDict
        pubkey.wrapping_entity = self.signed_ranges[start_address]
        if pubkey.wrapping_entity:
            pubkey.wrapping_entity.contained_keys.add(pubkey)

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
            except NonUniqueSignedEntity as e:
                signed_entity = e.existing
            header_entry.signed_entity = signed_entity
            return signed_entity
        return None

    def add_pubkey_entry(self, pubkey_entry: PubkeyEntry) -> (PublicKeyEntity, SignedEntity):
        signed_entity = SignedEntity._from_pubkey_entry(pubkey_entry)
        if signed_entity:
            try:
                self.add_signed_entity(signed_entity)
            except NonUniqueSignedEntity as e:
                signed_entity = e.existing
            pubkey_entry.signed_entity = signed_entity

        pubkey = PublicKeyEntity._from_pubkey_entry(pubkey_entry)
        if pubkey:
            try:
                self.add_pubkey_entity(pubkey)
            except NonUniquePublicKeyEntity as e:
                pubkey = e.existing
            pubkey_entry.pubkey_entity = pubkey

        return pubkey, signed_entity

    @staticmethod
    def from_blob(blob):
        ct = CertificateTree()

        for fet in blob.fets:
            for dr in fet.directories:
                for entry in dr.entries:
                    if type(entry) == PubkeyEntry:
                        ct.add_pubkey_entry(entry)
                    if type(entry) == HeaderEntry:
                        ct.add_header_entry(entry)

        # Add unlisted/inline keys as found by additional blob parsing efforts
        missing_key_ids = set(
            blob.pubkeys.keys()
        ).difference(
            set(
                ct.pubkeys.keys()
            )
        )

        for key_id in missing_key_ids:
            for entry in blob.pubkeys[key_id]:
                ct.add_pubkey_entry(entry)

        return ct
