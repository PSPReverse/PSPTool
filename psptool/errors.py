from .utils import NestedBuffer
from .crypto import PublicKey

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


class SignatureInconsistent(SignatureInvalid):
    def __str__(self):
        return f'Signature for {self.signed_entity} was verified successfully at least once, but could not be ' \
               f'verified by {self.pubkey}!'



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

