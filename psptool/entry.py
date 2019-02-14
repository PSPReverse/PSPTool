import struct
import utils

from binascii import hexlify


class Entry(utils.NestedBuffer):
    class ParseError(Exception):
        pass

    @classmethod
    def from_fields(cls, parent_directory, parent_buffer, type_, size, offset):
        try:
            # Option 1: it's a PubkeyEntry
            new_entry = PubkeyEntry(parent_directory, parent_buffer, type_, size, buffer_offset=offset)
        except (cls.ParseError, AssertionError):
            try:
                # Option 2: it's a HeaderEntry (most common)
                new_entry = HeaderEntry(parent_directory, parent_buffer, type_, size, buffer_offset=offset)
            except (cls.ParseError, AssertionError):
                # Option 3: it's a plain Entry
                new_entry = Entry(parent_directory, parent_buffer, type_, size, buffer_offset=offset)

        return new_entry

    def __init__(self, parent_directory, parent_buffer, type_, buffer_size, buffer_offset: int):
        super().__init__(parent_buffer, buffer_size, buffer_offset=buffer_offset)

        self.type = type_
        self.references = [parent_directory]

        try:
            self._parse()
        except (struct.error, AssertionError):
            raise Entry.ParseError()

    def __repr__(self):
        return f'{self.__class__.__name__}(type={hex(self.type)}, address={hex(self.get_address())}), ' \
               f'size={hex(self.buffer_size)}, len(references)={len(self.references)})'

    def __eq__(self, other):
        return self.type == other.type and self.get_address() == other.get_address() and \
               self.buffer_size == other.buffer_size

    def __hash__(self):
        return hash((self.type, self.get_address(), self.buffer_size))

    def _parse(self):
        pass


class PubkeyEntry(Entry):
    def _parse(self):
        """ SEV spec B.1 """

        pubexp_size = struct.unpack('<I', self[0x38:0x3c])[0] // 8
        modulus_size = signature_size = struct.unpack('<I', self[0x3c:0x40])[0] // 8
        pubexp_start = 0x40
        modulus_start = pubexp_start + pubexp_size

        # Byte order of the numbers is inverted over their entire length
        # Assumption: Only the most significant 4 bytes of pubexp are relevant and can be converted to int

        # todo: use NestedBuffers instead of saving by value
        self.pubexp = self[pubexp_start:modulus_start][::-1][-4:]
        self.modulus = self[modulus_start:modulus_start + modulus_size][::-1]

        self.version = struct.unpack('<I', self[0x0:0x4])[0]
        self.key_id = hexlify(self[0x4:0x14])
        self.certifying_id = hexlify(self[0x14:0x24])
        self.key_usage = struct.unpack('<I', self[0x24:0x28])[0]

        expected_size = 0x40 + pubexp_size + modulus_size + signature_size

        # Option 1: it's a regular Pubkey (with a trailing signature)
        if len(self) == expected_size:
            self.signature = self[modulus_start + modulus_size:]
        # Option 2: it's the AMD Root Signing Key (without a trailing signature)
        elif len(self) == expected_size - signature_size:
            self.signature = None
        else:
            raise Entry.ParseError()


class HeaderEntry(Entry):
    def _parse(self):
        self.header = utils.NestedBuffer(self, 0x100)
        self.body = utils.NestedBuffer(self, len(self) - 0x200, 0x100)
        self.signature = utils.NestedBuffer(self, 0x100, len(self) - 0x100)

        # todo: use NestedBuffers instead of saving by value
        self.id = self.header[0x10:0x14]
        self.size_signed = struct.unpack('<I', self.header[0x14:0x18])[0]
        self.signature_fingerprint = hexlify(self.header[0x38:0x48])
        self.compressed = struct.unpack('<I', self.header[0x48:0x4c])[0]
        self.size_full = struct.unpack('<I', self.header[0x50:0x54])[0]
        self.version = '.'.join([hex(b)[2:].upper() for b in self.header[0x63:0x5f:-1]])
        self.unknown = struct.unpack('<I', self.header[0x68:0x6c])[0]
        self.size_packed = struct.unpack('<I', self.header[0x6c:0x70])[0]

        assert(self.compressed in [0, 1])

        # if header['id'] == b'\x01\x00\x00\x00':
        #     # actually twice as long, but SMURULESMURULES is kinda redundant
        #     header['id'] = entry_content[0x0:0x4]
        # elif header['id'] == b'\x05\x00\x00\x00':
        #     header['id'] = b'0x05'

        # try:
        #     # Try to encode the id as ascii
        #     header['id'] = str(header['id'], encoding='ascii')
        #     # and remove unprintable chars
        #     header['id'] = ''.join(s for s in header['id'] if s in string.printable)
        #     # If no printable chars are left, remove
        #     if header['id'] == '':
        #         del header['id']
        # except UnicodeDecodeError:
        #     del header['id']
