from binascii import hexlify
from .utils import NestedBuffer


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

