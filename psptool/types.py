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
from .utils import NestedBuffer


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
