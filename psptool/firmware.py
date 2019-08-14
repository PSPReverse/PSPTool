# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2019 Christian Werling, Robert Buhren
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

from .utils import NestedBuffer


class Firmware(NestedBuffer):
    # todo: find out correct size
    def __init__(self, parent_buffer, buffer_offset: int, firmware_type: str, magic: bytes):
        super().__init__(parent_buffer, 0x100, buffer_offset=buffer_offset)

        self.magic = magic
        self.type = firmware_type

    def __repr__(self):
        return f'<Firmware(type={self.type}, address={hex(self.get_address())}, magic={self.magic})>)'
