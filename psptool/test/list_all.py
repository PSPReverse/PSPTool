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

import os

from .. import PSPTool
from ..blob import Blob

path = 'psptool/test/latest-ryzen-june-2019'

if __name__ == '__main__':
    for subdir, dirs, files in os.walk(path):
        for file in files:
            if file[0] == '.':
                continue
            filename = os.path.join(subdir, file)

            try:
                psp = PSPTool.from_file(filename)
                print(psp)
                psp.ls()

            except Blob.NoFirmwareEntryTableError:
                print('No FET found!')
            print()
