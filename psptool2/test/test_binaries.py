#!/usr/bin/env python3

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
from psptool2 import PSPTool, Blob

path = '/Users/cwerling/Git/psptool2/psptool2/test/binaries'

for subdir, dirs, files in os.walk(path):
    for file in files:
        if file[0] == '.':
            continue
        filename = os.path.join(subdir, file)

        print(f'File: {filename}')
        try:
            psp = PSPTool.from_file(f'{filename}')
            print(psp.blob.agesa_version)
            print(f'AMD Public Key: {psp.blob.get_entry_by_type(0).key_id}')
            print()
            contains_amd_tee = psp.blob.get_bytes().find(b'AMD-TEE')
            print(f'Contains AMD-TEE: {contains_amd_tee}')
        except Blob.NoFirmwareEntryTableError:
            print('No FET found!')
