#!/usr/bin/env python3

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
