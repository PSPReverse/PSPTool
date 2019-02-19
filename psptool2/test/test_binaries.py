#!/usr/bin/env python3

import os
from psptool2 import PSPTool

path = 'psptool2/test/binaries'

for file in os.listdir(path):
  filename = os.fsdecode(file)
  if filename.startswith('.'):
    continue

  print(f'File: {filename}')
  psp = PSPTool.from_file(f'{path}/{filename}')
  print(psp.blob.agesa_version)
  print(f'AMD Public Key: {psp.blob.get_entry_by_type(0).key_id}')
  print()

