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

from prettytable import PrettyTable

from .. import PSPTool, Blob


def get_vendor(filename):
    for vendor in ['AORUS', 'ASRock', 'Gigabyte', 'HP', 'ASUS', 'Lenovo', 'MSI']:
        if vendor in filename:
            return vendor

    return ''


def get_chipset(filename):
    for chipset in ['B350', 'B450', 'X399', 'A320', 'X370', 'X470']:
        if chipset in filename:
            return chipset

    return ''


def get_arch(agesa):
    if 'SummitPI' in agesa or 'RavenPI' in agesa:
        return 'Zen'
    elif 'PinnaclePI' in agesa or 'ThreadRipper' in agesa or 'Picasso' in agesa:
        return 'Zen+'
    elif 'Combo' in agesa:
        return 'Zen2'


path = 'psptool/test/latest-ryzen-june-2019'

if __name__ == '__main__':
    all_bootloaders = []

    for subdir, dirs, files in os.walk(path):
        for file in files:
            if file[0] == '.':
                continue
            filename = os.path.join(subdir, file)

            try:
                psp = PSPTool.from_file(filename)

                amd_pubkey = psp.blob.get_entries_by_type(0)[0]

                # contains_amd_tee = psp.blob.get_bytes().find(b'AMD-TEE')
                # print(f'Contains AMD-TEE: {contains_amd_tee}')

                bootloaders = psp.blob.get_entries_by_type(1)

                for bootloader in bootloaders:
                    try:
                        signing_pubkey = psp.blob.pubkeys[bootloader.signature_fingerprint]

                        all_bootloaders.append({
                            'vendor': get_vendor(file),
                            'agesa': f'{get_arch(psp.blob.agesa_version[9:])}: {psp.blob.agesa_version[9:]}',
                            'chipset': get_chipset(file),
                            'pubkey': signing_pubkey.get_readable_magic(),
                            'modulus_size': hex(len(signing_pubkey.modulus)),
                            'verified': bootloader.verify_signature(),
                            'bl_version': bootloader.get_readable_version(),
                            'bl_encrypted': bootloader.encrypted,
                            'bl_fp1': bootloader.unknown_fingerprint1[:4],
                            'bl_unkn_bool': bootloader.unknown_bool,
                            'bl_fp2': bootloader.unknown_fingerprint2[:4],
                            'file': file
                        })
                    except AttributeError:
                        print('Not a valid bootloader!')
            except Blob.NoFirmwareEntryTableError:
                print('No FET found!')

    pt = PrettyTable(['vendor', 'agesa', 'chipset', 'pubkey', 'modulus_size', 'verified', 'bl_version', 'bl_encrypted', 'bl_fp1', 'bl_unkn_bool', 'bl_fp2', 'file'])

    for psp in all_bootloaders:
        pt.add_row([value for value in psp.values()])

    pt.sortby = 'vendor'
    print(pt)
