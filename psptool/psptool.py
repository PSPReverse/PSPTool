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

from prettytable import PrettyTable
import sys, json

from .file import File
from .header_file import HeaderFile
from .pubkey_file import PubkeyFile
from .blob import Blob
from .utils import PrintHelper
from .cert_tree import CertificateTree
from . import errors


class PSPTool:
    @classmethod
    def from_file(cls, filename, verbose=False):
        with open(filename, 'rb') as f:
            file_bytes = bytearray(f.read())

        pt = PSPTool(file_bytes, verbose=verbose, filename=filename)

        return pt

    def __init__(self, rom_bytes, verbose=False, filename=None):
        self.filename = filename
        self.ph = PrintHelper(verbose)

        self.blob = Blob(rom_bytes, len(rom_bytes), self)
        self.cert_tree = CertificateTree.from_blob(self.blob, self)

    def __repr__(self):
        if self.filename is not None:
            return f'PSPTool(filename={self.filename})'
        else:
            return f'PSPTool(len(rom_bytes)={self.blob.buffer_size}'

    def to_file(self, filename):
        with open(filename, 'wb') as f:
            f.write(self.blob.get_buffer())

    def to_stdout(self):
        sys.stdout.buffer.write(self.blob.get_buffer())

    def ls(self, verbose=False):
        for rom_index, rom in enumerate(self.blob.roms):
            t = PrettyTable(['ROM', 'Addr', 'Size', 'FET', 'AGESA'])
            t.add_row([
                rom_index,
                hex(rom.get_address()),
                hex(rom.buffer_size),
                hex(rom.fet.get_address()),
                rom.agesa_version
            ])
            print(t)

            for index, directory in enumerate(rom.directories):
                t = PrettyTable(['', 'Directory', 'Addr', 'Generation', 'Magic', 'Secondary Directory'])
                t.add_row([
                    '',
                    index,
                    hex(directory.get_address()),
                    directory.zen_generation,
                    directory.magic.decode('utf-8', 'backslashreplace'),
                    ', '.join([hex(sda) for sda in directory.secondary_directory_offsets])
                ])

                print(t)

                self.ls_dir(rom, index, verbose=verbose)
                print('\n')

    def ls_dir(self, fet,  directory_index, verbose=False):
        directory = fet.directories[directory_index]
        self.ls_files(files=directory.files, verbose=verbose)

    def ls_files(self, files=None, verbose=False):
        # list all entries of all directories by default (sorted by their address)
        if files is None:
            files = sorted(self.blob.unique_files())

        basic_fields = ['', ' ', 'Entry', 'Address', 'Size', 'Type', 'Magic/ID', 'File Version', 'File Info']
        verbose_fields = ['type_flags', 'MD5', 'size_signed', 'size_full', 'size_packed', 'load_addr']

        t = PrettyTable(basic_fields + verbose_fields)
        t.align = 'r'

        # TODO: Skip this whole mess and introduce strict and non_strict mode
        #  strict mode should parse everything but give inconsistency errors like sha256_inconsistent
        file: File
        for index, file in enumerate(files):
            info = []
            if file.compressed:
                info.append('compressed')
            if file.is_signed:
                try:
                    if file.signed_entity.is_verified():
                        info.append(f'verified({file.get_readable_signed_by()})')
                    else:
                        info.append(f'veri-failed({file.get_readable_signed_by()})')
                except errors.NoCertifyingKey:
                    info.append(f'key_missing({file.signed_entity.certifying_id.as_string()[:4]})')
                except errors.SignatureInvalid:
                    info.append(f'invalid_sig({file.get_readable_signed_by()})')
            if file.is_legacy:
                info.append('legacy_header')
            if file.encrypted:
                info.append('encrypted')
            if issubclass(type(file), HeaderFile):
                if file.has_sha256_checksum:
                    if file.verify_sha256():
                        info.append(f'sha256_ok')
                    else:
                        info.append(f'sha256_inconsistent')
                elif file.has_sha384_checksum:
                    if file.verify_sha384():
                        info.append(f'sha384_ok')
                    else:
                        info.append(f'sha384_inconsistent')
                if file.inline_keys:
                    inline_keys = ', '.join(map(lambda k: k.get_readable_magic(), file.inline_keys))
                    info.append(f'inline_keys({inline_keys})')
            if type(file) == PubkeyFile:
                info.append(file.get_readable_key_usage())
                if file.get_readable_security_features():
                    info.append(file.get_readable_security_features())

            all_values = [
                '',
                '',
                index,
                hex(file.get_address()),
                hex(file.buffer_size),
                file.get_readable_type(),
                file.get_readable_magic(),
                file.get_readable_version(),
                ', '.join(info),
                '',  # hex(file.entry.type_flags) if 'entry' in file else '',
                file.md5()[:4].upper()
            ]

            if type(file) is HeaderFile:
                all_values += [hex(v) for v in [
                    file.size_signed,
                    file.size_uncompressed,
                    file.rom_size,
                    file.load_addr
                ]]
            else:
                all_values += (4 * [''])

            t.add_row(all_values)

        fields = basic_fields

        if verbose is True:
            fields += verbose_fields

        print(t.get_string(fields=fields))

    def ls_json(self, verbose=False):
        data = []
        # todo: add notion of Multi-ROMs
        for rom in self.blob.roms:
            for index, directory in enumerate(rom.directories):
                PrettyTable(['Directory', 'Addr', 'Magic', 'Secondary Directory'])
                d = {
                    'directory': index,
                    'address': directory.get_address(),
                    'magic': directory.magic.decode('utf-8', 'backslashreplace'),
                    'secondaryAddresses': directory.secondary_directory_offsets
                }

                entries = self.ls_dir_dict(rom, index, verbose=verbose)
                d['entries'] = entries
                data.append(d)
        print(json.dumps(data))

    def ls_dir_dict(self, fet,  directory_index, verbose=False):
        directory = fet.directories[directory_index]
        return self.ls_files_dict(files=directory.files)

    def ls_files_dict(self, files=None):
        # list all entries of all directories by default (sorted by their address)
        if files is None:
            files = sorted(self.rom.unique_files)

        out = []
        for index, file in enumerate(files):
            info = []
            if file.compressed:
                info.append('compressed')
            if file.is_signed:
                info.append(f'signed({file.get_readable_signed_by()})')
                try:
                    if file.signed_entity.is_verified():
                        info.append('verified')
                except errors.NoCertifyingKey:
                    info.append('no_key')
            if file.is_legacy:
                info.append('legacy header')
            if file.encrypted:
                info.append('encrypted')

            all_values = {
                'index': index,
                'address': file.get_address(),
                'size': file.buffer_size,
                'sectionType': file.get_readable_type(),
                'magic': file.get_readable_magic(),
                'version': file.get_readable_version(),
                'info': info,
                'md5': file.md5()[:4].upper()
            }

            if file.get_readable_type() == "BIOS":
                all_values['destinationAddress'] = file.get_readable_destination_address()

            if issubclass(type(file), HeaderFile):
                sizes = {
                    'signed': file.size_signed,
                    'uncompressed': file.size_uncompressed,
                    'packed': file.rom_size
                }
                all_values['sizes'] = sizes

            out.append(all_values)

        return out

    def print_metrics(self):
        print(self.filename)
        print(f'{self.ph.error_count=}')
        print(f'{self.ph.warning_count=}')
        print(f'{self.ph.info_count=}')

        rom_count = len(self.blob.roms)
        directory_count = sum([len(rom.directories) for rom in self.blob.roms])
        unique_files_count = len(self.blob.unique_files())

        print(f'{rom_count=}')
        print(f'{directory_count=}')
        print(f'{unique_files_count=}')
