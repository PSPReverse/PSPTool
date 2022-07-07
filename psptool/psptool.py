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

from .entry import Entry, HeaderEntry
from .blob import Blob
from .utils import PrintHelper
from .cert_tree import CertificateTree
from . import errors


class PSPTool:
    @classmethod
    def from_file(cls, filename, verbose=False):
        with open(filename, 'rb') as f:
            file_bytes = bytearray(f.read())

        pt = PSPTool(file_bytes, verbose=verbose)
        pt.filename = filename

        return pt

    def __init__(self, rom_bytes, verbose=False):
        self.ph = PrintHelper(verbose)

        self.blob = Blob(rom_bytes, len(rom_bytes), self)
        self.cert_tree = CertificateTree.from_blob(self.blob, self)

        self.filename = None

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
                t = PrettyTable(['', 'Directory', 'Addr', 'Type', 'Magic', 'Secondary Directory'])
                t.add_row([
                    '',
                    index,
                    hex(directory.get_address()),
                    directory.type,
                    directory.magic.decode('utf-8', 'backslashreplace'),
                    hex(directory.secondary_directory_address) if directory.secondary_directory_address else '--'
                ])

                print(t)

                self.ls_dir(rom, index, verbose=verbose)
                print('\n')

    def ls_dir(self, fet,  directory_index, verbose=False):
        directory = fet.directories[directory_index]
        self.ls_entries(entries=directory.entries, verbose=verbose)

    def ls_entries(self, entries=None, verbose=False):
        # list all entries of all directories by default (sorted by their address)
        if entries is None:
            entries = sorted(self.blob.unique_entries())

        basic_fields = ['', ' ', 'Entry', 'Address', 'Size', 'Type', 'Magic/ID', 'Version', 'Info']
        verbose_fields = ['MD5', 'size_signed', 'size_full', 'size_packed', 'load_addr']

        t = PrettyTable(basic_fields + verbose_fields)
        t.align = 'r'

        # TODO: Skip this whole mess and introduce strict and non_strict mode
        #  strict mode should parse everything but give inconsistency errors like sha256_inconsistent
        entry: Entry
        for index, entry in enumerate(entries):
            info = []
            if entry.compressed:
                info.append('compressed')
            if entry.signed:
                try:
                    if entry.signed_entity.is_verified():
                        info.append(f'verified({entry.get_readable_signed_by()})')
                except errors.NoCertifyingKey:
                    info.append(f'key_missing({entry.signed_entity.certifying_id.as_string()[:4]})')
                except errors.SignatureInvalid:
                    info.append(f'invalid_sig({entry.get_readable_signed_by()})')
            if entry.has_sha256_checksum:
                if entry.sha256_verified:
                    info.append(f'sha256_ok')
                else:
                    info.append(f'sha256_inconsistent')
            if entry.is_legacy:
                info.append('legacy_header')
            if entry.encrypted:
                info.append('encrypted')
            if type(entry) == HeaderEntry and entry.inline_keys:
                inline_keys = ', '.join(map(lambda k: k.get_readable_magic(), entry.inline_keys))
                info.append(f'inline_keys({inline_keys})')

            all_values = [
                '',
                '',
                index,
                hex(entry.get_address()),
                hex(entry.buffer_size),
                entry.get_readable_type(),
                entry.get_readable_magic(),
                entry.get_readable_version(),
                ', '.join(info),
                entry.md5()[:4].upper()
            ]

            if type(entry) is HeaderEntry:
                all_values += [hex(v) for v in [
                    entry.size_signed,
                    entry.size_uncompressed,
                    entry.rom_size,
                    entry.load_addr
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
                PrettyTable(['Directory', 'Addr', 'Type', 'Magic', 'Secondary Directory'])
                d = {
                    'directory': index,
                    'address': directory.get_address(),
                    'directoryType': directory.type,
                    'magic': directory.magic.decode('utf-8', 'backslashreplace'),
                }
                if directory.secondary_directory_address:
                    d['secondaryAddress'] = directory.secondary_directory_address

                entries = self.ls_dir_dict(rom, index, verbose=verbose)
                d['entries'] = entries
                data.append(d)
        print(json.dumps(data))

    def ls_dir_dict(self, fet,  directory_index, verbose=False):
        directory = fet.directories[directory_index]
        return self.ls_entries_dict(entries=directory.entries)

    def ls_entries_dict(self, entries=None):
        # list all entries of all directories by default (sorted by their address)
        if entries is None:
            entries = sorted(self.rom.unique_entries)

        out = []
        for index, entry in enumerate(entries):
            info = []
            if entry.compressed:
                info.append('compressed')
            if entry.signed:
                info.append(f'signed({entry.get_readable_signed_by()})')
                try:
                    if entry.signed_entity.is_verified():
                        info.append('verified')
                except errors.NoCertifyingKey:
                    info.append('no_key')
            if entry.is_legacy:
                info.append('legacy header')
            if entry.encrypted:
                info.append('encrypted')

            all_values = {
                'index': index,
                'address': entry.get_address(),
                'size': entry.buffer_size,
                'sectionType': entry.get_readable_type(),
                'magic': entry.get_readable_magic(),
                'version': entry.get_readable_version(),
                'info': info,
                'md5': entry.md5()[:4].upper()
            }

            if entry.get_readable_type() == "BIOS":
                all_values['destinationAddress'] = entry.get_readable_destination_address()

            if type(entry) is HeaderEntry:
                sizes = {
                    'signed': entry.size_signed,
                    'uncompressed': entry.size_uncompressed,
                    'packed': entry.rom_size
                }
                all_values['sizes'] = sizes

            out.append(all_values)

        return out
