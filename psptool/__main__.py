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

import sys
import os

from .psptool import PSPTool
from .utils import ObligingArgumentParser, print_warning
from .entry import PubkeyEntry, HeaderEntry

from argparse import RawTextHelpFormatter, SUPPRESS


def main():
    # CLI stuff to create a PSPTool object and interact with it
    parser = ObligingArgumentParser(description='Display, extract, and manipulate AMD PSP firmware inside BIOS ROMs.\n',
                                    formatter_class=RawTextHelpFormatter, add_help=False)

    parser.add_argument('file', help='Binary file to be parsed for PSP firmware')
    parser.add_argument('-h', '--help', action='help', help=SUPPRESS)
    parser.add_argument('-v', '--verbose', help=SUPPRESS, action='store_true')

    parser.add_argument('-d', '--directory-index', help=SUPPRESS, type=int)
    parser.add_argument('-e', '--entry-index', help=SUPPRESS, type=int)
    parser.add_argument('-s', '--subfile', help=SUPPRESS)
    parser.add_argument('-o', '--outfile', help=SUPPRESS)
    parser.add_argument('-u', '--decompress', help=SUPPRESS, action='store_true')
    parser.add_argument('-k', '--pem-key', help=SUPPRESS, action='store_true')
    parser.add_argument('-n', '--no-duplicates', help=SUPPRESS, action='store_true')

    action = parser.add_mutually_exclusive_group(required=False)

    action.add_argument('-E', '--entries', help='\n'.join([
        'Default: Parse and display PSP firmware entries.',
        '[-n]',
        '',
        '-n:      list unique entries only ordered by their offset',
        '', '']), action='store_true')

    action.add_argument('-X', '--extract-entry', help='\n'.join([
        'Extract one or more PSP firmware entries.',
        '[-d idx [-e idx]] [-n] [-u] [-k] [-o outfile]',
        '',
        '-d idx:  specifies directory_index (default: all directories)',
        '-e idx:  specifies entry_index (default: all entries)',
        '-n:      skip duplicate entries and extract unique entries only',
        '-u:      uncompress compressed entries',
        '-k:      convert pubkeys into PEM format',
        '-o file: specifies outfile/outdir (default: stdout/{file}_extracted)',
        '', '']), action='store_true')

    action.add_argument('-R', '--replace-entry', help='\n'.join([
        'Copy a new entry (including header and signature) into the',
        'ROM file and update metadata accordingly.',
        '-d idx -e idx -s subfile -o outfile',
        '',
        '-d idx:  specifies directory_index',
        '-e idx:  specifies entry_index',
        '-s file: specifies subfile (i.e. the new entry contents)',
        '-o file: specifies outfile',
        '', '']), action='store_true')

    args = parser.parse_args()
    psp = PSPTool.from_file(args.file, verbose=args.verbose)
    output = None

    if args.extract_entry:
        if args.directory_index is not None and args.entry_index is not None:
            entry = psp.blob.directories[args.directory_index].entries[args.entry_index]

            if args.decompress:
                output = entry.get_decompressed()
            elif args.pem_key:
                output = entry.get_pem_encoded()
            else:
                output = entry.get_bytes()

        else:
            if args.entry_index is None:  # if neither directory_index nor entry_index are specified
                if args.directory_index is not None:
                    directories = [psp.blob.directories[args.directory_index]]
                else:
                    directories = psp.blob.directories

                if args.no_duplicates is False:
                    for dir_index, directory in enumerate(directories):
                        for entry_index, entry in enumerate(directory.entries):
                            if args.decompress and type(entry) is HeaderEntry:
                                out_bytes = entry.get_decompressed()
                            elif args.pem_key and type(entry) is PubkeyEntry:
                                out_bytes = entry.get_pem_encoded()
                            else:
                                out_bytes = entry.get_bytes()

                            outdir = args.outfile or f'./{psp.filename}_extracted'
                            outpath = outdir + '/d%.2d_e%.2d_%s' % (dir_index, entry_index, entry.get_readable_type())
                            if type(entry) is HeaderEntry:
                                outpath += f'_{entry.get_readable_version()}'

                            os.makedirs(os.path.dirname(outpath), exist_ok=True)
                            with open(outpath, 'wb') as f:
                                f.write(out_bytes)
                else:  # no_duplicates is True
                    for entry in psp.blob.unique_entries:
                        if args.decompress and type(entry) is HeaderEntry:
                            out_bytes = entry.get_decompressed()
                        elif args.pem_key and type(entry) is PubkeyEntry:
                            out_bytes = entry.get_pem_encoded()
                        else:
                            out_bytes = entry.get_bytes()

                        outdir = args.outfile or f'./{psp.filename}_unique_extracted'
                        outpath = outdir + '/%s' % (entry.get_readable_type())

                        if type(entry) is HeaderEntry:
                            outpath += f'_{entry.get_readable_version()}'

                        os.makedirs(os.path.dirname(outpath), exist_ok=True)
                        with open(outpath, 'wb') as f:
                            f.write(out_bytes)
            else:
                parser.print_help(sys.stderr)

    elif args.replace_entry:
        if args.directory_index is not None and args.entry_index is not None and args.subfile is not None \
                and args.outfile is not None:
            with open(args.subfile, 'rb') as f:
                    sub_binary = f.read()

            entry = psp.blob.directories[args.directory_index].entries[args.entry_index]
            entry.move_buffer(entry.get_address(), len(sub_binary))
            entry.set_bytes(0, len(sub_binary), sub_binary)

            psp.to_file(args.outfile)
        else:
            parser.print_help(sys.stderr)
    else:
        if args.verbose:
            print(psp.blob.agesa_version)

        if args.no_duplicates:
            psp.ls_entries(verbose=args.verbose)
        else:
            psp.ls(verbose=args.verbose)

    # Output handling (stdout or outfile)
    if output is not None:
        if args.outfile is None:
            sys.stdout.buffer.write(output)
        else:
            with open(args.outfile, 'wb') as f:
                f.write(output)


if __name__ == '__main__':
    main()
