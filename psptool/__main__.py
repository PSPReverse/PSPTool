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

import sys
import os
import pkg_resources

from .psptool import PSPTool
from .utils import ObligingArgumentParser, PrintHelper
from .entry import PubkeyEntry, HeaderEntry
from .crypto import PrivateKeyDict

from argparse import RawTextHelpFormatter, SUPPRESS


def main():
    # CLI stuff to create a PSPTool object and interact with it
    parser = ObligingArgumentParser(description='Display, extract, and manipulate AMD PSP firmware inside BIOS ROMs.\n',
                                    formatter_class=RawTextHelpFormatter, add_help=False)
    # Create subparsers for top-level actions
    # Common  argument
    common_args = ObligingArgumentParser(add_help=False)
    common_args.add_argument('file', help='Binary file to be parsed for PSP firmware', nargs='?')
    common_args.add_argument('-v', '--verbose', help=SUPPRESS, action='store_true')
    parser.add_argument('-h', '--help', action='help', help=SUPPRESS)


    # Create subparsers for distinct actions
    subparsers = parser.add_subparsers(dest='action', required=True)

    # Version action
    subparsers.add_parser('version', help='Show version')

    # List entries action
    list_parser = subparsers.add_parser('list-entries', help='Parse and display PSP firmware entries.', aliases=['E'], parents=[common_args])
    list_parser.set_defaults(action='list-entries')

    list_parser.add_argument('-n', '--no-duplicates', help='list unique entries only ordered by their offset', action='store_true')
    list_parser.add_argument('-j', '--json', help='output in JSON format instead of tables', action='store_true')
    list_parser.add_argument('-t', '--key-tree', help='print tree of all signed entities and their certifying keys', action='store_true')
    list_parser.add_argument('-m', '--metrics', help='print entry parsing metrics for testing', action='store_true')

    # Extract entry action
    extract_parser = subparsers.add_parser('extract-entry', help='Extract one or more PSP firmware entries.', aliases=['X'], parents=[common_args])
    extract_parser.set_defaults(action='extract-entry')
    extract_parser.add_argument('-r', '--rom-index', help="specifies rom_index (default: 0)", type=int, default=0)
    extract_parser.add_argument('-d', '--directory-index', help='specifies directory_index (default: all directories)', type=int)
    extract_parser.add_argument('-e', '--entry-index', help='specifies entry_index (default: all entries)', type=int)
    extract_parser.add_argument('-n', '--no-duplicates', help='skip duplicate entries and extract unique entries only', action='store_true')
    extract_parser.add_argument('-u', '--decompress', help='uncompress compressed entries', action='store_true')
    extract_parser.add_argument('-c', '--decrypt', help='try to decrypt entries', action='store_true')
    extract_parser.add_argument('-k', '--pem-key', help='convert pubkeys into PEM format', action='store_true')
    extract_parser.add_argument('-o', '--outfile', help='specifies outfile/outdir (default: stdout/{file}_extracted)')

    # Replace entry action
    replace_parser = subparsers.add_parser('replace-entry', help='Copy a new entry into the ROM file and update metadata.', aliases=['R'], parents=[common_args])
    replace_parser.set_defaults(action='replace-entry')
    replace_parser.add_argument('-r', '--rom-index', help="specifies rom_index (default: 0)", type=int, default=0)
    replace_parser.add_argument('-d', '--directory-index', help='specifies directory_index', type=int)
    replace_parser.add_argument('-e', '--entry-index', help='specifies entry_index', type=int)
    replace_parser.add_argument('-s', '--subfile', help='subfile (i.e. the new entry contents)')
    replace_parser.add_argument('-o', '--outfile', help='outfile')
    replace_parser.add_argument('-p', '--privkeystub', help='specifies file-stub (e.g. \'keys/id\') for the re-signing keys')
    replace_parser.add_argument('-a', '--privkeypass', help='specifies password for the re-signing keys')

    args = parser.parse_args()
    ph = PrintHelper(args.verbose)

    if args.action == 'version':
        print(pkg_resources.get_distribution("psptool").version)
        sys.exit(0)
    elif not args.file:
        print("No file set", args.action)
        parser.print_help(sys.stderr)
        sys.exit(0)

    psp = PSPTool.from_file(args.file, verbose=args.verbose)
    output = None

    if args.action == 'extract-entry':
        if args.directory_index is not None and args.entry_index is not None:
            entry = psp.blob.roms[args.rom_index].directories[args.directory_index].entries[args.entry_index]

            if args.decompress:
                if not entry.compressed:
                    ph.print_error_and_exit(f'Entry is not compressed {entry.get_readable_type()}')
                output = entry.get_signed_bytes()
            elif args.decrypt:
                if not entry.encrypted:
                    ph.print_error_and_exit(f'Entry is not encrypted {entry.get_readable_type()}')
                output = entry.to_decrypted_entry_bytes()
            elif args.pem_key:
                output = entry.get_pem_encoded()
            else:
                output = entry.get_bytes()

        else:
            if args.entry_index is None:  # if neither directory_index nor entry_index are specified
                if args.directory_index is not None:
                    directories = [psp.blob.roms[args.rom_index].directories[args.directory_index]]
                else:
                    directories = psp.blob.roms[args.rom_index].directories

                if args.no_duplicates is False:
                    outdir = args.outfile or f'./{psp.filename}_extracted'
                    for dir_index, directory in enumerate(directories):
                        for entry_index, entry in enumerate(directory.entries):
                            if args.decompress and type(entry) is HeaderEntry:
                                out_bytes = entry.get_signed_bytes()
                            elif args.decrypt and type(entry) is HeaderEntry:
                                out_bytes = entry.get_decrypted()
                            elif args.pem_key and type(entry) is PubkeyEntry:
                                out_bytes = entry.get_pem_encoded()
                            else:
                                out_bytes = entry.get_bytes()

                            outpath = outdir + '/d%.2d_e%.2d_%s' % (dir_index, entry_index, entry.get_readable_type())
                            if type(entry) is HeaderEntry:
                                outpath += f'_{entry.get_readable_version()}'

                            os.makedirs(os.path.dirname(outpath), exist_ok=True)
                            with open(outpath, 'wb') as f:
                                f.write(out_bytes)
                    ph.print_info(f"Extracted all entries to {outdir}")
                else:  # no_duplicates is True
                    for entry in psp.blob.roms[args.rom_index].unique_entries:
                        if args.decompress and type(entry) is HeaderEntry:
                            out_bytes = entry.get_signed_bytes()
                        elif args.decrypt and type(entry) is HeaderEntry:
                            out_bytes = entry.get_decrypted()
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

    elif args.action == 'replace-entry':
        if args.directory_index is not None and args.entry_index is not None and args.outfile is not None:
            entry = psp.blob.roms[args.rom_index].directories[args.directory_index].entries[args.entry_index]

            # Substituting an entry is actually optional to allow plain re-signs
            if args.subfile is not None:
                with open(args.subfile, 'rb') as f:
                    sub_binary = f.read()
                # Keep the existing entry's address, but adapt its size
                entry.move_buffer(entry.get_address(), len(sub_binary))
                entry.set_bytes(0, len(sub_binary), sub_binary)

            privkeys = None
            if args.privkeystub:
                privkeys = PrivateKeyDict.read_from_files(args.privkeystub, args.privkeypass)

            if hasattr(entry, 'signed_entity') and entry.signed_entity:
                entry.signed_entity.resign_and_replace(privkeys=privkeys, recursive=True)
            else:
                ph.print_warning("Did not resign anything since target entry is not signed")

            psp.to_file(args.outfile)

            if privkeys:
                privkeys.save_to_files(args.privkeystub, args.privkeypass)
        else:
            parser.print_help(sys.stderr)
    elif args.action == 'list-entries':
        if args.json:
            psp.ls_json(verbose=args.verbose)
        elif args.key_tree:
            psp.cert_tree.print_key_tree()
        elif args.metrics:
            psp.print_metrics()
        elif args.no_duplicates:
            psp.ls_entries(verbose=args.verbose)
        else:
            psp.ls(verbose=args.verbose)
    else:
        parser.print_help(sys.stderr)

    # Output handling (stdout or outfile)
    if output is not None:
        if args.outfile is None:
            sys.stdout.buffer.write(output)
        else:
            with open(args.outfile, 'wb') as f:
                f.write(output)


if __name__ == '__main__':
    main()
