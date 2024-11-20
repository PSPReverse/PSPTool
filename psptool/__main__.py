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
from .header_file import HeaderFile
from .pubkey_file import PubkeyFile
from .crypto import PrivateKeyDict

from argparse import RawTextHelpFormatter, SUPPRESS


def main():
    # CLI stuff to create a PSPTool object and interact with it
    parser = ObligingArgumentParser(description='Display, extract, and manipulate AMD PSP firmware inside BIOS ROMs.\n',
                                    formatter_class=RawTextHelpFormatter, add_help=False)

    parser.add_argument('file', help='Binary file to be parsed for PSP firmware', nargs='?')
    parser.add_argument('-h', '--help', action='help', help=SUPPRESS)
    parser.add_argument('-v', '--verbose', help=SUPPRESS, action='store_true')

    parser.add_argument('-r', '--rom-index', help=SUPPRESS, type=int, default=0)
    parser.add_argument('-d', '--directory-index', help=SUPPRESS, type=int)
    parser.add_argument('-e', '--file-index', help=SUPPRESS, type=int)
    parser.add_argument('-s', '--subfile', help=SUPPRESS)
    parser.add_argument('-o', '--outfile', help=SUPPRESS)
    parser.add_argument('-u', '--decompress', help=SUPPRESS, action='store_true')
    parser.add_argument('-c', '--decrypt', help=SUPPRESS, action='store_true')
    parser.add_argument('-k', '--pem-key', help=SUPPRESS, action='store_true')
    parser.add_argument('-n', '--no-duplicates', help=SUPPRESS, action='store_true')
    parser.add_argument('-j', '--json', help=SUPPRESS, action='store_true')
    parser.add_argument('-t', '--key-tree', help=SUPPRESS, action='store_true')
    parser.add_argument('-m', '--metrics', help=SUPPRESS, action='store_true')
    parser.add_argument('-p', '--privkeystub', help=SUPPRESS)
    parser.add_argument('-a', '--privkeypass', help=SUPPRESS)

    action = parser.add_mutually_exclusive_group(required=False)

    action.add_argument('-V', '--version', action='store_true')

    action.add_argument('-E', '--entries', help='\n'.join([
        'Default: Parse and display PSP firmware entries.',
        '[-n] [-j] [-t]',
        '',
        '-n:      list unique entries only ordered by their offset',
        '-j:      output in JSON format instead of tables',
        '-t:      print tree of all signed entities and their certifying keys',
        '-m:      print parsing metrics for testing',
        '', '']), action='store_true')

    action.add_argument('-X', '--extract-file', help='\n'.join([
        'Extract one or more PSP firmware files.',
        '[-d idx [-e idx]] [-n] [-u] [-c] [-k] [-o outfile]',
        '',
        '-r idx:  specifies rom_index (default: 0)',
        '-d idx:  specifies directory_index (default: all directories)',
        '-e idx:  specifies file_index (default: all files)',
        '-n:      skip duplicate files and extract unique files only',
        '-u:      uncompress compressed files',
        '-c:      try to decrypt files',
        '-k:      convert pubkeys into PEM format',
        '-o file: specifies outfile/outdir (default: stdout/{file}_extracted)',
        '', '']), action='store_true')

    action.add_argument('-R', '--replace-file', help='\n'.join([
        'Copy a new file (including header and signature) into the',
        'ROM file and update file and other metadata accordingly.',
        '-d idx -e idx -s subfile -o outfile [-p file-stub] [-a pass]',
        '',
        '-r idx:  specifies rom_index (default: 0)',
        '-d idx:  specifies directory_index',
        '-e idx:  specifies file_index',
        '-s file: specifies subfile (i.e. the new file contents)',
        '-o file: specifies outfile',
        '-p file: specifies file-stub (e.g. \'keys/id\') for the re-signing keys',
        '-a pass: specifies password for the re-signing keys'
        '', '']), action='store_true')

    args = parser.parse_args()
    ph = PrintHelper(args.verbose)

    if args.version:
        print(pkg_resources.get_distribution("psptool").version)
        sys.exit(0)
    elif not args.file:
        parser.print_help(sys.stderr)
        sys.exit(0)

    psp = PSPTool.from_file(args.file, verbose=args.verbose)
    output = None

    if args.extract_file:
        if args.directory_index is not None and args.file_index is not None:
            file = psp.blob.roms[args.rom_index].directories[args.directory_index].files[args.file_index]

            if args.decompress:
                if not file.compressed:
                    ph.print_error_and_exit(f'File is not compressed {file.get_readable_type()}')
                output = file.get_signed_bytes()
            elif args.decrypt:
                if not file.encrypted:
                    ph.print_error_and_exit(f'File is not encrypted {file.get_readable_type()}')
                output = file.to_decrypted_file_bytes()
            elif args.pem_key:
                output = file.get_pem_encoded()
            else:
                output = file.get_bytes()

        else:
            if args.file_index is None:  # if neither directory_index nor file_index are specified
                if args.directory_index is not None:
                    directories = [psp.blob.roms[args.rom_index].directories[args.directory_index]]
                else:
                    directories = psp.blob.roms[args.rom_index].directories

                if args.no_duplicates is False:
                    outdir = args.outfile or f'./{psp.filename}_extracted'
                    for dir_index, directory in enumerate(directories):
                        for file_index, file in enumerate(directory.files):
                            if args.decompress and type(file) is HeaderFile:
                                out_bytes = file.get_signed_bytes()
                            elif args.decrypt and type(file) is HeaderFile:
                                out_bytes = file.get_decrypted()
                            elif args.pem_key and type(file) is PubkeyFile:
                                out_bytes = file.get_pem_encoded()
                            else:
                                out_bytes = file.get_bytes()

                            outpath = outdir + '/d%.2d_e%.2d_%s' % (dir_index, file_index, file.get_readable_type())
                            if type(file) is HeaderFile:
                                outpath += f'_{file.get_readable_version()}'

                            os.makedirs(os.path.dirname(outpath), exist_ok=True)
                            with open(outpath, 'wb') as f:
                                f.write(out_bytes)
                    ph.print_info(f"Extracted all files to {outdir}")
                else:  # no_duplicates is True
                    for file in psp.blob.roms[args.rom_index].unique_files:
                        if args.decompress and type(file) is HeaderFile:
                            out_bytes = file.get_signed_bytes()
                        elif args.decrypt and type(file) is HeaderFile:
                            out_bytes = file.get_decrypted()
                        elif args.pem_key and type(file) is PubkeyFile:
                            out_bytes = file.get_pem_encoded()
                        else:
                            out_bytes = file.get_bytes()

                        outdir = args.outfile or f'./{psp.filename}_unique_extracted'
                        outpath = outdir + '/%s' % (file.get_readable_type())

                        if issubclass(type(file), HeaderFile):
                            outpath += f'_{file.get_readable_version()}'

                        os.makedirs(os.path.dirname(outpath), exist_ok=True)
                        with open(outpath, 'wb') as f:
                            f.write(out_bytes)
            else:
                parser.print_help(sys.stderr)

    elif args.replace_file:
        if args.directory_index is not None and args.file_index is not None and args.outfile is not None:
            file = psp.blob.roms[args.rom_index].directories[args.directory_index].files[args.file_index]

            # Substituting an file is actually optional to allow plain re-signs
            if args.subfile is not None:
                with open(args.subfile, 'rb') as f:
                    sub_binary = f.read()
                # Keep the existing file's address, but adapt its size
                file.move_buffer(file.get_address(), len(sub_binary))
                file.set_bytes(0, len(sub_binary), sub_binary)

            privkeys = None
            if args.privkeystub:
                privkeys = PrivateKeyDict.read_from_files(args.privkeystub, args.privkeypass)

            if hasattr(file, 'signed_entity') and file.signed_entity:
                file.signed_entity.resign_and_replace(privkeys=privkeys, recursive=True)
            else:
                ph.print_warning("Did not resign anything since target file is not signed")

            psp.to_file(args.outfile)

            if privkeys:
                privkeys.save_to_files(args.privkeystub, args.privkeypass)
        else:
            parser.print_help(sys.stderr)
    else:
        if args.json:
            psp.ls_json(verbose=args.verbose)
        elif args.key_tree:
            psp.cert_tree.print_key_tree()
        elif args.metrics:
            psp.print_metrics()
        elif args.no_duplicates:
            psp.ls_files(verbose=args.verbose)
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
