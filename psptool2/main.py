from prettytable import PrettyTable
from .blob import Blob


class PSPTool:
    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as f:
            rom_bytes = bytearray(f.read())

        return PSPTool(rom_bytes)

    def __init__(self, rom_bytes):
        self.blob = Blob(rom_bytes, len(rom_bytes))

    def to_file(self, filename):
        with open(filename, 'wb') as f:
            f.write(self.blob.get_buffer())

    def ls(self, no_duplicates=False, display_entry_header=False):
        for index, directory in enumerate(self.blob.directories):
            t = PrettyTable(['Directory', 'Addr', 'Type', 'Magic', 'Secondary Directory'])
            t.add_row([
                index,
                hex(directory.get_address()),
                directory.type,
                directory.magic.decode('utf-8', 'backslashreplace'),
                hex(directory.secondary_directory_address) if directory.secondary_directory_address else '--'
            ])

            print(t)

            self.ls_dir(index, no_duplicates=no_duplicates, display_entry_header=display_entry_header)
            print('\n')

    def ls_dir(self, directory_index, verbose=False, no_duplicates=False, display_entry_header=False):
        directory = self.blob.directories[directory_index]

        basic_fields = [' ', 'Entry', 'Address', 'Size', 'Type', 'Type Name', 'Magic', 'Version', 'Signed by']
        t = PrettyTable(basic_fields)
        t.align = 'r'

        for index, entry in enumerate(directory.entries):
            t.add_row([
                '',
                index,
                hex(entry.get_address()),
                hex(entry.buffer_size),
                hex(entry.type),
                entry.get_readable_type(),
                entry.get_readable_magic(),
                entry.get_readable_version(),
                entry.get_readable_signed_by()
            ])

        print(t.get_string(fields=basic_fields))
