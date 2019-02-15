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

            self.ls_entry(index, no_duplicates=no_duplicates, display_entry_header=display_entry_header)
            print('\n')

    def ls_entry(self, directory_index, verbose=False, no_duplicates=False, display_entry_header=False):
        directory = self.blob.directories[directory_index]

        # Table head
        basic_fields = [' ', 'Entry', 'Address', 'Size', 'Type', 'Type Name', 'Magic', 'Version', 'Signed by']
        entry_header_fields = ['identifier', 'compressed', 'size_full', 'size_signed', 'size_packed', 'unknown',
                               'sig_fp']

        # Corresponding dict keys of entry dict
        all_keys = ['', 'index', 'address', 'size', 'type', 'version', 'signed_by', 'info', 'md5sum', 'entropy', 'id',
                    'compressed', 's_full', 's_signed', 's_packed', 'unknown',  'sig_fp']

        t = PrettyTable(basic_fields)
        t.align = 'r'
        t.align['Type (Magic)'] = 'l'

        for index, entry in enumerate(directory.entries):
            # entry = {'index': str(index), 'info': [], 'signed_by': '', **entry}

            # Incorporate string identifier into type field
            # if 'id' in entry:
            #     entry['type'] += ' (%s)' % entry['id']

            # Check if this is an AMD signing key
            # todo: extract!
            # pubkey = parse_amd_pubkey(entry['content'])

            # if pubkey:
            #     entry['sig_fp'] = pubkey['certifying_id']
            #     entry['id'] = pubkey['key_id']
            #     entry['info'].append('pubkey')
            #
            #     if self._verbose:
            #         entry['info'].append('key_version:%i' % pubkey['version'])
            #         entry['info'].append('key_usage:%i' % pubkey['key_usage'])
            #
            #     if pubkey['key_id'] not in self._pubkeys:
            #         self._pubkeys[pubkey['key_id']] = {
            #             'directory': directory_index,
            #             'entry': index,
            #             'type': entry['type']
            #         }

            # # Display info about signing
            # if 'sig_fp' in entry and entry['sig_fp'] != '' and entry['sig_fp'] in self._pubkeys:
            #     signed_by = self._pubkeys[entry['sig_fp']]
            #     entry['signed_by'] = signed_by['type']
            #
            #     if self._verify_signature(entry):
            #         entry['signed_by'] += '\n[verified]'
            #     else:
            #         entry['signed_by'] += '\n[not verified]'

            # # The following operations might be to expensive or impossible on bad entry sizes
            # if not (0 < entry['size'] < 0x100000):
            #     entry['entropy'] = 'n/a'
            # else:
            #     if entry['is_duplicate']:
            #         if no_duplicates:
            #             continue
            #         else:
            #             entry['info'].append('duplicate')
            #
            #     # Entropy calculation for detection of encrypted entries
            #     entry['entropy'] = round(shannon(entry['content']), 2)
            #
            #     # Zlib compression detection
            #     zlib_header = zlib_find_header(entry['content'])
            #
            #     # When entropy is high and the entry uncompressed, we assume that it's encrypted
            #     if 'compressed' in entry and entry['compressed'] == 1:
            #             entry['info'].append('compressed') if not self._verbose else entry['info'].append('zlib@0x%x' %
            #                                                                                               zlib_header)
            #     elif entry['entropy'] >= 0.9:
            #         entry['info'].append('encrypted?')
            #
            #     # Architecture detection
            #     if display_arch:
            #         data = entry['content']
            #
            #         if entry.get('compressed'):
            #             data = zlib_decompress(entry['content'])  # [:-0x100]
            #
            #         arch = find_arch(data)
            #         if arch is not None:
            #             entry['info'].append('arch=%s' % arch)

            # Line up all values according to all_keys (remember: dicts are not ordered!)
            # entry_row_values = []
            # for key in all_keys:
            #     try:
            #         value = entry[key]
            #     except KeyError:
            #         value = ''
            #
            #     if isinstance(value, bytes) and len(value) == 32:   # truncate hex-fingerprints to 4 uppercase chars
            #         value = value[:8].upper()
            #
            #     if isinstance(value, int):                          # convert numbers to hex
            #         entry_row_values.append(hex(value))
            #     elif isinstance(value, bytes):                      # convert bytes to string
            #         try:
            #             entry_row_values.append(str(value, 'ascii'))
            #         except UnicodeDecodeError:
            #             entry_row_values.append(value)
            #     elif isinstance(value, list):                       # convert lists (e.g. 'info') to string
            #         entry_row_values.append('\n'.join(entry['info']))
            #     else:
            #         entry_row_values.append(value)

            # all_keys = ['', 'index', 'address', 'size', 'type', 'version', 'signed_by', 'info', 'md5sum', 'entropy',
            #             'id',
            #             'compressed', 's_full', 's_signed', 's_packed', 'unknown', 'sig_fp']

            t.add_row([
                '',
                index,
                hex(entry.get_address()),
                hex(entry.buffer_size),
                hex(entry.type),
                entry.get_readable_type(),
                entry.get_readable_magic(),
                entry.get_readable_version(),
                entry.get_readable_signed_by(),
                #entry.get_readable_sizes()
            ])

        # See which fields are actually demanded (depending on -v and -i)
        fields = all_fields if verbose else basic_fields

        # if display_entry_header:
        #     fields += entry_header_fields
        # if self._verbose:
        #     fields += verbose_fields

        print(t.get_string(fields=fields))
