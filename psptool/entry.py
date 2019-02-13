import struct

from .directory import Directory
from .utils import chunker


class Entry:
    def __init__(self, parent_directory, type_, size, address):
        self.directory = parent_directory
        self.type = type_
        self.size = size
        self.address = address

        # self._parse()

    def __repr__(self):
        # this string is used to uniquely identify entries (and also to detect duplicates)
        return f'Entry(type={hex(self.type)}, address={hex(self.address)}), size={hex(self.size)})'


# start = entry_fields['address']
# end = start + entry_fields['size']
# entry_content = rstrip_padding(self.binary[start:end])
#
# entry_fields['content'] = entry_content
#
# # entry_bytes: merge in keys and values from a potential entry_header
# if entry_fields['type'] not in DIRECTORY_ENTRY_TYPES_SECONDARY_DIR:
#     entry_header = self._parse_entry_header(entry_fields)
#     entry_fields = {**entry_fields, **entry_header}
#
# # add md5 and duplicate info for entries with a valid size
# if 0 < entry_fields['size'] < 0x100000:
#     md5sum = md5(entry_content).hexdigest()[:8]
#     entry_fields['is_duplicate'] = True if md5sum in self._md5sums else False
#     self._md5sums.add(md5sum)
# else:
#     md5sum = 'n/a'
#     entry_fields['is_duplicate'] = False
#
# entry_fields['md5sum'] = md5sum
