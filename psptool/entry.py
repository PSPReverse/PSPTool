import utils


class Entry(utils.NestedBuffer):
    def __init__(self, parent_buffer, type_, buffer_size, buffer_offset: int):
        super().__init__(parent_buffer, buffer_size, buffer_offset=buffer_offset)

        self.type = type_
        self._parse()

    def __repr__(self):
        # this string is used to uniquely identify entries (and also to detect duplicates)
        return f'Entry(type={hex(self.type)}, address={hex(self.get_address())}), size={hex(self.buffer_size)})'

    def _parse(self):
        pass
