import sys


class NestedBuffer:
    def __init__(self, parent_buffer, buffer_size: int, buffer_offset: int = 0):
        self.parent_buffer = parent_buffer
        self.buffer_size = buffer_size
        self.buffer_offset = buffer_offset

    def __getitem__(self, item):
        if isinstance(item, slice):
            stop = self.buffer_offset + self.buffer_size
            if item.stop is not None:
                assert(item.stop <= self.buffer_size)
                stop = self.buffer_offset + item.stop
            new_slice = slice(self.buffer_offset + item.start, stop, item.step)
            return self.parent_buffer[new_slice]
        else:
            assert(isinstance(item, int))
            return self.parent_buffer[item]

    def __setitem__(self, key, value):
        self.parent_buffer[key] = value

    def get_address(self) -> int:
        if isinstance(self.parent_buffer, NestedBuffer):
            return self.buffer_offset + self.parent_buffer.get_address()
        else:
            return self.buffer_offset

    def get_buffer(self):
        return self.parent_buffer

    def get_bytes(self, address: int, size: int) -> bytes:
        return bytes(self[address:address + size])

    def get_chunks(self, size: int, offset: int = 0):
        return chunker(self[offset:], size)


def print_error_and_exit(arg0, *nargs, **kwargs):
    """ Wrapper function to print errors to stderr, so we don't interfere with e.g. extraction output. """
    arg0 = 'Error: ' + arg0 + '\n'
    sys.stderr.write(arg0, *nargs, **kwargs)
    sys.exit(1)


def print_warning(arg0, *nargs, **kwargs):
    """ Wrapper function to print warnings to stderr, so we don't interfere with e.g. extraction output. """
    arg0 = 'Warning: ' + arg0 + '\n'
    sys.stderr.write(arg0, *nargs, **kwargs)


def print_info(arg0, *nargs, **kwargs):
    """ Wrapper function to print info to stderr, so we don't interfere with e.g. extraction output. """
    arg0 = 'Info: ' + arg0 + '\n'
    sys.stderr.write(arg0, *nargs, **kwargs)


def chunker(seq, size):
    """ Utility function to chunk seq into a list of size sized sequences. """
    return (seq[pos:pos + size] for pos in range(0, len(seq), size))


def rstrip_padding(bytestring):
    """ Takes a bytestring and strips trailing 0xFFFFFFFF dwords. """
    i = 0
    while bytestring[-(4+i):len(bytestring)-i] == b'\xff\xff\xff\xff':
        i += 4
    return bytestring[:len(bytestring)-i]
