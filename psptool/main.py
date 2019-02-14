#!/usr/bin/env python3

from blob import Blob


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


if __name__ == '__main__':
    # CLI stuff to create a PSPTool object and interact with it
    psp = PSPTool.from_file('test/binaries/Supermicro_H11DSU7.804-selfread.bin')
    #psp.blob.directories[0].entries[0].set_bytes(0, 0x10, b'\x00' * 0x10)
    pass
