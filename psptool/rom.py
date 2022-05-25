import re

from .fet import Fet, EmptyFet
from .utils import NestedBuffer, sole


class Rom(NestedBuffer):
    def __init__(self, parent_blob, rom_size, rom_offset, fet_offset, psptool):
        super().__init__(parent_blob, rom_size, rom_offset)

        # ROMs will be mapped into memory to fit the very end of the 32 bit memory
        #  -> most ROMs are 16 MB in size, so addresses are starting at 0xFF000000
        #  -> some ROMs are 8 MB in size, so addresses are starting at 0xFF800000
        self.addr_mask = rom_size - 1

        self.unique_entries = set()
        self.pubkeys = {}

        self.agesa_version = self._find_agesa_version()
        self.fet = Fet(self, fet_offset, psptool)

        self.directories = self.fet.directories

    def _find_agesa_version(self):
        # from https://www.amd.com/system/files/TechDocs/44065_Arch2008.pdf

        # todo: use NestedBuffers instead of saving by value

        m = re.compile(b"AGESA!..\x00.*?\x00")
        res = m.findall(self.get_bytes())

        if not res:
            return 'AGESA_UNKNOWN'
        else:
            res = sole(set(res), assert_msg=f"Found conflicting AGESA version strings: {res}!")

        return str(re.sub(b'\x00', b' ', res).strip().decode("ascii"))

        # # We are only interested in different agesa versions
        # res = set(res)
        # res = list(res)
        #
        # # Some Images contain actually two ROM images. I.e. one for Naples and
        # # one for Rome. Both will contain a valid FET which needs to be parsed.
        # if len(res) == 2:
        #     self.dual_rom = True
        #     self.agesa_version = str(re.sub(b'\x00', b' ', res[0]).strip().decode("ascii"))
        #     self.agesa_version_second = str(re.sub(b'\x00', b' ', res[1]).strip().decode("ascii"))
        # elif len(res) == 1:
        #     self.agesa_version = str(re.sub(b'\x00', b' ', res[0]).strip().decode("ascii"))
        # else:
        #     self.agesa_version = str("UNKNOWN")

    def __repr__(self):
        return f'Rom({self.agesa_version=})'