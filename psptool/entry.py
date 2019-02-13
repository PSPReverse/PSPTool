class Entry:
    @classmethod
    def from_bytes(cls):
        pass

    def __init__(self, firmware, address):
        # take a reference to the (indirectly calling) PSPFirmware and address of the entry to be parsed
        # parse the entry header (always reference the Firmware's binary!)
        pass
