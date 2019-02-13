class Directory:
    def __init__(self, parent_blob, address, type_):
        # take a reference to the calling PSPFirmware and an address of the directory to be parsed
        # parse its directory header (always reference the Firmware's binary!) and create a PSPEntry
        self.blob = parent_blob
        self.address = address
        self.type = type_

    def __repr__(self):
        return f'Directory(address={hex(self.address)}, type={self.type}, count=TBD)'
