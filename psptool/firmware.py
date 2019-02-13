class Firmware:
    def __init__(self, parent_blob, firmware_type: str, address: int, magic: bytes):
        self.blob = parent_blob
        self.address = address
        self.magic = magic
        self.type = firmware_type

    def __repr__(self):
        return f'<Firmware(type={self.type}, address={hex(self.address)}, magic={self.magic})>)'
