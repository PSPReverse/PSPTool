from .utils import NestedBuffer


class Firmware(NestedBuffer):
    # todo: find out its size and make it a utils.NestedBuffer
    def __init__(self, parent_buffer, buffer_offset: int, firmware_type: str, magic: bytes):
        super().__init__(parent_buffer, 0x100, buffer_offset=buffer_offset)

        self.magic = magic
        self.type = firmware_type

    def __repr__(self):
        return f'<Firmware(type={self.type}, address={hex(self.get_address())}, magic={self.magic})>)'
