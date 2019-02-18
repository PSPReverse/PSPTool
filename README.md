

# psptool2

psptool is a Swiss Army knife for dealing with **binary blobs** mainly **delivered with BIOS updates** targeting **AMD platforms**. 

It is based on reverse-engineering efforts of AMD's proprietary **simple filesystem** used to **pack its blobs** into standardized **UEFI Firmware Images**. These are usually 16MB in size and can be conveniently parsed by [UEFITool](https://github.com/LongSoft/UEFITool). However, all binary blobs by AMD are located in an unparsable area of the UEFI image marked as *padding* by UEFITool.

**psptool favourably works with BIOS ROM files** such as UEFI images – as they can be obtained labeled *BIOS updates* from OEMs and IBVs. However, it won't complain about additional headers such as an Aptio Capsule header.

## Installation

```
git clone https://github.com/cwerling/psptool
cd psptool
sudo python3 setup.py install
```

## Usage

The first version of psptool has an extensive command line interface. Nevertheless, apart from major refactoring **psptool2's focus is on its use as a Python module**:

```
> from psptool2 import PSPTool
> psp = PSPTool.from_file('original_bios.bin')
> psp.blob.directories
[Directory(address=0x77000, type=PSP_NEW, count=16),
 Directory(address=0x149000, type=secondary, count=20),
 Directory(address=0x117000, type=BHD, count=14),
 Directory(address=0x249000, type=secondary, count=17)]
> psp.ls_dir(0)
+---+-------+----------+---------+------+-----------------------------+-------+------------+-----------------------+
|   | Entry |  Address |    Size | Type |                   Type Name | Magic |    Version |             Signed by |
+---+-------+----------+---------+------+-----------------------------+-------+------------+-----------------------+
|   |     0 |  0x77400 |   0x240 |  0x0 |              AMD_PUBLIC_KEY |       |            |                       |
|   |     1 | 0x149400 | 0x10000 |  0x1 |          PSP_FW_BOOT_LOADER |  $PS1 |   0.7.0.52 |        AMD_PUBLIC_KEY |
|   |     2 |  0x77700 |  0xcf40 |  0x3 | PSP_FW_RECOVERY_BOOT_LOADER |  $PS1 |  FF.7.0.51 |        AMD_PUBLIC_KEY |
|   |     3 |  0x84700 | 0x1e550 |  0x8 |              SMU_OFFCHIP_FW |  SMUR |  4.19.64.0 |        AMD_PUBLIC_KEY |
|   |     4 |  0xa2d00 |   0x340 |  0xa |       OEM_PSP_FW_PUBLIC_KEY |       |            |                       |
|   |     5 |  0xa3100 |  0x3eb0 | 0x12 |           SMU_OFF_CHIP_FW_2 |  SMUR |  4.19.64.0 |        AMD_PUBLIC_KEY |
|   |     6 |  0xa7000 |    0x10 | 0x21 |                             |       |            |                       |
|   |     7 |  0xa7100 |   0xcc0 | 0x24 |                             |  $PS1 |   12.2.0.9 |        AMD_PUBLIC_KEY |
|   |     8 |  0xa7e00 |   0xc20 | 0x30 |                             |  0BAR | 17.9.18.12 | OEM_PSP_FW_PUBLIC_KEY |
|   |     9 |  0xa8b00 |  0xbc50 | 0x31 |          0x31~ABL_ARM_CODE~ |  AR1B | 17.9.18.12 | OEM_PSP_FW_PUBLIC_KEY |
|   |    10 |  0xb4800 |  0xb5c0 | 0x32 |                             |  AR2B | 17.9.18.12 | OEM_PSP_FW_PUBLIC_KEY |
|   |    11 |  0xbfe00 |  0xdb00 | 0x33 |                             |  AR3B | 17.9.18.12 | OEM_PSP_FW_PUBLIC_KEY |
|   |    12 |  0xcd900 |  0xefd0 | 0x34 |                             |  AR4B | 17.9.18.12 | OEM_PSP_FW_PUBLIC_KEY |
|   |    13 |  0xdc900 |  0xf020 | 0x35 |                             |  AR5B | 17.9.18.12 | OEM_PSP_FW_PUBLIC_KEY |
|   |    14 |  0xeba00 |  0xbd60 | 0x36 |                             |  AR6B | 17.9.18.12 | OEM_PSP_FW_PUBLIC_KEY |
|   |    15 | 0x149000 |   0x400 | 0x40 |    !PL2_SECONDARY_DIRECTORY |       |            |                       |
+---+-------+----------+---------+------+-----------------------------+-------+------------+-----------------------+
> psp.blob.directories[0].entries[0]
PubkeyEntry(type=0x0, address=0x77400, size=0x240, len(references)=1)
> psp.blob.directories[0].entries[0].get_bytes()
b'\x01\x00\x00\x00\x1b\xb9\x87\xc3YIF\x06\xb1t\x94V\x01\xc9\xea[\x1b\xb9\x87\xc3YIF\x06\xb1t\x94V\x01\xc9\xea[\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x08\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
[...]
> my_stuff = [...]
> psp.blob.directories[0].entries[1].move_buffer(0x60000, 0x1000)
> psp.blob.set_bytes(0x60000, 0x1000, my_stuff)
> psp.to_file('my_modified_bios.bin')
```

