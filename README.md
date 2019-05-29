

# PSPTool

PSPTool is a Swiss Army knife for dealing with firmware of the **AMD Secure Processor** (formerly known as *Platform Security Processor* or **PSP**). It locates AMD firmware inside  **UEFI images** as part of BIOS updates targeting **AMD platforms**. 

It is based on reverse-engineering efforts of AMD's **proprietary filesystem** used to **pack firmware blobs** into **UEFI Firmware Images**. These are usually 16MB in size and can be conveniently parsed by [UEFITool](https://github.com/LongSoft/UEFITool). However, all binary blobs by AMD are located in padding volumes unparsable by UEFITool.

PSPTool favourably works with UEFI images as obtained through BIOS updates.

## Installation

```
git clone https://github.com/cwerling/psptool
cd psptool
sudo python3 setup.py install
```

## CLI Usage

PSPTool offers a range of features from the **command line**:

```
usage: psptool [-h] [-E | -X | -R | -U] file

Display, extract and manipulate PSP firmware inside UEFI images

positional arguments:
  file                  Binary file to be parsed for PSP firmware

optional arguments:
  -h, --help            Show this help message and exit.

  -E, --entries         Default: Parse and display PSP firmware entries.
                        [-d idx] [-n] [-i] [-v]

                        -d idx:     specifies directory_index (default: all directories)
                        -n:         hide duplicate entries from listings
                        -i:         display additional entry header info
                        -v:         display even more info (AGESA Version, Entropy, MD5)
                        -t csvfile: only display entries found in the given SPI trace
                                    (see psptrace for details)
  -X, --extract-entry   Extract one or more PSP firmware entries.
                        [-d idx [-e idx]] [-n] [-u] [-k] [-v] [-o outfile]

                        -d idx:  specifies directory_index (default: all directories)
                        -e idx:  specifies entry_index (default: all entries)
                        -n:      skip duplicate entries
                        -u:      uncompress compressed entries
                        -k:      convert _pubkeys into PEM format
                        -v:      increase output verbosity
                        -o file: specifies outfile/outdir (default: stdout/$PWD)
  -R, --replace-directory-entry
                        Copy a new entry body into the ROM file and update metadata accordingly.
                        Note: The given address is assumed to be overwritable (e.g. padding).
                        -d idx -e idx -b addr [-y] [-s subfile] [-o outfile]

                        -d idx:  specifies directory_index
                        -e idx:  specifies entry_index
                        -b addr: specifies destination address of the new entry
                        -s file: specifies subfile (i.e. the new entry) (default: stdin)
                        -o file: specifies outfile (default: stdout)
  -U, --update-signatures
                        Re-sign all signatures in the ROM file with a given private key and export
                        a new ROM file.
                        -p private_key [-o outfile]

                        -p file:   specifies a path to the private_key in PEM format for re-signing
                        -o file:   specifies outfile (default: stdout)
```

## Python Usage

A rewrite of PSPTool enables its **use as a Python module**, e.g. in an interactive IPython session:

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

## Code

The `psptool2` Python package is a rewrite of the original PSPTool and does not yet support the same functionality as PSPTool does. The original PSPTool codebase found in `bin/psptool` is only meant for providing support for the command line interface. It is not subject to further development.



# PSPTrace

PSPTrace can be used to **correlate an SPI capture** of a **boot procedure** recorded with a Saleae Logic analyzer to the **PSP firmware** of a UEFI image. SPI captures must be exported from the Saleae Logic software via *Analyzers > SPI > Export as text/csv file*.

It is installed along with PSPTool (see installation instructions above) and only provides a command line interface.

```
usage: psptrace [-h] [-o] [-n] [-c] [-t] [-l LIMIT_ROWS] [-v] csvfile romfile

Read in an SPI capture created by a Saleae Logic Analyzer and a ROM file
resembling the flash contents and display an access chronology. On first load,
psptrace needs to parse a lot of raw data which will be saved on disk. All
other loads will then be much faster.

positional arguments:
  csvfile               CSV file of SPI capture
  romfile               ROM file of SPI contents

optional arguments:
  -h, --help            show this help message and exit
  -o, --overview-mode   aggregate accesses to the same firmware entry
  -n, --no-duplicates   hide duplicate accesses (e.g. caused by multiple PSPs)
  -c, --collapse        collapse consecutive reads to the same PSP entry type
                        (denoted by [c] and sometimes by ~ if collapsing was
                        fuzzy)
  -t, --normalize-timestamps
                        normalize all timestamps
  -l LIMIT_ROWS, --limit-rows LIMIT_ROWS
                        limit the processed rows to a maximum of n
  -v, --verbose         increase output verbosity
```

## Example usage

After recording the boot procedure of a Supermicro server system with an AMD Epyc CPU, PSPTrace outputs the following boot in overview mode (`-o`):

```
$ psptrace -o spi_trace.txt flash.bin

Info: Found existing database in 50 MHz, 6 B Samples [2].txt.pickle.
Info: Loading database ...
Info: Loaded a capture of 14028942 rows.
+---------+---------------+----------+-----------------------------+------+
|   No.   | Lowest access |  Range   |             Type            | Info |
+---------+---------------+----------+-----------------------------+------+
|    0    |    0xe20000   | 0x180007 |     0x30062~UEFI-IMAGE~     |      |
|    10   |    0x020000   | 0xc00007 |         Unknown area        |      |
|    33   |    0x077000   | 0x00012a |         Header: $PSP        |      |
|    70   |    0x077000   | 0x000100 |         Header: $PSP        | CCP  |
|   107   |    0x077400   | 0x000240 |        AMD_PUBLIC_KEY       | CCP  |
|   177   |    0x149400   | 0x00d780 |      PSP_FW_BOOT_LOADER     | CCP  |
|         |               |          |                             |      |
|         |               |          |      ~ 3410 µs delay ~      |      |
|         |               |          |                             |      |
|   7084  |    0x149000   | 0x000180 |   !PL2_SECONDARY_DIRECTORY  | CCP  |
|   7090  |    0x000000   | 0x020046 |         Unknown area        |      |
|         |               |          |                             |      |
|         |               |          |       ~ 66 µs delay ~       |      |
|         |               |          |                             |      |
|   7095  |    0x117000   | 0x000160 |         Header: $BHD        |      |
|   7096  |    0x149000   | 0x000152 |   !PL2_SECONDARY_DIRECTORY  |      |
|   7554  |    0x000000   | 0x117280 |         Unknown area        |      |
|   7859  |    0x249000   | 0x000400 |   !BL2_SECONDARY_DIRECTORY  | CCP  |
|   7880  |    0x1170c0   | 0x000080 |         Header: $BHD        | CCP  |
|   8017  |    0x249010   | 0x00019a |   !BL2_SECONDARY_DIRECTORY  |      |
|   8560  |    0x17c100   | 0x001932 |             0x13            |      |
|   8939  |    0x17c200   | 0x001800 |             0x13            | CCP  |
|  10144  |    0x177a00   | 0x0001c0 |    AMD_SEC_DBG_PUBLIC_KEY   |      |
|  10576  |    0x177bc0   | 0x000180 |    AMD_SEC_DBG_PUBLIC_KEY   | CCP  |
|         |               |          |                             |      |
|         |               |          |       ~ 178 µs delay ~      |      |
|         |               |          |                             |      |
|  10582  |    0x17e000   | 0x000080 |             0x22            | CCP  |

[...]
```

