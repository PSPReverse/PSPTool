

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

PSPTool offers a range of features from the **command line**.

**Example 1:** *List all firmware entries of a given BIOS ROM.*

```
$ psptool Lenovo_Thinkpad_T495_r12uj35wd.iso

+-----------+----------+---------+-------+---------------------+
| Directory |   Addr   |   Type  | Magic | Secondary Directory |
+-----------+----------+---------+-------+---------------------+
|     0     | 0x28bb20 | PSP_NEW |  $PSP |       0x138000      |
+-----------+----------+---------+-------+---------------------+
+---+-------+----------+---------+---------------------------------+-------+------------+------------------------------------+
|   | Entry |  Address |    Size |                            Type | Magic |    Version |                               Info |
+---+-------+----------+---------+---------------------------------+-------+------------+------------------------------------+
|   |     0 | 0x28bf20 |   0x240 |              AMD_PUBLIC_KEY~0x0 |  60BB |            |                                    |
|   |     1 | 0x382f20 |  0xc300 |          PSP_FW_BOOT_LOADER~0x1 |  $PS1 |   0.8.2.59 |            signed(60BB), encrypted |
|   |     2 | 0x28c220 |  0xb300 | PSP_FW_RECOVERY_BOOT_LOADER~0x3 |  $PS1 |   0.8.2.59 |            signed(60BB), encrypted |
|   |     3 | 0x297520 | 0x22770 |                           0x208 |       |            |                                    |
|   |     4 | 0x2b9d20 |  0x71b0 |                           0x212 |       |            |                                    |
|   |     5 | 0x2c0f20 | 0x20830 |       PSP_SMU_FN_FIRMWARE~0x108 |       |            |                                    |
|   |     6 | 0x2e1820 |  0x5010 |        !SMU_OFF_CHIP_FW_3~0x112 |       |            |                                    |
|   |     7 | 0x2e6920 |    0x10 |               WRAPPED_IKEK~0x21 |       |            |                                    |
|   |     8 | 0x2e6b20 |  0x1000 |               TOKEN_UNLOCK~0x22 |       |            |                                    |
|   |     9 | 0x2e7b20 |  0x1860 |                           0x224 |  $PS1 |   A.2.3.27 |            signed(60BB), encrypted |
|   |    10 | 0x2e9420 |  0x1760 |                           0x124 |  $PS1 |   A.2.3.1A |            signed(60BB), encrypted |
|   |    11 | 0x2eac20 |   0xdd0 |                       ABL0~0x30 |  AW0B | 18.12.10.0 | compressed, signed(60BB), verified |
|   |    12 | 0x2eba20 |  0xcbb0 |                       ABL1~0x31 |  AW1B | 18.12.10.0 | compressed, signed(60BB), verified |
|   |    13 | 0x2f8620 |  0x8dc0 |                       ABL2~0x32 |  AW2B | 18.12.10.0 | compressed, signed(60BB), verified |
|   |    14 | 0x301420 |  0xbb90 |                       ABL3~0x33 |  AW3B | 18.12.10.0 | compressed, signed(60BB), verified |
|   |    15 | 0x30d020 |  0xcca0 |                       ABL4~0x34 |  AW4B | 18.12.10.0 | compressed, signed(60BB), verified |
|   |    16 | 0x319d20 |  0xc910 |                       ABL5~0x35 |  AW5B | 18.12.10.0 | compressed, signed(60BB), verified |
|   |    17 | 0x326720 |  0x9ef0 |                       ABL6~0x36 |  AW6B | 18.12.10.0 | compressed, signed(60BB), verified |
|   |    18 | 0x330620 |  0xc710 |                       ABL7~0x37 |  AW7B | 18.12.10.0 | compressed, signed(60BB), verified |
|   |    19 | 0x382b20 |     0x0 |   !PL2_SECONDARY_DIRECTORY~0x40 |       |            |                                    |
+---+-------+----------+---------+---------------------------------+-------+------------+------------------------------------+
[...]
```



**Example 2:** *Extract all unique firmware entries from a given BIOS ROM, uncompress compressed entries and convert public keys into PEM format.*

```
$ psptool -Xunk ASUS_PRIME-A320M-A-ASUS-4801.CAP
ll ASUS_PRIME-A320M-A-ASUS-4801.CAP_unique_extracted/
[...]
17007195  64 -rw-r--r--   1 cwerling  staff    32K 14 Aug 15:32 PSP_AGESA_RESUME_FW~0x10
17007235   8 -rw-r--r--   1 cwerling  staff   451B 14 Aug 15:32 PSP_BOOT_TIME_TRUSTLETS_KEY~0xd
17007244 224 -rw-r--r--   1 cwerling  staff   112K 14 Aug 15:32 PSP_BOOT_TIME_TRUSTLETS~0xc_0.7.0.1
17007237  64 -rw-r--r--   1 cwerling  staff    32K 14 Aug 15:32 PSP_FW_BOOT_LOADER~0x1
17007197 104 -rw-r--r--   1 cwerling  staff    49K 14 Aug 15:32 PSP_FW_BOOT_LOADER~0x1_0.8.0.5E
17007196 112 -rw-r--r--   1 cwerling  staff    55K 14 Aug 15:32 PSP_FW_BOOT_LOADER~0x1_0.D.0.1A
17007223  48 -rw-r--r--   1 cwerling  staff    24K 14 Aug 15:32 PSP_FW_RECOVERY_BOOT_LOADER~0x3
17007224  96 -rw-r--r--   1 cwerling  staff    45K 14 Aug 15:32 PSP_FW_RECOVERY_BOOT_LOADER~0x3_0.8.0.5E
17007232 288 -rw-r--r--   1 cwerling  staff   144K 14 Aug 15:32 PSP_FW_TRUSTED_OS~0x2
17007180 128 -rw-r--r--   1 cwerling  staff    61K 14 Aug 15:32 PSP_FW_TRUSTED_OS~0x2_0.8.0.5E
17007247 128 -rw-r--r--   1 cwerling  staff    60K 14 Aug 15:32 PSP_FW_TRUSTED_OS~0x2_0.D.0.1A
17007205 256 -rw-r--r--   1 cwerling  staff   128K 14 Aug 15:32 PSP_NV_DATA~0x4
17007182  24 -rw-r--r--   1 cwerling  staff    12K 14 Aug 15:32 PSP_S3_NV_DATA~0x1a
17007226 160 -rw-r--r--   1 cwerling  staff    80K 14 Aug 15:32 PSP_SMU_FN_FIRMWARE~0x108
17007202   8 -rw-r--r--   1 cwerling  staff   451B 14 Aug 15:32 SEC_DBG_PUBLIC_KEY~0x9
17007216  32 -rw-r--r--   1 cwerling  staff    14K 14 Aug 15:32 SEC_GASKET~0x24_11.3.0.8
17007206  16 -rw-r--r--   1 cwerling  staff   5,8K 14 Aug 15:32 SEC_GASKET~0x24_A.2.3.27
17007176 264 -rw-r--r--   1 cwerling  staff   129K 14 Aug 15:32 SMU_OFFCHIP_FW~0x8
17007217 520 -rw-r--r--   1 cwerling  staff   256K 14 Aug 15:32 SMU_OFFCHIP_FW~0x8_0.2E.16.0
[...]
```



**Example 3**: *Extract the firmware entry from a given BIOS ROM at directory index 1 entry index 8 (`PSP_BOOT_TIME_TRUSTLETS`) and show strings of length 8.*

```
$ psptool -X -d 1 -e 8 MSI_X399_E7B92AMS.130 | strings -n 8
AMD_TL_UTIL: Hashing the message: %p
AMD_TL_UTIL: ProcessCmd_Hash(), UTIL_ERR_INVALID_BUFFER, exit
RSA: Calling tlApiRandomGenerateData
RSA: Calling DbgUnlockRsaKeyGen
RSA: Done Calling DbgUnlockRsaKeyGen
DbgUnlockRsaKeyGen failed
AMD_TL_UTIL: Deriving AES key
AMD_TL_UTIL: ProcessCmd_Hmac(), UTIL_ERR_INVALID_BUFFER, exit
AMD_TL_UTIL: Deriving HMAC key
HMAC Signature Key for PSP Data saved in DRAM
AMD_TL_UTIL: Computing HMAC of payload
AMD_TL_UTIL: running
AMD_TL_UTIL: invalid TCI
TCI buffer: %p
TCI buffer length: %p
sizeof(tciMessage_t): %p
AMD_TL_UTIL: waiting for notification
RSA: Calling generateKeyPair and RSA signing
RSA: Calling DbgUnlockKeyVerfiy
AMD_TL_UTIL: Unknown command ID %d, ignore
AMD_TL_UTIL: notify TLC
```



**General usage:**

```
usage: psptool [-E | -X | -R] file

Display, extract, and manipulate AMD PSP firmware inside BIOS ROMs.

positional arguments:
  file                 Binary file to be parsed for PSP firmware

optional arguments:
  -E, --entries        Default: Parse and display PSP firmware entries.
                       [-n]

                       -n:      list unique entries only ordered by their offset

  -X, --extract-entry  Extract one or more PSP firmware entries.
                       [-d idx [-e idx]] [-n] [-u] [-k] [-o outfile]

                       -d idx:  specifies directory_index (default: all directories)
                       -e idx:  specifies entry_index (default: all entries)
                       -n:      skip duplicate entries and extract unique entries only
                       -u:      uncompress compressed entries
                       -k:      convert pubkeys into PEM format
                       -o file: specifies outfile/outdir (default: stdout/{file}_extracted)

  -R, --replace-entry  Copy a new entry (including header and signature) into the
                       ROM file and update metadata accordingly.
                       -d idx -e idx -s subfile -o outfile

                       -d idx:  specifies directory_index
                       -e idx:  specifies entry_index
                       -s file: specifies subfile (i.e. the new entry contents)
                       -o file: specifies outfile
```

## Python Usage

PSPTool can be **used as a Python module**, e.g. in an interactive IPython session:

```
> from psptool import PSPTool
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



# PSPTrace

PSPTrace can be used to **correlate an SPI capture** of a **boot procedure** recorded with a Saleae Logic analyzer to the **PSP firmware** of a UEFI image. SPI captures must be exported from the Saleae Logic software via *Analyzers > SPI > Export as text/csv file*. Please make sure you sampled with an appropriate sample rate and the SPI analyzer is set to `Hex`.

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

Info: Creating database in spi_trace.txt.pickle ...
Info: Parsed and stored a database of 14028942 rows.
+---------+---------------+----------+-----------------------------+------+
|   No.   | Lowest access |  Range   |             Type            | Info |
+---------+---------------+----------+-----------------------------+------+
|    0    |    0x820000   | 0x780007 |         Unknown area        |      |
|    22   |    0x020000   | 0x00001c |     Firmware Entry Table    |      |
|    33   |    0x077000   | 0x00012a |       Directory: $PSP       |      |
|    70   |    0x077000   | 0x000100 |       Directory: $PSP       | CCP  |
|   107   |    0x077400   | 0x000240 |        AMD_PUBLIC_KEY       | CCP  |
|   177   |    0x149400   | 0x00d780 |      PSP_FW_BOOT_LOADER     | CCP  |
|         |               |          |                             |      |
|         |               |          |      ~ 3410 µs delay ~      |      |
|         |               |          |                             |      |
|   7084  |    0x149000   | 0x000180 |       Directory: $PL2       | CCP  |
|   7090  |    0x000000   | 0x020046 |         Unknown area        |      |
|   7091  |    0x020000   | 0x000024 |     Firmware Entry Table    |      |
|         |               |          |                             |      |
|         |               |          |       ~ 66 µs delay ~       |      |
|         |               |          |                             |      |
|   7095  |    0x117000   | 0x000160 |       Directory: $BHD       |      |
|   7096  |    0x149000   | 0x000152 |       Directory: $PL2       |      |
|   7554  |    0x000000   | 0x117280 |         Unknown area        |      |
|   7581  |    0x020000   | 0x000022 |     Firmware Entry Table    |      |
|   7859  |    0x249000   | 0x0001c0 |       Directory: $BL2       | CCP  |
|   7880  |    0x1170c0   | 0x000080 |       Directory: $BHD       | CCP  |
|   7909  |    0x2491c0   | 0x000240 |         Unknown area        | CCP  |
|   8017  |    0x249010   | 0x00019a |       Directory: $BL2       |      |
|   8560  |    0x17c100   | 0x001932 |         DEBUG_UNLOCK        |      |
|   8939  |    0x17c200   | 0x001800 |         DEBUG_UNLOCK        | CCP  |
|  10144  |    0x177a00   | 0x0001c0 |      SEC_DBG_PUBLIC_KEY     |      |
|  10576  |    0x177bc0   | 0x000180 |      SEC_DBG_PUBLIC_KEY     | CCP  |
|         |               |          |                             |      |
|         |               |          |       ~ 178 µs delay ~      |      |
|         |               |          |                             |      |
|  10582  |    0x17e000   | 0x000080 |         TOKEN_UNLOCK        | CCP  |

[...]
```

