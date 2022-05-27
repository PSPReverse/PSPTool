# PSPTool

PSPTool is a Swiss Army knife for dealing with firmware of the **AMD Secure Processor (ASP)**, formerly known as *Platform Security Processor* or **PSP**. It can parse, extract, and replace AMD firmware inside  **UEFI images** as part of BIOS updates targeting **AMD platforms**.

It is based on reverse-engineering efforts of AMD's **proprietary filesystem** used to **pack firmware blobs** into **UEFI Firmware Images**. These are usually 16MB (or 8MB, or 32MB) in size and can be conveniently parsed by [UEFITool](https://github.com/LongSoft/UEFITool). However, all binary blobs by AMD are located in padding volumes unparsable by UEFITool.

PSPTool favourably works with UEFI images as obtained through BIOS updates. If these updates are only available through Windows executables, tools like [innoextract](https://github.com/dscharrer/innoextract) can help.

PSPTool was developed at TU Berlin in context of the following research:
- 2021, paper: [One Glitch to Rule Them All: Fault Injection Attacks Against AMD's Secure Encrypted Virtualization](https://arxiv.org/abs/2108.04575)
- 2020, talk: [All You Ever Wanted to Know about the AMD Platform Security Processor and were Afraid to Emulate](https://youtu.be/KR8bPLj4nKE)
- 2019, talk: [Uncover, Understand, Own - Regaining Control Over Your AMD CPU](https://media.ccc.de/v/36c3-10942-uncover_understand_own_-_regaining_control_over_your_amd_cpu)
- 2019, paper: [Insecure Until Proven Updated: Analyzing AMD SEV's Remote Attestation](https://arxiv.org/abs/1908.11680)
- 2019, talk: [Dissecting the AMD Platform Security Processor](https://media.ccc.de/v/thms-38-dissecting-the-amd-platform-security-processor)

## Installation

You can either install PSPTool's latest release from **PyPI**,

```
pip3 install psptool
```

or install it freshly off **GitHub**:

```
git clone https://github.com/PSPReverse/PSPTool
cd PSPTool
pip3 install .
```

If you intend to make changes to the code and would like your installation to point to the latest changes, install it _editable_:

```
pip3 install -e .
```

_Please note that the integration tests require ROM files from a private submodule (`tests/integration/fixtures`). If you would like to get access to these, contact us._


## CLI Usage

PSPTool offers a range of features from the **command line**.

**Example 1:** *List all firmware entries of a given BIOS ROM.*

```
$ psptool Lenovo_Thinkpad_T495_r12uj35wd.iso
```

<details>
  <summary>Click to expand output</summary>
  
  ```
+-----+----------+-----------+----------+--------------------------------+
| ROM |   Addr   |    Size   |   FET    |             AGESA              |
+-----+----------+-----------+----------+--------------------------------+
|  0  | 0x24ab20 | 0x1000000 | 0x26ab20 | AGESA!V9 PicassoPI-FP5 1.0.0.3 |
+-----+----------+-----------+----------+--------------------------------+
+--+-----------+----------+------+-------+---------------------+
|  | Directory |   Addr   | Type | Magic | Secondary Directory |
+--+-----------+----------+------+-------+---------------------+
|  |     0     | 0x28bb20 | PSP  |  $PSP |       0x138000      |
+--+-----------+----------+------+-------+---------------------+
+--+---+-------+----------+---------+---------------------------------+----------+------------+----------------------------+
|  |   | Entry |  Address |    Size |                            Type | Magic/ID |    Version |                       Info |
+--+---+-------+----------+---------+---------------------------------+----------+------------+----------------------------+
|  |   |     0 | 0x28bf20 |   0x240 |              AMD_PUBLIC_KEY~0x0 |     60BB |          1 |                            |
|  |   |     1 | 0x382f20 |  0xc300 |          PSP_FW_BOOT_LOADER~0x1 |     $PS1 |   0.8.2.59 |  verified(60BB), encrypted |
|  |   |     2 | 0x28c220 |  0xb300 | PSP_FW_RECOVERY_BOOT_LOADER~0x3 |     $PS1 |   0.8.2.59 |  verified(60BB), encrypted |
|  |   |     3 | 0x297520 | 0x22770 |                           0x208 |          |    0.0.0.0 | compressed, verified(60BB) |
|  |   |     4 | 0x2b9d20 |  0x71b0 |                           0x212 |          |    0.0.0.0 | compressed, verified(60BB) |
|  |   |     5 | 0x2c0f20 | 0x20830 |       PSP_SMU_FN_FIRMWARE~0x108 |          |    0.0.0.0 | compressed, verified(60BB) |
|  |   |     6 | 0x2e1820 |  0x5010 |        !SMU_OFF_CHIP_FW_3~0x112 |          |    0.0.0.0 | compressed, verified(60BB) |
|  |   |     7 | 0x2e6920 |    0x10 |               WRAPPED_IKEK~0x21 |          |            |                            |
|  |   |     8 | 0x2e6b20 |  0x1000 |               TOKEN_UNLOCK~0x22 |          |            |                            |
|  |   |     9 | 0x2e7b20 |  0x1860 |                           0x224 |     $PS1 |   A.2.3.27 |  verified(60BB), encrypted |
|  |   |    10 | 0x2e9420 |  0x1760 |                           0x124 |     $PS1 |   A.2.3.1A |  verified(60BB), encrypted |
|  |   |    11 | 0x2eac20 |   0xdd0 |                       ABL0~0x30 |     AW0B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    12 | 0x2eba20 |  0xcbb0 |                       ABL1~0x31 |     AW1B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    13 | 0x2f8620 |  0x8dc0 |                       ABL2~0x32 |     AW2B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    14 | 0x301420 |  0xbb90 |                       ABL3~0x33 |     AW3B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    15 | 0x30d020 |  0xcca0 |                       ABL4~0x34 |     AW4B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    16 | 0x319d20 |  0xc910 |                       ABL5~0x35 |     AW5B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    17 | 0x326720 |  0x9ef0 |                       ABL6~0x36 |     AW6B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    18 | 0x330620 |  0xc710 |                       ABL7~0x37 |     AW7B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    19 | 0x382b20 |   0x400 |   !PL2_SECONDARY_DIRECTORY~0x40 |          |            |                            |
+--+---+-------+----------+---------+---------------------------------+----------+------------+----------------------------+


+--+-----------+----------+-----------+-------+---------------------+
|  | Directory |   Addr   |    Type   | Magic | Secondary Directory |
+--+-----------+----------+-----------+-------+---------------------+
|  |     1     | 0x382b20 | secondary |  $PL2 |          --         |
+--+-----------+----------+-----------+-------+---------------------+
+--+---+-------+----------+----------+-----------------------------+----------+------------+----------------------------+
|  |   | Entry |  Address |     Size |                        Type | Magic/ID |    Version |                       Info |
+--+---+-------+----------+----------+-----------------------------+----------+------------+----------------------------+
|  |   |     0 | 0x382f20 |   0xc300 |      PSP_FW_BOOT_LOADER~0x1 |     $PS1 |   0.8.2.59 |  verified(60BB), encrypted |
|  |   |     1 | 0x38f220 |    0x240 |          AMD_PUBLIC_KEY~0x0 |     60BB |          1 |                            |
|  |   |     2 | 0x38f520 |   0xf300 |       PSP_FW_TRUSTED_OS~0x2 |     $PS1 |   0.8.2.59 |  verified(60BB), encrypted |
|  |   |     3 | 0x26bb20 |  0x20000 |             PSP_NV_DATA~0x4 |          |            |                            |
|  |   |     4 | 0x39e820 |  0x22770 |                       0x208 |          |    0.0.0.0 | compressed, verified(60BB) |
|  |   |     5 | 0x3c1020 |    0x340 |      SEC_DBG_PUBLIC_KEY~0x9 |     ED22 |          1 |             verified(60BB) |
|  |   |     6 | 0x24ab21 |      0x0 |      SOFT_FUSE_CHAIN_01~0xb |          |            |                            |
|  |   |     7 | 0x3c1420 |  0x11a50 | PSP_BOOT_TIME_TRUSTLETS~0xc |     $PS1 |    0.7.0.1 | compressed, verified(60BB) |
|  |   |     8 | 0x3d2f20 |   0x71b0 |                       0x212 |          |    0.0.0.0 | compressed, verified(60BB) |
|  |   |     9 | 0x3da120 |   0x1930 |           DEBUG_UNLOCK~0x13 |     $PS1 |   0.8.2.59 | compressed, verified(60BB) |
|  |   |    10 | 0x3dbb20 |     0x10 |           WRAPPED_IKEK~0x21 |          |            |                            |
|  |   |    11 | 0x3dcb20 |   0x1000 |           TOKEN_UNLOCK~0x22 |          |            |                            |
|  |   |    12 | 0x3ddb20 |   0x1860 |                       0x224 |     $PS1 |   A.2.3.27 |  verified(60BB), encrypted |
|  |   |    13 | 0x3df420 |   0x1760 |                       0x124 |     $PS1 |   A.2.3.1A |  verified(60BB), encrypted |
|  |   |    14 | 0x3e0c20 |   0x23e4 |                       0x225 |          |    4.2.1.1 |          inline_keys(76E9) |
|  |   |    15 | 0x3e3020 |   0x3b00 |                       0x125 |          |    3.2.2.1 |          inline_keys(76E9) |
|  |   |    16 | 0x3e6b20 |  0x18790 |         DRIVER_ENTRIES~0x28 |     $PS1 |   0.8.2.59 |  verified(60BB), encrypted |
|  |   |    17 | 0x3ff320 | 0x16e988 |                        0x29 |          |   1.20.8.1 |                     no_key |
|  |   |    18 | 0x56dd20 |   0x3100 |            S0I3_DRIVER~0x2d |     $PS1 |    0.7.0.1 |             verified(60BB) |
|  |   |    19 | 0x570e20 |    0xdd0 |                   ABL0~0x30 |     AW0B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    20 | 0x571c20 |   0xcbb0 |                   ABL1~0x31 |     AW1B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    21 | 0x57e820 |   0x8dc0 |                   ABL2~0x32 |     AW2B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    22 | 0x587620 |   0xbb90 |                   ABL3~0x33 |     AW3B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    23 | 0x593220 |   0xcca0 |                   ABL4~0x34 |     AW4B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    24 | 0x59ff20 |   0xc910 |                   ABL5~0x35 |     AW5B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    25 | 0x5ac920 |   0x9ef0 |                   ABL6~0x36 |     AW6B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    26 | 0x5b6820 |   0xc710 |                   ABL7~0x37 |     AW7B | 18.12.10.0 | compressed, verified(60BB) |
|  |   |    27 | 0x5c3020 |  0x20830 |   PSP_SMU_FN_FIRMWARE~0x108 |          |    0.0.0.0 | compressed, verified(60BB) |
|  |   |    28 | 0x5e3920 |   0x5010 |    !SMU_OFF_CHIP_FW_3~0x112 |          |    0.0.0.0 | compressed, verified(60BB) |
+--+---+-------+----------+----------+-----------------------------+----------+------------+----------------------------+


+--+-----------+----------+------+-------+---------------------+
|  | Directory |   Addr   | Type | Magic | Secondary Directory |
+--+-----------+----------+------+-------+---------------------+
|  |     2     | 0x34eb20 | BIOS |  $BHD |       0x3ef000      |
+--+-----------+----------+------+-------+---------------------+
+--+---+-------+-----------+---------+-------------------------------+----------+-----------+----------------------------+
|  |   | Entry |   Address |    Size |                          Type | Magic/ID |   Version |                       Info |
+--+---+-------+-----------+---------+-------------------------------+----------+-----------+----------------------------+
|  |   |     0 |  0x34ef20 |   0x340 |           BIOS_PUBLIC_KEY~0x5 |     3FC7 |         1 |             verified(60BB) |
|  |   |     1 |  0x34fb20 |  0x2000 |                   FW_IMC~0x60 |          |           |                            |
|  |   |     2 |  0x351b20 |  0x2000 |                      0x100060 |          |           |                            |
|  |   |     3 |  0x353b20 |  0x2000 |                      0x200060 |          |           |                            |
|  |   |     4 |  0x355b20 |  0x2000 |                      0x300060 |          |           |                            |
|  |   |     5 |  0x357b20 |  0x2000 |                      0x400060 |          |           |                            |
|  |   |     6 |  0x359b20 |  0x2000 |                      0x500060 |          |           |                            |
|  |   |     7 |  0x35bb20 |  0x2000 |                      0x600060 |          |           |                            |
|  |   |     8 |  0x35db20 |  0x2000 |                      0x700060 |          |           |                            |
|  |   |     9 |  0x35fb20 |  0x2000 |                          0x68 |          |           |                            |
|  |   |    10 |  0x361b20 |  0x2000 |                      0x100068 |          |           |                            |
|  |   |    11 |  0x363b20 |  0x2000 |                      0x200068 |          |           |                            |
|  |   |    12 |  0x365b20 |  0x2000 |                      0x300068 |          |           |                            |
|  |   |    13 |  0x367b20 |  0x2000 |                      0x400068 |          |           |                            |
|  |   |    14 |  0x369b20 |  0x2000 |                      0x500068 |          |           |                            |
|  |   |    15 |  0x36bb20 |  0x2000 |                      0x600068 |          |           |                            |
|  |   |    16 |  0x36db20 |  0x2000 |                      0x700068 |          |           |                            |
|  |   |    17 |  0x24ab20 |     0x0 |                   FW_GEC~0x61 |          |           |                            |
|  |   |    18 | 0x117ab20 | 0xd0000 |                          BIOS |          |           |                            |
|  |   |    19 |  0x36fb20 |  0x3c40 |                      0x100064 |     0x05 | 0.0.A1.41 | compressed, verified(60BB) |
|  |   |    20 |  0x373820 |   0x330 |                      0x100065 |     0x05 | 0.0.A1.41 | compressed, verified(60BB) |
|  |   |    21 |  0x373c20 |  0x4610 |                      0x400064 |     0x05 | 0.0.A1.41 | compressed, verified(60BB) |
|  |   |    22 |  0x378320 |   0x320 |                      0x400065 |     0x05 | 0.0.A1.41 | compressed, verified(60BB) |
|  |   |    23 |  0x378720 |  0x4830 |                     0x1100064 |     0x05 |  0.0.18.5 | compressed, verified(60BB) |
|  |   |    24 |  0x37d020 |   0x370 |                     0x1100065 |     0x05 |  0.0.18.5 | compressed, verified(60BB) |
|  |   |    25 |  0x37d420 |  0x47a0 |                     0x1400064 |     0x05 |  0.0.18.5 | compressed, verified(60BB) |
|  |   |    26 |  0x381c20 |   0x340 |                     0x1400065 |     0x05 |  0.0.18.5 | compressed, verified(60BB) |
|  |   |    27 |  0x639b20 |   0x400 | !BL2_SECONDARY_DIRECTORY~0x70 |          |           |                            |
+--+---+-------+-----------+---------+-------------------------------+----------+-----------+----------------------------+


+--+-----------+----------+-----------+-------+---------------------+
|  | Directory |   Addr   |    Type   | Magic | Secondary Directory |
+--+-----------+----------+-----------+-------+---------------------+
|  |     3     | 0x639b20 | secondary |  $BL2 |          --         |
+--+-----------+----------+-----------+-------+---------------------+
+--+---+-------+-----------+---------+---------------------+----------+-----------+----------------------------+
|  |   | Entry |   Address |    Size |                Type | Magic/ID |   Version |                       Info |
+--+---+-------+-----------+---------+---------------------+----------+-----------+----------------------------+
|  |   |     0 |  0x639f20 |   0x340 | BIOS_PUBLIC_KEY~0x5 |     3FC7 |         1 |             verified(60BB) |
|  |   |     1 |  0x63ab20 |  0x2000 |         FW_IMC~0x60 |          |           |                            |
|  |   |     2 |  0x63cb20 |  0x2000 |            0x100060 |          |           |                            |
|  |   |     3 |  0x63eb20 |  0x2000 |            0x200060 |          |           |                            |
|  |   |     4 |  0x640b20 |  0x2000 |            0x300060 |          |           |                            |
|  |   |     5 |  0x642b20 |  0x2000 |            0x400060 |          |           |                            |
|  |   |     6 |  0x644b20 |  0x2000 |            0x500060 |          |           |                            |
|  |   |     7 |  0x646b20 |  0x2000 |            0x600060 |          |           |                            |
|  |   |     8 |  0x648b20 |  0x2000 |            0x700060 |          |           |                            |
|  |   |     9 |  0x64ab20 |  0x2000 |                0x68 |          |           |                            |
|  |   |    10 |  0x64cb20 |  0x2000 |            0x100068 |          |           |                            |
|  |   |    11 |  0x64eb20 |  0x2000 |            0x200068 |          |           |                            |
|  |   |    12 |  0x650b20 |  0x2000 |            0x300068 |          |           |                            |
|  |   |    13 |  0x652b20 |  0x2000 |            0x400068 |          |           |                            |
|  |   |    14 |  0x654b20 |  0x2000 |            0x500068 |          |           |                            |
|  |   |    15 |  0x656b20 |  0x2000 |            0x600068 |          |           |                            |
|  |   |    16 |  0x658b20 |  0x2000 |            0x700068 |          |           |                            |
|  |   |    17 |  0x24ab20 |     0x0 |         FW_GEC~0x61 |          |           |                            |
|  |   |    18 | 0x117ab20 | 0xd0000 |                BIOS |          |           |                            |
|  |   |    19 |  0x65ab20 | 0x10000 |     FW_INVALID~0x63 |          |           |                            |
|  |   |    20 |  0x66ab20 |  0x3c40 |            0x100064 |     0x05 | 0.0.A1.41 | compressed, verified(60BB) |
|  |   |    21 |  0x66e820 |   0x330 |            0x100065 |     0x05 | 0.0.A1.41 | compressed, verified(60BB) |
|  |   |    22 |  0x66ec20 |  0x4610 |            0x400064 |     0x05 | 0.0.A1.41 | compressed, verified(60BB) |
|  |   |    23 |  0x673320 |   0x320 |            0x400065 |     0x05 | 0.0.A1.41 | compressed, verified(60BB) |
|  |   |    24 |  0x673720 |  0x4830 |           0x1100064 |     0x05 |  0.0.18.5 | compressed, verified(60BB) |
|  |   |    25 |  0x678020 |   0x370 |           0x1100065 |     0x05 |  0.0.18.5 | compressed, verified(60BB) |
|  |   |    26 |  0x678420 |  0x47a0 |           0x1400064 |     0x05 |  0.0.18.5 | compressed, verified(60BB) |
|  |   |    27 |  0x67cc20 |   0x340 |           0x1400065 |     0x05 |  0.0.18.5 | compressed, verified(60BB) |
|  |   |    28 |  0x67d020 |   0xc80 |                0x66 |          |           |                            |
|  |   |    29 |  0x67dd20 |   0xc80 |            0x100066 |          |           |                            |
|  |   |    30 |  0x67ea20 |   0xc80 |            0x200066 |          |           |                            |
|  |   |    31 |  0x67f720 |   0x560 |                0x6a |          |   0.0.0.0 |          inline_keys(76E9) |
+--+---+-------+-----------+---------+---------------------+----------+-----------+----------------------------+
  ```
</details>


**Example 2:** *Extract all unique firmware entries from a given BIOS ROM, uncompress compressed entries and convert public keys into PEM format.*

```
$ psptool -Xunk ASUS_PRIME-A320M-A-ASUS-4801.CAP
```

<details>
  <summary>Click to expand output</summary>

```
-rw-r--r--  1 cwerling  wheel   1.0K Nov 16 10:03 !BL2_SECONDARY_DIRECTORY~0x70
-rw-r--r--  1 cwerling  wheel   4.0K Nov 16 10:03 !FW_PSP_SMUSCS_2~0x15f
-rw-r--r--  1 cwerling  wheel   1.0K Nov 16 10:03 !PL2_SECONDARY_DIRECTORY~0x40
-rw-r--r--  1 cwerling  wheel   256B Nov 16 10:03 !PSP_MCLF_TRUSTLETS~0x14_0.0.0.0
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 !SMU_OFF_CHIP_FW_3~0x112_0.0.0.0
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 !SMU_OFF_CHIP_FW_3~0x112_0.2B.15.0
-rw-r--r--  1 cwerling  wheel    24K Nov 16 10:03 0x100064_0.0.A1.41
-rw-r--r--  1 cwerling  wheel    12K Nov 16 10:03 0x100065_0.0.A1.41
-rw-r--r--  1 cwerling  wheel   3.1K Nov 16 10:03 0x100066
-rw-r--r--  1 cwerling  wheel    32K Nov 16 10:03 0x1100064_0.0.10.1
-rw-r--r--  1 cwerling  wheel    32K Nov 16 10:03 0x1100064_0.0.18.5
-rw-r--r--  1 cwerling  wheel    16K Nov 16 10:03 0x1100065_0.0.10.1
-rw-r--r--  1 cwerling  wheel    16K Nov 16 10:03 0x1100065_0.0.18.5
-rw-r--r--  1 cwerling  wheel   5.6K Nov 16 10:03 0x124_A.2.3.1A
-rw-r--r--  1 cwerling  wheel    15K Nov 16 10:03 0x125_3.2.2.1
-rw-r--r--  1 cwerling  wheel    32K Nov 16 10:03 0x1400064_0.0.10.1
-rw-r--r--  1 cwerling  wheel    32K Nov 16 10:03 0x1400064_0.0.18.5
-rw-r--r--  1 cwerling  wheel    16K Nov 16 10:03 0x1400065_0.0.10.1
-rw-r--r--  1 cwerling  wheel    16K Nov 16 10:03 0x1400065_0.0.18.5
-rw-r--r--  1 cwerling  wheel   8.0K Nov 16 10:03 0x200060
-rw-r--r--  1 cwerling  wheel   3.1K Nov 16 10:03 0x200066
-rw-r--r--  1 cwerling  wheel   8.0K Nov 16 10:03 0x200068
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 0x208_0.0.0.0
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 0x212_0.0.0.0
-rw-r--r--  1 cwerling  wheel   5.8K Nov 16 10:03 0x224_A.2.3.27
-rw-r--r--  1 cwerling  wheel   8.7K Nov 16 10:03 0x225_4.2.1.1
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 0x2a_0.2E.16.0
-rw-r--r--  1 cwerling  wheel   3.1K Nov 16 10:03 0x300066
-rw-r--r--  1 cwerling  wheel    24K Nov 16 10:03 0x400064_0.0.A1.41
-rw-r--r--  1 cwerling  wheel    12K Nov 16 10:03 0x400065_0.0.A1.41
-rw-r--r--  1 cwerling  wheel   3.1K Nov 16 10:03 0x400066
-rw-r--r--  1 cwerling  wheel   3.1K Nov 16 10:03 0x500066
-rw-r--r--  1 cwerling  wheel   3.1K Nov 16 10:03 0x66
-rw-r--r--  1 cwerling  wheel   4.0K Nov 16 10:03 0x67
-rw-r--r--  1 cwerling  wheel   8.0K Nov 16 10:03 0x68
-rw-r--r--  1 cwerling  wheel   1.1K Nov 16 10:03 0x6a_0.0.0.0
-rw-r--r--  1 cwerling  wheel   520B Nov 16 10:03 0x800068
-rw-r--r--  1 cwerling  wheel   416B Nov 16 10:03 ABL0~0x30_0.0.0.0
-rw-r--r--  1 cwerling  wheel   4.5K Nov 16 10:03 ABL0~0x30_18.12.12.30
-rw-r--r--  1 cwerling  wheel   4.5K Nov 16 10:03 ABL0~0x30_19.1.14.0
-rw-r--r--  1 cwerling  wheel    84K Nov 16 10:03 ABL1~0x31_18.12.12.30
-rw-r--r--  1 cwerling  wheel    90K Nov 16 10:03 ABL1~0x31_19.1.14.0
-rw-r--r--  1 cwerling  wheel    95K Nov 16 10:03 ABL2~0x32_18.12.12.30
-rw-r--r--  1 cwerling  wheel   101K Nov 16 10:03 ABL2~0x32_19.1.14.0
-rw-r--r--  1 cwerling  wheel    75K Nov 16 10:03 ABL3~0x33_18.12.12.30
-rw-r--r--  1 cwerling  wheel    81K Nov 16 10:03 ABL3~0x33_19.1.14.0
-rw-r--r--  1 cwerling  wheel    79K Nov 16 10:03 ABL4~0x34_18.12.12.30
-rw-r--r--  1 cwerling  wheel    99K Nov 16 10:03 ABL4~0x34_19.1.14.0
-rw-r--r--  1 cwerling  wheel   101K Nov 16 10:03 ABL5~0x35_18.12.12.30
-rw-r--r--  1 cwerling  wheel    88K Nov 16 10:03 ABL5~0x35_19.1.14.0
-rw-r--r--  1 cwerling  wheel    76K Nov 16 10:03 ABL6~0x36_18.12.12.30
-rw-r--r--  1 cwerling  wheel    69K Nov 16 10:03 ABL6~0x36_19.1.14.0
-rw-r--r--  1 cwerling  wheel    98K Nov 16 10:03 ABL7~0x37_19.1.14.0
-rw-r--r--  1 cwerling  wheel   451B Nov 16 10:03 AMD_PUBLIC_KEY~0x0
-rw-r--r--  1 cwerling  wheel   1.9M Nov 16 10:03 BIOS
-rw-r--r--  1 cwerling  wheel   4.0K Nov 16 10:03 BIOS_RTM_FIRMWARE~0x6
-rw-r--r--  1 cwerling  wheel   7.9K Nov 16 10:03 DEBUG_UNLOCK~0x13_0.8.0.5E
-rw-r--r--  1 cwerling  wheel   8.0K Nov 16 10:03 DEBUG_UNLOCK~0x13_0.9.0.6B
-rw-r--r--  1 cwerling  wheel   8.8K Nov 16 10:03 DEBUG_UNLOCK~0x13_0.D.0.1A
-rw-r--r--  1 cwerling  wheel    98K Nov 16 10:03 DRIVER_ENTRIES~0x28_0.8.0.5E
-rw-r--r--  1 cwerling  wheel    82K Nov 16 10:03 DRIVER_ENTRIES~0x28_0.D.0.1A
-rw-r--r--  1 cwerling  wheel     0B Nov 16 10:03 FW_GEC~0x61
-rw-r--r--  1 cwerling  wheel   8.0K Nov 16 10:03 FW_IMC~0x60
-rw-r--r--  1 cwerling  wheel   160K Nov 16 10:03 FW_INVALID~0x63
-rw-r--r--  1 cwerling  wheel   4.0K Nov 16 10:03 FW_PSP_SMUSCS~0x5f
-rw-r--r--  1 cwerling  wheel   8.5K Nov 16 10:03 MP2_FW~0x25_3.18.0.1
-rw-r--r--  1 cwerling  wheel   800B Nov 16 10:03 OEM_PSP_FW_PUBLIC_KEY~0xa
-rw-r--r--  1 cwerling  wheel   256B Nov 16 10:03 PSP_AGESA_RESUME_FW~0x10_0.5.0.3E
-rw-r--r--  1 cwerling  wheel   451B Nov 16 10:03 PSP_BOOT_TIME_TRUSTLETS_KEY~0xd
-rw-r--r--  1 cwerling  wheel   256B Nov 16 10:03 PSP_BOOT_TIME_TRUSTLETS~0xc_0.0.0.0
-rw-r--r--  1 cwerling  wheel   112K Nov 16 10:03 PSP_BOOT_TIME_TRUSTLETS~0xc_0.7.0.1
-rw-r--r--  1 cwerling  wheel   256B Nov 16 10:03 PSP_FW_BOOT_LOADER~0x1_0.5.0.45
-rw-r--r--  1 cwerling  wheel    49K Nov 16 10:03 PSP_FW_BOOT_LOADER~0x1_0.8.0.5E
-rw-r--r--  1 cwerling  wheel    41K Nov 16 10:03 PSP_FW_BOOT_LOADER~0x1_0.9.0.6B
-rw-r--r--  1 cwerling  wheel    55K Nov 16 10:03 PSP_FW_BOOT_LOADER~0x1_0.D.0.1A
-rw-r--r--  1 cwerling  wheel   256B Nov 16 10:03 PSP_FW_RECOVERY_BOOT_LOADER~0x3_0.5.0.45
-rw-r--r--  1 cwerling  wheel    45K Nov 16 10:03 PSP_FW_RECOVERY_BOOT_LOADER~0x3_0.8.0.5E
-rw-r--r--  1 cwerling  wheel    41K Nov 16 10:03 PSP_FW_RECOVERY_BOOT_LOADER~0x3_FF.9.0.6A
-rw-r--r--  1 cwerling  wheel   256B Nov 16 10:03 PSP_FW_TRUSTED_OS~0x2_0.5.0.45
-rw-r--r--  1 cwerling  wheel    61K Nov 16 10:03 PSP_FW_TRUSTED_OS~0x2_0.8.0.5E
-rw-r--r--  1 cwerling  wheel   264K Nov 16 10:03 PSP_FW_TRUSTED_OS~0x2_0.9.0.6B
-rw-r--r--  1 cwerling  wheel    60K Nov 16 10:03 PSP_FW_TRUSTED_OS~0x2_0.D.0.1A
-rw-r--r--  1 cwerling  wheel   128K Nov 16 10:03 PSP_NV_DATA~0x4
-rw-r--r--  1 cwerling  wheel    12K Nov 16 10:03 PSP_S3_NV_DATA~0x1a
-rw-r--r--  1 cwerling  wheel   256B Nov 16 10:03 PSP_SMU_FN_FIRMWARE~0x108_0.0.0.0
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 PSP_SMU_FN_FIRMWARE~0x108_0.2B.15.0
-rw-r--r--  1 cwerling  wheel   800B Nov 16 10:03 SEC_DBG_PUBLIC_KEY~0x9
-rw-r--r--  1 cwerling  wheel    14K Nov 16 10:03 SEC_GASKET~0x24_11.3.0.8
-rw-r--r--  1 cwerling  wheel   6.7K Nov 16 10:03 SEC_GASKET~0x24_13.2.0.9
-rw-r--r--  1 cwerling  wheel   5.8K Nov 16 10:03 SEC_GASKET~0x24_A.2.3.27
-rw-r--r--  1 cwerling  wheel   256B Nov 16 10:03 SMU_OFFCHIP_FW~0x8_0.0.0.0
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 SMU_OFFCHIP_FW~0x8_0.19.54.0
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 SMU_OFFCHIP_FW~0x8_0.2E.16.0
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 SMU_OFF_CHIP_FW_2~0x12_0.0.0.0
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 SMU_OFF_CHIP_FW_2~0x12_0.19.54.0
-rw-r--r--  1 cwerling  wheel   256K Nov 16 10:03 SMU_OFF_CHIP_FW_2~0x12_0.2E.16.0
-rw-r--r--  1 cwerling  wheel     0B Nov 16 10:03 SOFT_FUSE_CHAIN_01~0xb
-rw-r--r--  1 cwerling  wheel   4.0K Nov 16 10:03 TOKEN_UNLOCK~0x22
-rw-r--r--  1 cwerling  wheel    16B Nov 16 10:03 WRAPPED_IKEK~0x21
```

</details>


**Example 3**: *Extract the firmware entry from a given BIOS ROM at directory index 1 entry index 8 (`PSP_BOOT_TIME_TRUSTLETS`) and show strings of length 10.*

```
$ psptool -X -d 1 -e 8 MSI_X399_E7B92AMS.130 | strings -n 10
```

<details>
  <summary>Click to expand output</summary>

```
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
 h(`ahi`!h
crAmd_ModExp aA failed, status = 0x%x
crAmd_ModExp aB failed status = 0x%x
crAmd_ModExp failed ret=0x%08x, exit
Not Composite
Subtract failed
GDB failed
RSAPrime value of total iteration j = %d
tlApiCipherInit failed with ret=0x%97X, exit
tlApiCipherUpdate failed with ret=0x%08X
tlApiCipherDoFinal failed with ret=0x%08X
Done Generating starting prime
Calling GetRsaPrime
DOne GetRsaPrime
Value of P
Value of Q
Value of Modulus ((0x%04X)):
Value of PrivateExponent (0x%04X):
PRF_HASH_OTP starting
crAmd_MessageDigestInitHwKey failed ret=0x%08x, exit
tlApiMessageDigestDoFinal failed ret=0x%08x, exit
RSA: Signing data
RSA: tlApiSignatureInit failed with ret=%x
Signature:
RSA: signature data length: %d
RSA: Verifying data
RSA: tlApiSignatureVerify failed with ret=%x
Rsa: tlApiSignatureVerify validity = %x
AMD_TL_UTIL: ProcessCmd_Hash(), tlApiMessageDigestInit ret=0x%08X, exit
AMD_TL_UTIL: processCmdSha256(), tlApiMessageDigestDoFinal ret=0x%08X, exit
AMD_TL_UTIL: processCmd_Hmac(), crAmd_CipherInitWithHwKey ret=0x%08X, exit
AMD_TL_UTIL: processCmd_Hmac(), tlApiCipherDoFinal ret=0x%08X, exit
AMD_TL_UTIL: ProcessCmd_Hmac(), tlApiSignatureInit ret=0x%08X, exit
AMD_TL_UTIL: ProcessCmd_Hmac(), tlApiSignatureSign ret=0x%08X, exit
RSA: Init data for signing with TLAPI_SIG_RSA_SHA256_PSS type signature
RSA: Init data for verifying with TLAPI_SIG_RSA_SHA256_PSS type signature
!F(F0"r120
dAd8k:F02@
 h(`ahi`!h
ph,Fh`xhqh
 pG00pG\0pG
 VLWM ```(`h`0
 NL(`h`0`p`
#HpG"HD0pG!H"0pG
 h8C `*F1F F
!%*.59WWWWWWI9?DW
"qEGvxJJEEENPR
EZ]_b]dh__jl
ProcessCmd_TpmManufacture
UnwrapDataFromNwd
WrapDataForNwd
ReadNvRecord
ReadNvRecordMustSucceed
WriteNvRecord
ReadNvRecordOnInit
AmdNv_Init
AmdNv_Commit
2L_plat__GetEntropy
_plat__NVEnable
_plat__NvMemoryRead
_plat__NvMemoryWrite
_plat__NvMemoryClear
_plat__NvMemoryMove
This is not really a unique value. A real unique value should be generated by the platform.
TPM2_ContextLoad
TPM2_ContextSave
ComputeContextProtectionKey
TPM2_EvictControl
TPM2_FlushContext
TPM2_Import
TPM2_Rewrap
TPM2_PolicyTicket
PolicyContextUpdate
PolicySptCheckCondition
TPM2_HierarchyChangeAuth
TPM2_HierarchyControl
TPM2_SetPrimaryPolicy
TPM2_NV_Extend
TPM2_Create
TPM2_CreateLoaded
SchemeChecks
SensitiveToPrivate
PrivateToSensitive
SensitiveToDuplicate
DuplicateToSensitive
SecretToCredential
TPM2_Shutdown
TPM2_Startup
Amd_Sha1Start
Amd_Sha256Start
Amd_Sha384Start
Amd_Sha512Start
Amd_ShaUpdate
Amd_ShaFinal
BnFromBytes
BnPointTo2B
CarryResolve
BnUnsignedCmp
BnShiftRight
C_2_2_ECDH
CryptEcc2PhaseKeyExchange
CryptEccGetParameter
CryptEccIsPointOnCurve
CryptEccGenerateKey
BnSignEcdsa
CryptEccSign
CryptEccValidateSignature
CryptEccCommitCompute
CryptHashCopyState
CryptDigestUpdate
CryptHashEnd
CryptDigestUpdate2B
CryptHmacEnd
MillerRabin
BnGeneratePrimeForRSA
PrimeSieve
PrimeSelectWithSieve
DRBG_GetEntropy
DRBG_Update
DRBG_Reseed
DRBG_SelfTest
DRBG_InstantiateSeeded
DRBG_Generate
DRBG_Instantiate
CryptRandMinMax
OaepEncode
OaepDecode
RSASSA_Decode
CryptRsaDecrypt
CryptRsaSign
CryptRsaValidateSignature
CryptRsaGenerateKey
CryptIncrementalSelfTest
CryptSymmetricEncrypt
CryptSymmetricDecrypt
CryptXORObfuscation
CryptSecretEncrypt
CryptSecretDecrypt
CryptParameterEncryption
CryptParameterDecryption
CryptCreateObject
CryptGetSignHashAlg
ParseHandleBuffer
CommandDispatcher
ExecuteCommand
IncrementLockout
IsAuthValueAvailable
CheckAuthSession
ParseSessionBuffer
UpdateAuditDigest
BuildResponseSession
HierarchyGetProof
HierarchyGetPrimarySeed
HierarchyIsEnabled
NvWriteNvListEnd
NvRamGetIndex
NvDeleteRAM
NvReadNvIndexInfo
NvGetIndexData
NvWriteIndexData
NvFlushHierarchy
NvCapGetPersistent
NvCapGetIndex
NvUpdatePersistent
ObjectIsSequence
HandleToObject
GetQualifiedName
FlushObject
ObjectFlushHierarchy
ObjectCapGetLoaded
GetSavedPcrPointer
GetPcrPointer
PCRChanged
PCRComputeCurrentDigest
PCRAllocate
PCRCapGetHandles
SessionIsLoaded
SessionIsSaved
SessionGet
ContextIdSessionCreate
SessionCreate
SessionContextSave
SessionContextLoad
SessionFlush
SessionResetPolicyData
SessionCapGetLoaded
SessionCapGetSaved
TimeClockUpdate
TimeSetAdjustRate
GetClosestCommandIndex
EntityGetLoadStatus
EntityGetAuthValue
EntityGetAuthPolicy
EntityGetHierarchy
Primary Object Creation
ECDAA Commit
PermanentCapGetHandles
PermanentHandleGetPolicy
MemoryGetActionInputBuffer
MemoryGetActionOutputBuffer
LocalityGetAttributes
UINT8_Marshal
UINT16_Marshal
UINT32_Marshal
UINT64_Marshal
BYTE_Array_Marshal
MemoryCopy2B
MemoryConcat2B
UnmarshalFail
```

</details>

**Example 4**: *Visualize the certificate chain of all firmware elements:*

```
$ psptool -t Lenovo_Thinkpad_T495_r12uj35wd.iso
```

<details>
  <summary>Click to expand output</summary>

```
AMD
 +-PubkeyEntity(60BB, @38f224)
 | PubkeyEntity(60BB, @28bf24)
 | +-SignedEntity(@5e3920:5010) (verified=True)
 | +-SignedEntity(@673720:4830) (verified=True)
 | +-SignedEntity(@57e820:8dc0) (verified=True)
 | +-SignedEntity(@2f8620:8dc0) (verified=True)
 | +-SignedEntity(@2b9d20:71b0) (verified=True)
 | +-SignedEntity(@34ef20:340) (verified=True)
 | | +-PubkeyEntity(3FC7, @34ef24)
 | | | PubkeyEntity(3FC7, @639f24)
 | +-SignedEntity(@39e820:22770) (verified=True)
 | +-SignedEntity(@37d420:47a0) (verified=True)
 | +-SignedEntity(@678020:370) (verified=True)
 | +-SignedEntity(@3c1020:340) (verified=True)
 | | +-PubkeyEntity(ED22, @3c1024)
 | +-SignedEntity(@587620:bb90) (verified=True)
 | +-SignedEntity(@301420:bb90) (verified=True)
 | +-SignedEntity(@2c0f20:20830) (verified=True)
 | +-SignedEntity(@36fb20:3c40) (verified=True)
 | +-SignedEntity(@381c20:340) (verified=True)
 | +-SignedEntity(@3e6b20:18790) (verified=True)
 | +-SignedEntity(@678420:47a0) (verified=True)
 | +-SignedEntity(@3c1420:11a50) (verified=True)
 | +-SignedEntity(@593220:cca0) (verified=True)
 | +-SignedEntity(@639f20:340) (verified=True)
 | | +-PubkeyEntity(3FC7, @34ef24)
 | | | PubkeyEntity(3FC7, @639f24)
 | +-SignedEntity(@30d020:cca0) (verified=True)
 | +-SignedEntity(@2e1820:5010) (verified=True)
 | +-SignedEntity(@373820:330) (verified=True)
 | +-SignedEntity(@67cc20:340) (verified=True)
 | +-SignedEntity(@3d2f20:71b0) (verified=True)
 | +-SignedEntity(@59ff20:c910) (verified=True)
 | +-SignedEntity(@66ab20:3c40) (verified=True)
 | +-SignedEntity(@319d20:c910) (verified=True)
 | +-SignedEntity(@2e7b20:1860) (verified=True)
 | +-SignedEntity(@373c20:4610) (verified=True)
 | +-SignedEntity(@3e2cc4:340) (verified=True)
 | | +-PubkeyEntity(76E9, @3e67e4)
 | | | PubkeyEntity(76E9, @67f944)
 | | | PubkeyEntity(76E9, @3e2cc8)
 | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | +-SignedEntity(@56dd20:3100) (verified=True)
 | +-SignedEntity(@3da120:1930) (verified=True)
 | +-SignedEntity(@5ac920:9ef0) (verified=True)
 | +-SignedEntity(@66e820:330) (verified=True)
 | +-SignedEntity(@382f20:c300) (verified=True)
 | +-SignedEntity(@326720:9ef0) (verified=True)
 | +-SignedEntity(@2e9420:1760) (verified=True)
 | +-SignedEntity(@378320:320) (verified=True)
 | +-SignedEntity(@3e67e0:340) (verified=True)
 | | +-PubkeyEntity(76E9, @3e67e4)
 | | | PubkeyEntity(76E9, @67f944)
 | | | PubkeyEntity(76E9, @3e2cc8)
 | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | +-SignedEntity(@67f940:340) (verified=True)
 | | +-PubkeyEntity(76E9, @3e67e4)
 | | | PubkeyEntity(76E9, @67f944)
 | | | PubkeyEntity(76E9, @3e2cc8)
 | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | +-SignedEntity(@570e20:dd0) (verified=True)
 | +-SignedEntity(@3ddb20:1860) (verified=True)
 | +-SignedEntity(@5b6820:c710) (verified=True)
 | +-SignedEntity(@66ec20:4610) (verified=True)
 | +-SignedEntity(@28c220:b300) (verified=True)
 | +-SignedEntity(@330620:c710) (verified=True)
 | +-SignedEntity(@2eac20:dd0) (verified=True)
 | +-SignedEntity(@378720:4830) (verified=True)
 | +-SignedEntity(@38f520:f300) (verified=True)
 | +-SignedEntity(@571c20:cbb0) (verified=True)
 | +-SignedEntity(@3df420:1760) (verified=True)
 | +-SignedEntity(@5c3020:20830) (verified=True)
 | +-SignedEntity(@673320:320) (verified=True)
 | +-SignedEntity(@297520:22770) (verified=True)
 | +-SignedEntity(@2eba20:cbb0) (verified=True)
 | +-SignedEntity(@37d020:370) (verified=True)
 +-PubkeyEntity(76E9, @3e67e4)
 | PubkeyEntity(76E9, @67f944)
 | PubkeyEntity(76E9, @3e2cc8)
 | +-SignedEntity(@67f720:560) (verified=False)
 | | +-PubkeyEntity(76E9, @3e67e4)
 | | | PubkeyEntity(76E9, @67f944)
 | | | PubkeyEntity(76E9, @3e2cc8)
 | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | +-PubkeyEntity(76E9, @3e67e4)
 | | | PubkeyEntity(76E9, @67f944)
 | | | PubkeyEntity(76E9, @3e2cc8)
 | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | +-PubkeyEntity(76E9, @3e67e4)
 | | | | | PubkeyEntity(76E9, @67f944)
 | | | | | PubkeyEntity(76E9, @3e2cc8)
 | | | | | +-SignedEntity(@67f720:560) (verified=False)
 | | | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | | | +-SignedEntity(@3e0c20:23e4) (verified=False)
 | | | +-SignedEntity(@3e3020:3b00) (verified=False)
 | +-SignedEntity(@3e3020:3b00) (verified=False)
```

</details>

**General usage:**

```
usage: psptool [-V | -E | -X | -R] [file]

Display, extract, and manipulate AMD PSP firmware inside BIOS ROMs.

positional arguments:
  file                 Binary file to be parsed for PSP firmware

optional arguments:
  -V, --version
  -E, --entries        Default: Parse and display PSP firmware entries.
                       [-n] [-j] [-t]
                       
                       -n:      list unique entries only ordered by their offset
                       -j:      output in JSON format instead of tables
                       -t:      print tree of all signed entities and their certifying keys
                       
  -X, --extract-entry  Extract one or more PSP firmware entries.
                       [[-r idx] -d idx [-e idx]] [-n] [-u] [-c] [-k] [-o outfile]
                       
                       -r idx:  specifies rom_index (default: 0)
                       -d idx:  specifies directory_index (default: all directories)
                       -e idx:  specifies entry_index (default: all entries)
                       -n:      skip duplicate entries and extract unique entries only
                       -u:      uncompress compressed entries
                       -c:      try to decrypt entries
                       -k:      convert pubkeys into PEM format
                       -o file: specifies outfile/outdir (default: stdout/{file}_extracted)
                       
  -R, --replace-entry  Copy a new entry (including header and signature) into the
                       ROM file and update metadata accordingly.
                       [-r idx] -d idx -e idx -s subfile -o outfile [-p file-stub] [-a pass]
                       
                       -r idx:  specifies rom_index (default: 0)
                       -d idx:  specifies directory_index
                       -e idx:  specifies entry_index
                       -s file: specifies subfile (i.e. the new entry contents)
                       -o file: specifies outfile
                       -p file: specifies file-stub (e.g. 'keys/id') for the re-signing keys
                       -a pass: specifies password for the re-signing keys
```

## Python Usage

PSPTool can be **used as a Python module**, e.g. in an interactive IPython session:

```
> from psptool import PSPTool
> psp = PSPTool.from_file('original_bios.bin')
> psp.blob.roms[0]
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
> psp.blob.roms[0].directories[0].entries[0]
PubkeyEntry(type=0x0, address=0x77400, size=0x240, len(references)=1)
> psp.blob.directories[0].entries[0].get_bytes()
b'\x01\x00\x00\x00\x1b\xb9\x87\xc3YIF\x06\xb1t\x94V\x01\xc9\xea[\x1b\xb9\x87\xc3YIF\x06\xb1t\x94V\x01\xc9\xea[\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x08\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
[...]
> my_stuff = [...]
> psp.blob.roms[0].directories[0].entries[1].move_buffer(0x60000, 0x1000)
> psp.blob.roms[0].set_bytes(0x60000, 0x1000, my_stuff)
> psp.to_file('my_modified_bios.bin')
```