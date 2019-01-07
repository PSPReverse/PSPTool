

# psptool

psptool is a Swiss Army knife for dealing with **binary blobs** mainly **delivered with BIOS updates** targeting **AMD platforms**. 

It is based on reverse-engineering efforts of AMD's proprietary **simple filesystem** used to **pack its blobs** into standardized **UEFI Firmware Images**. These are usually 16MB in size and can be conveniently parsed by [UEFITool](https://github.com/LongSoft/UEFITool). However, all binary blobs by AMD are located in an unparsable area of the UEFI image marked as *padding* by UEFITool.

**psptool favourably works with BIOS ROM files** such as UEFI images – as they can be obtained labeled *BIOS updates* from OEMs and IBVs. However, it won't complain about additional headers such as an Aptio Capsule header.

```
usage: psptool [-h] [-v] [-n] (-D | -E | -X | -R | -H) file

Find, display, extract and manipulate PSP firmware directories inside binary
files like UEFI volumes.

positional arguments:
  file                 binary file to be parsed for PSP firmware directories

optional arguments:
  -h, --help           show this help message and exit
  -v, --verbose        increase output verbosity
  -n, --no-duplicates  hide duplicate entries from listings
  -D, --directories    find, parse and display all PSP firmware directories in
                       file
  -E, --entries        find, parse and display all entries contained in all
                       PSP firmware directories or only of the given directory
                       index (-d)
  -X, --extract-entry  extract a raw PSP firmware entry (-a for all entries or
                       specify directory index -d, entry index -e); for
                       decompressing provide -u; for conversion of an AMD
                       Signing Key into PEM format provide -k
  -R, --replace-entry  replace a raw PSP firmware entry of the given directory
                       index (-d) and entry index (-e) by an equally large
                       subfile (stdin or -s) and save it as outfile (stdout or
                       -o)
```

