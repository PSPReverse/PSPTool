

# psptool

psptool is a Swiss Army knife for dealing with **binary blobs** mainly **delivered with BIOS updates** targeting **AMD platforms**. 

It is based on reverse-engineering efforts of AMD's proprietary **simple filesystem** used to **pack its blobs** into standardized **UEFI Firmware Images**. These are usually 16MB in size and can be conveniently parsed by [UEFITool](https://github.com/LongSoft/UEFITool). However, all binary blobs by AMD are located in an unparsable area of the UEFI image marked as *padding* by UEFITool.

**psptool favourably works with BIOS ROM files** such as UEFI images – as they can be obtained labeled *BIOS updates* from OEMs and IBVs. However, it won't complain about additional headers such as an Aptio Capsule header.

```
usage: psptool [-h] [-E | -X | -R] file

Parse, display, extract and manipulate PSP firmware inside BIOS ROMs, UEFI volumes and so on.

positional arguments:
  file                 Binary file to be parsed for PSP firmware _directories

optional arguments:
  -h, --help           Show this help message and exit.

  -E, --entries        Default: Parse and display PSP firmware entries.
                       [-d idx] [-n] [-i] [-v]

                       -d idx:     specifies directory_index (default: all _directories)
                       -n:         hide duplicate entries from listings
                       -i:         display additional entry header info
                       -a:         display entry architecture (powered by cpu_rec)
                       -v:         display even more info (AGESA Version, Entropy, MD5)
                       -t csvfile: only display entries found in the given SPI trace
                                   (see psptrace for details)
  -X, --extract-entry  Extract one or more PSP firmware entries.
                       [-d idx [-e idx]] [-n] [-u] [-k] [-v] [-o outfile]

                       -d idx:  specifies directory_index (default: all _directories)
                       -e idx:  specifies entry_index (default: all entries)
                       -n:      skip duplicate entries
                       -u:      uncompress compressed entries
                       -k:      convert _pubkeys into PEM format
                       -v:      increase output verbosity
                       -o file: specifies outfile/outdir (default: stdout/$PWD)
  -R, --replace-entry  Replace a raw PSP firmware entry and export new ROM file.
                       -d idx -e idx [-s subfile] [-o outfile]

                       -d idx:  specifies directory_index
                       -e idx:  specifies entry_index
                       -s file: specifies subfile (default: stdin)
                       -o file: specifies outfile (default: stdout)
```

