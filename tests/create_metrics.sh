#!/bin/bash

echo "Please run from PSPTool Git root directory!"

PSPTOOL="python3 -m psptool"
VERSION=$($PSPTOOL --version)
OUTFILE=tests/metrics.txt
ROMDIR=tests/integration/fixtures/roms

echo "Using PSPTool version $VERSION"
echo "Remove $OUTFILE and generate new one?"
read -s -n 1

echo "Creating metrics ..."
rm -f $OUTFILE
$PSPTOOL --version >> $OUTFILE
for f in $(ls $ROMDIR); do 
    $PSPTOOL --metrics $ROMDIR/$f 2>/dev/null >> $OUTFILE; 
done
echo "Done"
