#!/bin/bash

echo "Remove metrics.txt and generate new one?"
read -s -n 1

echo "Creating metrics ..."
rm -f metrics.txt
for f in $(ls integration/fixtures/roms); do psptool --metrics integration/fixtures/roms/$f 2>/dev/null >>metrics.txt; done
echo "Done"
