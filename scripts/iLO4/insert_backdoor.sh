#!/bin/bash

if [ $# -ne 1 ]; then
    echo "usage: $0 <firmware.bin>"
    exit 1
fi

DIR=`dirname $0`
FIRMWARE=$1

rm -rf outdir

python $DIR/ilo4_extract.py $FIRMWARE outdir
python $DIR/patch_bootloader_250.py outdir/bootloader.bin
python $DIR/patch_kernel_250.py outdir/kernel_main.bin
python $DIR/patch_webserver_250.py outdir/elf.bin

python $DIR/ilo4_repack.py $FIRMWARE outdir/firmware.map outdir/elf.bin.patched outdir/kernel_main.bin.patched outdir/bootloader.bin.patched

echo "[+] Firmware ready to be flashed"
