#!/bin/sh
exe=$(ls *.EXE)
pinpath="/cygdrive/c/Pin311"
for f in ${exe[@]} ; do
    echo Processing "$f"
    wf=$(cygpath -w $PWD/$f)
    $pinpath/pin.exe -- "$wf"
    read -p "Press enter to continue..."
done