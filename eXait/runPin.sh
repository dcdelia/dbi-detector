#!/bin/sh
dll=$(ls *.dll)
pinpath="/cygdrive/c/Pin311"
for d in ${dll[@]} ; do
    echo Processing "$d"
    wf=$(cygpath -w $PWD/exait.exe)
    $pinpath/pin.exe -- "$wf" -p $d
    read -p "Press enter to continue..."
done