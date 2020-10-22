#!/bin/sh
dll=$(ls *.dll)
driopath="$HOME/desktop/drio801/"
for d in ${dll[@]} ; do
    echo Processing "$d"
    wf=$(cygpath -w $PWD/exait.exe)
    $driopath/bin32/drrun.exe -- "$wf" -p $d
    read -p "Press enter to continue..."
done