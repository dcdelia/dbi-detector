#!/bin/sh
exe=$(ls *.EXE)
driopath="$HOME/desktop/drio801/"
for f in ${exe[@]} ; do
    echo Processing "$f"
    wf=$(cygpath -w $PWD/$f)
    $driopath/bin32/drrun.exe -- "$wf"
    read -p "Press enter to continue..."
done