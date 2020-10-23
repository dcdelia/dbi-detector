#!/bin/sh
exe32=$(ls *x86.exe)
exe64=$(ls *x64.exe)
driopath="$HOME/desktop/drio801/"
for f in ${exe32[@]} ; do
    echo Processing "$f"
    wf=$(cygpath -w $PWD/$f)
    $driopath/bin32/drrun.exe -- "$wf"
    read -p "Press enter to continue..."
done
for f in ${exe64[@]} ; do
    echo Processing "$f"
    wf=$(cygpath -w $PWD/$f)
    $driopath/bin64/drrun.exe -- "$wf"
    read -p "Press enter to continue..."
done