#!/bin/sh
# Build the PE fixtures. Usage: build.sh OUT_DIR. Needs clang, lld-link, llvm-dlltool.
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$1
mkdir -p "$OUT"
cd "$OUT"
for d in kernel32 advapi32 wevtapi ws2_32; do
    llvm-dlltool -m i386:x86-64 -d "$SRC/$d.def" -l "$d.lib"
done
CC="clang --target=x86_64-pc-windows-msvc -O1 -fno-stack-protector -c"
LINK="lld-link /nologo /nodefaultlib /machine:x64"
$CC "$SRC/helper.c" -o helper.obj
$LINK /dll /noentry /out:helper.dll /implib:helper.lib helper.obj kernel32.lib
$CC "$SRC/agent.c" -o agent.obj
$LINK /entry:start /subsystem:console /out:agent.exe agent.obj \
    kernel32.lib advapi32.lib wevtapi.lib ws2_32.lib helper.lib /delayload:wevtapi.dll
