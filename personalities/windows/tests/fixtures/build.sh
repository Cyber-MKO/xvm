#!/bin/sh
# Build the loader fixtures as PE32 i386. Usage: build.sh OUT_DIR.
# Needs clang, lld-link, llvm-dlltool.
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$1
mkdir -p "$OUT"
cd "$OUT"
llvm-dlltool -m i386 -k -d "$SRC/kernel32.def" -l kernel32.lib
CC="clang --target=i686-pc-windows-msvc -O1 -fno-stack-protector -c"
LINK="lld-link /nologo /nodefaultlib /machine:x86"
$CC "$SRC/sample.c" -o sample.obj
$LINK /dll /noentry /out:sample.dll /implib:sample.lib \
    /export:hidden,@7,NONAME /export:Ticks=kernel32.GetTickCount sample.obj
$CC "$SRC/tls.c" -o tls.obj
$LINK /dll /noentry /out:tls.dll /base:0x30000000 tls.obj
$CC "$SRC/importer.c" -o importer.obj
$LINK /entry:start /subsystem:console /out:importer.exe importer.obj kernel32.lib sample.lib
