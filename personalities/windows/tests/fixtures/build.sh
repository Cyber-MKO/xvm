#!/bin/sh
# Build the loader fixtures as PE32 i386. Usage: build.sh OUT_DIR.
# Needs clang, lld-link, llvm-dlltool.
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$1
mkdir -p "$OUT"
cd "$OUT"
for d in kernel32 advapi32; do
    llvm-dlltool -m i386 -k -d "$SRC/$d.def" -l $d.lib
done
CC="clang --target=i686-pc-windows-msvc -O1 -fno-stack-protector -c"
LINK="lld-link /nologo /nodefaultlib /machine:x86"
$CC "$SRC/sample.c" -o sample.obj
$LINK /dll /noentry /out:sample.dll /implib:sample.lib \
    /export:hidden,@7,NONAME /export:Ticks=kernel32.GetTickCount sample.obj
$CC "$SRC/tls.c" -o tls.obj
$LINK /dll /noentry /out:tls.dll /base:0x30000000 tls.obj
$CC "$SRC/calls.c" -o calls.obj
$LINK /dll /noentry /out:calls.dll calls.obj kernel32.lib
for d in initdll faildll; do
    $CC "$SRC/$d.c" -o $d.obj
    $LINK /dll /entry:DllMain /out:$d.dll /implib:$d.lib $d.obj
done
$CC "$SRC/startup.c" -o startup.obj
$LINK /entry:start /subsystem:console /out:startup.exe startup.obj initdll.lib
$CC "$SRC/failing.c" -o failing.obj
$LINK /entry:start /subsystem:console /out:failing.exe failing.obj faildll.lib
$CC "$SRC/service.c" -o service.obj
$LINK /entry:start /subsystem:console /out:service.exe service.obj advapi32.lib kernel32.lib
$CC "$SRC/importer.c" -o importer.obj
$LINK /entry:start /subsystem:console /out:importer.exe importer.obj kernel32.lib sample.lib
