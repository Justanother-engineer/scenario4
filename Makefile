CC=x86_64-w64-mingw32-gcc
CFLAGS=-O2 -s

all: P0wershell.exe userenv.dll elevcheck.exe

P0wershell.exe: p0wershell.c payload_extract.c payload_extract.h miniz.c miniz.h miniz_tdef.c miniz_tinfl.c miniz_zip.c miniz_common.h miniz_tdef.h miniz_tinfl.h miniz_zip.h
	$(CC) $(CFLAGS) -o $@ p0wershell.c payload_extract.c miniz.c miniz_tdef.c miniz_tinfl.c miniz_zip.c -lurlmon -lshell32

elevcheck.exe: elevcheck.c
	$(CC) $(CFLAGS) -o $@ $< -lurlmon

userenv.dll: userenv_proxy.c userenv_proxy.def
	$(CC) $(CFLAGS) -o $@ userenv_proxy.c userenv_proxy.def -shared -lole32 -loleaut32 -luuid

clean:
	rm -f P0wershell.exe userenv.dll elevcheck.exe
