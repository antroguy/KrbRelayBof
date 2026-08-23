MINGW_PREFIX ?= /tmp/krb-mingw-root
# Override this prefix when using a different MinGW-w64 sysroot.
CC := $(MINGW_PREFIX)/usr/bin/x86_64-w64-mingw32-gcc-posix
SYSROOT := $(MINGW_PREFIX)
GCCLIB := $(MINGW_PREFIX)/usr/lib/gcc/x86_64-w64-mingw32/15-posix/
BINPREFIX := $(MINGW_PREFIX)/usr/x86_64-w64-mingw32/bin/
INCLUDE := $(MINGW_PREFIX)/usr/x86_64-w64-mingw32/include
CFLAGS := --sysroot=$(SYSROOT) -B$(GCCLIB) -B$(BINPREFIX) -Os \
	-fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables \
	-mno-stack-arg-probe -I$(INCLUDE)

.PHONY: all verify clean

all: bof/krbrelay.x64.o

bof/krbrelay.x64.o: bof/krbrelay.c bof/beacon.h
	$(CC) $(CFLAGS) -c $< -o $@

verify: bof/krbrelay.x64.o
	$(MINGW_PREFIX)/usr/bin/x86_64-w64-mingw32-objdump -f $<
	$(MINGW_PREFIX)/usr/bin/x86_64-w64-mingw32-objdump -h $<
	! $(MINGW_PREFIX)/usr/bin/x86_64-w64-mingw32-nm -u $< | rg -v '(__imp_|Beacon)'

clean:
	$(RM) bof/krbrelay.x64.o
