MINGW_PREFIX ?= /tmp/krb-mingw-root
# The raw PIC is linked without the CRT. Override this prefix when using a
# different MinGW-w64 sysroot.
CC := $(MINGW_PREFIX)/usr/bin/x86_64-w64-mingw32-gcc-posix
SYSROOT := $(MINGW_PREFIX)
GCCLIB := $(MINGW_PREFIX)/usr/lib/gcc/x86_64-w64-mingw32/15-posix/
BINPREFIX := $(MINGW_PREFIX)/usr/x86_64-w64-mingw32/bin/
INCLUDE := $(MINGW_PREFIX)/usr/x86_64-w64-mingw32/include
CFLAGS := --sysroot=$(SYSROOT) -B$(GCCLIB) -B$(BINPREFIX) -Os -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -I$(INCLUDE)
LD := $(MINGW_PREFIX)/usr/bin/x86_64-w64-mingw32-ld

.PHONY: all verify clean

all: bof/krbrelay-pic.x64.o

# Embed the linker-produced raw core in a Cobalt-loadable COFF section. The
# target never receives the .bin as a separate file.
bof/embed-pic.x64.o: bof/embed_pic.S bof/krbrelay-pic-core.x64.bin
	$(CC) $(CFLAGS) -c $< -o $@

bof/launcher-pic.x64.o: bof/launcher_pic.c bof/beacon.h
	$(CC) $(CFLAGS) -c $< -o $@

bof/krbrelay-pic.x64.o: bof/launcher-pic.x64.o bof/embed-pic.x64.o
	$(LD) -r $^ -o $@

# Inspect the final launcher rather than only the intermediate core.
verify: bof/krbrelay-pic.x64.o
	$(MINGW_PREFIX)/usr/bin/x86_64-w64-mingw32-objdump -f $<
	$(MINGW_PREFIX)/usr/bin/x86_64-w64-mingw32-objdump -h $<

# The PIC build resolves its own imports and places all required data in .text.
PIC_CFLAGS := $(CFLAGS) -DKRBRELAY_PIC -fPIC -ffunction-sections -fdata-sections -mno-stack-arg-probe

bof/krbrelay-pic-core.x64.o: bof/krbrelay.c bof/pic_compat.h bof/pic_runtime.h
	$(CC) $(PIC_CFLAGS) -c $< -o $@

bof/krbrelay-pic-core.x64.exe: bof/krbrelay-pic-core.x64.o bof/pic_link.ld
	$(LD) -mi386pep --entry krbrelay_pic_entry --image-base 0 --section-alignment 1 --file-alignment 1 --no-insert-timestamp -T bof/pic_link.ld $< -o $@

bof/krbrelay-pic-core.x64.bin: bof/krbrelay-pic-core.x64.exe
	$(MINGW_PREFIX)/usr/bin/x86_64-w64-mingw32-objcopy -O binary --only-section=.text $< $@

clean:
	# All names below are generated products; no wildcard can capture source.
	$(RM) bof/krbrelay-pic-core.x64.o bof/krbrelay-pic-core.x64.exe \
		bof/krbrelay-pic-core.x64.bin bof/embed-pic.x64.o \
		bof/launcher-pic.x64.o bof/krbrelay-pic.x64.o
