CROSS  ?= aarch64-elf-
CC      = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy

QEMU   ?= ../../qemu/build/qemu-system-aarch64

CFLAGS  = -ffreestanding -nostdlib -nostartfiles -mgeneral-regs-only \
          -mlittle-endian -Wall -Wextra

all: test.bin

test.elf: test.S link.ld
	$(CC) $(CFLAGS) -T link.ld -o $@ test.S

test.bin: test.elf
	$(OBJCOPY) -O binary $< $@

run: test.bin
	$(QEMU) -machine virt,secure=on,virtualization=on -cpu max \
	    -nographic -display none -no-reboot \
	    -bios test.bin

clean:
	rm -f test.elf test.bin

.PHONY: all run clean
