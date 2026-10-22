# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Makefile for the rr-entropy-monitor guest kernel module.
#
# Usage:
#   make                  Build against the running kernel
#   make KDIR=/path/to/kernel   Build against a specific kernel tree
#   make clean            Remove build artifacts
#

MODULE_NAME := rr_entropy_monitor

obj-m := $(MODULE_NAME).o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

.PHONY: all clean install
