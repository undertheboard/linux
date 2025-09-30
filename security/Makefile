# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the kernel security code
# Security subsystem has been disabled
#

obj-$(CONFIG_KEYS)			+= keys/

# always enable default capabilities
obj-y					+= commoncap.o
obj-$(CONFIG_MMU)			+= min_addr.o

# All other security modules are disabled
