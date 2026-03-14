MODULE_NAME := packet_monitor
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m += $(MODULE_NAME).o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f Module.symvers modules.order

load: all
	sudo insmod $(MODULE_NAME).ko

unload:
	sudo rmmod $(MODULE_NAME)

reload: unload load

stats:
	@cat /proc/packet_monitor

filter:
	@cat /proc/packet_filter
