KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += hooking.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
