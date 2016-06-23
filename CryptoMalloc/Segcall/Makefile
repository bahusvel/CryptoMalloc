obj-m+=segcall.o

all: clean
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

insert: all remove
	insmod segcall.ko

remove:
	rmmod segcall.ko
