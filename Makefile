obj-m += rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

hello:
	echo Aloha
	echo $(PWD)
	echo $(shell uname -r)

