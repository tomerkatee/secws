obj-m += firewall.o

firewall-objs := hw3secws.o

# Name of the user-space executable
EXECUTABLE = main

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc $(EXECUTABLE).c -o $(EXECUTABLE)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f $(EXECUTABLE)
