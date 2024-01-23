sudo rmmod hw3secws
make
sudo insmod hw3secws.ko
sudo cat /dev/fw_log
dmesg