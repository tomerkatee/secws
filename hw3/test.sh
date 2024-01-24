sudo rmmod firewall
make
sudo insmod firewall.ko
sudo cat /dev/fw_log
