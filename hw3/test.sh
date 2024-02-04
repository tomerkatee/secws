rmmod firewall
make
insmod firewall.ko
./main.py load_rules my_rules.txt
./main.py show_rules

