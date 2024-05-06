sudo rmmod firewall
sudo make
sudo insmod firewall.ko
sudo ./main.py load_rules my_rules.txt
sudo ./main.py show_rules
sudo ./main.py show_conns