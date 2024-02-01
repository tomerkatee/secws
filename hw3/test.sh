rmmod firewall
make
insmod firewall.ko
./main.py load_rules my_rules.txt
sshpass -p 'fw' scp client_test.py fw@10.1.1.1:~/client_test.py
sshpass -p 'fw' scp server_test.py fw@10.1.2.2:~/server_test.py
./main.py show_rules

