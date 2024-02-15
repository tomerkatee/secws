from scapy.all import *


#spoof1
send(IP(src="10.1.1.5", dst="10.1.1.1") / ICMP())

#telnet2
send(IP(dst="10.1.1.1") / TCP(dport=4000, sport=23, flags='A'))

#XMAS
send(IP(dst="10.1.1.1") / TCP(flags='UFP'))


