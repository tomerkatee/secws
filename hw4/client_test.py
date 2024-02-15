from scapy.all import *


#GW_attack
send(IP(dst="10.1.2.15") / ICMP())


#spoof2
send(IP(src="10.1.2.2", dst="10.1.2.2") / ICMP())

#telnet1
send(IP(dst="10.1.2.2") / TCP(dport=23, sport=4000))

#XMAS
send(IP(dst="10.1.2.2") / TCP(flags='UFP'))



