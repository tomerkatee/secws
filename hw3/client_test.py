from scapy.all import *


send(IP(dst="10.1.2.2") / TCP(dport=23, sport=3000, flags='S'))
send(IP(src="10.1.2.2", dst="10.1.1.1") / TCP(dport=23, sport=3000, flags='S'))




