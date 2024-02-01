from scapy.all import *


send(IP(src="10.1.2.4", dst="10.1.2.2") / TCP(dport=4000, sport=23, flags='A'))




