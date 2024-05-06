#!/usr/bin/python3

import click
from scapy.all import ICMP, IP, send

"""
This script is used to send a spoofed ICMP packet to a target IP address.
Notice that in order for the router to successfully route this packet,
you first need to turn off the reverse path filtering.
More info about this here:
https://sysctl-explorer.net/net/ipv4/rp_filter/
"""


@click.command()
@click.option("--target-ip", prompt="Target IP", help="IP address of the target")
@click.option("--source-ip", prompt="Source IP", help="IP address of the source")
def send_spoof_icmp_packet(target_ip: str, source_ip: str):
    icmp_packet = IP(src=source_ip, dst=target_ip) / ICMP()
    send(icmp_packet, verbose=0)
    print("ICMP packet sent from {0} to {1}".format(source_ip, target_ip))


if __name__ == "__main__":
    send_spoof_icmp_packet()
