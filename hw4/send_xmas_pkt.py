#!/usr/bin/python3

import click
from scapy.all import IP, TCP, send

"""
This script is used to send a XMAS packet to a target IP address and port number.
The XMAS packet is a TCP packet with the FIN, URG, and PSH flags set.
The purpose of the XMAS packet is to probe the target to see how it responds to a packet with these flags set.
If the target responds with a RST packet, then the port is closed.
If the target does not respond, then the port is open.
"""


@click.command()
@click.option("--target-ip", prompt="Target IP", help="IP address of the target")
@click.option(
    "--target-port", prompt="Target port", type=int, help="Port number of the target"
)
def send_xmas_packet(target_ip: str, target_port: int):
    xmas_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="FPU")
    send(xmas_packet, verbose=0)
    print("XMAS packet sent to: {0}:{1}".format(target_ip, target_port))


if __name__ == "__main__":
    send_xmas_packet()
