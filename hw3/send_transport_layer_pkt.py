#!/usr/bin/python3

import click
from scapy.all import IP, TCP, UDP, send


@click.command()
@click.option("--target-ip", prompt="Target IP", help="IP address of the target")
@click.option(
    "--target-port", prompt="Target port", type=int, help="Target port number"
)
@click.option(
    "--source-port",
    prompt="Source port",
    type=int,
    default=0,
    help="Source port number (0 for random)",
)
@click.option(
    "--protocol", prompt=True, type=click.Choice(["tcp", "udp"]), default="tcp"
)
def send_packet(target_ip: str, target_port: int, source_port: int, protocol: str):
    transport_layer = None
    if protocol == "tcp":
        transport_layer = TCP(dport=target_port)
    elif protocol == "udp":
        transport_layer = UDP(dport=target_port)
    else:
        raise ValueError("Invalid protocol")

    if source_port:
        transport_layer.sport = source_port

    packet = IP(dst=target_ip) / transport_layer
    send(packet, verbose=0)
    print("TCP packet sent to: {0}:{1}".format(target_ip, target_port))


if __name__ == "__main__":
    send_packet()
