#!/usr/bin/env python3
import errno
import struct
import socket
import sys
from main import Rule, convert_to_little_end_port, convert_to_big_end_port, TwoDirectionalDict
import base64
import selectors
   

path_to_mitm_attr = "/sys/class/fw/conns/mitm"
mitm_update_format = "<I H H"
mitm_get_server_format = "<I H"
BUFFER_SIZE = 1024
client_to_mitm_client = TwoDirectionalDict({})
sock_to_send_buff = {}


def send_until_blocking(send_socket, data):
    try:
        sent_cnt = send_socket.send(data)
        
    except socket.error as e:
        err = e.args[0]
        if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
            return sent_cnt
        else:
            # a "real" error occurred
            print(e)
            send_socket.close()
            sys.exit(1)

    return sent_cnt
    
    
def recv_until_blocking(recv_socket):
    data = None
    try:
        data = recv_socket.recv(BUFFER_SIZE)
        
    except socket.error as e:
        err = e.args[0]
        if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
            return data
        else:
            # a "real" error occurred
            print(e)
            recv_socket.close()
            sys.exit(1)

    return data


def accept_and_register(sel, sock):
    client_socket, client_addr = sock.accept()

    with open(path_to_mitm_attr, 'wb') as mitm_attr:
        mitm_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mitm_client_socket.bind(('', 0))
        client_ip = Rule.ip_str_to_int(client_addr[0])
        client_port = convert_to_big_end_port(client_addr[1])
        mitm_port = convert_to_big_end_port(mitm_client_socket.getsockname()[1])

        print(str.format("client_ip: {}, client_port: {}, mitm_port: {}", client_ip, client_port, mitm_port))

        mitm_attr.write(struct.pack(mitm_update_format, client_ip, client_port, mitm_port))

    with open(path_to_mitm_attr, 'rb') as mitm_attr:

        data = mitm_attr.read(struct.calcsize(mitm_get_server_format)+5)

        server_addr_unformatted = struct.unpack(mitm_get_server_format, data)

        server_ip = Rule.int_to_ip_str(server_addr_unformatted[0])
        server_port = convert_to_little_end_port(server_addr_unformatted[1])

    mitm_client_socket.connect((server_ip, server_port))

    client_socket.setblocking(False)
    mitm_client_socket.setblocking(False)
    client_to_mitm_client.add_pair(client_socket, mitm_client_socket)
    sock_to_send_buff[client_socket] = bytearray()
    sock_to_send_buff[mitm_client_socket] = bytearray()
    sel.register(client_socket, selectors.EVENT_READ | selectors.EVENT_WRITE)
    sel.register(mitm_client_socket, selectors.EVENT_READ | selectors.EVENT_WRITE)
    

    

def main():

    mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_socket.setblocking(False)
    mitm_socket.bind(('', 800))
    mitm_socket.listen(10)

    sel = selectors.DefaultSelector()
    sel.register(mitm_socket, selectors.EVENT_READ | selectors.EVENT_WRITE)

    
    while True:

        events = sel.select()

        for key, mask in events:
            if key.fileobj == mitm_socket:
                accept_and_register()
            
            else:
                sock = key.fileobj

                if mask & selectors.EVENT_READ:
                    data = sock.recv(BUFFER_SIZE)

                    if data:
                        print(data)
                        res = client_to_mitm_client.get_key(sock)
                        sibling = res if res != -1 else client_to_mitm_client.get_value(sock)
                
                        sock_to_send_buff[sibling] += data

                elif mask & selectors.EVENT_WRITE:
                    print("Sending: " + str(sock_to_send_buff[sock]))
                    sock.sendall(bytes(sock_to_send_buff[sock]))
                


if __name__ == "__main__":
    main()

    