#!/usr/bin/env python3
import errno
import struct
import socket
import sys
from main import Rule, convert_to_little_end_port, convert_to_big_end_port
import base64
   

path_to_mitm_attr = "/sys/class/fw/conns/mitm"
mitm_update_format = "<I H H"
mitm_get_server_format = "<I H"
BUFFER_SIZE = 1024


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

    
def main():


    mitm_http = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_http.bind(('', 800))
    mitm_http.listen(10)


    while True:
        client_socket, client_addr = mitm_http.accept()


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
            print(server_ip + " " +str(server_port))

            mitm_client_socket.connect((server_ip, server_port))

            client_socket.setblocking(False)
            mitm_client_socket.setblocking(False)

            while True:
                data = recv_until_blocking(client_socket)
                if data:
                    print(data)
                    send_until_blocking(mitm_client_socket, data)

                data = recv_until_blocking(mitm_client_socket)
                if data:
                    print(data)
                    send_until_blocking(client_socket, data)


            
"""             buffer_size = 1024
            while True:
                data = client_socket.recv(buffer_size) """
                





if __name__ == "__main__":
    main()

    