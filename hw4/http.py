#!/usr/bin/env python3
import struct
import socket
from main import Rule, convert_to_little_end_port, convert_to_big_end_port
import base64
   

path_to_mitm_attr = "/sys/class/fw/conns/mitm"
mitm_update_format = "<I H H"
mitm_get_server_format = "<I H"


    
def main():


    mitm_http = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_http.bind(('', 800))
    mitm_http.listen(10)


    while True:
        client_socket, client_addr = mitm_http.accept()

        print("client arrived")

        with open(path_to_mitm_attr, 'w+b') as mitm_attr:
            mitm_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mitm_client_socket.bind(('', 0))
            client_ip = Rule.ip_str_to_int(client_addr[0])
            client_port = convert_to_big_end_port(client_addr[1])
            mitm_port = convert_to_big_end_port(mitm_client_socket.getsockname()[1])

            print(str.format("client_ip: {}, client_port: {}, mitm_port: {}", client_ip, client_port, mitm_port))

            mitm_attr.write(struct.pack(mitm_update_format, client_ip, client_port, mitm_port))

            data = mitm_attr.read(struct.calcsize(mitm_get_server_format))

            server_addr_unformatted = struct.unpack(mitm_get_server_format, data)
            server_ip = Rule.int_to_ip_str(server_addr_unformatted[0])
            server_port = convert_to_little_end_port(server_addr_unformatted[1])

            mitm_client_socket.connect((server_ip, server_port))

            mitm_client_socket.send("hello".encode('utf-8'))

            
"""             buffer_size = 1024
            while True:
                data = client_socket.recv(buffer_size) """
                





if __name__ == "__main__":
    main()

    