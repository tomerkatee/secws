#!/usr/bin/env python3
import mitm
import signal
import sys
import re
import struct
from main import conn_format, convert_to_big_end_port, Rule


def signal_handler(sig, frame):
    print("\nCtrl+C detected. Cleaning up...")
    http_inspector.mitm_listen_socket.close()
    sys.exit(0)
    

signal.signal(signal.SIGINT, signal_handler)

data_buffer = ""
data_buffer_max_len = mitm.BUFFER_SIZE*2
http_inspector = None
port_re_format = r"PORT ([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)"
path_to_add_conn_attr = "/sys/class/fw/conns/add_conn"
add_conn_format = "<I I H H"
FTP_DATA_CONNECTION_PORT = 20


class FTPInspector(mitm.MITMInspector):
    def inspect_from_client(self, data, sock):
        global data_buffer

        if(not super().inspect_from_client(data)):
            return False


        # convert base64 encoded bytes to actual data text
        #data_str = base64.b64decode(data+b'==').decode('utf-8')

        data_buffer += data.decode('utf-8')
        data_buffer = data_buffer[-data_buffer_max_len:]


        match = re.search(port_re_format, data_buffer)

        if match:
            with open(path_to_add_conn_attr, 'wb') as add_conn_attr:
                server_addr = self.client_to_mitm_client[sock].getpeername()
                server_ip = Rule.ip_str_to_int(server_addr[0])
                server_port = convert_to_big_end_port(FTP_DATA_CONNECTION_PORT)

                client_ip_str = match.group(1)+"."+match.group(2)+"."+match.group(3)+"."+match.group(4)
                client_ip = Rule.ip_str_to_int(client_ip_str)
                client_port_little = int(match.group(5))*256 + int(match.group(6))
                client_port = convert_to_big_end_port(client_port_little)

                add_conn_attr.write(struct.pack(conn_format, client_ip, server_ip, client_port, server_port))

        return True
    

def main():
    global http_inspector
    http_inspector = FTPInspector()
    http_inspector.start_mitm()
    
                    

if __name__ == "__main__":
    main()

    