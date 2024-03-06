#!/usr/bin/env python3
import mitm
import signal
import sys
import re
import struct
from main import convert_to_big_end_port, Rule


def signal_handler(sig, frame):
    print("\nCtrl+C detected. Cleaning up...")
    ftp_inspector.keep_running = False
    sys.exit(0)
    

signal.signal(signal.SIGINT, signal_handler)

data_buffer = ""
data_buffer_max_len = mitm.BUFFER_SIZE*2
ftp_inspector = None
port_re_format = r"PORT ([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)"
path_to_add_conn_attr = "/sys/class/fw/conns/add_conn"
add_conn_format = "<I I H H"
FTP_DATA_CONNECTION_PORT = 20


class FTPInspector(mitm.MITMInspector):
    def __init__(self):
        super().__init__(210)

    def inspect_from_client(self, data, sock):
        global data_buffer

        print("inspecting...")

        if(not super().inspect_from_client(data, sock)):
            return False
            

        # convert base64 encoded bytes to actual data text
        #data_str = base64.b64decode(data+b'==').decode('utf-8')

        data_buffer += data.decode('utf-8')
        data_buffer = data_buffer[-data_buffer_max_len:]


        print("Searching...")
        last_match = None
        for m in re.finditer(port_re_format, data_buffer):
            last_match = m


        if last_match:
            print("match!")

            with open(path_to_add_conn_attr, 'wb') as add_conn_attr:
                server_addr = self.client_to_mitm_client.get_value(sock).getpeername()
                server_ip = Rule.ip_str_to_int(server_addr[0])
                server_port = convert_to_big_end_port(FTP_DATA_CONNECTION_PORT)

                client_ip_str = last_match.group(1)+"."+last_match.group(2)+"."+last_match.group(3)+"."+last_match.group(4)
                client_ip = Rule.ip_str_to_int(client_ip_str)
                client_port_little = int(last_match.group(5))*256 + int(last_match.group(6))
                client_port = convert_to_big_end_port(client_port_little)

                print(client_ip_str + ": " + str(client_port_little))

                add_conn_attr.write(struct.pack(add_conn_format, client_ip, server_ip, client_port, server_port))

        else:
            print("no match!")
            
        return True
    
    

def main():
    global ftp_inspector
    ftp_inspector = FTPInspector()
    ftp_inspector.start_mitm()
    
                    

if __name__ == "__main__":
    main()

    