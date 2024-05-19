#!/usr/bin/env python3
import mitm
import signal
import sys
import classifier
import urllib.parse
import ipaddress


def signal_handler(sig, frame):
    print("\nCtrl+C detected. Cleaning up...")
    http_inspector.keep_running = False
    sys.exit(0)
    

signal.signal(signal.SIGINT, signal_handler)

server_data_buffer = ""
client_data_buffer = ""
data_buffer_max_len = mitm.BUFFER_SIZE*2
http_inspector = None
HTTP_REGULAR_TRAFFIC_FILENAME = "www.programiz.com_Archive [24-05-15 17-43-55].har.tmp"
internal_subnet = ipaddress.IPv4Network('10.1.1.0/24')


class HTTPInspector(mitm.MITMInspector):
    def __init__(self):
        super().__init__(800)
        self.bad_packet = False
        self.clf = classifier.train(HTTP_REGULAR_TRAFFIC_FILENAME)

    def inspect_from_server(self, data, sock):
        global server_data_buffer

        if(not super().inspect_from_server(data, sock)):
            return False

            
        server_data_buffer += urllib.parse.unquote_plus(data.decode('utf-8', errors='ignore'))
        server_data_buffer = server_data_buffer[-data_buffer_max_len:]


        # this represents a new "innocent" packet
        if("Content-Type:" in server_data_buffer):
            self.bad_packet = False

        # if we are still in the same bad packet as before don't pass the data
        if(self.bad_packet):
            return False
           
        # detecting a bad packet
        if("Content-Type: text/csv" in server_data_buffer or "Content-Type: application/zip" in server_data_buffer):
            self.bad_packet = True
            server_data_buffer = ""
            return False

        return True    
    
    def inspect_from_client(self, data, sock):
        global client_data_buffer

        if(not super().inspect_from_client(data, sock)):
            return False

        client_data_buffer += urllib.parse.unquote_plus(data.decode('utf-8', errors='ignore'))
        client_data_buffer = client_data_buffer[-data_buffer_max_len:]

        # this represents a new "innocent" packet
        if("Content-Type:" in client_data_buffer):
            self.bad_packet = False

        # if we are still in the same bad packet as before don't pass the data
        if(self.bad_packet):
            return False
    
        client_ip = ipaddress.IPv4Address(sock.getpeername()[0])

        if client_ip in internal_subnet and classifier.contains_c_code(self.clf, client_data_buffer):
            print("C code transfer detected, dropping packet!")
            self.bad_packet = True
            client_data_buffer = ""
            return False    

        return True    


def main():
    global http_inspector
    http_inspector = HTTPInspector()
    http_inspector.start_mitm()
    
                    

if __name__ == "__main__":
    main()

    