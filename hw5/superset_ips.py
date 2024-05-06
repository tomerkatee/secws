#!/usr/bin/env python3
import mitm
import signal
import sys
import re


def signal_handler(sig, frame):
    print("\nCtrl+C detected. Cleaning up...")
    superset_inspector.keep_running = False
    sys.exit(0)
    

signal.signal(signal.SIGINT, signal_handler)

server_data_buffer = ""
client_data_buffer = ""
data_buffer_max_len = mitm.BUFFER_SIZE*2
superset_inspector = None
valid_session_cookies = set()
session_cookie_re_format = r"session=([0-9a-zA-Z_\-.]+);"


class SupersetInspector(mitm.MITMInspector):
    def __init__(self):
        super().__init__(808)
        self.bad_packet = False

    def inspect_from_server(self, data, sock):
        if(not super().inspect_from_server(data, sock)):
            return False
        
        return True


        global server_data_buffer
        server_data_buffer += data.decode('utf-8', errors='ignore')
        server_data_buffer = server_data_buffer[-data_buffer_max_len:]
    
        for m in re.finditer(session_cookie_re_format, server_data_buffer):
            valid_session_cookies.add(m.group(1))


        return True
    

    def inspect_from_client(self, data, sock):
        if(not super().inspect_from_client(data, sock)):
            return False
        
        return True
        
        global client_data_buffer
        client_data_buffer += data.decode('utf-8', errors = 'ignore')
        client_data_buffer = client_data_buffer[-data_buffer_max_len:]

        print(len(valid_session_cookies))

        # this represents a new "innocent" packet
        if("Content-Type:" in client_data_buffer):
            self.bad_packet = False

        # if we are still in the same bad packet as before don't pass the data
        if(self.bad_packet):
            print("dropped the rest of the bad packet")
            return False
    
        for m in re.finditer(session_cookie_re_format, client_data_buffer):
            if m.group(1) not in valid_session_cookies:
                self.bad_packet = True
                client_data_buffer = ""
                print("dropped packet due to unknown session-cookie")
                return False
        

        return True
        

def main():
    global superset_inspector
    superset_inspector = SupersetInspector()
    superset_inspector.start_mitm()
    
                    

if __name__ == "__main__":
    main()

    