#!/usr/bin/env python3
import mitm
import signal
import sys
import classifier
import ipaddress


def signal_handler(sig, frame):
    print("\nCtrl+C detected. Cleaning up...")
    smtp_inspector.keep_running = False
    sys.exit(0)
    

signal.signal(signal.SIGINT, signal_handler)

client_data_buffer = ""
data_buffer_max_len = mitm.BUFFER_SIZE*2
smtp_inspector = None
HTTP_REGULAR_TRAFFIC_FILENAME = "www.programiz.com_Archive [24-05-15 17-43-55].har.tmp"
internal_subnet = ipaddress.IPv4Network('10.1.1.0/24')



class SMTPInspector(mitm.MITMInspector):
    def __init__(self):
        super().__init__(250)
        self.bad_packet = False
        self.clf = classifier.train(HTTP_REGULAR_TRAFFIC_FILENAME)
    
    def inspect_from_client(self, data, sock):
        global client_data_buffer

        if(not super().inspect_from_client(data, sock)):
            return False

        client_data_buffer += data.decode('utf-8', errors='ignore')
        client_data_buffer = client_data_buffer[-data_buffer_max_len:]

        # this represents a new "innocent" packet
        if("EHLO" in client_data_buffer):
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
    global smtp_inspector
    smtp_inspector = SMTPInspector()
    smtp_inspector.start_mitm()
    
                    

if __name__ == "__main__":
    main()

    