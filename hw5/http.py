#!/usr/bin/env python3
import mitm
import signal
import sys
import classifier


def signal_handler(sig, frame):
    print("\nCtrl+C detected. Cleaning up...")
    http_inspector.keep_running = False
    sys.exit(0)
    

signal.signal(signal.SIGINT, signal_handler)

data_buffer = ""
data_buffer_max_len = mitm.BUFFER_SIZE*2
http_inspector = None
HTTP_REGULAR_RESPONSES_FILENAME = "www.offsec.com_Archive [24-05-09 12-37-19].har"


class HTTPInspector(mitm.MITMInspector):
    def __init__(self):
        super().__init__(800)
        self.bad_packet = False
        self.clf = classifier.train(HTTP_REGULAR_RESPONSES_FILENAME)

    def inspect_from_server(self, data, sock):
        global data_buffer

        if(not super().inspect_from_server(data, sock)):
            return False

            
        data_buffer += data.decode('utf-8', errors='ignore')
        data_buffer = data_buffer[-data_buffer_max_len:]


        # this represents a new "innocent" packet
        if("Content-Type:" in data_buffer):
            self.bad_packet = False

        # if we are still in the same bad packet as before don't pass the data
        if(self.bad_packet):
            return False
           
        # detecting a bad packet
        if("Content-Type: text/csv" in data_buffer or "Content-Type: application/zip" in data_buffer):
            self.bad_packet = True
            data_buffer = ""
            return False
        
        if classifier.contains_c_code(self.clf, data_buffer):
            print("C code transfer detected, dropping packet!")
            self.bad_packet = True
            data_buffer = ""
            return False    

        return True    


def main():
    global http_inspector
    http_inspector = HTTPInspector()
    http_inspector.start_mitm()
    
                    

if __name__ == "__main__":
    main()

    