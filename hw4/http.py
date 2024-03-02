#!/usr/bin/env python3
import mitm
import base64

class HTTPInspector(mitm.MITMInspector):
    def inspect_from_server(self, data):
        if(not super().inspect_from_server(data)):
            return False
        
        # convert base64 encoded bytes to actual data text
        data_str = base64.b64decode(data.decode('utf-8')).decode('utf-8')

        print(data_str)

        return True


def main():
    http_inspector = mitm.MITMInspector()
    http_inspector.start_mitm()
    
                    

if __name__ == "__main__":
    main()

    