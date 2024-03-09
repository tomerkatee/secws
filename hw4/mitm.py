import struct
import socket
from main import Rule, convert_to_little_end_port, convert_to_big_end_port, TwoDirectionalDict
import selectors
import time
   

path_to_mitm_attr = "/sys/class/fw/conns/mitm"
mitm_update_format = "<I H H"
mitm_get_server_format = "<I H"
BUFFER_SIZE = 1024




class MITMInspector():
    def __init__(self, port):
        self.mitm_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.mitm_listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sel = selectors.DefaultSelector()
        self.client_to_mitm_client = TwoDirectionalDict({})
        self.sock_to_send_buff = {}
        self.listen_port = port        
        self.sockets = [self.mitm_listen_socket]
        self.keep_running = True

    def accept_and_register(self):
        client_socket, client_addr = self.mitm_listen_socket.accept()
        self.sockets.append(client_socket)

        with open(path_to_mitm_attr, 'wb') as mitm_attr:
            mitm_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mitm_client_socket.bind(('', 0))
            client_ip = Rule.ip_str_to_int(client_addr[0])
            client_port = convert_to_big_end_port(client_addr[1])
            mitm_port = convert_to_big_end_port(mitm_client_socket.getsockname()[1])

            print(str.format("client_ip: {}, client_port: {}, mitm_port: {}", client_ip, client_port, mitm_port))

            mitm_attr.write(struct.pack(mitm_update_format, client_ip, client_port, mitm_port))

        with open(path_to_mitm_attr, 'rb') as mitm_attr:
            
            data = mitm_attr.read(struct.calcsize(mitm_get_server_format))

            server_addr_unformatted = struct.unpack(mitm_get_server_format, data)

            server_ip = Rule.int_to_ip_str(server_addr_unformatted[0])
            server_port = convert_to_little_end_port(server_addr_unformatted[1])

        mitm_client_socket.connect((server_ip, server_port))
        self.sockets.append(mitm_client_socket)

        client_socket.setblocking(False)
        mitm_client_socket.setblocking(False)
        self.client_to_mitm_client.add_pair(client_socket, mitm_client_socket)
        self.sock_to_send_buff[client_socket] = bytearray()
        self.sock_to_send_buff[mitm_client_socket] = bytearray()
        self.sel.register(client_socket, selectors.EVENT_READ | selectors.EVENT_WRITE)
        self.sel.register(mitm_client_socket, selectors.EVENT_READ | selectors.EVENT_WRITE)
        
    def inspect_from_server(self, data, sock):
        return True
    
    def inspect_from_client(self, data, sock):
        return True

    def start_mitm(self):

        self.mitm_listen_socket.setblocking(False)
        self.mitm_listen_socket.bind(('', self.listen_port))
        self.mitm_listen_socket.listen(10)

        self.sel.register(self.mitm_listen_socket, selectors.EVENT_READ | selectors.EVENT_WRITE)

    
        
        while self.keep_running:
            events = self.sel.select()

            for key, mask in events:
                if key.fileobj == self.mitm_listen_socket:
                    self.accept_and_register()
                
                else:
                    sock = key.fileobj

                    if mask & selectors.EVENT_READ:
                        data = sock.recv(BUFFER_SIZE)

                        res = self.client_to_mitm_client.get_key(sock)
                    
                        if data:
                            inspection_ok = self.inspect_from_server(data, sock) if res != -1 else self.inspect_from_client(data, sock)
                            if(inspection_ok):
                                sibling = res if res != -1 else self.client_to_mitm_client.get_value(sock)

                                self.sock_to_send_buff[sibling] += data
                        else:
                            self.sel.unregister(sock)
                            sock.close()
                            self.sockets.remove(sock)
                        

                    elif mask & selectors.EVENT_WRITE:
                        try:
                            data_to_send = bytes(self.sock_to_send_buff[sock])
                            if(len(data_to_send) > 0):
                                sock.sendall(data_to_send)
                                self.sock_to_send_buff[sock] = bytearray()
                            else:
                                time.sleep(0.02) # this prevents a scenario of empty EVENT_WRITE's sucking too many CPU time

                        except:
                            self.sel.unregister(sock)
                            sock.close()
                            self.sockets.remove(sock)

        self.sel.close()
        self.close_sockets()


    def close_sockets(self):
        print("closing sockets")
        for sock in self.sockets:
            sock.close()

    