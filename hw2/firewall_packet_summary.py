import sys, os

def main():
    argc = len(sys.argv)

    if(argc > 2):
        print("Error: too many arguments passed")
        return -1
    
    path_to_device = "/sys/class/firewall_devices/firewall_devices_packet_summary"
    path_to_accepted = path_to_device + "/accepted_attr"
    path_to_dropped = path_to_device + "/dropped_attr"

    if(argc == 1):
        def read_attr(path):
            with open(path, 'r') as file:
                return int(file.read())
            
        accepted = read_attr(path_to_accepted)
        dropped = read_attr(path_to_dropped)
        
        print('''Firewall Packets Summary:
Number of accepted packets: {0}
Number of dropped packets: {1}
Total number of packets: {2}'''.format(accepted, dropped, accepted+dropped))

    if(argc == 2):
        if(sys.argv[1] != "0"):
            print("Error: only argument \"0\" is allowed")
            return -1

        zero_attr = lambda path: os.system("echo 0 | sudo tee {0} > /dev/null".format(path))
        zero_attr(path_to_accepted)
        zero_attr(path_to_dropped)
    

if __name__ == "__main__":
    main()