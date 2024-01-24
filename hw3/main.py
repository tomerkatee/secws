import struct
import os
import sys

class Rule:
    def __init__(self, rule_name, direction, src_ip, src_prefix_mask, src_prefix_size,
                 dst_ip, dst_prefix_mask, dst_prefix_size, src_port, dst_port,
                 protocol, ack, action):
        self.rule_name = rule_name
        self.direction = direction
        self.src_ip = src_ip
        self.src_prefix_mask = src_prefix_mask
        self.src_prefix_size = src_prefix_size
        self.dst_ip = dst_ip
        self.dst_prefix_mask = dst_prefix_mask
        self.dst_prefix_size = dst_prefix_size
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.ack = ack
        self.action = action


def load_rules(path):
    if not os.path.isfile(path):
        print("Invalid file path")
        return -1

    # TODO: Implement loading rules from the file
    pass

def show_rules():
    path_to_rules_attr = "/sys/class/fw/rules/rules"
    format = "<20s I I I B I I B H H B I B"

    try:
        with open(path_to_rules_attr, "rb") as file:
            while True:
                rule_data = file.read(struct.calcsize(format))
                if not rule_data:
                    break

                rule = struct.unpack(format, rule_data)
                print(rule)

    except IOError as e:
        print("Error opening rules file: "+e)
        return -1
    
def main():
    if len(sys.argv) < 2:
        print("error: not enough arguments")
        sys.exit(-1)

    if sys.argv[1] == "load_rules":
        if len(sys.argv) != 3:
            print("error: there should be exactly 2 arguments given")
            sys.exit(-1)
        load_rules(sys.argv[1])
    elif len(sys.argv) != 2:
        print("error: too many arguments")
        sys.exit(-1)

    if sys.argv[1] == "show_rules":
        show_rules()
    elif sys.argv[1] == "show_log":
        pass  # TODO: Implement show_log
    elif sys.argv[1] == "clear_log":
        pass  # TODO: Implement clear_log
    else:
        print("error: bad arguments")



if __name__ == "__main__":
    main()

    