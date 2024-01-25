import struct
import os
import sys
from enum import Enum
import ipaddress
import bidict

class TwoDirectionalDict:
    # assuming that forward_dict is injective
    def __init__(self, forward_dict:dict):
        self.forward_dict = forward_dict
        self.reverse_dict = {forward_dict[k]:k for k in forward_dict.keys()}

    def get_key(self, key):
        try:
            return self.forward_dict[key]
        except KeyError:
            return -1

    def get_value(self, value):
        try:
            return self.reverse_dict[value]
        except KeyError:
            return -1
    
    

"""

class ValidatableEnum(Enum):
    @classmethod
    def is_valid_field(cls, field:str):
        return field.isalpha() and field.islower() and field.upper() in cls.__members__ 

class Direction(ValidatableEnum):
    IN = 1
    OUT = 2
    ANY = 3

class Ack(ValidatableEnum):
    NO = 1
    YES = 2
    ANY = 3

class Protocol(ValidatableEnum):
    ICMP = 1
    TCP = 6
    UDP = 17
    OTHER = 255
    ANY = 143

"""

path_to_rules_attr = "/sys/class/fw/rules/rules"
rule_format = "<20s I I I B I I B H H B I B"
port_dict = TwoDirectionalDict({">1023": 1023, "any": 0})
protocol_dict = TwoDirectionalDict({"ICMP": 1, "TCP": 6, "UDP": 17, "other": 255, "any": 143})
direction_dict = TwoDirectionalDict({"in": 1, "out": 2, "any": 3})
ack_dict = TwoDirectionalDict({"no": 1, "yes": 2, "any": 3})
action_dict = TwoDirectionalDict({"accept": 1, "drop": 0})

class Rule:
    def __init__(self, name=None, direction=None, src_ip=None, src_prefix_size=None,
             dst_ip=None, dst_prefix_size=None, src_port=None, dst_port=None,
             protocol=None, ack=None, action=None):
        self.name = name
        self.direction = direction
        self.src_ip = src_ip
        self.src_prefix_size = src_prefix_size
        self.dst_ip = dst_ip
        self.dst_prefix_size = dst_prefix_size
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.ack = ack
        self.action = action


def try_convert_to_ip_and_prefix(s):
    splitted = s.split('/')
    if(len(splitted == 2)):
        try:
            ip = ipaddress.ip_address(splitted[0])
            prefix = splitted[1]
            if(prefix.is_decimal() and 0 <= int(prefix) <= 32):
                return ip, prefix
        except ValueError:
            return -1

def try_convert_to_port(s):
    res = port_dict.get_value(s)
    if res != -1:
        return res
    if s.is_decimal() and 0 < int(s) < 1023:
        return int(s)
    return -1

# here we can assume rule is ok since it has come from kernel module
def line_from_rule(rule: Rule):
    name = rule.name
    direction = direction_dict.get_key(rule.direction)
    src_ip_prefix = ipaddress.IPv4Address(rule.src_ip) + "/" + rule.src_prefix_size
    dst_ip_prefix = ipaddress.IPv4Address(rule.dst_ip) + "/" + rule.dst_prefix_size
    protocol = protocol_dict.get_key(rule.protocol)
    src_port = rule.src_port if 0<rule.src_port<1023 else port_dict.get_key(rule.src_port)
    dst_port = rule.dst_port if 0<rule.dst_port<1023 else port_dict.get_key(rule.dst_port)
    ack = ack_dict.get_key(rule.ack)
    action = action_dict.get_key(rule.action)
    return ' '.join([name, direction, src_ip_prefix, dst_ip_prefix, protocol, src_port, dst_port, ack, action])


def line_to_rule(line:str):
    rule = Rule()
    print_error = lambda fname: print("The "+fname+" field is not valid")
    fields = line.split(" ")
    if len(fields) != 9:
        return -1
    
    # name
    if(not 0 < len(fields[0]) < 20):
        return -1
    rule.name = fields[0]
    
    # direction
    res = direction_dict.get_value(fields[1])
    if(res == -1):
        print_error("direction")
        return -1
    rule.direction = res
    
    # source IP/prefix
    res = try_convert_to_ip_and_prefix(fields[2])
    if(res == -1):
        print_error("source IP/prefix")
        return -1
    rule.src_ip = res[0]
    rule.src_prefix_size = res[1]

    # destination IP/prefix
    res = try_convert_to_ip_and_prefix(fields[3])
    if(res == -1):
        print_error("destination IP/prefix")
        return -1
    rule.dst_ip = res[0]
    rule.dst_prefix_size = res[1]

    # protocol
    res = protocol_dict.get_value(fields[4])
    if(res == -1):
        print_error("protocol")
        return -1
    rule.protocol = res

    res = try_convert_to_port(fields[5])
    if(res == -1):
        print_error("source port")
        return -1
    rule.src_port = res
    
    res = try_convert_to_port(fields[6])
    if(res == -1):
        print_error("destination port")
        return -1
    rule.dst_port = res

    # ack
    res = ack_dict.get_value(fields[7])
    if(res == -1):
        print_error("ack")
        return -1
    rule.ack = res

    # action
    res = action_dict.get_value(fields[8])
    if(res == -1):
        print_error("action")
        return -1
    rule.action = res

    return rule


def rule_to_bytes(rule: Rule):
    try:
        data = struct.pack(rule_format, rule.name, rule.direction, rule.src_ip,
                            rule.src_prefix_size, rule.dst_ip, rule.dst_prefix_size,
                            rule.src_port, rule.dst_port, rule.protocol, rule.ack, rule.action)
        return data
    except:
        print("Error converting rule to bytes, check entry values")
        return -1

def rule_from_bytes(bin: bytes):
    try:
        rule_data = struct.unpack(rule_format, bin)
        rule = Rule()
        rule.name = rule_data[0]
        rule.direction = rule_data[1]
        rule.src_ip = rule_data[2]
        rule.src_prefix_size = rule_data[3]
        rule.dst_ip = rule_data[4]
        rule.dst_prefix_size = rule_data[5]
        rule.src_port = rule_data[6]
        rule.dst_port = rule_data[7]
        rule.protocol = rule_data[8]
        rule.ack = rule_data[9]
        rule.action = rule_data[10]
        return rule
    except:
        return -1

def load_rules(path):
    if not os.path.isfile(path):
        print("Invalid file path")
        return -1

    rules = []
    with open(path, "r") as file:
        for line in file.readlines():
            rule = line_to_rule(line)
            if(rule != -1):
                rules.append(rule)
            else:
                return -1
    
    with open(path_to_rules_attr, "wb") as rules_attr:
        rules_attr.write(b''.join([rule_to_bytes(r) for r in rules]))

    return 0


def show_rules():
    rules = []
    try:
        with open(path_to_rules_attr, "rb") as file:
            while True:
                rule_data = file.read(struct.calcsize(rule_format))
                if not rule_data:
                    break

                rule = rule_from_bytes()
                if(rule == -1):
                    print("Error converting bytes to rule")
                    return -1
                
                rules.append(rule)

            print('\n'.join([line_from_rule(r) for r in rules]))

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

    