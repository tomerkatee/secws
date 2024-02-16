#!/usr/bin/env python3
import struct
import os
import sys
import ipaddress
import datetime

# a dict that can get value from key and key from value
class TwoDirectionalDict:
    # assuming that forward_dict is injective
    def __init__(self, forward_dict:dict):
        self.forward_dict = forward_dict
        self.reverse_dict = {forward_dict[k]:k for k in forward_dict.keys()}

    def get_value(self, key):
        try:
            return self.forward_dict[key]
        except KeyError:
            return -1
        
    def get_key(self, value):
        try:
            return self.reverse_dict[value]
        except KeyError:
            return -1


path_to_rules_attr = "/sys/class/fw/rules/rules"
path_to_reset_attr = "/sys/class/fw/fw_log/reset"
path_to_log = "/dev/fw_log"
path_to_conns_attr = "/sys/class/fw/conns/conns"
rule_format = "<20s I I B I B H H B I B"
log_format = "<L B B I I H H i I"
conn_format = "<I I H H I"
port_dict = TwoDirectionalDict({">1023": 1023, "any": 0})
protocol_dict = TwoDirectionalDict({"ICMP": 1, "TCP": 6, "UDP": 17, "other": 255, "any": 143})
direction_dict = TwoDirectionalDict({"in": 1, "out": 2, "any": 3})
ack_dict = TwoDirectionalDict({"no": 1, "yes": 2, "any": 3})
action_dict = TwoDirectionalDict({"accept": 1, "drop": 0})
reason_dict = TwoDirectionalDict({"REASON_FW_INACTIVE" : -1, "REASON_NO_MATCHING_RULE": -2, "REASON_XMAS_PACKET": -4, "REASON_ILLEGAL_VALUE": -6})
state_dict = TwoDirectionalDict({"SYN_SENT" : 0, "SYN_ACK_SENT": 1, "WAIT_FOR_SYN_ACK": 2, "WAIT_FOR_ACK": 3, "ESTABLISHED": 4})

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

    @staticmethod
    def int_to_ip_str(ip_n):
        return str(ipaddress.IPv4Address(ip_n.to_bytes(4, byteorder='little')))
        
    @staticmethod
    def ip_str_to_int(ip_str):
        return int.from_bytes(ipaddress.IPv4Address(ip_str).packed, byteorder='little')
    


class LogRow:
    def __init__(self, timestamp=None, protocol=None, action=None, src_ip=None, dst_ip=None,
                 src_port=None, dst_port=None, reason=None, count=None):
        self.timestamp = timestamp
        self.protocol = protocol
        self.action = action
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.reason = reason
        self.count = count

    @staticmethod 
    def timestamp_seconds_to_format(ts_epoch):
        return datetime.datetime.fromtimestamp(ts_epoch).strftime('%d/%m/%Y %H:%M:%S')


class ConnRow:
    def __init__(self, src_ip=None, dst_ip=None,
                 src_port=None, dst_port=None, state=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.state = state


def try_convert_to_ip_and_prefix(s):
    if(s == "any"):
        return try_convert_to_ip_and_prefix("0.0.0.0/0")

    splitted = s.split('/')
    if len(splitted) == 2:
        try:
            ip = Rule.ip_str_to_int(splitted[0])
            prefix = int(splitted[1])
            if(0 <= prefix <= 32):
                return ip, prefix
        except:
            return -1


def convert_to_little_end_port(p):
    big_endian_bytes = p.to_bytes(2, byteorder='big')
    return int.from_bytes(big_endian_bytes, byteorder='little')

def convert_to_big_end_port(p):
    little_endian_bytes = p.to_bytes(2, byteorder='little')
    return int.from_bytes(little_endian_bytes, byteorder='big')

def try_convert_to_port(s):
    res = port_dict.get_value(s)
    if res != -1:
        return convert_to_big_end_port(res)
    if s.isdigit() and 0 < int(s) < 1023:
        return convert_to_big_end_port(int(s))
    return -1

# here we can assume rule is ok since it has come from kernel module
def line_from_rule(rule: Rule):
    name = rule.name.rstrip(b'\x00').decode('utf-8')
    direction = direction_dict.get_key(rule.direction)
    get_ip_prefix = lambda ip,prefix_size: "any" if prefix_size == 0 else Rule.int_to_ip_str(ip) + "/" + str(prefix_size)
    src_ip_prefix = get_ip_prefix(rule.src_ip, rule.src_prefix_size)
    dst_ip_prefix = get_ip_prefix(rule.dst_ip, rule.dst_prefix_size)
    protocol = protocol_dict.get_key(rule.protocol)
    get_port = lambda port: port if 0<port<1023 else port_dict.get_key(port)
    src_port = get_port(convert_to_little_end_port(rule.src_port))
    dst_port = get_port(convert_to_little_end_port(rule.dst_port))
    ack = ack_dict.get_key(rule.ack)
    action = action_dict.get_key(rule.action)
    return ' '.join(map(str,[name, direction, src_ip_prefix, dst_ip_prefix, protocol, src_port, dst_port, ack, action]))


def line_to_rule(line:str):
    rule = Rule()
    fields = line.split(" ")
    if len(fields) != 9:
        return -1
    
    # name
    if(not 0 < len(fields[0]) < 20):
        return -1
    rule.name = fields[0].encode('utf-8')

    print_error = lambda fname: print("The "+fname+" field is not valid in rule "+rule.name)

    
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
    except ValueError:
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
            rule = line_to_rule(line.rstrip())
            if(rule != -1):
                rules.append(rule)
            else:
                return -1
    
    rules_data = b''.join([rule_to_bytes(r) for r in rules])
    
    with open(path_to_rules_attr, "wb") as rules_attr:
        rules_attr.write(rules_data)
        
    return 0



def show_rules():
    rules = []
    try:
        with open(path_to_rules_attr, "rb") as rules_attr:
            while True:
                rule_data = rules_attr.read(struct.calcsize(rule_format))
                if not rule_data:
                    break

                rule = rule_from_bytes(rule_data)
                if(rule == -1):
                    print("Error converting bytes to rule")
                    return -1
                
                rules.append(rule)

        print('\n'.join([line_from_rule(r) for r in rules]))

    except IOError as e:
        print("Error opening rules file: "+str(e))
        return -1
    
def log_row_from_bytes(bin: bytes):
    try:
        log_data = struct.unpack(log_format, bin)
        log_row = LogRow()
        
        log_row.timestamp = log_data[0]
        log_row.protocol = log_data[1]
        log_row.action = log_data[2]
        log_row.src_ip = log_data[3]
        log_row.dst_ip = log_data[4]
        log_row.src_port = log_data[5]
        log_row.dst_port = log_data[6]
        log_row.reason = log_data[7]
        log_row.count = log_data[8]
        return log_row
    except:
        return -1


# here we can assume log_row is ok since it has come from kernel module
def line_from_log_row(log_row: LogRow):
    timestamp = LogRow.timestamp_seconds_to_format(log_row.timestamp)
    src_ip = Rule.int_to_ip_str(log_row.src_ip)
    dst_ip = Rule.int_to_ip_str(log_row.dst_ip)
    src_port = convert_to_little_end_port(log_row.src_port)
    dst_port = convert_to_little_end_port(log_row.dst_port)
    protocol = protocol_dict.get_key(log_row.protocol)
    action = action_dict.get_key(log_row.action)
    reason = reason_dict.get_key(log_row.reason)
    reason = reason if reason != -1 else log_row.reason
    count = log_row.count

    return '\t\t'.join(map(str,[timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, reason, count]))


def show_log():
    log_rows = []
    try:
        with open(path_to_log, 'rb') as log_file:
            while True:
                log_data = log_file.read(struct.calcsize(log_format))
                if not log_data:
                    break

                log_row = log_row_from_bytes(log_data)
                if(log_row == -1):
                    print("Error converting bytes to log row")
                    return -1
                
                log_rows.append(log_row)

        print('\t\t\t'.join(["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action", "reason", "count"]))
        print('\n'.join([line_from_log_row(r) for r in log_rows]))

    except IOError as e:
        print("Error opening log file: "+str(e))
        return -1
    
        
        
def clear_log():
    with open(path_to_reset_attr, 'w') as reset_attr:
        reset_attr.write("0")



def conn_row_from_bytes(bin: bytes):
    try:
        conn_data = struct.unpack(conn_format, bin)
        conn_row = ConnRow()
        conn_row.src_ip = conn_data[0]
        conn_row.dst_ip = conn_data[1]
        conn_row.src_port = conn_data[2]
        conn_row.dst_port = conn_data[3]
        conn_row.state = conn_data[4]
        return conn_row
    except:
        return -1


# here we can assume conn_row is ok since it has come from kernel module
def line_from_conn_row(conn_row: ConnRow):
    src_ip = Rule.int_to_ip_str(conn_row.src_ip)
    dst_ip = Rule.int_to_ip_str(conn_row.dst_ip)
    src_port = convert_to_little_end_port(conn_row.src_port)
    dst_port = convert_to_little_end_port(conn_row.dst_port)
    state = state_dict.get_key(conn_row.state)
    return '\t\t'.join(map(str,[src_ip, dst_ip, src_port, dst_port, state]))


def show_conns():
    conn_rows = []
    try:
        with open(path_to_conns_attr, 'rb') as conns_file:
            while True:
                conns_data = conns_file.read(struct.calcsize(conn_format))
                if not conns_data:
                    break

                conn_row = conn_row_from_bytes(conns_data)
                if(conn_row == -1):
                    print("Error converting bytes to connection row")
                    return -1
                
                conn_rows.append(conn_row)

        print('\t\t\t'.join(["src_ip", "dst_ip", "src_port", "dst_port", "state"]))
        print('\n'.join([line_from_conn_row(r) for r in conn_rows]))

    except IOError as e:
        print("Error opening conns file: "+str(e))
        return -1

    
def main():
    if len(sys.argv) < 2:
        print("error: not enough arguments")
        sys.exit(-1)

    if sys.argv[1] == "load_rules":
        if len(sys.argv) != 3:
            print("error: there should be exactly 2 arguments given")
            sys.exit(-1)
        load_rules(sys.argv[2])
    elif len(sys.argv) != 2:
        print("error: too many arguments")
        sys.exit(-1)
    elif sys.argv[1] == "show_rules":
        show_rules()
    elif sys.argv[1] == "show_log":
        show_log()
    elif sys.argv[1] == "clear_log":
        clear_log()
    elif sys.argv[1] == "show_conns":
        show_conns()
    else:
        print("error: bad arguments")



if __name__ == "__main__":
    main()

    