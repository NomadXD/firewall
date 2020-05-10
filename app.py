def get_ip_header(frame):
    """ Extract ip header from a frame(a hex stream)
        Frame is obtained by reading the text file and stripping white space.
        Method returns a object that contain IP header information.
    """
    ip_header = {}
    ip_header['version'] = int(frame[28:29],16)
    ip_header['header_length'] = int(frame[29:30],16)
    ip_header['length'] = int(frame[32:36],16)
    ip_header['ttl'] = int(frame[44:46],16)
    ip_header['protocol'] = int(frame[46:48],16)
    ip_src = [int(frame[52:54],16),int(frame[54:56],16),int(frame[56:58],16),int(frame[58:60],16)]
    ip_header['source_address'] = '.'.join([str(x) for x in ip_src])
    ip_dest = [int(frame[60:62],16),int(frame[62:64],16),int(frame[64:66],16),int(frame[66:68],16)]
    ip_header['destination_address'] = '.'.join([str(x) for x in ip_dest])
    
    return ip_header


def get_tcp_header(frame):
    """Extract tcp header information from a frame(a hex stream)
        Frame is obtained by reading the text file and stripping white space.
        Method returns a object that contain TCP header information.
    """
    tcp_header = {}
    tcp_header['source_port'] = int(frame[68:72],16)
    tcp_header['destination_port'] = int(frame[72:76],16)
    
    return tcp_header


def read_frames(filename):
    """Method to read a text file line by line and store values
        in an array.
    """
    with open(filename) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    for frame in content:
        get_ip_header(frame)
        get_tcp_header(frame)
    return content


def read_rules(filename):
    """ Read a config file and parse the
        rules stored in it. Stores the rules 
        in an array.
    """
    rules = []
    with open(filename) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    lines = list(filter(None,content))
    for line in content:
        if(line and not line.startswith("#")):
            line = line.split('\t\t\t')
            rules.append(line)
    return rules


def simulate_firewall(interface):
    if(interface == 'external'):
        frames = read_frames('interface_external.txt')
    else:
        frames = read_frames('interface_internal.txt')
    rules = read_rules('config.txt')
    for frame in frames:
        accepted = False
        ip_header = get_ip_header(frame)
        tcp_header = get_tcp_header(frame)
        print(ip_header,tcp_header)
        for rule in rules:
            if(rule[1] == 'TCP' and ip_header['protocol'] == 6 and rule[6] == '1'):
                if((rule[2] == 'anywhere' or ip_header['source_address'] == rule[2]) and 
                    (str(tcp_header['destination_port']) == 'any' or str(tcp_header['destination_port']) == rule[5])):
                    if(rule[0] == 'ACCEPT'):
                        accepted = True
                        print("Packet accepted under rule {0}".format(rule[7]))
                    else:
                        accepted = False
                        print("Packet dropped under rule {0}".format(rule[7]))
                    
            elif(rule[1] == 'UDP' and ip_header['protocol'] == 17 and rule[6] == '1'):
                if((rule[2] == 'anywhere' or ip_header['source_address'] == rule[2]) and 
                    (str(tcp_header['destination_port']) == 'any' or str(tcp_header['destination_port']) == rule[5])):
                    if(rule[0] == 'ACCEPT'):
                        accepted = True
                        print("Packet accepted under rule %s" %rule[7])
                    else:
                        accepted = False
                        print("Packet dropped under rule %s" %rule[7])

        if(accepted):
            print("Forwarding packet to {0}".format(ip_header["destination_address"]))
        else:
            print("Packet dropped.")
        
        #print(accepted)


simulate_firewall('external')


