


def get_ip_header(frame):
    ip_header = {}
    ip_header['version'] = int(frame[28:29],16)
    ip_header['header_length'] = int(frame[29:30],16)
    ip_header['length'] = int(frame[32:36],16)
    ip_header['ttl'] = int(frame[44:46],16)
    ip_header['protocol'] = int(frame[46:48],16)
    ip_header['source_address'] = [int(frame[52:54],16),int(frame[54:56],16),int(frame[56:58],16),int(frame[58:60],16)]
    ip_header['destination_address'] = [int(frame[60:62],16),int(frame[62:64],16),int(frame[64:66],16),int(frame[66:68],16)]
    #print(ip_header['protocol'])
    #print(ip_header['source_address'])
    #print(ip_header['destination_address'])
    #print(frame[56:58])
    #print(ip_header['version'])
    #print(ip_header['length'])
    #print(ip_header['ttl'])
    #print(ip_header['protocol'])
    print(ip_header)


def get_tcp_header(frame):
    tcp_header = {}
    tcp_header['source_port'] = int(frame[68:72],16)
    tcp_header['destination_port'] = int(frame[72:76],16)
    print(frame[72:76])


def read_frames(filename):
    with open(filename) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    print(content)
    return content
    #for frame in content:
        #get_ip_header(frame)
        #get_tcp_header(frame)
    #print(content)


def read_rules(filename):
    rules = []
    with open(filename) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    lines = list(filter(None,content))
    for line in content:
        if(line and not line.startswith("#")):
            line = line.split('\t\t\t')
            rules.append(line)

    print(rules)


def simulate_int_one():
    frames = read_frames('interface_external.txt')
    for frame in frames:
        print(frame)

        
        


#simulate_int_one()

#read_frames('interface_external.txt')

#read_rules('config.txt')
#read_frames('interface_external.txt')



# def get_ip_header(frame):
#     ip_header = {}
#     ip_header['version'] = int(frame[])
