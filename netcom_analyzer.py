import struct


tftp = list()
ip_addresses = list()
ip_rank = dict()

def print_bytes(buffer):
    line_length = 0
    for spot in range(0, (len(buffer))):
        line_length += 1
        char = buffer[spot:spot + 1]
        first = (ord(char) >> 4) & 15
        second = ord(char) & 15
        print(format(first, 'x'), format(second, 'x'), " ", sep='', end='')
        if line_length == 8:
            print(" ", end='')
        if line_length == 16 or spot == len(buffer) - 1:
            print()
            line_length = 0


def print_mac(quelle, address):
    print("\n", quelle, sep='', end='')
    for spot in range(0, (len(address))):
        char = address[spot:spot + 1]
        first = (ord(char) >> 4) & 15
        second = ord(char) & 15
        print(format(first, 'x'), format(second, 'x'), " ", sep='', end='')


def print_srcip(buffer):
    src_ip1 = buffer[26:27]
    src_ip2 = buffer[27:28]
    src_ip3 = buffer[28:29]
    src_ip4 = buffer[29:30]
    print("Source IP: ", end='')
    source_ip = str(ord(src_ip1)) + '.' + str(ord(src_ip2)) + '.' + str(ord(src_ip3)) + '.' + str(ord(src_ip4))
    print(source_ip)
    if source_ip not in ip_addresses:
        ip_addresses.append(source_ip)
    if source_ip not in ip_rank.keys():
        ip_rank[source_ip] = 1
    else:
        ip_rank[source_ip] = ip_rank[source_ip] + 1

def print_dstip(buffer):
    dst_ip1 = buffer[30:31]
    dst_ip2 = buffer[31:32]
    dst_ip3 = buffer[32:33]
    dst_ip4 = buffer[33:34]
    print("Destination IP: ", end='')
    destination_ip = str(ord(dst_ip1))+'.'+str(ord(dst_ip2))+'.'+str(ord(dst_ip3))+'.'+str(ord(dst_ip4))
    print(destination_ip)


def print_udp(buffer):
    src_udp_port = buffer[34:36]
    src_udp_port = struct.unpack('>H', src_udp_port)
    src_udp_port = src_udp_port[0]
    dst_udp_port = buffer[36:38]
    dst_udp_port = struct.unpack('>H', dst_udp_port)
    dst_udp_port = dst_udp_port[0]
    if dst_udp_port == 69:
        tftp.append(src_udp_port)
        if src_udp_port in tftp and dst_udp_port not in tftp:
            tftp.append(dst_udp_port)
        if src_udp_port in tftp and dst_udp_port in tftp:
            print("TFTP")
    if dst_udp_port != 69 and (dst_udp_port in tftp or src_udp_port in tftp):
        if dst_udp_port in tftp and src_udp_port not in tftp:
            tftp.append(src_udp_port)
        if src_udp_port in tftp and dst_udp_port not in tftp:
            tftp.append(dst_udp_port)
        if src_udp_port in tftp and dst_udp_port in tftp:
            print("TFTP")
    if src_udp_port == 53 or dst_udp_port == 53:
        print("DNS")
    if src_udp_port == 137 or dst_udp_port == 137:
        print("NetBIOS Name Service")
    print("Source port: ", src_udp_port, "\nDestination port: ", dst_udp_port, sep='')
    pass


def print_tcp(buffer):
    src_tcp_port = buffer[34:36]
    src_tcp_port = struct.unpack('>H', src_tcp_port)
    src_tcp_port = src_tcp_port[0]
    dst_tcp_port = buffer[36:38]
    dst_tcp_port = struct.unpack('>H', dst_tcp_port)
    dst_tcp_port = dst_tcp_port[0]
    if src_tcp_port == 139 or dst_tcp_port == 139:
        print("NetBIOS Session Service")
    print("Source port: ", src_tcp_port, "\nDestination port: ", dst_tcp_port, sep='')
    pass


def print_ethernet_ip(buffer):
    print("Ethernet II", end='')
    print_mac('Source MAC: ', buffer[6:12])
    print_mac('Destination MAC: ', buffer[0:6])

    ip_info = buffer[14:15]
    ip_v = int(ord(ip_info) >> 4) & 15
    ip_hl = int(ord(ip_info)) & 15
    # print("\n", ord(ip_info))
    if ip_v == 4:
        print("\nIPv4 (IHL", str(ip_hl) + ")")
    transport_protocol = buffer[23:24]
    transport_protocol = ord(transport_protocol)
    print_srcip(buffer)
    print_dstip(buffer)
    if transport_protocol == 17:
        print("UDP")
        print_udp(buffer)
    elif transport_protocol == 6:
        print("TCP")
        print_tcp(buffer)
    print("File size", saved[0], ", sent by wire", wire[0], ", type", ftype[0])
    print()
    pass


def print_ethernet_arp(buffer):
    print("Ethernet II\nARP", end='')
    print_mac('Source MAC: ', buffer[6:12])
    print_mac('Destination MAC: ', buffer[0:6])
    print()
    pass

fh = open("/home/nicolas/Documents/FIIT/PKS/Zadanie_2/vzorky_pcap_na_analyzu/trace-16.pcap", "rb")
frame_number = 0
byte = fh.read(32)
while byte:
    frame_number += 1
    if frame_number > 1:
        byte = fh.read(8)
    saved = fh.read(4)
    if len(saved) < 1:
        break
    print("FRAME :", frame_number)
    saved = struct.unpack('<I', saved)
    wire = fh.read(4)
    wire = struct.unpack('<I', wire)
    next_frame_offset = wire[0]
    byte = buffer = fh.read(next_frame_offset)
    destination_address = buffer[6:12]
    source_address = buffer[0:6]
    ftype = buffer[12:14]
    ftype = struct.unpack('>H', ftype)
    print(ftype[0])
    next_frame_offset -= 12
    if ftype[0] > 1500:
        if ftype[0] == 2048:
            print_ethernet_ip(buffer)
        elif ftype[0] == 2054:
            print_ethernet_arp(buffer)
    else:
        ieee_type = buffer[14:15]
        if ieee_type[0] == 170:
            print("IEEE 802.3 SNAP")
        elif ieee_type[0] == 255:
            print("IEEE 802.3 Raw")
        else:
            print("IEEE 802.3 LLC")
        print_mac('Source MAC: ', source_address)
        print_mac('Destination MAC: ', destination_address)
        print()
    print_bytes(buffer)
    print()
print("IP addresses of sending nodes:")
for ipv4 in ip_rank.keys():
    print(ipv4)
sorted_ip_rank = sorted(ip_rank.items(), key=lambda kv: kv[1], reverse=True)
# print(sorted_ip_rank)
print("\nHighest number of packets (", sorted_ip_rank[0][1], ") was sent by ", sorted_ip_rank[0][0], sep='')
fh.close()
