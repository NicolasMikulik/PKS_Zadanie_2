import struct


def print_bytes(buffer):
    line_length = 0
    for spot in range(0, (len(buffer))):
        line_length += 1
        char = buffer[spot:spot + 1]
        first = (ord(char) >> 4) & 15
        second = ord(char) & 15
        print(format(first, 'x'), format(second, 'x'), " ", sep='', end='')
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
    print(ord(src_ip1), ord(src_ip2), ord(src_ip3), ord(src_ip4), sep='.')

def print_dstip(buffer):
    dst_ip1 = buffer[30:31]
    dst_ip2 = buffer[31:32]
    dst_ip3 = buffer[32:33]
    dst_ip4 = buffer[33:34]
    print("Destination IP: ", end='')
    print(ord(dst_ip1), ord(dst_ip2), ord(dst_ip3), ord(dst_ip4), sep='.')


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
    '''src_ip1 = buffer[26:27]
    src_ip2 = buffer[27:28]
    src_ip3 = buffer[28:29]
    src_ip4 = buffer[29:30]
    print("Source IP: ", end='')
    print(ord(src_ip1), ord(src_ip2), ord(src_ip3), ord(src_ip4), sep='.')'''
    print_srcip(buffer)
    '''dst_ip1 = buffer[30:31]
    dst_ip2 = buffer[31:32]
    dst_ip3 = buffer[32:33]
    dst_ip4 = buffer[33:34]
    print("Destination IP: ", end='')
    print(ord(dst_ip1), ord(dst_ip2), ord(dst_ip3), ord(dst_ip4), sep='.')'''
    print_dstip(buffer)
    if transport_protocol == 17:
        print("UDP")
    elif transport_protocol == 6:
        print("TCP")
    print_bytes(buffer)
    print("File size", saved[0], ", sent by wire", wire[0], ", type", ftype[0])
    print()
    pass


def print_ethernet_arp(buffer):
    print("Ethernet II\nARP", end='')
    print_mac('Source MAC: ', buffer[6:12])
    print_mac('Destination MAC: ', buffer[0:6])
    print()
    print_bytes(buffer)
    print()
    pass

fh = open("/home/nicolas/Documents/FIIT/PKS/Zadanie_2/vzorky_pcap_na_analyzu/eth-8.pcap", "rb")
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
            print_mac('Source MAC: ', source_address)
            print_mac('Destination MAC: ', destination_address)
            print()
            print_bytes()
            print()
        elif ieee_type[0] == 255:
            print("IEEE 802.3 Raw")
            print_mac('Source MAC: ', source_address)
            print_mac('Destination MAC: ', destination_address)
            print()
            print_bytes()
            print()
        else:
            print("IEEE 802.3 LLC")
            print_mac('Source MAC: ', source_address)
            print_mac('Destination MAC: ', destination_address)
            print()
            print_bytes()
            print()

fh.close()
