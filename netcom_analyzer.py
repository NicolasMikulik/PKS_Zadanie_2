import struct
import binascii

fh = open("/home/nicolas/Documents/FIIT/PKS/Zadanie_2/vzorky_pcap_na_analyzu/eth-8.pcap", "rb")
byte = fh.read(32)
saved = fh.read(4)
saved = struct.unpack('<I', saved)
wire = fh.read(4)
next_frame_offset = wire[0]
byte = buffer = fh.read(next_frame_offset)
fh.seek(40, 0)
wire = struct.unpack('<I', wire)
destination_address = buffer[0:6]
source_adress = buffer[6:12]
ftype = buffer[12:14]
ftype = struct.unpack('>H', ftype)
print(ftype[0])
next_frame_offset -= 12
if ftype[0] == 2048:
    ip_info = buffer[14:15]
    print(ord(ip_info))
    ip_v = int(ord(ip_info) >> 4) & 15
    ip_hl = int(ord(ip_info)) & 15
    print("IPv", ip_v, "IHL", ip_hl)
    transport_protocol = buffer[23:24]
    transport_protocol = ord(transport_protocol)
    src_ip1 = buffer[26:27]
    src_ip2 = buffer[27:28]
    src_ip3 = buffer[28:29]
    src_ip4 = buffer[29:30]
    print(ord(src_ip1), ord(src_ip2), ord(src_ip3), ord(src_ip4))
    dst_ip1 = buffer[30:31]
    dst_ip2 = buffer[31:32]
    dst_ip3 = buffer[32:33]
    dst_ip4 = buffer[33:34]
    print(ord(dst_ip1), ord(dst_ip2), ord(dst_ip3), ord(dst_ip4))
    print("Transport protocol", transport_protocol)
    print(buffer, len(buffer))
    line_length = 0
    for spot in range(0, (len(buffer))):
        line_length += 1
        char = buffer[spot:spot+1]
        first = (ord(char) >> 4) & 15
        second = ord(char) & 15
        print(format(first, 'x'), format(second, 'x'), " ", sep='', end='')
        if line_length == 16:
            print()
            line_length = 0
    pass
print("\nFile size", saved[0], ", sent by wire", wire[0], ", type", ftype[0])
fh.close()