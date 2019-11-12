import struct

fh = open("/home/nicolas/Documents/FIIT/PKS/Zadanie_2/vzorky_pcap_na_analyzu/eth-8.pcap", "rb")
byte = fh.read(32)
# while byte:
saved = fh.read(4)
saved = struct.unpack('<I', saved)
wire = fh.read(4)
next_frame_offset = wire[0]
wire = struct.unpack('<I', wire)
destination_address = fh.read(6)
source_adress = fh.read(6)
ftype = fh.read(2)
ftype = struct.unpack('>H', ftype)
next_frame_offset -= 12
if ftype[0] == 2048:
    ip_info = fh.read(1)
    print(ord(ip_info))
    ip_v = int(ord(ip_info) >> 4) & 15
    ip_hl = int(ord(ip_info)) & 15
    print("IPv", ip_v, "IHL", ip_hl)
    byte = fh.read(8)
    transport_protocol = fh.read(1)
    transport_protocol = ord(transport_protocol)
    byte = fh.read(2)
    src_ip1 = fh.read(1)
    src_ip2 = fh.read(1)
    src_ip3 = fh.read(1)
    src_ip4 = fh.read(1)
    print(ord(src_ip1), ord(src_ip2), ord(src_ip3), ord(src_ip4))
    dst_ip1 = fh.read(1)
    dst_ip2 = fh.read(1)
    dst_ip3 = fh.read(1)
    dst_ip4 = fh.read(1)
    print(ord(dst_ip1), ord(dst_ip2), ord(dst_ip3), ord(dst_ip4))
    print("Transport protocol", transport_protocol)
    pass
print("File size", saved[0], ", sent by wire", wire[0], ", type", ftype[0])
fh.close()