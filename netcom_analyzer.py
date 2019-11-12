import struct

fh = open("/home/nicolas/Documents/FIIT/PKS/Zadanie_2/vzorky_pcap_na_analyzu/eth-8.pcap", "rb")
byte = fh.read(406)
byte = fh.read(4)
print(byte)
port = struct.unpack('>I', byte)
print(port[0])
fh.close()