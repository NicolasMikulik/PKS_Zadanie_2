import struct

fh = open("/home/nicolas/Documents/FIIT/PKS/Zadanie_2/vzorky_pcap_na_analyzu/eth-8.pcap", "rb")
byte = fh.read(32)
saved = fh.read(4)
saved = struct.unpack('<I', saved)
wire = fh.read(4)
wire = struct.unpack('<I', wire)
destination_address = fh.read(6)
source_adress = fh.read(6)
type = fh.read(2)
type = struct.unpack('>H',type)
print(saved[0], wire[0], type[0])
fh.close()