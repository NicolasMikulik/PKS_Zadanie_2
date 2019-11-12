import struct

fh = open("/home/nicolas/Documents/FIIT/PKS/Zadanie_2/vzorky_pcap_na_analyzu/eth-8.pcap", "rb")
byte = fh.read(75)
# while byte:
byte = fh.read(1)
first = ord(byte) & 240
second = ord(byte) & 15
print(ord(byte), first, second, hex(ord(byte))[2:], hex(first), hex(second))
# print(ord(fh.read(1)))
fh.close()