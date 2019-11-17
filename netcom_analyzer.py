import struct


tftp = list()
ip_addresses = list()
ip_rank = dict()
arp_rank = dict()
http = dict()
https = dict()
telnet = dict()
ssh = dict()
ftp_data = dict()
ftp_control = dict()
tftp_rec = dict()
icmp = dict()

FIN = 1
SYN = 2
RST = 4
PSH = 8
ACK = 16

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


def read_mac(address):
    mac_record = ""
    for spot in range(0, (len(address))):
        char = address[spot:spot + 1]
        first = (ord(char) >> 4) & 15
        second = ord(char) & 15
        mac_record = mac_record + format(first, 'x') + format(second, 'x')
    return mac_record


def print_arp_srcip(buffer):
    src_ip1 = buffer[28:29]
    src_ip2 = buffer[29:30]
    src_ip3 = buffer[30:31]
    src_ip4 = buffer[31:32]
    source_ip = str(ord(src_ip1)) + '.' + str(ord(src_ip2)) + '.' + str(ord(src_ip3)) + '.' + str(ord(src_ip4))
    return source_ip


def print_arp_dstip(buffer):
    dst_ip1 = buffer[38:39]
    dst_ip2 = buffer[39:40]
    dst_ip3 = buffer[40:41]
    dst_ip4 = buffer[41:42]
    destination_ip = str(ord(dst_ip1))+'.'+str(ord(dst_ip2))+'.'+str(ord(dst_ip3))+'.'+str(ord(dst_ip4))
    return destination_ip

def print_srcip(buffer):
    src_ip1 = buffer[26:27]
    src_ip2 = buffer[27:28]
    src_ip3 = buffer[28:29]
    src_ip4 = buffer[29:30]
    source_ip = str(ord(src_ip1)) + '.' + str(ord(src_ip2)) + '.' + str(ord(src_ip3)) + '.' + str(ord(src_ip4))
    if source_ip not in ip_addresses:
        ip_addresses.append(source_ip)
    if source_ip not in ip_rank.keys():
        ip_rank[source_ip] = 1
    else:
        ip_rank[source_ip] = ip_rank[source_ip] + 1
    return source_ip


def print_dstip(buffer):
    dst_ip1 = buffer[30:31]
    dst_ip2 = buffer[31:32]
    dst_ip3 = buffer[32:33]
    dst_ip4 = buffer[33:34]
    destination_ip = str(ord(dst_ip1))+'.'+str(ord(dst_ip2))+'.'+str(ord(dst_ip3))+'.'+str(ord(dst_ip4))
    return destination_ip


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
    if dst_udp_port == 69 or src_udp_port == 69 or src_udp_port in tftp or dst_udp_port in tftp:
        ip_and_port = print_srcip(buffer) + str(src_udp_port) + print_dstip(buffer)
        reply_ip_and_port = print_dstip(buffer) + str(dst_udp_port) + print_srcip(buffer)
        print(ip_and_port, reply_ip_and_port)
        if ip_and_port not in tftp_rec.keys():
            if reply_ip_and_port not in tftp_rec.keys():
                tftp_rec[ip_and_port] = list()
                tftp_rec[ip_and_port].append(frame_number)
            elif reply_ip_and_port in tftp_rec.keys():
                tftp_rec[reply_ip_and_port].append(frame_number)
        elif ip_and_port in tftp_rec.keys():
            tftp_rec[ip_and_port].append(frame_number)
    if src_udp_port == 53 or dst_udp_port == 53:
        print("DNS")
    if src_udp_port == 137 or dst_udp_port == 137:
        print("NetBIOS Name Service")
    print("Source port: ", src_udp_port, "\nDestination port: ", dst_udp_port, sep='')
    pass


def get_tcp_flags(buffer):
    tcp_flags = buffer[47:48]
    tcp_flags = struct.unpack('>B', tcp_flags)
    tcp_flags = tcp_flags[0]
    flag_status = "Flags: "
    if tcp_flags & FIN:
        flag_status += "[FIN] "
    if tcp_flags & SYN:
        flag_status += "[SYN] "
    if tcp_flags & RST:
        flag_status += "[RST] "
    if tcp_flags & PSH:
        flag_status += "[PSH] "
    if tcp_flags & ACK:
        flag_status += "[ACK]"
    print(flag_status)


def print_tcp(buffer):
    src_tcp_port = buffer[34:36]
    src_tcp_port = struct.unpack('>H', src_tcp_port)
    src_tcp_port = src_tcp_port[0]
    dst_tcp_port = buffer[36:38]
    dst_tcp_port = struct.unpack('>H', dst_tcp_port)
    dst_tcp_port = dst_tcp_port[0]
    if src_tcp_port == 139 or dst_tcp_port == 139:
        print("NetBIOS Session Service")
    elif src_tcp_port == 20 or dst_tcp_port == 20:
        print("FTP-DATA")
        ip_and_port = print_srcip(buffer) + str(src_tcp_port) + print_dstip(buffer) + str(dst_tcp_port)
        reply_ip_and_port = print_dstip(buffer) + str(dst_tcp_port) + print_srcip(buffer) + str(src_tcp_port)
        if ip_and_port not in ftp_data.keys():
            if reply_ip_and_port not in ftp_data.keys():
                ftp_data[ip_and_port] = list()
                ftp_data[ip_and_port].append(frame_number)
            elif reply_ip_and_port in ftp_data.keys():
                ftp_data[reply_ip_and_port].append(frame_number)
        elif ip_and_port in ftp_data.keys():
            ftp_data[ip_and_port].append(frame_number)
    elif src_tcp_port == 21 or dst_tcp_port == 21:
        print("FTP-CONTROL")
        ip_and_port = print_srcip(buffer) + str(src_tcp_port) + print_dstip(buffer) + str(dst_tcp_port)
        reply_ip_and_port = print_dstip(buffer) + str(dst_tcp_port) + print_srcip(buffer) + str(src_tcp_port)
        if ip_and_port not in ftp_control.keys():
            if reply_ip_and_port not in ftp_control.keys():
                ftp_control[ip_and_port] = list()
                ftp_control[ip_and_port].append(frame_number)
            elif reply_ip_and_port in ftp_control.keys():
                ftp_control[reply_ip_and_port].append(frame_number)
        elif ip_and_port in ftp_control.keys():
            ftp_control[ip_and_port].append(frame_number)
    elif src_tcp_port == 22 or dst_tcp_port == 22:
        print("SSH")
        ip_and_port = print_srcip(buffer)+str(src_tcp_port)+print_dstip(buffer)+str(dst_tcp_port)
        reply_ip_and_port = print_dstip(buffer)+str(dst_tcp_port)+print_srcip(buffer)+str(src_tcp_port)
        if ip_and_port not in ssh.keys():
            if reply_ip_and_port not in ssh.keys():
                ssh[ip_and_port] = list()
                ssh[ip_and_port].append(frame_number)
            elif reply_ip_and_port in ssh.keys():
                ssh[reply_ip_and_port].append(frame_number)
        elif ip_and_port in ssh.keys():
            ssh[ip_and_port].append(frame_number)
    elif src_tcp_port == 23 or dst_tcp_port == 23:
        print("TELNET")
        ip_and_port = print_srcip(buffer) + str(src_tcp_port) + print_dstip(buffer) + str(dst_tcp_port)
        reply_ip_and_port = print_dstip(buffer) + str(dst_tcp_port) + print_srcip(buffer) + str(src_tcp_port)
        # print(ip_and_port)
        if ip_and_port not in telnet.keys():
            if reply_ip_and_port not in telnet.keys():
                telnet[ip_and_port] = list()
                telnet[ip_and_port].append(frame_number)
            elif reply_ip_and_port in telnet.keys():
                telnet[reply_ip_and_port].append(frame_number)
        elif ip_and_port in telnet.keys():
            telnet[ip_and_port].append(frame_number)
    elif src_tcp_port == 80 or dst_tcp_port == 80:
        print("HTTP")
        ip_and_port = print_srcip(buffer)+str(src_tcp_port)+print_dstip(buffer)+str(dst_tcp_port)
        reply_ip_and_port = print_dstip(buffer)+str(dst_tcp_port)+print_srcip(buffer)+str(src_tcp_port)
        if ip_and_port not in http.keys():
            if reply_ip_and_port not in http.keys():
                http[ip_and_port] = list()
                http[ip_and_port].append(frame_number)
            elif reply_ip_and_port in http.keys():
                http[reply_ip_and_port].append(frame_number)
        elif ip_and_port in http.keys():
            http[ip_and_port].append(frame_number)
    elif src_tcp_port == 443 or dst_tcp_port == 443:
        print("HTTPS")
        ip_and_port = print_srcip(buffer) + str(src_tcp_port) + print_dstip(buffer) + str(dst_tcp_port)
        reply_ip_and_port = print_dstip(buffer) + str(dst_tcp_port) + print_srcip(buffer) + str(src_tcp_port)
        if ip_and_port not in https.keys():
            if reply_ip_and_port not in https.keys():
                https[ip_and_port] = list()
                https[ip_and_port].append(frame_number)
            elif reply_ip_and_port in https.keys():
                https[reply_ip_and_port].append(frame_number)
        elif ip_and_port in https.keys():
            https[ip_and_port].append(frame_number)
    print("Source port: ", src_tcp_port, "\nDestination port: ", dst_tcp_port, sep='')


def get_icmp_type(buffer):
    icmp_type = buffer[34]
    icmp_type_display = " - Type: "
    if icmp_type == 0:
        icmp_type_display += "Reply"
    elif icmp_type == 3:
        icmp_type_display += "Destination Unreachable"
        icmp_code = buffer[35]
        if icmp_code == 0:
            icmp_type_display += " - Net Unreachable"
        if icmp_code == 1:
            icmp_type_display += " - Host Unreachable"
        if icmp_code == 2:
            icmp_type_display += " - Protocol Unreachable"
        if icmp_code == 3:
            icmp_type_display += " - Port Unreachable"
    elif icmp_type == 5:
        icmp_type_display += "Redirect"
    elif icmp_type == 8:
        icmp_type_display += "Request"
    elif icmp_type == 11:
        icmp_type_display += "Time Exceeded"
        icmp_code = buffer[35]
        if icmp_code == 0:
            icmp_type_display += " - Time to Live exceeded in Transit"
        elif icmp_code == 1:
            icmp_type_display += " - Fragment Reassembly Time Exceeded"
    elif icmp_type == 30:
        icmp_type_display += "Traceroute"
    print(icmp_type_display)
    pass


def print_icmp(buffer):
    get_icmp_type(buffer)
    '''icmp_type = buffer[34]
    icmp_type_display = "ICMP type: "
    if icmp_type == 0:
        icmp_type_display += "Reply"
    elif icmp_type == 3:
        icmp_type_display += "Destination Unreachable"
        icmp_code = buffer[35]
        if icmp_code == 0:
            icmp_type_display += " - Net Unreachable"
        if icmp_code == 1:
            icmp_type_display += " - Host Unreachable"
        if icmp_code == 2:
            icmp_type_display += " - Protocol Unreachable"
        if icmp_code == 3:
            icmp_type_display += " - Port Unreachable"
    elif icmp_type == 5:
        icmp_type_display += "Redirect"
    elif icmp_type == 8:
        icmp_type_display += "Request"
    elif icmp_type == 11:
        icmp_type_display += "Time Exceeded"
        icmp_code = buffer[35]
        if icmp_code == 0:
            icmp_type_display += " - Time to Live exceeded in Transit"
        elif icmp_code == 1:
            icmp_type_display += " - Fragment Reassembly Time Exceeded"
    elif icmp_type == 30:
        icmp_type_display += "Traceroute"
    print(icmp_type_display)'''
    icmp_seq_num = buffer[40:42]
    icmp_seq_num = struct.unpack('>H', icmp_seq_num)
    icmp_seq_num = icmp_seq_num[0]
    ip_and_seqn = print_srcip(buffer) + print_dstip(buffer) + str(icmp_seq_num)
    reply_ip_and_seqn = print_dstip(buffer) + print_srcip(buffer) + str(icmp_seq_num)
    if ip_and_seqn not in icmp.keys():
        if reply_ip_and_seqn not in icmp.keys():
            icmp[ip_and_seqn] = list()
            icmp[ip_and_seqn].append(frame_number)
        elif reply_ip_and_seqn in icmp.keys():
            icmp[reply_ip_and_seqn].append(frame_number)
    elif ip_and_seqn in icmp.keys():
        icmp[ip_and_seqn].append(frame_number)

def print_ethernet_ip(buffer):
    '''print("Ethernet II", end='')
    print_mac('Source MAC: ', buffer[6:12])
    print_mac('Destination MAC: ', buffer[0:6])'''

    ip_info = buffer[14:15]
    ip_v = int(ord(ip_info) >> 4) & 15
    ip_hl = int(ord(ip_info)) & 15
    # print("\n", ord(ip_info))
    if ip_v == 4:
        print("\nIPv4 (IHL", str(ip_hl) + ")")
    transport_protocol = buffer[23:24]
    transport_protocol = ord(transport_protocol)
    print("Source IP:", print_srcip(buffer))
    print("Destination IP:", print_dstip(buffer))
    if transport_protocol == 17:
        print("UDP")
        print_udp(buffer)
    elif transport_protocol == 6:
        print("TCP")
        print_tcp(buffer)
    elif transport_protocol == 1:
        print("ICMP", end='')
        print_icmp(buffer)
    elif transport_protocol == 88:
        print("EIGRP")
    print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
    print()
    pass


def print_ethernet_arp(buffer):
    '''print("Ethernet II\nARP", end='')
    print_mac('Source MAC: ', buffer[6:12])
    print_mac('Destination MAC: ', buffer[0:6])'''
    src_mac_record = read_mac(buffer[6:12])
    dst_mac_record = read_mac(buffer[0:6])
    mac_and_ip = src_mac_record + print_arp_srcip(buffer) + print_arp_dstip(buffer)
    reply_mac_and_ip = dst_mac_record + print_arp_dstip(buffer) + print_arp_srcip(buffer)
    print("MAC and IP", mac_and_ip, "REPLY MAC and IP", reply_mac_and_ip)
    if mac_and_ip not in arp_rank.keys():
        if dst_mac_record == 'ffffffffffff':
            arp_rank[mac_and_ip] = list()
            arp_rank[mac_and_ip].append(frame_number)
        elif dst_mac_record != 'ffffffffffff':
            if reply_mac_and_ip in arp_rank.keys():
                arp_rank[reply_mac_and_ip].append(frame_number)
            else:
                arp_rank[mac_and_ip] = list()
                arp_rank[mac_and_ip].append(frame_number)
    elif mac_and_ip in arp_rank.keys() and dst_mac_record == 'ffffffffffff' and arp_rank[mac_and_ip].count(frame_number)<=0:
        arp_rank[mac_and_ip].append(frame_number)
    print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
    print()
    pass

fh = open("/home/nicolas/Documents/FIIT/PKS/Zadanie_2/vzorky_pcap_na_analyzu/icmp.pcap", "rb")
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
    # print(ftype[0])
    next_frame_offset -= 12
    if ftype[0] > 1500:
        print("Ethernet II", end='')
        print_mac('Source MAC: ', source_address)
        print_mac('Destination MAC: ', destination_address)
        print()
        print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
        if ftype[0] == 2048:
            print_ethernet_ip(buffer)
        elif ftype[0] == 2054:
            print_ethernet_arp(buffer)
    else:
        print("IEEE ", end='')
        ieee_type = buffer[14:15]
        if ieee_type[0] == 170:
            print("802.3 SNAP", end='')
        elif ieee_type[0] == 255:
            print("802.3 Raw", end='')
        else:
            print("802.3 LLC", end='')
        print_mac('Source MAC: ', source_address)
        print_mac('Destination MAC: ', destination_address)
        print()
        print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
    print_bytes(buffer)
    print()
print("IP addresses of sending nodes:")
for ipv4 in ip_rank.keys():
    print(ipv4)
sorted_ip_rank = sorted(ip_rank.items(), key=lambda kv: kv[1], reverse=True)
if len(sorted_ip_rank) > 0:
    print("\nHighest number of packets (", sorted_ip_rank[0][1], ") was sent by ", sorted_ip_rank[0][0], sep='')
print(arp_rank)

'''
if len(http) > 0:
    print("HTTP Communication", http)
    http_com = 0
    for key in http.keys():
        http_com += 1
        if len(http[key]) > 20:
            http[key] = http[key][:10] + http[key][-10:]
            print("HTTP communication nr.", http_com,
                  "contained more than twenty frames, only the first ten and the last ten will be displayed.")
        else:
            print("HTTP communication nr. ", http_com)
        while len(http[key]) > 0:
            http_frame = http[key].pop(0)
            fh.seek(0, 0)
            frame_number = 0
            byte = fh.read(32)
            while http_frame != (frame_number + 1):
                frame_number += 1
                if frame_number > 1:
                    byte = fh.read(8)
                saved = fh.read(4)
                saved = struct.unpack('<I', saved)
                wire = fh.read(4)
                wire = struct.unpack('<I', wire)
                next_frame_offset = wire[0]
                byte = buffer = fh.read(next_frame_offset)
                next_frame_offset -= 12
            if frame_number != 0:
                byte = fh.read(8)
            saved = fh.read(4)
            saved = struct.unpack('<I', saved)
            wire = fh.read(4)
            wire = struct.unpack('<I', wire)
            next_frame_offset = wire[0]
            byte = buffer = fh.read(next_frame_offset)
            print("Frame :", http_frame, "\nEthernet II", end='')
            print_mac('Source MAC: ', buffer[6:12])
            print_mac('Destination MAC: ', buffer[0:6])
            ip_info = buffer[14:15]
            ip_v = int(ord(ip_info) >> 4) & 15
            ip_hl = int(ord(ip_info)) & 15
            if ip_v == 4:
                print("\nIPv4 (IHL", str(ip_hl) + ")")
            print("Source IP:", print_srcip(buffer))
            print("Destination IP:", print_dstip(buffer))
            print("TCP")
            src_tcp_port = buffer[34:36]
            src_tcp_port = struct.unpack('>H', src_tcp_port)
            src_tcp_port = src_tcp_port[0]
            dst_tcp_port = buffer[36:38]
            dst_tcp_port = struct.unpack('>H', dst_tcp_port)
            dst_tcp_port = dst_tcp_port[0]
            get_tcp_flags(buffer)
            print("HTTP")
            print("Source port: ", src_tcp_port, "\nDestination port: ", dst_tcp_port, sep='')
            print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
            print(), print_bytes(buffer), print()
else:
    print("No HTTP communication recorded.")
'''

if len(https) > 0:
    print("HTTPS Communication", https)
    https_com = 0
    for key in https.keys():
        https_com += 1
        if len(https[key]) > 20:
            https[key] = https[key][:10] + https[key][-10:]
            print("HTTPS communication nr.", https_com,
                  "contained more than twenty frames, only the first ten and the last ten will be displayed.")
        else:
            print("HTTPS communication nr. ", https_com)
        while len(https[key]) > 0:
            https_frame = https[key].pop(0)
            fh.seek(0, 0)
            frame_number = 0
            byte = fh.read(32)
            while https_frame != (frame_number + 1):
                frame_number += 1
                if frame_number > 1:
                    byte = fh.read(8)
                saved = fh.read(4)
                saved = struct.unpack('<I', saved)
                wire = fh.read(4)
                wire = struct.unpack('<I', wire)
                next_frame_offset = wire[0]
                byte = buffer = fh.read(next_frame_offset)
                next_frame_offset -= 12
            if frame_number != 0:
                byte = fh.read(8)
            saved = fh.read(4)
            saved = struct.unpack('<I', saved)
            wire = fh.read(4)
            wire = struct.unpack('<I', wire)
            next_frame_offset = wire[0]
            byte = buffer = fh.read(next_frame_offset)
            print("Frame :", https_frame, "\nEthernet II", end='')
            print_mac('Source MAC: ', buffer[6:12])
            print_mac('Destination MAC: ', buffer[0:6])
            ip_info = buffer[14:15]
            ip_v = int(ord(ip_info) >> 4) & 15
            ip_hl = int(ord(ip_info)) & 15
            if ip_v == 4:
                print("\nIPv4 (IHL", str(ip_hl) + ")")
            print("Source IP:", print_srcip(buffer))
            print("Destination IP:", print_dstip(buffer))
            print("TCP")
            src_tcp_port = buffer[34:36]
            src_tcp_port = struct.unpack('>H', src_tcp_port)
            src_tcp_port = src_tcp_port[0]
            dst_tcp_port = buffer[36:38]
            dst_tcp_port = struct.unpack('>H', dst_tcp_port)
            dst_tcp_port = dst_tcp_port[0]
            get_tcp_flags(buffer)
            if len(buffer) >= 55:
                content_type = buffer[54]
                if content_type == 23:
                    print("HTTPS over TLS - Sending application data")
                else:
                    print("HTTPS")
            print("Source port: ", src_tcp_port, "\nDestination port: ", dst_tcp_port, sep='')
            print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
            print(), print_bytes(buffer), print()
else:
    print("No HTTPS communication recorded.")


'''
if len(telnet) > 0:
    print("TELNET Communication", telnet)
    telnet_com = 0
    for key in telnet.keys():
        telnet_com += 1
        if len(telnet[key]) > 20:
            telnet[key] = telnet[key][:10] + telnet[key][-10:]
            print("TELNET communication nr.", telnet_com, "contained more than twenty frames, only the first ten and the last ten will be displayed.")
        else:
            print("TELNET communication nr. ", telnet_com)
        while len(telnet[key]) > 0:
            telnet_frame = telnet[key].pop(0)
            fh.seek(0, 0)
            frame_number = 0
            byte = fh.read(32)
            while telnet_frame != (frame_number + 1):
                frame_number += 1
                if frame_number > 1:
                    byte = fh.read(8)
                saved = fh.read(4)
                saved = struct.unpack('<I', saved)
                wire = fh.read(4)
                wire = struct.unpack('<I', wire)
                next_frame_offset = wire[0]
                byte = buffer = fh.read(next_frame_offset)
                next_frame_offset -= 12
            if frame_number != 0:
                byte = fh.read(8)
            saved = fh.read(4)
            saved = struct.unpack('<I', saved)
            wire = fh.read(4)
            wire = struct.unpack('<I', wire)
            next_frame_offset = wire[0]
            byte = buffer = fh.read(next_frame_offset)
            print("Frame :", telnet_frame, "\nEthernet II", end='')
            print_mac('Source MAC: ', buffer[6:12])
            print_mac('Destination MAC: ', buffer[0:6])
            ip_info = buffer[14:15]
            ip_v = int(ord(ip_info) >> 4) & 15
            ip_hl = int(ord(ip_info)) & 15
            if ip_v == 4:
                print("\nIPv4 (IHL", str(ip_hl) + ")")
            print("Source IP:", print_srcip(buffer))
            print("Destination IP:", print_dstip(buffer))
            print("TCP")
            src_tcp_port = buffer[34:36]
            src_tcp_port = struct.unpack('>H', src_tcp_port)
            src_tcp_port = src_tcp_port[0]
            dst_tcp_port = buffer[36:38]
            dst_tcp_port = struct.unpack('>H', dst_tcp_port)
            dst_tcp_port = dst_tcp_port[0]
            get_tcp_flags(buffer)
            print("TELNET")
            print("Source port: ", src_tcp_port, "\nDestination port: ", dst_tcp_port, sep='')
            print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
            print(), print_bytes(buffer), print()
else:
    print("No TELNET communication recorded.")
'''


'''
if len(ssh) > 0:
    print("SSH Communication", ssh)
    ssh_com = 0
    for key in ssh.keys():
        ssh_com += 1
        if len(ssh[key]) > 20:
            ssh[key] = ssh[key][:10] + ssh[key][-10:]
            print("SSH communication nr.", ssh_com,
                  "contained more than twenty frames, only the first ten and the last ten will be displayed.")
        else:
            print("SSH communication nr. ", ssh_com)
        while len(ssh[key]) > 0:
            ssh_frame = ssh[key].pop(0)
            fh.seek(0, 0)
            frame_number = 0
            byte = fh.read(32)
            while ssh_frame != (frame_number + 1):
                frame_number += 1
                if frame_number > 1:
                    byte = fh.read(8)
                saved = fh.read(4)
                saved = struct.unpack('<I', saved)
                wire = fh.read(4)
                wire = struct.unpack('<I', wire)
                next_frame_offset = wire[0]
                byte = buffer = fh.read(next_frame_offset)
                next_frame_offset -= 12
            if frame_number != 0:
                byte = fh.read(8)
            saved = fh.read(4)
            saved = struct.unpack('<I', saved)
            wire = fh.read(4)
            wire = struct.unpack('<I', wire)
            next_frame_offset = wire[0]
            byte = buffer = fh.read(next_frame_offset)
            print("Frame :", ssh_frame, "\nEthernet II", end='')
            print_mac('Source MAC: ', buffer[6:12])
            print_mac('Destination MAC: ', buffer[0:6])
            ip_info = buffer[14:15]
            ip_v = int(ord(ip_info) >> 4) & 15
            ip_hl = int(ord(ip_info)) & 15
            if ip_v == 4:
                print("\nIPv4 (IHL", str(ip_hl) + ")")
            print("Source IP:", print_srcip(buffer))
            print("Destination IP:", print_dstip(buffer))
            print("TCP")
            src_tcp_port = buffer[34:36]
            src_tcp_port = struct.unpack('>H', src_tcp_port)
            src_tcp_port = src_tcp_port[0]
            dst_tcp_port = buffer[36:38]
            dst_tcp_port = struct.unpack('>H', dst_tcp_port)
            dst_tcp_port = dst_tcp_port[0]
            get_tcp_flags(buffer)
            print("SSH")
            print("Source port: ", src_tcp_port, "\nDestination port: ", dst_tcp_port, sep='')
            print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
            print(), print_bytes(buffer), print()
else:
    print("No SSH communication recorded.")
'''

'''
if len(ftp_data) > 0:
    print("FTP-DATA Communication", ftp_data)
    ftp_data_com = 0
    for key in ftp_data.keys():
        ftp_data_com += 1
        if len(ftp_data[key]) > 20:
            ftp_data[key] = ftp_data[key][:10] + ftp_data[key][-10:]
            print("FTP-DATA communication nr.", ftp_data_com,
                  "contained more than twenty frames, only the first ten and the last ten will be displayed.")
        else:
            print("FTP-DATA communication nr. ", ftp_data_com)
        while len(ftp_data[key]) > 0:
            ftp_data_frame = ftp_data[key].pop(0)
            fh.seek(0, 0)
            frame_number = 0
            byte = fh.read(32)
            while ftp_data_frame != (frame_number + 1):
                frame_number += 1
                if frame_number > 1:
                    byte = fh.read(8)
                saved = fh.read(4)
                saved = struct.unpack('<I', saved)
                wire = fh.read(4)
                wire = struct.unpack('<I', wire)
                next_frame_offset = wire[0]
                byte = buffer = fh.read(next_frame_offset)
                next_frame_offset -= 12
            if frame_number != 0:
                byte = fh.read(8)
            saved = fh.read(4)
            saved = struct.unpack('<I', saved)
            wire = fh.read(4)
            wire = struct.unpack('<I', wire)
            next_frame_offset = wire[0]
            byte = buffer = fh.read(next_frame_offset)
            print("Frame :", ftp_data_frame, "\nEthernet II", end='')
            print_mac('Source MAC: ', buffer[6:12])
            print_mac('Destination MAC: ', buffer[0:6])
            ip_info = buffer[14:15]
            ip_v = int(ord(ip_info) >> 4) & 15
            ip_hl = int(ord(ip_info)) & 15
            if ip_v == 4:
                print("\nIPv4 (IHL", str(ip_hl) + ")")
            print("Source IP:", print_srcip(buffer))
            print("Destination IP:", print_dstip(buffer))
            print("TCP")
            src_tcp_port = buffer[34:36]
            src_tcp_port = struct.unpack('>H', src_tcp_port)
            src_tcp_port = src_tcp_port[0]
            dst_tcp_port = buffer[36:38]
            dst_tcp_port = struct.unpack('>H', dst_tcp_port)
            dst_tcp_port = dst_tcp_port[0]
            get_tcp_flags(buffer)
            print("FTP-DATA")
            print("Source port: ", src_tcp_port, "\nDestination port: ", dst_tcp_port, sep='')
            print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
            print(), print_bytes(buffer), print()
else:
    print("No FTP-DATA communication recorded.")
'''

if len(ftp_control) > 0:
    print("FTP-CONTROL Communication", ftp_control)
    ftp_control_com = 0
    for key in ftp_control.keys():
        ftp_control_com += 1
        if len(ftp_control[key]) > 20:
            ftp_control[key] = ftp_control[key][:10] + ftp_control[key][-10:]
            print("FTP-CONTROL communication nr.", ftp_control_com,
                  "contained more than twenty frames, only the first ten and the last ten will be displayed.")
        else:
            print("FTP-CONTROL communication nr. ", ftp_control_com)
        while len(ftp_control[key]) > 0:
            ftp_control_frame = ftp_control[key].pop(0)
            fh.seek(0, 0)
            frame_number = 0
            byte = fh.read(32)
            while ftp_control_frame != (frame_number + 1):
                frame_number += 1
                if frame_number > 1:
                    byte = fh.read(8)
                saved = fh.read(4)
                saved = struct.unpack('<I', saved)
                wire = fh.read(4)
                wire = struct.unpack('<I', wire)
                next_frame_offset = wire[0]
                byte = buffer = fh.read(next_frame_offset)
                next_frame_offset -= 12
            if frame_number != 0:
                byte = fh.read(8)
            saved = fh.read(4)
            saved = struct.unpack('<I', saved)
            wire = fh.read(4)
            wire = struct.unpack('<I', wire)
            next_frame_offset = wire[0]
            byte = buffer = fh.read(next_frame_offset)
            print("Frame :", ftp_control_frame, "\nEthernet II", end='')
            print_mac('Source MAC: ', buffer[6:12])
            print_mac('Destination MAC: ', buffer[0:6])
            ip_info = buffer[14:15]
            ip_v = int(ord(ip_info) >> 4) & 15
            ip_hl = int(ord(ip_info)) & 15
            if ip_v == 4:
                print("\nIPv4 (IHL", str(ip_hl) + ")")
            print("Source IP:", print_srcip(buffer))
            print("Destination IP:", print_dstip(buffer))
            print("TCP")
            src_tcp_port = buffer[34:36]
            src_tcp_port = struct.unpack('>H', src_tcp_port)
            src_tcp_port = src_tcp_port[0]
            dst_tcp_port = buffer[36:38]
            dst_tcp_port = struct.unpack('>H', dst_tcp_port)
            dst_tcp_port = dst_tcp_port[0]
            get_tcp_flags(buffer)
            print("FTP-CONTROL")
            print("Source port: ", src_tcp_port, "\nDestination port: ", dst_tcp_port, sep='')
            print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
            print(), print_bytes(buffer), print()
else:
    print("No FTP-CONTROL communication recorded.")


if len(tftp_rec) > 0:
    print("TFTP Communication", tftp_rec)
    tftp_rec_com = 0
    for key in tftp_rec.keys():
        tftp_rec_com += 1
        if len(tftp_rec[key]) > 20:
            tftp_rec[key] = tftp_rec[key][:10] + tftp_rec[key][-10:]
            print("TFTP communication nr.", tftp_rec_com,
                  "contained more than twenty frames, only the first ten and the last ten will be displayed.")
        else:
            print("TFTP communication nr. ", tftp_rec_com)
        while len(tftp_rec[key]) > 0:
            tftp_rec_frame = tftp_rec[key].pop(0)
            fh.seek(0, 0)
            frame_number = 0
            byte = fh.read(32)
            while tftp_rec_frame != (frame_number + 1):
                frame_number += 1
                if frame_number > 1:
                    byte = fh.read(8)
                saved = fh.read(4)
                saved = struct.unpack('<I', saved)
                wire = fh.read(4)
                wire = struct.unpack('<I', wire)
                next_frame_offset = wire[0]
                byte = buffer = fh.read(next_frame_offset)
                next_frame_offset -= 12
            if frame_number != 0:
                byte = fh.read(8)
            saved = fh.read(4)
            saved = struct.unpack('<I', saved)
            wire = fh.read(4)
            wire = struct.unpack('<I', wire)
            next_frame_offset = wire[0]
            byte = buffer = fh.read(next_frame_offset)
            print("Frame :", tftp_rec_frame, "\nEthernet II", end='')
            print_mac('Source MAC: ', buffer[6:12])
            print_mac('Destination MAC: ', buffer[0:6])
            ip_info = buffer[14:15]
            ip_v = int(ord(ip_info) >> 4) & 15
            ip_hl = int(ord(ip_info)) & 15
            if ip_v == 4:
                print("\nIPv4 (IHL", str(ip_hl) + ")")
            print("Source IP:", print_srcip(buffer))
            print("Destination IP:", print_dstip(buffer))
            print("UDP")
            src_udp_port = buffer[34:36]
            src_udp_port = struct.unpack('>H', src_udp_port)
            src_udp_port = src_udp_port[0]
            dst_udp_port = buffer[36:38]
            dst_udp_port = struct.unpack('>H', dst_udp_port)
            dst_udp_port = dst_udp_port[0]
            print("TFTP")
            print("Source port: ", src_udp_port, "\nDestination port: ", dst_udp_port, sep='')
            print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
            print(), print_bytes(buffer), print()
else:
    print("No TFTP communication recorded.")


if len(icmp) > 0:
    print("ICMP Communication", icmp)
    icmp_com = 0
    for key in icmp.keys():
        icmp_com += 1
        if len(icmp[key]) > 20:
            icmp[key] = icmp[key][:10] + icmp[key][-10:]
            print("ICMP communication nr.", icmp_com,
                  "contained more than twenty frames, only the first ten and the last ten will be displayed.")
        else:
            print("ICMP communication nr. ", icmp_com)
        while len(icmp[key]) > 0:
            icmp_frame = icmp[key].pop(0)
            fh.seek(0, 0)
            frame_number = 0
            byte = fh.read(32)
            while icmp_frame != (frame_number + 1):
                frame_number += 1
                if frame_number > 1:
                    byte = fh.read(8)
                saved = fh.read(4)
                saved = struct.unpack('<I', saved)
                wire = fh.read(4)
                wire = struct.unpack('<I', wire)
                next_frame_offset = wire[0]
                byte = buffer = fh.read(next_frame_offset)
                next_frame_offset -= 12
            if frame_number != 0:
                byte = fh.read(8)
            saved = fh.read(4)
            saved = struct.unpack('<I', saved)
            wire = fh.read(4)
            wire = struct.unpack('<I', wire)
            next_frame_offset = wire[0]
            byte = buffer = fh.read(next_frame_offset)
            print("Frame :", icmp_frame, "\nEthernet II", end='')
            print_mac('Source MAC: ', buffer[6:12])
            print_mac('Destination MAC: ', buffer[0:6])
            ip_info = buffer[14:15]
            ip_v = int(ord(ip_info) >> 4) & 15
            ip_hl = int(ord(ip_info)) & 15
            if ip_v == 4:
                print("\nIPv4 (IHL", str(ip_hl) + ")")
            print("Source IP:", print_srcip(buffer))
            print("Destination IP:", print_dstip(buffer))
            print("ICMP")
            print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0])
            print(), print_bytes(buffer), print()
else:
    print("No ICMP communication recorded.")


'''arp_com = 0
for key in arp_rank.keys():
    arp_com += 1
    print("ARP communication nr. ", arp_com)
    while len(arp_rank[key]) > 0:
        arp_frame = arp_rank[key].pop(0)
        fh.seek(0, 0)
        frame_number = 0
        byte = fh.read(32)
        while arp_frame != (frame_number + 1):
            frame_number += 1
            if frame_number > 1:
                byte = fh.read(8)
            saved = fh.read(4)
            # print("FRAME :", frame_number)
            saved = struct.unpack('<I', saved)
            wire = fh.read(4)
            wire = struct.unpack('<I', wire)
            next_frame_offset = wire[0]
            byte = buffer = fh.read(next_frame_offset)
            next_frame_offset -= 12
        if(frame_number != 0):
            byte = fh.read(8)
        saved = fh.read(4)
        saved = struct.unpack('<I', saved)
        wire = fh.read(4)
        wire = struct.unpack('<I', wire)
        next_frame_offset = wire[0]
        byte = buffer = fh.read(next_frame_offset)
        arp_opcode = buffer[20:22]
        arp_opcode = struct.unpack('>H', arp_opcode)
        if arp_opcode[0] == 1:
            print("ARP-Request, IP address: ", print_arp_dstip(buffer), end=' ')
            print("MAC: ???")
            print("Sender IP: ", print_arp_srcip(buffer), end='')
            print(", Target IP: ", print_arp_dstip(buffer), end='')
            print("\nFRAME :", frame_number + 1)
            print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0], "\nEthernet II - ARP", end='')
            source_address = buffer[6:12]
            destination_address = buffer[0:6]
            print_mac('Source MAC: ', source_address)
            print_mac('Destination MAC: ', destination_address)
            print(), print_bytes(buffer), print()
        elif arp_opcode[0] == 2:
            print("ARP-Reply, IP address: ", print_arp_srcip(buffer), end=' ')
            print_mac('MAC: ', buffer[22:28])
            print("\nSender IP: ", print_arp_srcip(buffer), end='')
            print_arp_srcip(buffer)
            print(", Target IP: ", print_arp_dstip(buffer), end='')
            print_arp_dstip(buffer)
            print("\nFRAME :", frame_number + 1)
            print("Frame length available to pcap API", saved[0], ", frame length sent by medium", wire[0], "\nEthernet II - ARP", end='')
            source_address = buffer[6:12]
            destination_address = buffer[0:6]
            print_mac('Source MAC: ', source_address)
            print_mac('Destination MAC: ', destination_address)
            print(), print_bytes(buffer), print()'''


fh.close()
