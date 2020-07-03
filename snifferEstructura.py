
#Carmela Sandra Calliconde Carrasco  
#realizamos las importaciones
import struct
import socket

TAB_1 = '\t-'
def get_mac_addr(bytes_addr):
 
 bytes_str = map("{:02x}".format, bytes_addr)
 return ':'.join(bytes_str).upper()

def get_ipv4(addr):
 return '.'.join(map(str,addr))


def parse_frame(frame):
 eth_len = 14
 eth_header = frame[:eth_len]
 eth_data = frame[eth_len:]
 dest_mac,src_mac,proto_field1,proto_field2 = struct.unpack('!6s6scc' , eth_header) 
 dest_mac = get_mac_addr(dest_mac)
 src_mac = get_mac_addr(src_mac)

 
 p1 = ''.join(map(str,proto_field1))
 p2 = ''.join(map(str,proto_field2))
 varpro = p1+p2
 
 if varpro == '80':
  ip_proto = 'IPv4'
 elif varpro == '86':
  ip_proto = 'ARP'
 elif varpro == '86DD':
  ip_proto = 'IPv6' 
 else:
  ip_proto = varpro
 print("\nCarmela Sandra Calliconde Carrasco_9186629")
 print('\n\n    Ethernet Header    ')
 print("\t|-Destination_Adrdess :{0}".format(dest_mac))
 print("\t|-Source_Address      :{0}".format(src_mac))
 print("\t|-Protocol            :{0}".format(p1))
 return eth_data,ip_proto


def parse_packet(packet):
 #version IP y longitud del encabezado
 first_byte = packet[0]

 
 ip_version = first_byte >> 4
 ihl = first_byte & 0xF
 
 ip_header_length = (first_byte & 15) * 4

 ttl,varpro,src,dest = struct.unpack('!8xBB2x4s4s',packet[:20])
 iph = struct.unpack('!BBHHHBBH4s4s',packet[0:20])
 ip_tos = iph[1] # char
 ip_len = iph[2] # short int
 ip_id = iph[3]  # short in
 ip_sum = iph[7] #shor int
 #Direccion IP
 src_ip = get_ipv4(src)
 dest_ip = get_ipv4(dest)

 if varpro == 1:
  transport_proto = 'ICMP'
 elif varpro == 6:
  transport_proto = 'TCP'
 elif varpro == 17:
  transport_proto = 'UDP'
 else:
  transport_proto = 'Unknown Protocol Field = '+str(varpro)
 print("\nCarmela Sandra Calliconde Carrasco_9186629")
 print('     IP Header    ')
 
 print("\n\t|-IP_Version         :{0}".format(ip_version),"\n\t|-IP_Heder_Length    :",ihl," DWORD or {0} bytes".format(ip_header_length),
    '\n\t|-Type_Of_Service    :{0}'.format(ip_tos))
 print("\n\t|-IP_Total_Length    :{0}".format(ip_len)," DWORD or {0} bytes".format(ip_len*32//8),
    '\n\t|-Identification     :{0}'.format(ip_id))
 print("\n\t|-TTL                :{0}".format(ttl),"\n\t|-Protocol           :{0}".format(varpro),
    '\n\t|-Checksum           :{0}'.format(ip_sum))
 print("\n\t|-Source_IP          :{0}".format(src_ip),"\n\t|-Destination_IP     :{0}".format(dest_ip),
    '\n\t|-Transport_Protocol :{0}'.format(transport_proto))


 
 return packet[ip_header_length:],transport_proto

def parse_ICMP(data):
 
 icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
 print("\n|Carmela Sandra Calliconde Carrasco_9186629")
 print('     ICMP Header   ')
 print("\n\t|-Type    :{0}".format(icmp_type))
 print("\n\t|-code    :{0}".format(code))
 print("\n\t|-Checksum:{0}".format(checksum))
 return data[8:]



def parse_UDP(data):
 udp_hdr = struct.unpack("!4H", data[:8])
 src_port = udp_hdr[0]
 dest_port = udp_hdr[1]
 length = udp_hdr[2]
 checksum = udp_hdr[3]
 print("\nCarmela Sandra Calliconde Carrasco_9186629")
 print('      UDP Header       ')
 print("\n\t|-Source_Port:{0}".format(src_port))
 print("\n\t|-Destination_Port:{0}".format(dest_port))
 print("\n\t|-Packet_Length:{0}".format(length))
 print("\n\t|-Checksum:{0}".format(checksum))
 return data[8:]

def parse_TCP(data):
 src_port,dest_port,seq,ack,offset_flags = struct.unpack('!HHLLH',data[:14])
 
 tcph =struct.unpack('!HHLLBBHHH' , data[:20])
 sequence = tcph[2]      # uint32_t
 acknowledgement = tcph[3]   # uint32_t
 doff_reserved = tcph[4]     # uint8_t
 tcph_length = doff_reserved >> 12
 tcph_window_size = tcph[6]      #uint16_t
 tcph_checksum = tcph[7]         #uint16_t
 tcph_urgent_pointer = tcph[8]   #uint16_t
 
 
 tcp_header_length = (offset_flags >> 12) * 4
 tcph_length1=offset_flags >> 12

 
 flag_urg = tcph[5] #(offset_flags & 32) >> 5
 flag_ack = (offset_flags & 16) >> 4
 flag_psh = (offset_flags & 8) >> 3
 flag_rst = (offset_flags & 4) >> 2
 flag_syn = (offset_flags & 2) >> 1
 flag_fin = offset_flags & 1
 print("\nCarmela Sandra Calliconde Ca
rrasco_9186629")
 print('      TCP Header  ')
 print("\n\t|-Source_Port          :{0}".format(src_port))
 print("\n\t|-Destination_Port     :{0}".format(dest_port))
 print("\n\t|-Sequence_Number      :{0}".format(seq))
 print("\n\t|-Acknowledge_Number   :{0}".format(ack))
 print("\n\t|-Header_Length        :"+str(tcph_length1)+" DWORD or {0} bytes".format(tcp_header_length))
 #flags
 print("\n\t|-Urgent_Flag          :{0}".format(flag_urg))
 print("\n\t|-Acknowledgement_Flag :{0}".format(flag_ack))
 print("\n\t|-Push_Flag            :{0}".format(flag_psh))
 print("\n\t|-Reset_Flag     :{0}".format(flag_rst))
 print("\n\t|-Synchronise_Flag    :{0}".format(flag_syn))
 print("\n\t|-Finish_Flag     :{0}".format(flag_fin))
 print("\n\t|-Window_Size      :{0}".format(tcph_window_size))
 print("\n\t|-Checksum       :{0}".format(tcph_checksum))
 print("\n\t|-Urgent_Pointer      :{0}".format(tcph_urgent_pointer))
 return data[tcp_header_length:]

def parse_transport_packet(data,protocol):
 application_packet = None
 if protocol == 'TCP':
  application_packet = parse_TCP(data)
 elif protocol == 'UDP':
  application_packet = parse_UDP(data)
 elif protocol == 'ICMP':
  application_packet = parse_ICMP(data)
 return application_packet
 



#Principal
def main():
 #conexion con el socket
 conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3))

 while True:
  #Recibir ethernet
  payload,addr = conn.recvfrom(65535)
  ip_packet,ip_protocol = parse_frame(payload)
  if ip_protocol == 'IPv4':
   transport_packet,transport_proto = parse_packet(ip_packet)
   application_packet = parse_transport_packet(transport_packet,transport_proto)

if __name__=="__main__":
 main()
