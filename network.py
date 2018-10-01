import socket, sys
import codecs
from struct import *
import re
import redis


r = redis.StrictRedis(host='localhost', port=6379, db=0)
for key in r.scan_iter("prefix:*"):
    r.delete(key)
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error  :
    print ('Socket could not be created. Error Code : ')
    sys.exit()

while True:
    packet = s.recvfrom(65565)

    # packet string from tuple
    packet = packet[0]

    # parse ethernet header
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
   # print ('Destination MAC : ' + get_mac_addres(packet[0:6])+ ' Source MAC : ' + get_mac_addres(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
   # print("**************************")
    if eth_protocol == 8:
        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = packet[eth_length:20 + eth_length]

        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        if protocol == 6:#tcp  paketleri icin
            
            t = iph_length + eth_length
            tcp_header = packet[t:t + 20]
            tcph = unpack('!HHLLBBHHH', tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            if d_addr=="192.168.1.35":
                if r.get(s_addr):
                    print(r.get(s_addr))

            elif s_addr=="192.168.1.35":
                r.set(d_addr,sequence)
                
            
            if d_addr=="192.168.1.45":
                if r.get(s_addr):
                    if sequence==r.get(s_addr) or int(sequence) ==int(r.get(s_addr))+1:
                        print("sfaf")
                    else:
                        print(s_addr)
                else:
                    r.set(s_addr,acknowledgement)
            else:
                r.set(d_addr,acknowledgement)
                
