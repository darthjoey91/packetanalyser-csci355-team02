#!/usr/bin/env python
#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
#Silver Moon (m00n.silv3r@gmail.com)




import socket, sys
from struct import *
#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
      b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
      return b

class packetSniffer():
    def __init___(self):
      self.sniff();



    #create a AF_PACKET type raw socket (thats basically packet level)
    #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */

    def sniff(self):
        try:
            s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

        # receive a packet
        while True:
            packet = s.recvfrom(65565)

        #packet string from tuple
            packet = packet[0]

        #parse ethernet header
            eth_length = 14
            eth_header = packet[:eth_length]
            eth = unpack('!6s6sH' , eth_header)
            eth_protocol = socket.ntohs(eth[2])
            print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

            #Parse IP packets, IP Protocol number = 8
             #Parse IP packets, IP Protocol number = 8
            if eth_protocol == 8 :
                #Parse IP header
                #take first 20 characters for the ip header
                ip_header = packet[eth_length:20+eth_length]

                #now unpack them :)
                iph = unpack('!BBHHHBBH4s4s' , ip_header)

                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF

                iph_length = ihl * 4

                ttl = iph[5]
                self.protocol = iph[6]
                self.s_addr = socket.inet_ntoa(iph[8]);
                self.d_addr = socket.inet_ntoa(iph[9]);

                print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(self.protocol) + ' Source Address : ' + str(self.s_addr) + ' Destination Addre$

                #TCP protocol
                if self.protocol == 6 :
                    t = iph_length + eth_length
                    tcp_header = packet[t:t+20]

                    #now unpack them :)
                    tcph = unpack('!HHLLBBHHH' , tcp_header)

                    self.source_port = tcph[0]
                    self.dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    doff_reserved = tcph[4]
                    tcph_length = doff_reserved >> 4

                    print 'Source Port : ' + str(self.source_port) + ' Dest Port : ' + str(self.dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header l$

                    h_size = eth_length + iph_length + tcph_length * 4
                    data_size = len(packet) - h_size

                   #get data from the packet
                    self.data = packet[h_size:]

                    print 'Data : ' + self.data

                    #ICMP Packets
                elif self.protocol == 1 :
                    u = iph_length + eth_length
                    icmph_length = 4
                    icmp_header = packet[u:u+4]

                    #now unpack them :)
                    icmph = unpack('!BBH' , icmp_header)

                    icmp_type = icmph[0]
                    code = icmph[1]
                    checksum = icmph[2]

                    print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

                    h_size = eth_length + iph_length + icmph_length
                    data_size = len(packet) - h_size

                    #get data from the packet
                    self.data = packet[h_size:]

                    print 'Data : ' + self.data

                    #UDP packets
                elif self.protocol == 17 :
                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = packet[u:u+8]

                   #now unpack them :)
                    udph = unpack('!HHHH' , udp_header)

                    self.source_port = udph[0]
                    self.dest_port = udph[1]
                    self.length = udph[2]
                    checksum = udph[3]

                    print 'Source Port : ' + str(self.source_port) + ' Dest Port : ' + str(self.dest_port) + ' Length : ' + str(self.length) + ' Checksum : ' + str(checksum)

                    h_size = eth_length + iph_length + udph_length
                    data_size = len(packet) - h_size

                    #get data from the packet
                    self.data = packet[h_size:]

                    print 'Data : ' + self.data

                #some other IP packet like IGMP
                else :
                    print 'Protocol other than TCP/UDP/ICMP'


