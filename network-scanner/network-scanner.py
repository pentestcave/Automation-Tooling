#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range")
    options = parser.parse_args()
    return options


def scan(ip):
    # scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    # set the destination IP
    # arp_request.pdst=ip
    # create an Ethernet object
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    # print(broadcast.summary())
    # Check available methods in scapy Ether class
    # scapy.ls(scapy.Ether())
    # combine into one packet
    arp_request_broadcast = broadcast / arp_request
    # send and receive packets with custom Ether() part
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # now break the answered_list to access individual elements
    clients_list = []
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        # append the dictionary to the bigger list
        clients_list.append(clients_dict)
    return clients_list
    # print(element[1].psrc + "\t\t" + element[1].hwsrc)
    # print(answered_list.summary())
    # print(arp_request_broadcast.summary())
    # show more packet details
    # arp_request_broadcast.show()

    # print(arp_request.summary())
    # Check available methods in scapy ARP class
    # scapy.ls(scapy.ARP())


def print_result(results_list):
    print("-------------------------------------------------")
    print("IP Address\t\t\tMAC Address")
    print("-------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
