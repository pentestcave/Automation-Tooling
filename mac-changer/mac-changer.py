#!/usr/bin/env python

import subprocess
import optparse
import re


def get_arguments():
    # Object to Handle or Parse User Inputs Using Arguments
    parser = optparse.OptionParser()
    # Adding Options to Parser Object
    parser.add_option("-i", "--interface", dest="interface", help="Network Interface to Change MAC Address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC Address")
    # Return Arguments & Values
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[+] Please Specify an Interface, use --help for More Info")
    elif not options.new_mac:
        parser.error("[+] Please Specify a New MAC, use --help for More Info")
    return options


def change_mac(interface, new_mac):
    # A Much More Secure Version
    print("\n[+] Changing MAC Address for " + interface + " to " + new_mac + "\n")
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])
    print("[+] Interface MAC Address Successfully Changed!\n")
    # subprocess.call(["ifconfig", interface])


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    # print(ifconfig_result)
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))

    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not read MAC address.")


# interface = options.interface
# new_mac = options.new_mac

# Function Calls
options = get_arguments()
current_mac = get_current_mac(options.interface)
print("Current MAC Address =  " + str(current_mac))

change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)

if current_mac == options.new_mac:
    print("[+] MAC address was successfully changed to " + current_mac)
else:
    print("[-] Mac address change was not successful")

# For Python 2, use raw_input()
# interface = input("Please Enter Network Interface >")
# new_mac = input("Please Enter New MAC Address >")
# print("[+] Changing MAC Address for " + interface + " to " + new_mac)
# subprocess.call("ifconfig " + interface + " down", shell=True)
# subprocess.call("ifconfig " + interface + " hw ether " + new_mac, shell=True)
# subprocess.call("ifconfig " + interface + " up", shell=True)
# print("[+] Interface MAC Address Successfully Changed!")
# subprocess.call("ifconfig " + interface, shell=True)
