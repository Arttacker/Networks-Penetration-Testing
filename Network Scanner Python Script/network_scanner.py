#!/usr/bin/env python3
import argparse

import manuf
import scapy.all as scapy
from halo import Halo


# The below function will take an ip and call the arping() function
# to make an arp request to the given ip to get its MAC Address
# def scan(ip):
#   scapy.arping(ip)

# Now we will implement the arping() function ourselves
# To achieve that we will follow these steps :
# 1 - create an arp request directed to broadcast MAC asking for the IP
# 2 - send packet and receive response
# 3 - parse the response
# 4 - print the result

def scan(ip):
    # A List of dictionaries that the function will store in it the information and return it
    answered_list = []
    # 1 - create an arp request directed to broadcast MAC asking for the IP
    # Creating our request object from ARP Class
    arp_request = scapy.ARP(pdst=ip)
    # To know what are all the fields that this constructor takes you can call ls() :
    # scapy.ls(scapy.ARP())
    # To see the ARP request created :
    # arp_request.summary()
    # To see more details about the contents of this packet :
    # arp_request.show()
    # Creating an ethernet frame object to send this request as a broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # To know what are all the fields that this constructor takes you can call ls() :
    # scapy.ls(scapy.Ether())
    # To see the Ether frame created :
    # broadcast.summary()
    # To see more details about the contents of this packet :
    # broadcast.show()

    # Now we have an arp request and an ether frame
    # To combine them in order to make a broadcast arp request we can use '/' :
    arp_request_broadcast = broadcast / arp_request

    # To see the created final request :
    # arp_request_broadcast.summary()
    # To see more details about the contents of this final packet :
    # arp_request_broadcast.show()

    # 2 - send packet and receive response
    # To send the created packet in our network we will use srp() function
    # This function takes the packet,and it also can take a timeout argument
    # as if it didn't receive a response it will go on for another request
    # It also takes a verbose argument, that controls the amount of details of the function
    # It returns two lists, one for the answered packets and one for the not answered ones.
    # (answered_list,notAnswered_list) = scapy.srp(arp_request_broadcast, timeout=1)
    # since we are not interested in the notAnswered list we can use [0] at the end :
    answered = scapy.srp(arp_request_broadcast,
                         timeout=1, verbose=False)[0]
    # To see the result of answered :
    # answered.show()

    # 3 - parse the response
    # 4 - print the result
    # To get the vendor of the mac address we will use manuf
    # # Create an instance of the MacParser class
    parser = manuf.MacParser()
    # Creating a dictionary for each device in the network and append it to the answered_list
    for packet in answered:
        device = {
            'ip': packet[1].psrc,
            'mac': packet[1].hwsrc,
            'vendor': parser.get_manuf(packet[1].hwsrc) or 'unknown vendor'
        }
        answered_list.append(device)
    return answered_list


def get_arguments():
    # getting the ip range as an argument from the terminal
    parser = argparse.ArgumentParser()
    parser.usage = u"This tool will scan the local network and returns information about the connected devices\nDeveloped By (BigTrader) \u2620\ufe0f"
    parser.add_argument("-r", "--range", dest="ip_range",
                        help="The range of IP Addresses you need to scan")
    arguments = parser.parse_args()
    if not arguments.ip_range:
        parser.error("You need to specify the range of IP Addresses using -r... Type --help")
    else:
        return arguments


def main():
    # Showing the progress via a user-friendly view
    spinner = Halo(text="Scanning...", spinner='dots')
    spinner.start()
    # getting the arguments
    arguments = get_arguments()
    ip_range = arguments.ip_range
    devices = scan(ip_range)
    spinner.stop()

    print("\n---------------------------------------------------------------")
    print("     IP\t\tMAC Address\t\tVendor")
    print("---------------------------------------------------------------")
    for index, device in enumerate(devices, start=1):
        ip = device['ip']
        mac = device['mac']
        vendor = device['vendor']
        print(f"{index}- {ip} | {mac} | {vendor}")
    print("---------------------------------------------------------------")


if __name__ == "__main__":
    main()
