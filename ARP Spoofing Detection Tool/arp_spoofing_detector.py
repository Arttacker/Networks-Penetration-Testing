#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import sys
from halo import Halo
from colorama import init, Fore


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.usage = f"This is a tool that detects ARP spoofing by listening for any fake ARP Responses\nDeveloped By (BigTrader) \u2620\ufe0f"
    parser.add_argument("-i", "--interface", dest="interface",
                        help="The interface that you want to listen on", required=True)
    arguments = parser.parse_args()

    return arguments


# Creating a global spinner object for showing the progress of our script:
spinner = Halo(text=" Monitoring For Any Fake ARP Responses...", spinner='dots')
# Initialize colorama
init()


# This function takes an IP address and gets its MAC using ARP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    exploring_packet = broadcast / arp_request

    # Checking if the target gave us its MAC Address
    try:
        for i in range(4):
            response = scapy.srp1(exploring_packet, timeout=2, verbose=False)
            if response:
                return response.hwsrc

        if not response:
            sys.exit(
                "[-] An ARP Response Captured But When We Tried To Validate The Sender Device, It Didn't Respond With Its MAC Address")
    except Exception as e:
        sys.exit(f"\n[-] An unexpected error occurred: {str(e)}")


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# We already knew how to perform the attack, and the spoofing was that the hacker tells the victim that he is-at a spoofed IP
# So, if we checked that the received packet's ip actually has the MAC Address that he is telling us, It is then a
# legitimate ARP Response.
# But if we detected that he actually doesn't own this ip, So we are under an ARP Spoofing Attack !
def process_sniffed_packet(packet):
    # Capturing all the ARP Responses:
    if packet.haslayer(scapy.ARP) and (packet[scapy.ARP].op == 2):
        # Checking the legitimacy of the response by asking for the actual mac address of the ip in the response:
        response_ip = packet[scapy.ARP].psrc
        response_mac = packet[scapy.ARP].hwsrc
        actual_mac = get_mac(response_ip)
        if actual_mac != response_mac:
            spinner.stop()
            print(Fore.RED + "[!!] ARP Spoofing Detected, You Are Under Attack [!!]")


def main():
    try:
        arguments = get_arguments()
        interface = arguments.interface
        spinner.start()
        sniff(interface)
    except KeyboardInterrupt:
        spinner.stop()
        sys.exit("\n[x] Monitoring Stopped")
    except Exception as e:
        sys.exit("\n[-] An unexpected error occurred: ", str(e))


if __name__ == '__main__':
    main()