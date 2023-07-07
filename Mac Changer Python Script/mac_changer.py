#!/usr/bin/env python3

import optparse
import re
import subprocess


# This function will return that arguments that are passed by the user , to use them in the script
def get_arguments():
    # Here we are creating an instance of the "OptionParser" class to use its features
    parser = optparse.OptionParser()
    # Setting the main usage of the script
    parser.usage = u"This tool changes the MAC Address for a given interface\nDeveloped By (BigTrader) \u2620\ufe0f"
    # Now we need to define the options that are available for the script
    # The first two args are for the option:
    # The "dest" arg is for the variable name that will store the value for this option
    # The "help" arg is for explaining what is this arg used for , if we typed the name of the script --help :
    parser.add_option("-i", "--interface", dest="interface", help="The interface to change its MAC Address")
    parser.add_option("-m", "--mac", dest="newMac", help="The new MAC Address To be set")

    # To parse the arguments that the user will pass we will use "parse_args()" function
    # The options will carry an object of type "<class 'optparse.Values'>"
    # The parameters will carry a List of the parameters passed
    (options, parameters) = parser.parse_args()

    # Handling the missing args:
    if not options.interface or not options.newMac:
        parser.error("[-] unexpected arguments for mac_changer ...Type --help")
    else:
        return options

    # This function will change the MAC Address using the parameters returned by get_arguments() function


def change_mac(interface, new_mac):
    # "call" function takes the command to be rum as arguments
    # To pass the command in a secure way we will make list for each command :
    down_interface = ["sudo", "ifconfig", interface, "down"]
    change_mac = ["sudo", "ifconfig", interface, "hw", "ether", new_mac]
    up_interface = ["sudo", "ifconfig", interface, "up"]

    print(f"[+] Changing the MAC Address for <{interface}> ,To <{new_mac}>")

    # executing the commands
    subprocess.call(down_interface)
    subprocess.call(change_mac)
    subprocess.call(up_interface)


def main():
    try:
        options = get_arguments()
        interface, new_mac = [options.interface, options.newMac]
        # Getting the old MAC Address for the interface
        old_ifconfig = subprocess.check_output(["ifconfig", interface], text=True)
        old_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", old_ifconfig)
        change_mac(interface, new_mac)
        # Checking if the mac has changed:
        ifconfig = subprocess.check_output(["ifconfig", interface], text=True)
        mac_after_change = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig)
        if mac_after_change:
            print(f"[+] Old MAC Address For <{interface}> Is <{old_mac[0]}>")
            if mac_after_change[0] == new_mac:
                print(f"[+] The MAC Address For <{interface}> Changed Successfully To <{new_mac}>")
            else:
                print("[-] The MAC Address Failed To Change")
        else:
            print(f"[-] Couldn't Find MAC Address For <{interface}> Interface")
    except Exception as e:
        print("\n[-] An unexpected error occurred :", str(e))


if __name__ == '__main__':
    main()
