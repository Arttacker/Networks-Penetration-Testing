
# Mac Changer Python Script



This script allows you to change the MAC (Media Access Control) address of a given network interface on your system. It is useful for scenarios where you want to modify your device's MAC address for security or privacy reasons.
## Prerequisites 
- Python 3.x 
- Linux-based operating system (script tested on Linux)

## Usage
1. Clone the repository or download the `mac_changer.py` file to your local machine.
2. Open a terminal and navigate to the directory containing the script.
3. Run the following command to view the available options and usage instructions:
```bash
python3 mac_changer.py --help
```

1. Specify the interface and new MAC address to change:
```bash
python3 mac_changer.py -i <interface_name> -m <new_mac_address>
```

Replace `<interface_name>` with the name of the network interface you want to modify (e.g., eth0, wlan0). Provide the `<new_mac_address>` in the format of `XX:XX:XX:XX:XX:XX`.

2. After executing the command, the script will attempt to change the MAC address of the specified interface. It will display the current and new MAC addresses, along with a success or failure message.

## Examples

- To change the MAC address of the `eth0` interface to `00:11:22:33:44:55`, run the following command:
```bash
python3 mac_changer.py -i eth0 -m 00:11:22:33:44:55
```

- If the MAC address change is successful, you will see the following output:
```
[+] Old MAC Address For <eth0> Is <AA:BB:CC:DD:EE:FF>
[+] The MAC Address For <eth0> Changed Successfully To <00:11:22:33:44:55>
```

- If the MAC address change fails due to any reason, you will see the following output:
```
[-] The MAC Address Failed To Change
```

## Disclaimer
This script is intended for educational and testing purposes only. Use it responsibly and with proper authorization. The developer assumes no liability for any misuse or damage caused by this script.