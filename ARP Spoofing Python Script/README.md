
# ARP Spoofing Python Script

This script enables ARP spoofing, a technique used in network security testing to intercept and manipulate network traffic between a target device and the gateway. It allows you to capture network packets and analyze the traffic for security assessment purposes.

**Note: ARP spoofing is an advanced technique that should only be used legally and with proper authorization. Misusing this technique may violate laws and harm network integrity and privacy. Use this script responsibly and at your own risk.**

## Prerequisites

- Python 3.x
- Required Python packages: `scapy`

## Usage 
1. Clone the repository or download the `arp_spoof.py` file to your local machine.
2. Open a terminal and navigate to the directory containing the script. 
3. Run the following command to install the required dependencies:
```bash
pip install scapy
```

1. Execute the script using the following command:
```bash
python3 arp_spoof.py -i <interface> -t <target_ip> -g <gateway_ip> -f <ip_forwarding>
```
Replace `<interface>` with the network interface to use for the attack (e.g., eth0, wlan0). Provide the `<target_ip>` and `<gateway_ip>` as the IP addresses of the target device and the gateway, respectively. The `-f` or `--ip_forwarding` option is used to enable or disable IP forwarding (set it to `1` to enable and `0` to disable).

**Example:**
```bash
python3 arp_spoof.py -i eth0 -t 192.168.0.100 -g 192.168.0.1 -f 1
```

3. The script will initiate the ARP spoofing attack, tricking the target device into believing that the script is the gateway and vice versa. This allows you to intercept and analyze the network traffic between them.
    
4. Press `Ctrl+C` to stop the attack and restore the ARP tables of the target device and the gateway.

**Warning: Use this script responsibly and with proper authorization. ARP spoofing can disrupt network connectivity and potentially violate laws and policies. Use it in controlled environments and only with consent from the network owner.**

## Disclaimer

- This script is intended for educational and testing purposes only. Use it responsibly and with proper authorization. The developer assumes no liability for any misuse or damage caused by this script.