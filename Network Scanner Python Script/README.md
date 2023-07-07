
# Network Scanner Python Script

This script allows you to perform network scanning based on the ARP protocol. It discovers and displays the connected devices in the network, including their MAC addresses, IP addresses, and vendor information.

## Prerequisites
- Python 3.x 
- Required Python packages: `manuf`, `scapy`, `halo`

## Usage
1. Clone the repository or download the `network_scanner.py` file to your local machine.
2. Open a terminal and navigate to the directory containing the script. 
3. Run the following command to install the required dependencies:
```bash
pip install -r requirements.txt
```
4. Run the following command to view the available options and usage instructions:
```bash
python3 network_scanner.py --help
```

1. Specify the interface and new MAC address to change:
```bash
python3 network_scanner.py -r <ip_range> 
```

Replace `<ip_range>` with you wanted IP Address Range in the format of `x.x.x.x/prefix`.

2. The script will initiate the scanning process and display a spinner indicating the progress. Once the scanning is complete, it will show a table with the connected devices, including their IP addresses, MAC addresses, and vendor information.
## Example Output
```
------------------------------------------------------------
 IP              MAC Address          Vendor
------------------------------------------------------------
 1- 192.168.1.1 | 00:11:22:33:44:55 | Cisco Systems, Inc.
 2- 192.168.1.2 | AA:BB:CC:DD:EE:FF | unknown vendor
 3- 192.168.1.3 | 11:22:33:44:55:66 | Apple, Inc.
------------------------------------------------------------

```

## Disclaimer

- This script is intended for educational and testing purposes only. Use it responsibly and with proper authorization. The developer assumes no liability for any misuse or damage caused by this script.
