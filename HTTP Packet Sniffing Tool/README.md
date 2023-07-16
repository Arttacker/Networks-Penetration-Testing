
# Packet Sniffer Tool

This tool allows you to sniff and analyze network traffic traveling through a specific interface. It captures packets and provides useful information such as visited URLs and potential login data. This tool can be used to sniff the http  packets travelling through a remote device in the network, but you need first to be **MITM (Man In The Middle)** so you use also my  [ARP Spoofing Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Tool "ARP Spoofing Tool") to achieve that. Please use this tool responsibly and for educational purposes only.


## Features

- Sniff network traffic on a specified interface
- Capture and display HTTP requests
- Extract visited URLs from HTTP packets
- Detect potential login data from HTTP packets

## Prerequisites

Before running the tool, ensure you have the following requirements:

- Python 3.x
- Required Python packages: `scapy`, `scapy_http`, `halo`, `colorama`

## Usage 

1. Clone the repository or download the `packet_sniffer.py` file to your local machine. 
2. Open a terminal and navigate to the directory containing the script. 
3. Run the following command to install the required dependencies:
```bash
pip install -r requirements.txt
```

Execute the script using the following command:
 ```bash
python packet_sniffer.py -i <interface>
```
 
Replace `<interface>` with the name of the network interface you want to sniff on (e.g., eth0, wlan0).

The tool will start sniffing the network traffic and display captured information in real-time. Press `Ctrl+C` to stop the sniffing process.

## Example Output

```
[+] Sniffing Is Running ☠️ 
[+] HTTP Request >> http://example.com/login 
[+] Possible <Usernames/Passwords> >> username=admin&password=pass ☠️ ☠️ ☠️
```

In the example output above, the tool captured an HTTP request to `http://example.com/login` and detected potential login data in the form of `username=admin&password=pass`.

## Disclaimer

- This tool is meant for educational purposes only. Do not use it for any unauthorized activities.
- Use this tool responsibly and respect the privacy and security of others.
- The developer assumes no liability for any misuse or damage caused by this tool.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## See Also

- [ARP Spoofing Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Tool "ARP Spoofing Tool")
- [ARP Spoofing Detection Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Detection%20Tool)
- [NetCut Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/NetCut%20Tool "NetCut Tool")