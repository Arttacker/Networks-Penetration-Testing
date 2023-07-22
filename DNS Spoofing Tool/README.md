
# DNS Spoofing Tool

The DNS Spoofing Tool is a powerful tool that intercepts DNS responses, modifies them, and forwards them to their destinations after being modified. It is designed for educational purposes and ethical hacking teaching only. This tool demonstrates the vulnerabilities present in the DNS system and helps users understand the importance of securing DNS infrastructure.

**Disclaimer: This tool should only be used for educational purposes and with proper authorization. Unauthorized use is strictly prohibited.**

## Features

- Intercepts DNS responses and modifies them
- Redirects victims to a fake website by modifying DNS responses
- Works as a man-in-the-middle (MITM) attack

## Prerequisites

- Python 3
- Required Python libraries: `argparse`, `subprocess`, `sys`, `time`, `functools`, `netfilterqueue`, `scapy`, `colorama`, `halo`

## Usage 
1. Clone the repository or download the `dns_spoof.py` file to your local machine. 
2. Open a terminal and navigate to the directory containing the script. 
3. Run the following command to install the required dependencies:
```bash
pip install -r requirements.txt
```

Execute the script using the following command:

```bash
sudo python dns_spoofing_tool.py -i <interface> -f <fake_ip> -t <target_website> -l <local_test>
```

- `<interface>`: The network interface you want to use in the attack (e.g., eth0, wlan0).
- `<fake_ip>`: The IP address of the fake website you want to redirect the victim to.
- `<target_website>`: The website you are waiting for its DNS response to spoof it.
- `<local_test>`: Set it to 1 if you are testing on your local machine.

**Wait for the victim to request the target website**. Once the DNS response is captured, the DNS spoofing process will start. The victim will be redirected to the fake website.

**DNS Spoofing Process:** Once the DNS response for the target website is captured, the DNS spoofing process will begin. The tool will modify the DNS response to redirect the victim to the specified fake IP address and send the modified response to the victim.

## Example Output

```
[+] A DNS Response For The Request : facebook.com. Is Captured !
[+] DNS Spoofing Started...
[+] DNS Spoofing Done ☠️ 
```


**Note:**
- Run the tool with root privileges (`sudo`) to allow network packet manipulation.
- Its better that the history of the browsing data for the device being tested to be cleared.

## Important Note

This tool should only be used for educational purposes and with proper authorization. Unauthorized use is strictly prohibited. The developer is not responsible for any misuse or damage caused by this tool.

## See Also

- [ARP Spoofing Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Tool "ARP Spoofing Tool")
- [ARP Spoofing Detection Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Detection%20Tool)
- [HTTP Packet Sniffing Too](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/HTTP%20Packet%20Sniffing%20Tool "HTTP Packet Sniffing Tool")
- [NetCut Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/NetCut%20Tool "NetCut Tool")