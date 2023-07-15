
# NetCut Tool

The NetCut Tool is a Python script that allows you to cut network traffic between a device and its gateway. This tool is designed for educational purposes and testing only.

## Prerequisites

- Python 3.x installed on your system 
- Required Python packages: `netfilterqueue` 
- Administrative privileges (required for modifying firewall rules)

## Usage 

1. Clone the repository or download the netcut.py` file to your local machine.
2. Open a terminal and navigate to the directory containing the script. 
3. Run the following command to install the required dependencies:
```bash
pip install netfilterqueue
```


1. Execute the script using the following command:
```bash
python3 netcut.py -i <interface> -l <local_test>
```
Replace `<interface>` with the name of the network interface you want to use for the attack. Set `<local_test>` to 1 if you are testing on your local machine.

2. The tool will intercept and drop network packets between the specified device and its gateway.

## Important Notes

- This tool should be used responsibly and legally. Do not use it for malicious purposes.
- Make sure you have the necessary permissions and legal authorization before running this tool.
- Be cautious when using the NetCut Tool, as it can disrupt network communication.


## Disclaimer

The NetCut Tool is provided for educational and testing purposes only. The developer assumes no responsibility for any misuse or damage caused by this tool. Use at your own risk.

## See Also

- [ARP Spoofing Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Tool "ARP Spoofing Tool")
- [ARP Spoofing Detection Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Detection%20Tool)

