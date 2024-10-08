# Code Injector Tool

The **Code Injector Tool** is a Python script designed for intercepting HTTP responses and injecting custom payloads into them. This tool can be used for educational purposes and ethical hacking scenarios to demonstrate potential security vulnerabilities related to code injection in web applications.

**Disclaimer:** This tool should only be used for educational purposes and with proper authorization. Unauthorized use is strictly prohibited.

## Features

- Intercepts HTTP responses and injects custom payloads.
- Supports injecting payloads into HTML responses.
- Can be used for educational purposes and ethical hacking teaching.

## Prerequisites

Ensure you have the following prerequisites installed on your system:

- Python 3
- Required Python libraries: `argparse`, `subprocess`, `sys`, `time`, `functools`, `netfilterqueue`, `scapy`, `colorama`, `halo`

## Usage

### Installation

1. Clone the repository or download the `code_injector.py` file to your local machine.
    
2. Open a terminal and navigate to the directory containing the script.
    
3. Install the required dependencies by running:
```bash
pip install -r requirements.txt
```
 
### Execution

Execute the script using the following command:
```bash
python code_injector.py -l <local_mode> -i <interface> --payload <custom_payload> --port <listening_port>
```

- `<local_mode>`: Use `-l` or `--local` if you are testing on your local machine or when using [bettercap].
    
- `<interface>`: The network interface you want to use in the attack.
    
- `--payload`: The custom payload you want to inject into HTTP responses, which can be JavaScript code, HTML code, or any other code snippet.
    
- `--port`: The port number on which you will listen and transmit packets (e.g., `8080` if you are using [bettercap]).
    

**Important:** This tool requires root privileges to manipulate network packets, so ensure that you run it with appropriate permissions.

### Example
```bash
python code_injector.py -l -i eth0 --payload "<script>alert('Injected Code');</script>" --port 8080
```

### Workflow

1. The tool intercepts HTTP responses containing HTML content.
    
2. It injects the custom payload into the HTML response at a specified location (e.g., before `</body>`).
    
3. The modified response is forwarded to the victim's machine.
    
4. The injected code is executed when the victim's browser renders the page.
    

## Important Note

This tool should only be used for educational purposes and with proper authorization. Unauthorized use is strictly prohibited. The developer is not responsible for any misuse or damage caused by this tool.

## See Also

- [ARP Spoofing Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Tool "ARP Spoofing Tool")
- [ARP Spoofing Detection Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Detection%20Tool)
- [DNS Spoofing Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/DNS%20Spoofing%20Tool)
- [HTTP Packet Sniffing Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/HTTP%20Packet%20Sniffing%20Tool)