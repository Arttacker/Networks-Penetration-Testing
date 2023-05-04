# FTP Port 21

## 1-Running The Metasploitable2 To Act As The Server.

## 2-Exploring The Network 
First we should explore our network to see what is the active devices , what is the opened ports , etc..

So I will begin with scanning  the network to see the active hosts on the network by using a tool called `nbtscan` .
`nbtscan` is a command-line tool in Linux used to discover devices in a network that use NetBIOS over TCP/IP protocol. It sends a NetBIOS Name Service (NBT-NS) request to the specified IP address and displays the response, which includes the device's NetBIOS name, MAC address, and whether the device is a workstation or a server. It is useful for enumerating devices in a local area network and for identifying potential security risks associated with the use of NetBIOS.

So lets try it by typing : `nbtscan -r 192.168.0.0/16 ` 

![Screenshot 2023-05-02 222142](https://user-images.githubusercontent.com/99927650/235774983-37a88daa-84f3-446b-b778-5c353db73c65.png)

So I found that the Metasploitable server is already running and I have its IP Address.

After that lets see what is the opened ports in this server , I will use Nmap for this by typing this command : `nmap -sV 192.168.37.137`

![Screenshot 2023-05-02 223039](https://user-images.githubusercontent.com/99927650/235775179-2cdbdb98-779c-4eb7-95dc-78adb7b3b973.png)

So that tells us that there are many ports opened now , But let me test the FTP this time,
first we should know what may cause vulnerability through the FTP service ? 

As we see that the FTP version here is vsftpd 2.3.4

## 3-Vulnerability Testing

After some search I found that there are some of these vulnerabilities like :
1.  Anonymous access: FTP servers often allow anonymous access, which can be used by attackers to gain unauthorized access to files on the server. Testing for anonymous access involves attempting to connect to the FTP server without providing any credentials.
    
2.  Weak authentication: FTP servers may allow weak authentication methods such as plain text passwords, which can be intercepted by attackers. Testing for weak authentication involves attempting to connect to the FTP server with commonly used usernames and passwords.
    
3.  FTP bounce attack: FTP bounce attacks can be used to scan other hosts or networks that are not directly accessible to the attacker. Testing for FTP bounce attacks involves attempting to connect to a remote host using the FTP server as a proxy.
    
4.  File permission issues: FTP servers may have misconfigured file permissions that allow unauthorized access or modification of files. Testing for file permission issues involves attempting to access or modify files that should not be accessible or modifiable by the attacker.
    
5.  Data injection attacks: FTP servers may be vulnerable to data injection attacks, where an attacker can inject malicious code or commands into files on the server. Testing for data injection attacks involves attempting to upload files with malicious content to the FTP server.


### 1-Anonymous access

>So lets see what about the Anonymous access .

To test Anonymous access we can use the built in nmap scripts , here we should use the `ftp-anon` script to test that by typing this command :
`nmap --script ftp-anon -p21 192.168.37.137`

And as we see that there is "Anonymous access" vulnerability here !
![Screenshot 2023-05-02 225302](https://user-images.githubusercontent.com/99927650/235775249-192e4a71-2649-4be6-8a3f-dcba303d09d5.png)


----------------------------------------------------------------------

## Testing The Remaining FTP Vulnerabilities After Exams!

----------------------------------------------------------------------
