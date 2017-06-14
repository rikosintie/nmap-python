# nmap-python
Python Script for my most used nmap scripts

written in Python 3.4.4

To execute on windows
```
python nmap3.py 
```
On Linux
```
python3 nmap3.py
```
You will be prompted to enter y is you are on Linux. If you answer y it will add sudo to the commmand that need root.

To save a default IP address or range create a file called ip.txt in the same folder as the script. In the file add just the IP Address or IP Address range in Nmap format. When you run the script it will list the IP address in the file. Just hit enter to accept or type a new IP address and hit enter.

0. Download Cisco Configs using SNMP
1. Checking Server Cipher Suites using ports 443, 465, 993 and 995
2. Display SSH fingerprint (Host Keys) 
3. Performs routing information gathering through Cisco's (EIGRP) Protocol
4. Display DHCP with the NMAP DHCP-Discover scripts
5. Nmap script to find vulnerable Samba devices such as a printer, NAS or any device that allows Windows clients to connect.
6. Brute Forcing Telnet with NMAP - Requires files of users and guesses 
7. BACNET - scripts from https://github.com/digitalbond/Redpoint#enip-enumeratense
8. DNS Broadcast Discover
9. Banner Grab using banner-plus from HD Moore
10. NTP Monlist - Pull down NTP server information
11. NTP INFO - Pull down general NTP information
12. DNS Brute - Uses nselib/data/dns-srv-names for list of SRV records to try, nselib/data/vhosts-full.lst for hosts
13. SMB - Various scripts for SMB servers
14. SNMP on Windows
15. Scan for MS17-010 Wannacry vulnerability
16. MSSQL - Attempt to determine version, config info and check for blank password
17. Check for SSH V1

```
Input a number to select 0
Enter the IP Address 192.168.10.250
Enter SNMP Private Community String private
nmap -sU -p 161 --script snmp-ios-config --script-args snmpcommunity= private 192.168.10.250
```

Once you select a number you will be asked for an IP address or SNMP string if the script requires it
The script will output the appropriate nmap command. Copy it and paste into a command line or shell

