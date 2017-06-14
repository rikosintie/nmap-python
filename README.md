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
You will be prompted to enter y is you are on Linux. If you answer y it will add sudo to the commands that need root.

To save a default IP address or range create a file called ip.txt in the same folder as the script. In the file add just the IP Address or IP Address range in Nmap format. When you run the script it will list the IP address in the prompt. Just hit enter to accept the default or type a new IP address and hit enter.

0. Download Cisco Configs using SNMP - https://nmap.org/nsedoc/scripts/snmp-ios-config.html

1. Checking Server Cipher Suites using ports 443, 465, 993 and 995 - https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html

2. Display SSH fingerprint (Host Keys) on an SSh server - https://nmap.org/nsedoc/scripts/ssh-hostkey.html

3. Performs routing information gathering through Cisco's (EIGRP) Protocol - https://nmap.org/nsedoc/scripts/broadcast-eigrp-discovery.html

4. Display DHCP with the NMAP DHCP-Discover scripts - https://nmap.org/nsedoc/scripts/dhcp-discover.html 
   https://nmap.org/nsedoc/scripts/broadcast-dhcp-discover.html
   Display IPv6 DHCP with a broadcast discover - https://nmap.org/nsedoc/scripts/broadcast-dhcp6-discover.html

5. Nmap script to find vulnerable Samba devices such as a printer, NAS or any device that allows Windows clients to connect.
   Download script from https://svn.nmap.org/nmap/scripts/smb-vuln-cve-2017-7494.nse
   
6. Brute Forcing Telnet with NMAP - Requires files of users and guesses - https://nmap.org/nsedoc/scripts/telnet-brute.html 

7. BACNET - scripts from https://github.com/digitalbond/Redpoint#enip-enumeratense

8. DNS Broadcast Discover - https://nmap.org/nsedoc/scripts/broadcast-dns-service-discovery.html

9. Banner Grab using banner-plus from HD Moore - https://github.com/hdm/scan-tools/blob/master/nse/banner-plus.nse

10. NTP Monlist - Pull down NTP server information - https://nmap.org/nsedoc/scripts/ntp-monlist.html

11. NTP INFO - Pull down general NTP information - https://nmap.org/nsedoc/scripts/ntp-info.html

12. DNS Brute - Uses nselib/data/dns-srv-names for list of SRV records to try, nselib/data/vhosts-full.lst for hosts.

13. SMB - Various scripts for SMB servers

14. Is SNMP running on a Windows machine - https://nmap.org/nsedoc/scripts/snmp-processes.html
    Grab HP printer password

15. Scan for MS17-010 Wannacry vulnerability - https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html  

16. MSSQL - MSSQL - Attempt to determine version, config info and check for blank password -- https://nmap.org/nsedoc/scripts/ms-sql-info.html

17. Check for SSH V1 - https://nmap.org/nsedoc/scripts/sshv1.html

Once you select a number you will be asked for an IP address or SNMP string if the script requires it
The script will output the appropriate nmap command. Copy it and paste into a command line or shell.

```
Input a number to select 0
Enter the IP Address 192.168.10.250
Enter SNMP Private Community String private
nmap -sU -p 161 --script snmp-ios-config --script-args snmpcommunity= private 192.168.10.250
```

