# http://stackoverflow.com/questions/31233780/nameerror-when-using-input-with-python-3-4
#written in Python 3.4.4
#version is printed out on the output
#If you receive "File "<string>", line 1" when running look at the version information printed.
#If it shows other than 3.4 use "python nmap3.py"
#once you select a number you will be asked for an IP address or SNMP string if the script requires it
#The script will output the appropriate nmap command. Copy it and paste into a command line or shell

print('''
0 Download Cisco Configs using SNMP
1 Checking Server Cipher Suites using ports 443, 465, 993 and 995
2 Display SSH fingerprint (Host Keys) 
3 Troubleshooting DHCP with the NMAP Broadcast-DHCP-Discover script
4 Troubleshooting DHCP with the NMAP DHCP-Discover script
5 Troubleshooting IPv6 DHCP with a broadcast discover
6 Brute Forcing SNMP with NMAP - Requires a text file of guesses in c:\tftp-root\snmp-string.txt 
7 BACNET - scripts from https://github.com/digitalbond/Redpoint#enip-enumeratense
8 DNS Broadcast Discover
9 Banner Grab using banner-plus from HD Moore
10 NTP Monlist - Pull down NTP server information
11 NTP INFO - Pull down general NTP information
12 DNS Brute - Uses nselib/data/dns-srv-names for list of SRV records to try, nselib/data/vhosts-full.lst for hosts
13 SMB - Various scripts for SMB servers
14 SNMP on Windows
15 Basic Script Scan the -vv option includes more detail
16 SQL nmap --script smb-os-discovery.nse -p445 192.168.10.221
17 - Check for SSH V1

''')

import sys; print(sys.version)

print()
print()

nmapTest=int(input('Input a number to select '))

if nmapTest == 0:
# 0 Download Cisco Configs
    IPAddress=input('Enter the IP Address ')
    SNMP=input('Enter SNMP Private Community String ')
    print('nmap -sU -p 161 --script snmp-ios-config --script-args snmpcommunity=',SNMP,IPAddress)

elif nmapTest == 1:
# 1 Checking Server Cipher Suites
    IPAddress=input('Enter the IP Address ')
    print('nmap --script ssl-cert,ssl-enum-ciphers -p 443,465,993,995',IPAddress)

elif nmapTest == 2:
# 2 Discovering SSH Host Keys
    IPAddress=input('Enter the IP Address ')
    print('nmap --script ssh-hostkey',IPAddress)

elif nmapTest == 3:
#3 Troubleshooting DHCP with the NMAP Broadcast-DHCP-Discover script
    print('nmap -sU -p67 --script broadcast-dhcp-discover')

elif nmapTest == 4:
#4 Troubleshooting DHCP with the NMAP DHCP-Discover script
    IPAddress=input('Enter the IP Address ')
    print('nmap -sU -p67 --script dhcp-discover',IPAddress)

elif nmapTest == 5:
#5 Troubleshooting IPv6 DHCP discover
    IPAddress=input('Enter the v6 IP Address ')
    print('nmap -6 --script broadcast-dhcp6-discover',IPAddress)

elif nmapTest == 6:
#6 Brute Forcing Telnet with NMAP
    IPAddress=input('Enter the IP Address ')
    print('nmap -p 23 --script telnet-brute --script-args userdb=users.txt,passdb=pw4.txt',IPAddress)

elif nmapTest == 7:
#7 BACNET
#https://github.com/digitalbond/Redpoint#enip-enumeratense
    IPAddress=input('Enter the IP Address ')
    print('nmap -sU -p 47808 -n --script bacnet-info.nse',IPAddress)
    print('nmap -sU -p 47808 -n --script BACnet-discover-enumerate',IPAddress)
    print('nmap -sU -p 47808 -n --script BACnet-discover-enumerate --script-args full=yes',IPAddress)
    print('nmap -p 44818 --script enip-enumerate',IPAddress)
    print('nmap -p 1911 --script fox-info',IPAddress)
    print('nmap -p 502 --script modicon-info.nse -sV',IPAddress)
    print('nmap -p 9600 --script omrontcp-info',IPAddress)
    print('nmap -sU -p 9600 --script omronudp-info',IPAddress)
    print('nmap -p 1962 --script pcworx-info -sV',IPAddress)
    print('nmap -p 20547 --script proconos-info -sV',IPAddress)
    print('nmap -p 102 --script s7-enumerate -sV',IPAddress)

    print('sudo nmap -sU -p 47808 -n --script BACnet-discover-enumerate',IPAddress)
    print('sudo nmap -sU -p 47808 -n --script BACnet-discover-enumerate --script-args full=yes',IPAddress)
    print('sudo nmap -p 1911 --script fox-info',IPAddress)
    print('nmap -p 9600 --script omrontcp-info',IPAddress)
    print('sudo nmap -sU -p 9600 --script omronudp-info',IPAddress)
    print('nmap -p 1962 --script pcworx-info -sV',IPAddress)
    print('nmap -p 20547 --script proconos-info -sV',IPAddress)
    print('sudo nmap -p 102 --script s7-enumerate -sV',IPAddress) 
    print('sudo nmap -p 44818 --script enip-enumerate',IPAddress)
    print('sudo nmap -p 502 --script modicon-info.nse -sV',IPAddress)

elif nmapTest == 8:
#8 DNS Broadcast Discover
    print('nmap --script=broadcast-dns-service-discovery')

elif nmapTest == 9:
#9 Banner Grab
    IPAddress=input('Enter the IP Address ')
    print('nmap -sV --script=banner-plus.nse',IPAddress)

elif nmapTest == 10:
#10 NTP Monlist
    IPAddress=input('Enter the IP Address ')
    print('nmap -sU -pU:123 -n --script=ntp-monlist',IPAddress)

elif nmapTest == 11:
#11 NTP INFO
    IPAddress=input('Enter the IP Address ')
    print('nmap -sU -p 123 --script ntp-info',IPAddress)

elif nmapTest == 12:
#12 DNS Brute
    DNSDomain=input('Enter the DNS Domain Name ')
    print('nmap --script dns-brute --script-args dns-brute.threads=10,dns-brute.domain=DNSDomain')
    print('nmap --script dns-brute --script-args dns-brute.srv,dns-brute.threads=10,dns-brute.domain=DNSDomain dns-brute.hostlist')
    print('The filename of a list of host strings to try. Defaults to nselib/data/vhosts-full.lst')
    print('http://securityblog.gr/2547/enumerate-dns-hostnames-using-nmap/ for more information')     

elif nmapTest == 13:
#13 SMB
    IPAddress=input('Enter the IP Address ')
    print('nmap --script smb-os-discovery.nse -p445',IPAddress)
    print('nmap --script smb-enum-shares,smb-ls -p445',IPAddress)
    print('nmap --script smb-ls --script-args share=c$,path=\\temp -p445',IPAddress)
    print('nmap -p 445 --script smb-mbenum (Master Browser)',IPAddress)
    print('nmap --script smb-security-mode.nse -p445 127.0.0.1')
    print('nmap -sU -sS --script smb-security-mode.nse -p U:137,T:139 127.0.0.1')
    print('nmap --script smbv2-enabled.nse -p445',IPAddress)
    print('nmap -sU -sS --script smbv2-enabled.nse -p U:137,T:139',IPAddress)

elif nmapTest == 14:
#14 SNMP on Windows
    IPAddress=input('Enter the IP Address ')
    print('nmap -sU -p 161 --script=snmp-processes',IPAddress)

elif nmapTest == 15:
#15 Basic Script Scan
    IPAddress=input('Enter the IP Address ')
    print('nmap -sV -sC',IPAddress)
    print('nmap -sV -sC -vv',IPAddress)

elif nmapTest == 16:
#16 SQL
    IPAddress=input('Enter the IP Address ')
    print('nmap --script smb-os-discovery.nse -p445',IPAddress)

elif nmapTest == 17:
#17 SSH V1
    IPAddress=input('Enter the IP Address ')
    print('nmap -script sshv1',IPAddress) 
