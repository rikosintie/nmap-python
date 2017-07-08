nmap3.python changelog

------------------------------------------------------------------------------------
2017-07-08 (YYYY-MM-DD) - CHANGED

Added port 3389 to script 1 SSL ciphers. This checks the ciphers offered by the Microsoft RDP service. I have found that a fully patched 2008 R2 server offers up RC4 by default.

The best I could find for server 2008R2/Win7SP1 was to enable FIPS level security per this MS document [Tip: Secure RDS (Remote Desktop Services) Connections with SSL](https://technet.microsoft.com/en-us/library/ff458357.aspx?f=255&MSPPError=-2147217396)

Pretty lame though, it still uses 3DES and SHA1. If anyone knows how to setup RDP for modern ciphers please let me know.

**_Example before enabling FIPS_**

Input a number to select a script 1

Enter the IP Address [192.168.97.136]: 192.168.10.221

<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>

nmap --script ssl-cert,ssl-enum-ciphers -p 443,465,993,995,**3389** 192.168.10.221

<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
mhubbard@1S1K-SYS76:~/Dropbox/Python/Scripts$ nmap --script ssl-cert,ssl-enum-ciphers -p 443,465,993,995,3389 192.168.10.221
```
Starting Nmap 7.50 ( https://nmap.org ) at 2017-07-08 10:28 PDT
Nmap scan report for win-l6hbt78g89g.pu.pri (192.168.10.221)
Host is up (0.0052s latency).

PORT     STATE  SERVICE
443/tcp  closed https
465/tcp  closed smtps
993/tcp  closed imaps
995/tcp  closed pop3s
3389/tcp open   ms-wbt-server
| ssl-cert: Subject: commonName=WIN-L6HBT78G89G.pu.pri
| Issuer: commonName=WIN-L6HBT78G89G.pu.pri
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2017-05-27T19:55:04
| Not valid after:  2017-11-26T19:55:04
| MD5:   6429 05ea b708 ffa1 fb56 cd62 8a7e 8acb
|_SHA-1: c160 c6b5 8d2c 0702 b86b fa8b c717 d25c 44a1 89df
| ssl-enum-ciphers: 
|   TLSv1.0: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (secp256r1) - A
|       TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 1024) - A
|       TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 1024) - A
|       TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|       TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C
|       TLS_RSA_WITH_RC4_128_MD5 (rsa 2048) - C
|     compressors: 
|       NULL
|     cipher preference: server
|     warnings: 
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|       Broken cipher RC4 is deprecated by RFC 7465
|       Ciphersuite uses MD5 for message integrity
|       Key exchange (dh 1024) of lower strength than certificate key
|       Weak certificate signature: SHA1
|_  least strength: C

Nmap done: 1 IP address (1 host up) scanned in 5.74 seconds
```

**_Example after enabling FIPS_**

```
mhubbard@1S1K-SYS76:~/Dropbox/Python/Scripts$ nmap --script ssl-cert,ssl-enum-ciphers -p 443,465,993,995,3389 192.168.97.135

Starting Nmap 7.50 ( https://nmap.org ) at 2017-07-08 13:50 PDT
Nmap scan report for 192.168.97.135
Host is up (0.00058s latency).

PORT     STATE  SERVICE
443/tcp  closed https
465/tcp  closed smtps
993/tcp  closed imaps
995/tcp  closed pop3s
3389/tcp open   ms-wbt-server
| ssl-cert: Subject: commonName=FFKN25S
| Issuer: commonName=FFKN25S
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2017-07-07T19:43:57
| Not valid after:  2018-01-06T19:43:57
| MD5:   835d ab76 7752 5d8a 4a3e d5d9 5fc3 4248
|_SHA-1: ac32 dc26 ae9d 2308 405e 595f 0e9f 4102 f661 8341
| ssl-enum-ciphers: 
|   TLSv1.0: 
|     ciphers: 
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|     compressors: 
|       NULL
|     cipher preference: indeterminate
|     cipher preference error: Too few ciphers supported
|     warnings: 
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|       Weak certificate signature: SHA1
|_  least strength: C

Nmap done: 1 IP address (1 host up) scanned in 6.97 seconds
```

------------------------------------------------------------------------------------

