nmap3.python changelog
------------------------------------------------------------------------------------
2017-07-09 (YYYY-MM-DD) - CHANGED

1. Added option -1 to display some nmap options
2. Changed `Enter the IP Address:` to `Enter the IP Address or Domain Name:` on the prompt.

------------------------------------------------------------------------------------
2017-07-08 (YYYY-MM-DD) - CHANGED

Added port 3389 to script 1 SSL ciphers. This checks the ciphers offered by the Microsoft RDP service. I found that a fully patched 2008 R2 server offers up RC4 by default.

I documented the steps needed to enable TLS1.1/1.2 in this blog post [Enabling TLS 1.1/1.2 for RDP in Microsoft Server 2008R2/Windows 7 SP1](https://mwhubbard.blogspot.com/2017/07/enabling-tls-1112-for-rdp-in-microsoft.html)

------------------------------------------------------------------------------------

