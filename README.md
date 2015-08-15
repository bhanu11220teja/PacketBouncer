bouncer
=======

Done by: | Bhanu Teja Kotte | btkotte@kth.se | | Debopam Bhattacherjee | debopam@kth.se |

A bouncer is a program that "bounces" connections from one machine to another. Similar to proxies, a user always connects to the machine where the bouncer resides and this machine, in turn, connects to the remote server or to any other user's computer. Thus, the server or any other user "sees" only the IP address of the machine where the bouncer is. A bouncer can be used as a means to hide a users’ real IP address, or simply as a way to reach some ports on some machines which are usually unreachable when user is behind a firewall. For example, if user is sitting in a private network with a proxy that only allows web traffic (i.e. port 80 outgoing traffic), user could use a bouncer listening in port 80 on an outer machine and redirect that traffic to a secure shell daemon listening in another server.

The following functionalities were implemented:
a.	A "ping" bouncer (ICMP Echo Request/Reply). The bouncer validates the IP packet headers to make sure that only correct IP headers are bounced. All the IP header fields are validated according to the RFCs. ICMP header is also validated.
b.	A TCP bouncer. The bouncer validates the TCP headers before bouncing. Bouncing between various (non-standard) ports is supported. In addition, concurrent (multiple) connections are supported.
c.	 A FTP proxy, so that it is possible to run FTP via the bouncer. FTP active mode, that is, the FTP PORT command is supported. Concurrent (multiple) FTP connections and Non-standard ports are also supported.

Protocols handled: IP, ICMP, TCP and FTP
Programming language: C (raw socket API, Pcap library)
Tools used for testing: SendIP, w3m
