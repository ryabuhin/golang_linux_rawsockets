# Implementation Linux raw sockets with Golang (Go)

### ***IP/ICMP network layer | TCP/UDP transport layer - custom realization***

### *Network capabilities:*
* *Listening for all incoming traffic (Ethernet, ARP, IP, ICMP, TCP, UDP etc)*
* *Changing IP options (0x14 - 0x3C | + hlen > 5) before sending packets*
* *Changing Network layer packet as a whole (for example, manual entry source IP and destinaton IP etc)*
* *Changing Transport layer packet as a whole (for example, manual entry TCP/UDP ports, ICMP type requests etc)*
* *Is the host alive on the network*
* *Traceroute with writing IP from output/input interface machine (IP RR & IP TTL respectively)*
* *Ping*

### *In the future:*
* *The realization of the opportunity to reach the machine behind NAT ( IP(SR)+ICMP(ECHO_REQ) )*
