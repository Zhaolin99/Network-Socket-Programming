# NetworkProgramming-INTRO
Overview of computer networks, TCP/IP protocol suite, computer-networking applications and protocols, transport-layer protocols, network architectures, Internet Protocol (IP), routing, link-layer protocols, local area and wireless networks, medium access control, physical aspects of data transmission, and network-performance analysis. 

### 1. Socket Programming: DNS Project

Implement a DNS Client ((1&8) in Figure 1). The client should send a DNS request to the IP address of three different DNS resolvers provided in Table 1 to query tmz.com. After getting the IP address of the tmz.com’s web server, initiate a TCP connection to the HTTPs server process located at port 80 at that IP address.
 - Build a DNS query
 - UDP Socket Calls
 - Receive the response per request from the DNS server
 - Parse response message
 - Returning the resolved IP address for an A record

Implement the local DNS resolver using the socket API to find the IP address of tmz.com. 
Implement the iterative strategy to resolve input DNS queries by consulting the root name server, the TLD name server, and finally the authoritative DNS server to get the IP address of the requested hostname.

- Build a DNS query
- UDP Socket Calls
- Receive responses per request from the DNS server hierarchy
- Parse response message, (parsing responses from root server and TLD server)
- Returning the resolved IP address for an A record

Implement a cache for your local DNS server. Increase the efficieny.
