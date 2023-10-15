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


### 2. Reliable and Congestion Controlled Data Transfer over UDP

Add connection support to UDP using a three-way handshake (just like TCP) and create a new version of UDP called UDP Putah.
(When a client connects to a server, it will send a handshake message to the server. If the server is willing to connect, it will send the response back to the client telling it that a connection has been established on the server’s end. Finally, the client also sets up a connection and sends an acknowledgement for it back to the server.)

SELF-Defined separate header for UDP.

Adding Reliability to UDP Putah (UDP Solano)
(A similar acknowledgement process as TCP, where instead of acknowledging each individual packet, acknowledge the number of bytes that the receiver has successfully received so far. as cumulative acknowledgement)

Adding Congestion Control to UDP Solano (UDP Berryessa)
(Adding a flavour of congestion control to UDP Solano (making it a connection-oriented, reliable, congestion-controlled UDP Berryessa, quite a mouthful).)
