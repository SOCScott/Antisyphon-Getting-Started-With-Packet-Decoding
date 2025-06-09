# Getting Started in Packet Decoding

# Day 1

[https://blackhillsinfosec.zoom.us/rec/share/VCTW3MQRp50WOYI4X6a-dlFbmv7_gCP_wW72TV20HdyDGGDTyRJBr-oYl9DcbaCm.QZ6wyVjie3qIjfEU](https://blackhillsinfosec.zoom.us/rec/share/VCTW3MQRp50WOYI4X6a-dlFbmv7_gCP_wW72TV20HdyDGGDTyRJBr-oYl9DcbaCm.QZ6wyVjie3qIjfEU)

---

### Packet Decoding and Class Schedule

- In the meeting, Chris discussed the process of getting started with packet decoding, including downloading the necessary virtual machine and setting up SSH connections. He also shared his experiences with building science projects and his interest in metalworking. Chris then outlined the class schedule and explained the difference between hands-on walkthroughs and labs. He emphasized the importance of using spoilers when posting answers in the channel.

### Packet Decoding in Cybersecurity Basics

- Chris explains the importance of packet decoding in cybersecurity. He highlights that packet decoding is a universal skill applicable across different operating systems, unlike host-based security which varies. Packet decoding allows for passive information gathering about systems and provides a single point for implementing consistent security across all devices. Chris focuses on IPv4 in the class but compares it to IPv6 where relevant. He explains that packet decoding tools convert binary data into readable formats, with different tools being suited for different tasks. Chris also clarifies the difference between frames and packets, and emphasizes that understanding packet structure is primarily about offset measurements.

### Wireshark and T-Shark Network Traffic Analysis

- Chris explains how to use T-Shark and Wireshark for analyzing network traffic. He demonstrates using T-Shark command line options to read pcap files, filter traffic, and display specific fields like DNS query names or HTTP user agents. Chris shows how to use sorting and summarization options to analyze the data more effectively. He then explains how to find and use Wireshark display filters, demonstrating grep commands to search through the available filters. Finally, Chris gives an overview of the Wireshark interface, explaining the three main panes (packet summary, decoded headers, and payload) and how they interact. He shows how clicking on fields in the header decode pane highlights the corresponding bytes in the payload pane.

### Network Analysis Tools Overview

- Chris discusses various network analysis tools and their features. He explains that Wireshark is a popular tool but has limitations, such as potential packet loss during captures and difficulty in scripting. He mentions that Wireshark's statistics may not always be accurate due to its static analysis approach. Chris then introduces Zeek, highlighting its ability to summarize network activity and focus on security-relevant information. He explains Zeek's log structure, including the main con.log file and application-specific logs. Chris also mentions tools like zcut and zcutter for parsing Zeek logs. Finally, he discusses Ngrep, a tool for searching packet contents, noting its quirks and usefulness in certain scenarios like investigating potential command and control traffic over DNS.

### Layer 2 Communications and Attacks

- Chris explains layer 2 communications and common attacks at this level. He describes how MAC addresses work, including their structure and how they can be changed. Chris outlines the decision tree systems use to determine how to send traffic, including ARP for local communications and routing for external networks. He then details several layer 2 attacks, including ARP cache poisoning, DHCP spoofing, and ICMP redirects. Chris provides methods to protect against these attacks, such as dynamic ARP inspection, DHCP snooping, and limiting MAC addresses per port. He notes that ICMP redirect attacks are the most challenging to prevent, with disabling ICMP redirects being the main solution, though this can potentially break some network configurations.

### Tcpdump and Tshark Network Analysis

- Chris led a hands-on walkthrough of network analysis using Tcpdump and Tshark tools. He explained the importance of understanding network communication, particularly at the application layer, and demonstrated how to decode network traffic. Chris also discussed the use of specific fields in Tshark for detailed analysis and how to identify the type of system involved in network communication. He ended the session with a lab for participants to analyze a network traffic capture file, encouraging them to identify any suspicious activity. The next session will focus on IP.

### IP Header Structure and Analysis

- Chris discusses IP (Internet Protocol) and its role in handling non-local packet delivery. He explains that IP uses IP addresses to move data around and is unreliable by itself, but reliability can be built on top of it using protocols like TCP. Chris then delves into the structure of IP headers, explaining how to read them and the conventions used, such as starting byte counts at zero. He covers the conversion between binary and decimal representations in IP headers and explains why subnet masks typically use contiguous ones and zeros. Chris also touches on the use of hexadecimal notation in packet analysis and demonstrates how to interpret IP header fields using packet capture tools like Wireshark and Tcpdump. He goes into detail about specific header fields such as version, header length, differentiated services, and total length, explaining their purposes and limitations.

### IP Identification Field Demonstration

- Chris discusses the IP identification field, explaining that it is a unique number stamped in every IP packet. He demonstrates how this field can be used to distinguish between retransmissions and spanning tree problems. Chris then explains that different operating systems implement IP ID incrementation differently, with Windows using a predictable pattern and Linux varying based on the transport protocol. He warns that predictable IP IDs can be leveraged for malicious purposes, such as idle scans. Chris conducts a hands-on demonstration using Wireshark to show how IP IDs can reveal information about a system's communication patterns, even for remote hosts.

# Day 2

[https://blackhillsinfosec.zoom.us/rec/share/vKOl3GCPzhcT3FdIiahLyTWWOATMJ3h6Hu6KBN7To_9xO2ebbiCyu7X4ooJWo-Y.lhLqxJYHlYhvoC7K](https://blackhillsinfosec.zoom.us/rec/share/vKOl3GCPzhcT3FdIiahLyTWWOATMJ3h6Hu6KBN7To_9xO2ebbiCyu7X4ooJWo-Y.lhLqxJYHlYhvoC7K)

---

## IP Fragmentation and Security Implications

- Chris led a discussion on IP fragmentation, explaining how it works and the potential issues it can cause. He also discussed various attacks that have been based on fragmentation, such as the "ping of death" and "teardrop" attacks. Chris then demonstrated how to use Tcpdump to capture and analyze fragmented packets. He emphasized the importance of understanding IP fragmentation for network security and troubleshooting.

## TTL Value in IP Packets

- Chris discussed the Time to Live (TTL) value in IP packets, which identifies how many routers a packet should be allowed to go through. He explained that each router decrements the TTL value by one and returns an ICMP error if it reaches zero. Chris also mentioned that different operating systems and network devices set different default TTL values, which can provide information about the system's identity and distance. He further explained how the TTL value can be used to map network links and how it can be leveraged to identify potential vulnerabilities in a network.

## IP Packet Routing and Analysis

- In the meeting, Chris discussed the three options for IP packet routing: record route, brick source routing, and loose source routing. He explained the layout of the IP header and the options field, including the use of padding to ensure even boundaries. Chris also demonstrated how to use Wireshark to analyze packets and decode the record route option. He showed how the record route option can be used to trace the route of a packet, but it is limited to recording up to eight hops. Chris also discussed the use of packet crafting tools like Hping and Scapy for more advanced packet manipulation. The team was encouraged to explore these tools and not be afraid of making mistakes.

## Source Routing: Strict vs Loose

- Chris discussed the concept of source routing, which allows for control over where a packet goes on the internet. He explained two types of source routing: strict and loose. Strict source routing requires defining every router a packet will pass through, while loose source routing only requires defining the routers to bounce off of. Chris also mentioned the limitations of source routing, such as the maximum of 8 hops and the need for the destination IP address to be in the options field. He provided examples of how source routing can be used to bypass firewalls and discussed the potential for disabling source routing support in firewalls or endpoints.

## Wireshark Packet Analysis Walkthrough Challenges

- Chris conducted a hands-on walkthrough of packet analysis using Wireshark, Tcpdump, and TShark. He demonstrated how to decode packets, particularly focusing on a loose source route packet. He highlighted the challenges of interpreting the data, especially when Wireshark and TShark label the destination as "current route" instead of the actual destination IP address. Chris also explained the concept of an idle scan, which can exploit predictable IP IDs to make it appear as though another system is the culprit. He emphasized the importance of understanding how these tools present data to effectively analyze packets.

## Port Scanning and Packet Analysis

- Chris discussed the process of port scanning and how to identify if someone is doing a direct port scan or an idle scan. He explained the use of IP IDs and how they can be used to determine if a port is open or closed. Chris also mentioned the importance of understanding how systems communicate and the attributes that should be present in packets. He suggested using tools like nmap and hping to verify results and identify potential issues. Chris also touched on the potential for misinterpretation of packet data and the importance of understanding the Rfc protocols.

## Combining Techniques for Abuse Reporting

- Chris discussed the potential of combining two techniques, possibly involving the IT or security team. He explained that when a pattern of abuse is identified, the source is investigated, and if it's from a legitimate company, it's reported to their abuse department. Chris also clarified that spoofing a packet is possible. He mentioned that they were on Slide 134 and would continue with Icmp after a 20-minute break. Chris also explained the meaning of Lsrr, which is a loose source routing option, and its implementation. He emphasized the importance of referring to the Internet standards when reading the Rfcs.

## ICMP: Error Reporting and Maintenance Protocol

- Chris discussed the Internet Protocol (IP) and Internet Control Message Protocol (ICMP) in the meeting. He explained that IP is a mandatory protocol, while not all RFCs are mandatory. Chris also discussed the role of ICMP as a maintenance protocol for network testing and error reporting. He mentioned that ICMP is non-reliable and supports unicast, broadcast, and multicast communication. Chris also discussed the use of type and code in ICMP, and the different types of error reporting codes. He emphasized the importance of following RFCs and the need to report errors rather than quietly dropping packets. Chris also explained the structure of ICMP headers and the additional fields in echo request and echo reply packets.

## IP Tables and Passive Fingerprinting

- Chris discussed the functionality of IP tables and their role in network communication. He explained how IP tables can be used to reject traffic patterns and how this can help in troubleshooting network issues. Chris also discussed the concept of passive fingerprinting, where the size and content of echo request packets can be used to identify the operating system of a remote system. He demonstrated this using Wireshark, showing how different operating systems respond to echo requests with different payloads and sequence numbers. Chris concluded by explaining how the TTL (Time to Live) value in the IP header can be used to identify the operating system of a responding system.

## Windows vs Linux Echo Request

- In the meeting, Chris discussed the differences in how Windows and Linux systems generate echo request packets. He highlighted that Windows generates predictable packets, which can be exploited, while Linux generates packets with some predictability but not as much as Windows. Chris also demonstrated how to use Wireshark to analyze these packets and identify the operating system. He emphasized the importance of understanding these nuances to identify potential attack targets. The team was tasked with analyzing a pcap file shared by the IT team to identify any unusual ping packets.

# Day 3

[https://blackhillsinfosec.zoom.us/rec/share/UY7xX_eAkCr_9CfwL7iK2C5IvcokySdUFy9p-HQoNAX1297G1dhE8Pk5Jm78hT8y.Zr1hltFxUsPHU3dn](https://blackhillsinfosec.zoom.us/rec/share/UY7xX_eAkCr_9CfwL7iK2C5IvcokySdUFy9p-HQoNAX1297G1dhE8Pk5Jm78hT8y.Zr1hltFxUsPHU3dn)

---

## Network Traffic Analysis and Security

- In the meeting, Chris discussed the importance of summarizing reports to get quick responses and attention. He emphasized the need to prioritize tasks and focus on the main points. Chris also discussed the process of packet decoding, highlighting the importance of identifying anomalies and understanding the underlying issues. He demonstrated how to use Wireshark and Tshark to analyze network traffic and identify potential security threats. The team also discussed the challenges of detecting unusual network activity and the importance of understanding the context of the data.

## TCP vs UDP Protocol Differences

- Chris discussed the differences between TCP and UDP protocols. He explained that UDP is a lightweight protocol with less overhead, making it more efficient than TCP. However, UDP lacks error reporting and is stateless, meaning it cannot determine if a packet is the first in a session or a reply. Chris also mentioned that UDP can be unidirectional or bidirectional, and it can be used for applications like DNS queries. He also touched on the concept of Quick, a protocol designed to optimize HTTPS communications, but expressed concerns about its security implications. Chris also discussed the importance of understanding the TCP header, which can grow larger than 20 bytes, and the use of TCP options. He emphasized the need for security administrators to monitor these protocols to ensure secure communication.

## TCP Sequence Numbers and Acknowledgement

- In the meeting, Chris explained the concept of sequence numbers and acknowledgement numbers in TCP communication. He clarified that sequence numbers are assigned randomly in the first packet and then incrementally based on the payload size and the presence of the SYN flag. Acknowledgement numbers, on the other hand, are transmitted by the other side of the connection and identify the expected next sequence number. Chris also discussed the difference between absolute and relative sequence numbers, with the latter being a tool's representation for easier human understanding. He emphasized that the sequence number and acknowledgement number are independently calculated and should be the same. Chris also addressed the issue of sequence number rollover and its potential impact on communication. He concluded by encouraging the team to practice understanding sequence numbers and acknowledgement numbers through exercises.

## TCP Sequence Numbers and Acknowledgement

- Chris discussed the use of sequence numbers and acknowledgement numbers in TCP communication. He explained how these numbers help identify missing data and facilitate the recovery of lost packets. Chris also highlighted the difference between relative and absolute sequence numbers, and how Wireshark displays them. He demonstrated how to use Wireshark's statistics flow graph option to monitor sequence numbers in a session. Chris also discussed the concept of windowing and how it affects the transmission of data. He mentioned the use of the reset packet in TCP communication and its implications. Finally, Chris emphasized the importance of practice in understanding these concepts and encouraged the team to continue practicing with Wireshark.

## TCP Handshake and Connection Closure

- Chris discussed the TCP 3 packet handshake, which is a formal introduction between two systems before any data is allowed to flow. He also explained the process of closing a connection with FIN/ACK packets. Chris then discussed the potential issues with stateful firewalls, which can maintain stale state table entries if both endpoints power off simultaneously. He also mentioned the concept of Explicit Congestion Notification (ECN) and its limitations. Chris also explained the TCP flags, including the FIN, ACK, and PUSH flags, and their respective uses. He concluded the session by mentioning the potential misuse of the PUSH flag and its impact on the receiving system's efficiency.

## TCP/IP Protocols and Bit Masking

- In the meeting, Chris discussed various aspects of TCP/IP protocols. He explained the concept of bit masking, which allows filtering based on individual bits within a byte. He demonstrated how to use bit masking with examples, including filtering packets with the SYN flag turned on. Chris also discussed the use of the FIN flag and its implications for port scanning. He explained the concept of window size in TCP/IP and how it affects data transmission. Chris also mentioned the use of pseudo access for packet crafting and the differences in how Linux and Windows handle FIN packets. The conversation ended with Chris encouraging participants to ask questions in the Discord channel.

# Day 4

[https://blackhillsinfosec.zoom.us/rec/share/jQZZcyGiAbrDrpS44FtmhoMpjIrau14B5QJQophxzkpG_IguO2anrfGdgScwqRH4.suSjZJScKGxKcfzw](https://blackhillsinfosec.zoom.us/rec/share/jQZZcyGiAbrDrpS44FtmhoMpjIrau14B5QJQophxzkpG_IguO2anrfGdgScwqRH4.suSjZJScKGxKcfzw)

---

## TCP Connection States and Optimization

- In the meeting, Chris discussed the state of TCP connections, focusing on the official list of states as defined in RFC 793 and RFC 9263. He also explained the concept of window size, its relation to buffer size, and how it can be adjusted to control data flow. Chris also discussed the TCP options, including maximum segment size, window scaling, and selective acknowledgments, and how they can be used to optimize data transmission. He also touched on the issue of duplicate ACKs and how they can be identified and resolved. The conversation ended with a discussion on the differences in TCP options between Windows and Linux systems.

## Changing Linux Network Fingerprint With TTL

- Chris discusses how to change the TTL (Time To Live) value on a Linux system to alter its network fingerprint. He demonstrates changing the default TTL from 64 to 128 by modifying the /proc/sys/net/ipv4/ip_default_ttl file. This makes the Linux system appear more like a Windows system to passive fingerprinting tools. Chris explains that while this type of deception has limited practical use for defenders, it can provide some satisfaction in making attackers' jobs more difficult. He notes that changing the TTL doesn't significantly impact normal network operations. Chris also mentions that other aspects of the network fingerprint can be modified on Linux systems, though some characteristics are harder to change than others. Overall, he suggests the main value in understanding and modifying network fingerprints is for threat intelligence purposes - to gain insight into the skill level and tools of potential attackers based on how they present themselves on the network.

## Wireshark Packet Analysis and Protocol Overview

- Chris explains how to use Wireshark's "Follow" feature to analyze packet streams, particularly for HTTP and SSH protocols. He demonstrates that the available follow options depend on the specific packet selected, not the entire stream. Chris then discusses the SSH handshake process, including software identification and parameter negotiation. He also covers common HTTP header fields such as URI, host, user agent, and X-forwarded-for, explaining their purposes and implications for network analysis. Finally, Chris touches on server response status codes and content types, mentioning how they can be used in various scenarios, including security measures and command and control channels.

## Exploiting File Types for Malware

- Chris explains how attackers can exploit file types and content types to bypass endpoint security software. He describes a technique where malicious code in PHP files can be disguised as text, allowing it to evade detection. Chris also discusses his past experiments with antivirus software vulnerabilities, particularly exploiting alternate data streams in NTFS file systems. He emphasizes the importance of understanding file systems and not making assumptions about how they work. Chris concludes by explaining how user agent strings can be manipulated for various purposes, including identifying test traffic or signaling compromised systems to malicious servers.

## Web Session Security Issue Discussion

- Chris discussed a potential security issue related to a web session on the network. He mentioned that the networking team had identified a strange session but everything seemed to be working fine. Chris suggested that the issue should be handed over to the security team for further investigation. He provided a pcap file for the team to analyze and determine if the session was benign or if there were any concerns. Chris also mentioned that they would spend more time on this issue after a break.

## Suspicious Network Activity With PPTP.jpeg

- Chris discussed a suspicious network activity involving a file named 'PPTP.jpeg' accessed from an 'Admin' directory. The host parameter in the URL contained a number '1' instead of the letter 'L', which Chris suspected was a typo to mimic a legitimate URL. The user agent string identified the system as a 20-year-old operating system, which could indicate a compromised system. Chris also noted that the server was reporting the file as plain text, which was unusual for an image file. He suggested that this could be a way to bypass endpoint security. Chris asked the team to investigate further, including checking if the source IP was from a known system and if the system was consistently identifying itself as an older OS.

## Zeek for Network Traffic Analysis

- Chris discusses a suspicious file that was converted to base64 and compressed, which he believes may be an attempt to obfuscate malicious content. He explains that this technique could potentially bypass security tools that only perform one level of conversion. Chris then introduces Zeek, a tool for analyzing network traffic, and demonstrates how to use it to process a pcap file. He shows that Zeek can significantly reduce the file size while retaining important security-related information, making it useful for long-term log retention. Chris also provides commands for viewing the Zeek logs effectively.

## Analyzing Network Traffic Logs With Zcutter

- Chris demonstrates how to analyze network traffic logs using various command-line tools. He shows how to use Zcutter to extract specific fields from the con.log file, including source IP, destination IP, and original bytes transferred. Chris then explains how to sort this data to identify top talkers on the network. He discusses the importance of looking at cumulative data transfers rather than just individual sessions. Chris also mentions the potential use of datamash to aggregate data, though it wasn't included in the setup. Finally, he begins to explain how to count the number of connections between IP pairs, suggesting that this information can provide valuable context about network activity.

## Analyzing Network Connection Data With Unique

- Chris explains how to use the 'unique' command with various options to analyze network connection data. He demonstrates using 'unique -c' to count and collapse connection pairs, then sorting the results to identify the most frequent connections. Chris highlights a suspicious IP address with an unusually high number of connections (2,869) and investigates it further using grep and less commands. He discovers that these connections are HTTP traffic to the same PHP file repeatedly, with suspicious characteristics like an IP address as the host parameter and a constant referrer field. Chris emphasizes the importance of log retention and demonstrates how to use DNS logs to get a summary of network activity, including queries and responses.

## DNS Log Files for Security

- Chris discussed the importance of DNS log files in identifying potential security threats. He highlighted the recent increase in attacks originating from Azure due to Microsoft's change in IP address management. Chris also demonstrated how to use tools like T. Shark and Wireshark to analyze network traffic and identify suspicious activity. He assigned a lab for the participants to practice their skills in identifying potential security issues.

## Analyzing and Decoding Suspicious Network Traffic

- Chris demonstrates how to analyze and decode suspicious network traffic using Wireshark and CyberChef. He shows that the traffic contains base64 encoded and gzipped data, which when decoded reveals malicious code attempting a sideload attack. The code tries to masquerade as system.dll to evade detection. Chris explains this is particularly dangerous as it loads directly into memory, bypassing file-based antivirus scans. He notes that while rebooting would clear this specific payload, there is likely other malware present that downloaded this code, requiring further investigation and cleanup.

# Getting Started With Packet Decoding - Study Guide

## Introductory Summary

This comprehensive 4-day training module covers the fundamentals of network packet analysis and decoding, focusing on practical skills for cybersecurity professionals. The course emphasizes hands-on learning through virtual machine labs and real-world packet captures from suspicious network activities. Students learn to use essential tools like tcpdump, tshark, Wireshark, ngrep, and Zeek to analyze network traffic at multiple protocol layers. The training progresses from basic concepts of binary data interpretation to advanced techniques for detecting network attacks, OS fingerprinting, and identifying command & control (C2) channels. Key protocol layers covered include Ethernet (Layer 2), IP (Layer 3), ICMP, UDP, and TCP, with practical applications in network security monitoring, threat detection, and incident response. Real-world examples include analyzing suspicious HTTP sessions, base64-encoded malware payloads, and memory-based attack techniques that bypass traditional antivirus solutions.

---

## Key Takeaways

### 1. **Packet Decoding is Binary Offset and Measurement**

Network packet analysis fundamentally involves understanding how data is structured in binary format and using offset calculations to extract meaningful information from headers. All packet decoders work by knowing where specific fields are located within headers and measuring the appropriate number of bytes to extract values.

### 2. **Layer 2 Attacks Exploit Unauthenticated Communications**

ARP-based attacks (cache poisoning, flooding, DHCP spoofing) are possible because Layer 2 communications typically lack authentication. Understanding MAC address behavior and ARP cache operations is crucial for detecting traffic hijacking attempts and understanding network security vulnerabilities.

### 3. **OS Fingerprinting Through Protocol Analysis**

Different operating systems implement network protocols with unique characteristics (TTL values, TCP option ordering, ICMP payloads, IP ID incrementation patterns). These implementation differences create "fingerprints" that allow passive identification of operating systems without active probing.

### 4. **Real-World Threat Detection and Analysis**

Modern attackers use sophisticated techniques like base64 encoding, compression, and memory-based attacks to evade detection. Effective analysis requires understanding normal vs. abnormal traffic patterns, correlating multiple data sources (DNS logs, connection logs, HTTP headers), and recognizing when legitimate-looking traffic contains malicious payloads. Tools like Zeek provide efficient log summarization for long-term retention and pattern recognition across large datasets.

---

## Comprehensive Study Notes

### **Day-by-Day Learning Progression**

### **Foundation Concepts**

- **Tool Setup**: VM configuration, SSH connections, and development environment
- **Binary Fundamentals**: Understanding packet structure as offset and measurement
- **Tool Overview**: tcpdump, tshark, Wireshark capabilities and limitations
- **Layer 2 Attacks**: ARP cache poisoning, DHCP spoofing, ICMP redirects
- **Hands-on Labs**: MAC/IP correlation analysis, suspicious traffic identification

### **Day 2: IP Protocol Deep Dive**

- **IP Header Analysis**: Structure, fields, and interpretation techniques
- **IP ID Patterns**: OS fingerprinting through identification field behavior
- **Fragmentation**: Attack vectors (ping of death, teardrop) and detection
- **TTL Analysis**: Distance measurement and OS identification
- **Routing Options**: Record route, strict/loose source routing exploitation

### **Day 3: Transport Layer Protocols**

- **UDP Analysis**: Lightweight protocol characteristics and QUIC evolution
- **TCP Deep Dive**: Connection states, sequence numbers, acknowledgments
- **Flag Analysis**: Bit masking techniques for filtering and detection
- **Window Management**: Flow control and congestion handling
- **Security Implications**: Port scanning detection and evasion techniques

### **Day 4: Advanced Analysis and Real Threats**

- **Passive Fingerprinting**: TCP options ordering, TTL manipulation
- **Application Layer**: HTTP analysis, suspicious user agents, content types
- **Malware Detection**: Base64 encoding, compression obfuscation, memory attacks
- **Zeek Integration**: Log analysis, space-efficient retention, pattern recognition
- **Incident Response**: Correlating multiple data sources for threat hunting

### Binary Data Interpretation

- **Fundamental Principle**: All network data is binary (1s and 0s)
- **Display Formats**: Binary can be displayed as ASCII, decimal, or hexadecimal
- **Critical Rule**: The interpretation table determines how binary is decoded
- **Common Issue**: Wrong interpretation tables lead to garbled output
- **Bit Values**: Within a byte, bits have decimal values: 128, 64, 32, 16, 8, 4, 2, 1

### Packet Structure Hierarchy

```
Ethernet Header → IP Header → Transport Header → App Header → Payload → CRC

```

- **Frame**: Complete data unit including Ethernet headers
- **Packet**: IP-level data unit
- **Decoders**: Use RFC standards to determine offset positions and field lengths

### **Essential Tools Overview**

### tcpdump

- **Purpose**: Lightweight packet capturing and basic analysis
- **Best Use**: Automated traffic collection, audit trails
- **Key Feature**: Cross-platform support (windump on Windows)
- **Automation Example**: Rotating captures every 60 minutes with compression
- **Command Structure**: `tcpdump -i interface -G rotation_time -w filename`

### tshark

- **Purpose**: Advanced packet field extraction and analysis
- **Key Advantage**: Scriptable and automatable
- **Display Filters**: Nearly 185,000 different filter options available
- **Field Extraction**: Use `T fields -e fieldname` for specific data
- **Frame Check Errors**: Often false positives when sniffing on transmitting system

### Wireshark

- **Purpose**: GUI-based packet analysis with visual aids
- **Strengths**: Stream following, statistical analysis, conversation tracking
- **Limitations**:
    - Resource intensive (loads entire pcap into RAM)
    - Cannot be scripted
    - Cumbersome for large files
- **Best Use**: Manual analysis of specific sessions

### Zeek (formerly Bro)

- **Purpose**: Network traffic logging and analysis
- **Space Efficiency**: 1/20th the storage space of raw pcaps
- **Log Types**: conn.log, http.log, dns.log, ssl.log, etc.
- **Use Case**: Scalable network monitoring and session summarization
- **zeek-cut**: Tool for extracting specific fields from Zeek logs

### ngrep

- **Purpose**: Real-time pattern matching on network traffic
- **Function**: "grep for network traffic"
- **Useful Switches**:
    - `q`: Suppress non-matching packet indicators
    - `I`: Read from pcap file
- **Best Use**: Quick content searches and real-time monitoring

### **Layer 2 (Link Layer) Analysis**

### MAC Address Structure

- **Format**: 6-byte value (48 bits)
- **Display**: Usually hexadecimal with separators (colons, dashes, spaces)
- **Components**: First 3 bytes = vendor code, Last 3 bytes = unique serial
- **Trust Model**: Layer 2 typically assumes all local systems are trusted
- **Lookup**: IEEE OUI database for vendor identification

### ARP (Address Resolution Protocol)

- **Function**: Maps IP addresses to MAC addresses on local network
- **Process**: "Who has IP X? Tell IP Y" → "IP X is at MAC Z"
- **Cache**: Systems maintain ARP tables for recently resolved addresses
- **Scope**: Only works on local subnet (unless forwarding configured)

### Common Layer 2 Attacks

1. **ARP Cache Poisoning**: Overwrite legitimate ARP entries with attacker's MAC
2. **ARP Cache Flooding**: Overwhelm switch CAM table, forcing hub behavior
3. **DHCP Spoofing**: Malicious DHCP server providing false network information
4. **ICMP Redirects**: Type 5 messages redirecting traffic through attacker

### Layer 2 Attack Defenses

- **Dynamic ARP Inspection**: Validates ARP packets against DHCP snooping database
- **Port Security**: Limit number of MAC addresses per switch port
- **DHCP Snooping**: Distinguish between trusted and untrusted DHCP sources
- **Disable ICMP Redirects**: Prevent dynamic route learning (may impact performance)

### **Layer 3 (Internet Protocol) Analysis**

### IPv4 Header Structure (20 bytes minimum)

- **Version** (4 bits): Always 4 for IPv4
- **IHL** (4 bits): Header length in 32-bit words (minimum 5 = 20 bytes)
- **Type of Service/DSCP** (8 bits): Traffic prioritization (often ignored)
- **Total Length** (16 bits): Complete IP packet size including header
- **Identification** (16 bits): Unique packet identifier, varies by OS
- **Flags** (3 bits): Reserved, Don't Fragment (DF), More Fragments (MF)
- **Fragment Offset** (13 bits): Position of fragment in original datagram
- **TTL** (8 bits): Maximum router hops before discard
- **Protocol** (8 bits): Next layer protocol (1=ICMP, 6=TCP, 17=UDP)
- **Header Checksum** (16 bits): Error detection for IP header only
- **Source/Destination** (32 bits each): IPv4 addresses

### IP ID Patterns by Operating System

- **Windows**: Increments by +1 for every packet
- **Linux**:
    - ICMP: Fixed ID per session
    - UDP: Incremental
    - TCP: Random
- **Security Implication**: Predictable IP IDs enable idle scanning attacks

### TTL Values and OS Identification

- **32**: Older Apple systems
- **64**: Linux, UNIX, modern macOS
- **128**: Windows systems
- **255**: Network equipment
- **Internet Reality**: Most hosts 15-20 hops apart

### IP Options (Rarely Used but Important)

- **Record Route** (Type 7): Stores router IPs along path (8 hops max)
- **Strict Source Route** (Type 137): Define every router hop
- **Loose Source Route** (Type 131): Define specific bounce points
- **Security Implication**: 99.9% of legitimate traffic doesn't use IP options

### **ICMP (Internet Control Message Protocol)**

### ICMP Message Types

- **Type 0**: Echo Reply
- **Type 3**: Destination Unreachable (various codes)
- **Type 5**: Redirect Messages
- **Type 8**: Echo Request
- **Type 11**: Time Exceeded
- **Type 13/14**: Timestamp Request/Reply

### ICMP Header Structure

- **Minimum**: 4 bytes (Type, Code, Checksum, Unused)
- **Echo Messages**: Additional Identifier and Sequence fields
- **Error Messages**: Include original packet headers (minimum 28 bytes)

### OS Fingerprinting via ICMP

- **Windows**: Lowercase alphabetic payload in ping
- **Linux**: Timestamp and special characters in payload
- **Consistency**: Reply payloads echo request payloads exactly

### ICMP Attack Detection

- **Covert Channels**: Unusual payload patterns or sizes
- **C2 Communication**: Mismatched request/reply payload sizes
- **Tunneling**: Excessive ICMP traffic or non-standard payloads

### **UDP (User Datagram Protocol)**

### UDP Characteristics

- **Connectionless**: No state maintenance
- **Unreliable**: No guaranteed delivery
- **Lightweight**: 8-byte header only
- **Port-Based**: Supports multiple services per host
- **Broadcast/Multicast**: Supports one-to-many communication

### UDP Header Fields

- **Source Port** (16 bits): Originating service identifier
- **Destination Port** (16 bits): Target service identifier
- **Length** (16 bits): UDP header + data length
- **Checksum** (16 bits): Error detection

### QUIC Protocol (Quick UDP Internet Connections)

- **Transport**: Built on UDP but functions as reliable transport
- **Port**: Uses UDP/443
- **Features**: Multiplexing, congestion control, connection migration
- **Purpose**: Replace TCP+HTTP+TLS with optimized single protocol
- **Status**: Version 2 as of October 2024 (RFC 9369)

### **TCP (Transmission Control Protocol)**

### TCP Characteristics

- **Connection-Oriented**: Maintains state information
- **Reliable**: Guarantees data delivery and ordering
- **Flow Control**: Built-in mechanisms to manage data flow
- **Unicast Only**: Point-to-point communication
- **Port-Based**: Multiple services per host

### TCP Header Structure (20 bytes minimum)

- **Source/Destination Port** (16 bits each): Service identification
- **Sequence Number** (32 bits): Data ordering and reliability
- **Acknowledgment Number** (32 bits): Confirms received data
- **Data Offset** (4 bits): TCP header length in 32-bit words
- **Flags** (6 bits): Control connection state
- **Window Size** (16 bits): Flow control mechanism
- **Checksum** (16 bits): Error detection
- **Urgent Pointer** (16 bits): Out-of-band data location

### TCP Flags (Control Bits)

- **URG** (32): Urgent data present
- **ACK** (16): Acknowledgment field valid
- **PSH** (8): Push data to application immediately
- **RST** (4): Reset connection
- **SYN** (2): Synchronize sequence numbers (connection start)
- **FIN** (1): Finished sending data (connection close)

### TCP Connection States

1. **Establishment**: SYN → SYN/ACK → ACK (3-way handshake)
2. **Data Transfer**: ACK flags set, sequence/acknowledgment tracking
3. **Termination**: FIN → FIN/ACK → ACK (graceful close)
4. **Reset**: RST for immediate termination

### Sequence and Acknowledgment Numbers

- **Sequence**: Tracks bytes sent by each side
- **Acknowledgment**: Confirms bytes received, indicates next expected sequence
- **Initial Values**: Randomly generated for security
- **Increment Rules**: +1 for SYN/FIN flags, +payload_size for data

### TCP Options (Usually Present)

- **MSS** (Maximum Segment Size): Avoid fragmentation
- **Window Scale**: Multiply window size beyond 65,535 bytes
- **SACK** (Selective Acknowledgments): Efficient retransmission
- **Timestamp**: Assist with sequence number wrap-around
- **No Operation**: Padding to 32-bit boundary

### TCP Window Management

- **Window Size**: Amount of data that can be "in flight"
- **Flow Control**: Receiver advertises available buffer space
- **Zero Window**: "Stop sending" signal
- **Window Scaling**: Multiplier for windows larger than 64K

### **Advanced Analysis Techniques**

### Passive OS Fingerprinting

- **TCP Options Order**: Different operating systems arrange options differently
- **TTL Values**: Starting values vary by OS
- **Window Sizes**: Default values differ between implementations
- **ICMP Payloads**: Unique patterns per operating system
- **IP ID Patterns**: Increment algorithms vary

### Bit Masking for Filtering

- **Purpose**: Check specific bits within bytes
- **Syntax**: `header[byte]&bitmask=value`
- **Examples**:
    - `tcp[13]&2!=0`: Match when SYN flag set
    - `tcp[13]&16!=0`: Match when ACK flag set
    - `tcp[13]&18=18`: Match when both SYN and ACK set

### Attack Detection Patterns

- **Layer 2**: Inconsistent MAC/IP pairings, ARP anomalies
- **Layer 3**: IP spoofing, unusual TTL values, fragmentation attacks
- **ICMP**: Covert channels, unusual payload patterns
- **TCP**: Sequence number anomalies, flag combinations, option inconsistencies

### Stream Analysis

- **TCP Stream Following**: Reassemble application-layer conversations
- **Payload Extraction**: Use tshark field extraction with xxd for ASCII conversion
- **Bidirectional Analysis**: Separate client and server communications
- **Encryption Impact**: Limited visibility into encrypted streams

---

## 🧠 Quick Quiz

### **Question 1**

What is the primary reason that Layer 2 (Ethernet) attacks like ARP cache poisoning are possible?

**Answer: Layer 2 communications typically lack authentication**

*Explanation: Layer 2 protocols like ARP assume that all systems on the local network are trusted. Since there's typically no authentication mechanism at Layer 2, attackers can send false ARP responses to poison cache entries and redirect traffic.*

---

### **Question 2**

An attacker wants to perform a stealth port scan while hiding their source IP address. Which combination of techniques would allow this?

**Answer: Idle scan using a system with predictable IP ID increments**

*Explanation: An idle scan leverages a "zombie" host with predictable IP ID increments. The attacker sends spoofed packets to the target, making it appear the zombie is scanning. By monitoring the zombie's IP ID changes, the attacker can determine if ports are open without revealing their true IP address.*

---

### **Question 3**

While analyzing a packet capture, you notice ICMP echo-request packets where the payload size in replies is significantly smaller than in requests. What does this most likely indicate?

**Answer: Command and control (C2) communication channel**

*Explanation: In legitimate ICMP communications, echo-reply packets should contain the exact same payload as the corresponding echo-request. When reply payloads are consistently smaller, it suggests data exfiltration through a covert channel, where commands are sent in requests and responses/data are returned in replies.*

---

### **Question 4**

During incident response, you find HTTP traffic where the server reports a ".jpeg" file with Content-Type: text/plain, and the payload contains base64-encoded data. The user agent identifies a 20-year-old operating system. What is the most likely scenario?

**Answer: Malware using evasion techniques to bypass security controls**

*Explanation: The combination of content-type mismatch (image file served as text), base64 encoding, and an extremely outdated user agent string are classic malware evasion techniques. The content-type mismatch can bypass endpoint security that only scans files based on reported MIME types, while the old user agent may indicate a compromised system.*

---

### **Question 5**

You observe TCP packets with the following characteristics: correct destination IP, wrong sequence numbers, TTL of 255, and missing negotiated TCP options. What is most likely happening?

**Answer: Network intrusion detection system (NIDS) sending reset packets**

*Explanation: These characteristics indicate a NIDS attempting to terminate a connection by sending RST packets. The wrong sequence numbers, unusual TTL (255), and missing TCP options suggest the packets are being generated by security equipment rather than the original endpoints in the conversation.*

---

## 💡 Additional Study Resources

### **Recommended Practice Labs**

1. **ARP Analysis**: Examine decode1.pcap and decode2.pcap for MAC/IP correlations
2. **OS Fingerprinting**: Compare Windows vs Linux ping patterns
3. **ICMP Covert Channels**: Analyze weird-ping.pcap for C2 communication
4. **TCP Stream Analysis**: Follow HTTP and SSH sessions for application data
5. **Attack Detection**: Identify layer 2 injection attacks in capture files

### **Key Commands for Practice**

```bash
# Extract specific packet fields
tshark -r file.pcap -T fields -e eth.src -e ip.src -e ip.dst

# Filter on TCP flags
tcpdump -r file.pcap 'tcp[13]&2!=0'  # SYN packets

# Follow TCP streams for payload analysis
tshark -r file.pcap -T fields -e tcp.payload | xxd -r -p

# Zeek analysis for session summaries
zeek readpcap file.pcap output_directory

# ICMP payload extraction
tshark -r file.pcap -T fields -e data.data -Y icmp

```

### **Reference Materials**

- **RFC Standards**: Protocol specifications for accurate header interpretation
- **IANA Protocol Numbers**: Official assignments for protocol field values
- **Wireshark Display Filter Reference**: Comprehensive filter syntax guide
- **IEEE OUI Database**: MAC address vendor lookups
- **CVE Database**: Known vulnerabilities in network protocols

### **Security Applications**

- **Incident Response**: Packet analysis for breach investigation
- **Threat Hunting**: Identifying anomalous network behaviors
- **Forensics**: Reconstructing network-based attacks
- **Penetration Testing**: Understanding defensive monitoring capabilities
- **Compliance**: Network security monitoring requirements