

# IP
```
########################## IPv4 header ##############################
#  0                   1                   2                   3    #
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  #
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ #
# |Version|  IHL  |Type of Service|          Total Length         | #
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ #
# |         Identification        |Flags|      Fragment Offset    | #
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ #
# |  Time to Live |    Protocol   |         Header Checksum       | #
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ #
# |                       Source Address                          | #
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ #
# |                    Destination Address                        | #
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ #
# |                    Options                    |    Padding    | #
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ #
# Note that each tick mark represents one bit position.             #
# e.g., version and IHL is 4 bytes                                  #
#####################################################################
```

### breakdown
    - version   ==> Version no. of Internet Protocol used
    - ihl       (Internet Header Length) ==> length of entire IP header
    - tos       (Type of Service, Differentiated Services Code Point)
    - len       ==> Length of entire IP Packet
    - id        ==> IP packet fragmented, fragments contain same identification num. to identify original IP packet
    - flags     ==> if IP Packet is too large, ‘flags’ say if fragment OK
    - frag      ==> exact position of the fragment in the original IP Packet
    - ttl       ==> avoid looping, many routers (hops) this packet can cross. At each hop, value is decremented (0 = kill)
    - proto     ==> which Protocol this packet belongs to, i.e. the next level Protocol
    - chksum    ==> keep checksum value of entire header which is then used to check if the packet is received error-free
    - src       ==> 32-bit address of the source
    - dst       ==> 32-bit address of the destination
    - options
                ==> copy_flag
                ==> optclass
                ==> option
                ==> length
                ==> pointer
                ==> routers
    <data>

- See [6] for details

### version [0,15]
```
+---------------------------------------------+
| 0 ----------- reserved.                     |
| 1,2,3                                       |
| 4 ----------- IP, Internet Protocol.        |
| 5 ----------- ST, ST Datagram Mode.         |
| 6 ----------- SIP, SIPP, IPv6               |
| 7 ----------- TP/IX, The Next Internet.     |
| 8 ----------- PIP, The P Internet Protocol. |
| 9 ----------- TUBA.                         |
| 10,11,12,13,14                              |
| 15----------- reserved.                     |
+---------------------------------------------+
```

### internet header length [0,15]
- length of header in 32 bit words. minimum value for header is 5 (0101) and max is 15 (1111) [7]

### type of service [0,255]
```
0	1	2	3	4	5	6	7
      Precedence	D	T	R	M	0
```

```
Precedence. 3 bits.
0	    Routine.
1	    Priority.
2	    Immediate.
3	    Flash.
4	    Flash override.
5	    CRITIC/ECP.
6	    Internetwork control.
7	    Network control.
------------------------------------------------------------
D. 1 bit. Minimize delay.
0	    Normal delay.
1	    Low delay.
------------------------------------------------------------
T. 1 bit. Maximize throughput.
0	    Normal throughput.
1	    High throughput.
------------------------------------------------------------
R. 1 bit. Maximize reliability.
0	    Normal reliability.
1	    High reliability.
------------------------------------------------------------
M. 1 bit. Minimize monetary cost.
0	    Normal monetary cost.
1   	    Minimize monetary cost.
```

### length of packet [0,65535]
- 16 bits

### id of the packet [0,65535]
- 16 bits
- used to identify the fragments of one datagram from those of another
- is required to be unique within the maximum lifetime for all datagrams with a given source address/destination address/protocol tuple [8]

### flags [0,7]
```
00	01	02
R	DF	MF
```
- **R** reserved. 1 bit. Should be cleared to 0
- **DF** Don't fragment. 1 bit. Controls the fragmentation of the datagram.
- **MF** More fragments. 1 bit. Indicates if the datagram contains additional fragments.


### frag [0,8191]
- 13 bits
- used to direct the reassembly of a fragmented datagram.

### ttl [0,255]
- 8 bits
- a timer field used to track the lifetime of the datagram
- when the TTL field is decremented down to zero, the datagram is discarded.

### proto [0,255]
- 8 bits
```
Value	Protocol
0	HOPOPT, IPv6 Hop-by-Hop Option.
1	ICMP, Internet Control Message Protocol.
2	IGAP, IGMP for user Authentication Protocol. IGMP, Internet Group Management Protocol. RGMP, Router-port Group Management Protocol
3	GGP, Gateway to Gateway Protocol.
4	IP in IP encapsulation.
5	ST, Internet Stream Protocol.
6	TCP, Transmission Control Protocol.
7	UCL, CBT.
8	EGP, Exterior Gateway Protocol.
9	IGRP, Interior Gateway Routing Protocol.
10	BBN RCC Monitoring.
11	NVP, Network Voice Protocol.
12	PUP.
13	ARGUS.
14	EMCON, Emission Control Protocol.
15	XNET, Cross Net Debugger.
16	Chaos.
17	UDP, User Datagram Protocol.
18	TMux, Transport Multiplexing Protocol.
19	DCN Measurement Subsystems.
20	HMP, Host Monitoring Protocol.
21	Packet Radio Measurement.
22	XEROX NS IDP.
23	Trunk-1.
24	Trunk-2.
25	Leaf-1.
26	Leaf-2.
27	RDP, Reliable Data Protocol.
28	IRTP, Internet Reliable Transaction Protocol.
29	ISO Transport Protocol Class 4.
30	NETBLT, Network Block Transfer.
31	MFE Network Services Protocol.
32	MERIT Internodal Protocol.
33	DCCP, Datagram Congestion Control Protocol.
34	Third Party Connect Protocol.
35	IDPR, Inter-Domain Policy Routing Protocol.
36	XTP, Xpress Transfer Protocol.
37	Datagram Delivery Protocol.
38	IDPR, Control Message Transport Protocol.
39	TP++ Transport Protocol.
40	IL Transport Protocol.
41	IPv6 over IPv4.
42	SDRP, Source Demand Routing Protocol.
43	IPv6 Routing header.
44	IPv6 Fragment header.
45	IDRP, Inter-Domain Routing Protocol.
46	RSVP, Reservation Protocol.
47	GRE, General Routing Encapsulation.
48	DSR, Dynamic Source Routing Protocol.
49	BNA.
50	ESP, Encapsulating Security Payload.
51	AH, Authentication Header.
52	I-NLSP, Integrated Net Layer Security TUBA.
53	SWIPE, IP with Encryption.
54	NARP, NBMA Address Resolution Protocol.
55	Minimal Encapsulation Protocol.
56	TLSP, Transport Layer Security Protocol using Kryptonet key management.
57	SKIP.
58	ICMPv6, Internet Control Message Protocol for IPv6. MLD, Multicast Listener Discovery.
59	IPv6 No Next Header.
60	IPv6 Destination Options.
61	Any host internal protocol.
62	CFTP.
63	Any local network.
64	SATNET and Backroom EXPAK.
65	Kryptolan.
66	MIT Remote Virtual Disk Protocol.
67	Internet Pluribus Packet Core.
68	Any distributed file system.
69	SATNET Monitoring.
70	VISA Protocol.
71	Internet Packet Core Utility.
72	Computer Protocol Network Executive.
73	Computer Protocol Heart Beat.
74	Wang Span Network.
75	Packet Video Protocol.
76	Backroom SATNET Monitoring.
77	SUN ND PROTOCOL-Temporary.
78	WIDEBAND Monitoring.
79	WIDEBAND EXPAK.
80	ISO-IP.
81	VMTP, Versatile Message Transaction Protocol.
82	SECURE-VMTP
83	VINES.
84	TTP.
85	NSFNET-IGP.
86	Dissimilar Gateway Protocol.
87	TCF.
88	EIGRP.
89	OSPF, Open Shortest Path First Routing Protocol. MOSPF, Multicast Open Shortest Path First.
90	Sprite RPC Protocol.
91	Locus Address Resolution Protocol.
92	MTP, Multicast Transport Protocol.
93	AX.25.
94	IP-within-IP Encapsulation Protocol.
95	Mobile Internetworking Control Protocol.
96	Semaphore Communications Sec. Pro.
97	EtherIP.
98	Encapsulation Header.
99	Any private encryption scheme.
100	GMTP.
101	IFMP, Ipsilon Flow Management Protocol.
102	PNNI over IP.
103	PIM, Protocol Independent Multicast.
104	ARIS.
105	SCPS.
106	QNX.
107	Active Networks.
108	IPPCP, IP Payload Compression Protocol.
109	SNP, Sitara Networks Protocol.
110	Compaq Peer Protocol.
111	IPX in IP.
112	VRRP, Virtual Router Redundancy Protocol.
113	PGM, Pragmatic General Multicast.
114	any 0-hop protocol.
115	L2TP, Level 2 Tunneling Protocol.
116	DDX, D-II Data Exchange.
117	IATP, Interactive Agent Transfer Protocol.
118	ST, Schedule Transfer.
119	SRP, SpectraLink Radio Protocol.
120	UTI.
121	SMP, Simple Message Protocol.
122	SM.
123	PTP, Performance Transparency Protocol.
124	ISIS over IPv4.
125	FIRE.
126	CRTP, Combat Radio Transport Protocol.
127	CRUDP, Combat Radio User Datagram.
128	SSCOPMCE.
129	IPLT.
130	SPS, Secure Packet Shield.
131	PIPE, Private IP Encapsulation within IP.
132	SCTP, Stream Control Transmission Protocol.
133	Fibre Channel.
134	RSVP-E2E-IGNORE.
135	Mobility Header.
136	UDP-Lite, Lightweight User Datagram Protocol.
137	MPLS in IP.
138	MANET protocols.
139	HIP, Host Identity Protocol.
140	Shim6, Level 3 Multihoming Shim Protocol for IPv6.
141	WESP, Wrapped Encapsulating Security Payload.
142	ROHC, RObust Header Compression.
143
-
252
253
254	Experimentation and testing.
255	reserved.
```

### chksum [0,65535]
- 16 bits
- one's complement checksum of the IP header and IP options.
- **not fuzzed**

### src [0,255.255.255.255]
- 32 bits
- **not fuzzed**

### dest [0,255.255.255.255]
- 32 bits
- **not fuzzed**

### options

##### copy_flag [0,1]
- 1 bit
- indicates if the option is to be copied into all fragments.

##### optclass [0,3]
- 2 bits
```
Value	Description
0	Control.
1	Reserved.
2	Debugging and measurement.
3	Reserved.
```

##### option [0,31]
- 5 bits
```
Option	Copy	Class	Value	Length	    Description
0	0	0	0	1	    End of options list.
1	0	0	1	1	    NOP.
2	1	0	130	11	    Security.
3	1	0	131	variable    Loose Source Route.
4	0	2	68	variable    Time stamp.
5	1	0	133	3 to 31	    Extended Security.
6	1	0	134		    Commercial Security.
7	0	0	7	variable    Record Route.
8	1	0	136	4	    Stream Identifier.
9	1	0	137	variable    Strict Source Route.
10	0	0	10		    Experimental Measurement.
11	0	0	11	4	    MTU Probe. (obsolete).
12	0	0	12	4	    MTU Reply. (obsolete).
13	1	2	205		    Experimental Flow Control.
14	1	0	142		    Expermental Access Control.
15	0	0	15		    ENCODE.
16	1	0	144		    IMI Traffic Descriptor.
17	1	0	145	variable    Extended Internet Protocol.
18	0	2	82	12	    Traceroute.
19	1	0	147	10	    Address Extension.
20	1	0	148	4	    Router Alert.
21	1	0	149	6 to 38     Selective Directed Broadcast Mode.
22	1	0	150		
23	1	0	151		    Dynamic Packet State.
24	1	0	152		    Upstream Multicast Packet.
25	0	0	25		    QS, Quick-Start.
26
-
29				
30	0	0	30		    EXP - RFC3692-style Experiment.
30	0	2	94		    EXP - RFC3692-style Experiment.
30	1	0	158		    EXP - RFC3692-style Experiment
30	1	2	222		    EXP - RFC3692-style Experiment.
31					
```

# option-length
- variable, not present for NOP at end of option list

# option-data
- variable, no present for NOP at end of option list. See RFC 791

# sniffing

Here we can see how to filter and tag returned packets from the server [12].

- **count**: number of packets to capture. 0 means infinity
- **store**: wether to store sniffed packets or discard them
- **prn**: function to apply to each packet. If something is returned, it is displayed. Ex: ex: prn = lambda x: x.summary()
- **lfilter**: python function applied to each packet to determine if further action may be done ex: `lfilter = lambda x: x.haslayer(Padding)`
- **offline**: pcap file to read packets from, instead of sniffing them
- **timeout**: stop sniffing after a given time (default: None)
- **L2socket**: use the provided L2socket
- **opened_socket**: provide an object ready to use .recv() on
- **stop_filter**: python function applied to each packet to determine if we have to stop the capture after this packet ex: `stop_filter = lambda x: x.haslayer(TCP)`


# misc

see [13] "Since you are not completing the full TCP handshake your operating system might try to take control and can start sending RST (reset) packets, to avoid this we can use iptables:"

`iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <your IP> -j DROP`
