# 4182-project1

- [Installation](#installation)
  * [this_repo](#this_repo)
  * [server](#server)
- [User_Guide](#User_Guide)
  * [Basic_Fuzzing](#Basic_Fuzzing)
  * [Videos](#Videos)
- [Error_Handling](#Error_Handling)
- [Code_Clarity](#Code_Clarity)
- [misc](#misc)
  * [sniffer](#sniffer)
  * [tcp_send](#tcp_send)

## installation

> it is assumed that you are using a Ubuntu 18.x VM per the spec!

### this_repo

0. I suggest putting this on a new VM (install script includes upgrade and installs scapy, npyscreen, and numpy)
1. navigate to the folder you would like to put the sourcecode
2. download the repository (https://github.com/nathanReitinger/4182-project1)
- if you don't have git, run `sudo apt-get install git -y`

```
git clone https://github.com/nathanReitinger/4182-project1.git
cd 4182-project1
```

3. use the installation bash script to install dependencies

```
chmod 777 install.sh
sudo ./install.sh
```

4. with the server running (see next section) execute the program
- this will still work if the server is not running, but packets won't be received

```
python3 fuzzer.py
```

### server

1. navitage to https://615058023285.signin.aws.amazon.com/console
2. for the "IAM user name" enter "public-4182"
3. for the password, enter the one I provided via email
4. navigate to https://us-west-2.console.aws.amazon.com/cloud9/ide/d69da74bc43d4210bd9c23b3b8711e46
5. start the server with:
```
python3 server.py
```

You should now be logged in to the publicly facing ubuntu server!

> Check out the readme in the GUI's tabs (also left-pane) and feel free to make your edits to "server.py". Ceck out the "hex_pattern.txt" file which is where the hex pattern match comes from. To add a new hex pattern, type hex values without a "\x" or "0x" ==> e.g., abff01---the server will not accept non-hex values. This server has a static external IP address for this class, and should work for any testing you need.

> warning, the server is built to work only in this environment. My installation guide does not cover moving the server to your personal computer, but feel free to do so---I just wanted to provide an easily accessible server that was already up and running for testing!

this is what the server from the cloud9 website should look like:

![server image](https://github.com/nathanReitinger/4182-project1/blob/master/media/server.png)

## User_Guide

- default payload is found in file "payload_default.txt" ==> can change with new hex values if you want
    - make sure this file does not have a trailing "\n" which is read as input and is not hex
- see  the background.md file for some information on IP layer

### Basic_Fuzzing

- full parameters of fuzzer
```
usage: fuzzer.py [-h] [-ip_destination IP_DESTINATION]
                 [-p_destination PORT_DESTINATION] [-ip_source IP_SOURCE]
                 [-p_source PORT_SOURCE] [-log LOG_FILE_PATH]
```
- may also simply run the fuzzer (defaults like IP destination (35.188.14.53) automatically applied)

```
bash-3.2# python3 fuzzer.py
```

### Videos

> please note, many of these videos were made from macOS. There are slight differences when using Ubuntu. One difference is that Ubuntu sends packets that actually appear on the server (e.g., `connected with xxx.xxx.xxx.xxx`) when sending the SYN and SYNACK in TCP_send(). These do not appear when sending initiating TCP packets with macOS---this does not affect the functionality of the server or the fuzzer.

- *packets from files* - IP layer and APPLICATION layer using payload from file (application, 'application_from_file.txt' and packet from file (IP, 'ip_from_file.txt'))

![from files](https://github.com/nathanReitinger/4182-project1/blob/master/media/example%20-%20from%20files.gif)

- *parameter setting and error handling* - fuzzer allows the selection non-default IP and ports, but checks for invalid ranges

![from files](https://github.com/nathanReitinger/4182-project1/blob/master/media/example%20-%20parameter%20setting%20and%20error%20handling.gif)

- *server specify pattern and no match on pattner* - We set the "hex_pattern.txt" to something new, try to send packets from the fuzzer to the server with a non-matched pattern, and see the results. This shows that although one of the payloads was received (the correct version, 4), the hex pattern did not match!

![from files](https://github.com/nathanReitinger/4182-project1/blob/master/media/example%20-%20payload%20patterns.gif)

- *packets fields from files* - We have both the IP layer and APPLICATION layer select input from files. This is done by running a selected test as "File"---as opposed to default---for both IP layer and APPLICATION layer, and editing the "application_from_file.txt" or "ip_from_file.txt" files. Note, the application file needs to be one packet per line and needs to be hex values. The ip_from_file file needs to be a correctly formatted dictionary--but this should be easy since there are a few examples. If a line is incorrectly formatted it will be ignored.

![from files](https://github.com/nathanReitinger/4182-project1/blob/master/media/example%20-%20fuzzing%20from%20file.gif)

- *IP layer selected field (version) and APPLICATION layer variable length* - fuzzing the "version" field of the IP packet and sending variable length hex values on the application layer

![from files](https://github.com/nathanReitinger/4182-project1/blob/master/media/example%20-%20fuzz%20version%20and%20variable%20length%20application%20layer.gif)

- *wireshark testing* - checking to see if packets are being modified with wireshark. We will run through the time to live field and send a packet for every single possible value of `ttl` (see background.md for details).  

![from files](https://github.com/nathanReitinger/4182-project1/blob/master/media/example%20-%20wireshark%20ttl.gif)

for more examples, please see [link](https://github.com/nathanReitinger/4182-project1/blob/master/lowlevelgui.md)



## Error_Handling

- invalid command line arguments
```
bash-3.2# python3 fuzzer.py nothing to say here
usage: fuzzer.py [-h] [-ip_destination IP_DESTINATION]
                 [-p_destination PORT_DESTINATION] [-ip_source IP_SOURCE]
                 [-p_source PORT_SOURCE] [-log LOG_FILE_PATH]
fuzzer.py: error: unrecognized arguments: nothing to say here

<> the same is true for entering invalid arguments

```
- missing or inaccessible files

```
<> assume 'ip_from_file.txt' is missing

bash-3.2# python3 fuzzer.py
[-] please include a file named 'payload_default.txt' and 'ip_from_file.txt' and 'application_from_file.txt
```

- invalid file contents

```
<> this for fields: {'version':pizza, 'internet_header_length':None, 'type_of_service':1, 'length_of_packet':None, 'id_of_packet':1, 'flags':'', 'frag':0, 'time_to_live': 64, 'protocol':'tcp'}
<> should fail to send and not crash ==> pizza should be in quotes

bash-3.2# python3 fuzzer.py
would you like to check if the server is running (command line IP address for server): [1] yes [2] no ---> 2
would you like to fuzz the IP layer: [1] yes [2] no ---> 1
would you like to run all default tests with set default values: [1] yes [2] no ---> 2
would you like to run default tests and specify the fields: [1] yes [2] no ---> 2
would you like to run IP tests via file: [1] yes [2] no ---> 1
[-] this line was not correctly formatted as a dictionary:

 {'version':pizza, 'internet_header_length':None, 'type_of_service':1, 'length_of_packet':None, 'id_of_packet':1, 'flags':'',
'frag':0, 'time_to_live': 64, 'protocol':'tcp'}

Begin emission:
..Finished sending 1 packets.
.*
Received 4 packets, got 1 answers, remaining 0 packets
.
Sent 1 packets.
Begin emission:
Finished sending 1 packets.
...........*
Received 12 packets, got 1 answers, remaining 0 packets
.
Sent 1 packets.
Begin emission:
.Finished sending 1 packets.
.*
Received 3 packets, got 1 answers, remaining 0 packets
.
Sent 1 packets.
<_io.StringIO object at 0x125865b88> True-True
False False-False
<_io.StringIO object at 0x1258680d8> True-True
received_and_match: 2
received_not_match: 0
not_matched_not_received 1
total: 3
bash-3.2#
```

- invalid command line arguments
```
<> try the fuzzer with invalid IP address

bash-3.2# python3 fuzzer.py -ip_destination 299.299.299.299
[-] invalid
```

- missing or inaccessible pattern file
```
<> removal of file "payload_default" will throw a flag
<> if the content of "payload_default" is piazza, invalid hex, then it fails
<> be sure not to have any trailing \n at the end of the file! This is read as input and viewed as invalid


bash-3.2# python3 fuzzer.py
==> the string in hex_pattern is not in hex!
==> try something like '9f' instead
[-] fuzzer will not run until valid hex is entered in payload_default.txt!
```

## Code_Clarity

- at a  high level, the code looks like this
```
                                                           ----------- 35.188.14.53
                +---------------------------------------->| server.py |
                |                                          ----------- 9090
                |
        TCP_send (main function)
        1. sets up TCP initial connection (SYN and SYNACK)
        2. sends custom ACK packet (if valid packet is given)
        - user may optionally turn `is_fast` to false for TCP close connection
        3. sniffs for a returned packet, stops when received or timeout
        4. logs the scapy packet in a dictionary called `log`
                |
                |
+---------------+-----------------+
|fuzzer.py                        |
|- asks user questions            |
|- either runs through defaults or|
|- generates packets from files   |
+---------------+-----------------+
                |
                |
                |
                |
                v
  post_processing (finishing function)
  - prints out the following:
  ~ received_and_match: packet sent, received by server, had server's pattern
  ~ received_not_matched: packet sent, received by server, no pattern
  ~ not_matched_not_received: ACK failed, likely bad values
  <> packets are stored in _io.StringIO objects as a string of scapy's pkt.show()
     - this is useful for viewing packets
     - log flag also helps, see line 376 in fuzzer.py for what to do with pkts
```

- you should see comments throughout
- I did not follow the coding style of shortening lines because I think it makes the lines harder to understand
- if you see a reference [number] just check out references.txt

## misc

> there are two core features of this project: (1) sniffing and (2) sending

![from files](https://github.com/nathanReitinger/4182-project1/blob/master/media/overall_design.jpg)

### sniffer

The sniffing feature's core functionality comes from this line of code:

```
sniff(count=0, prn=customAction(capture, log), filter=specific_filter, store=0, timeout=1, stop_filter=hasCode)
```

- `prn` is applied to each packet, logging the ACK information
- `filter` is used so that only responsive packets are grabbed
    - the filter works on correct sequence of packets
    ```
    sequence = ACK[TCP].seq + len(ACK[Raw])
    specific_filter = "tcp[8:4] = " + str(sequence)
    # tcp[8:4] is for ack <== return ACK needs to be ACK[TCP].seq + len(ACK[Raw]) ==> see [17]
    ```
- `stop_filter` is used to kill the sniff once it sees the responsive hex-pattern from the server
- `timeout` is so that we stop the sniff eventually if a stop_filter is not triggered
    - _notably_ the delay in fuzzing all fields comes from this timeout, but it is useful to make sure delayed packets aren't considered non-responsive  


### TCP_send

- the main functionality of fuzzing comes from the packet-filled ACK

```
ACK =

    IP(dst=IP_DESTINATION,
       version=fields['version'],
       ihl=fields['internet_header_length'],
       tos=fields['type_of_service'],
       len=fields['length_of_packet'],
       id=fields['id_of_packet'],
       flags=fields['flags'],
       frag=fields['frag'],
       ttl=fields['time_to_live'],
       proto=fields['protocol'],
       options=IPOption(copy_flag=options['copy_flag'],
                        optclass=options['optclass'],
                        option=options['option']))

     /

     TCP(sport=SYNACK.dport,
         dport=PORT_DESTINATION,
         flags="A",
         seq=SYNACK.ack,
         ack=SYNACK.seq + 1)

    /

    payload
```

- the IP part has fields that are dictionary filled from user-specified values or a series of all values being tested
    - this includes the options, which although included a few variable length fields, are fully traversed
- the TCP part of the packet is not fuzzed, but the parameters are properly in sequence
- the payload is filled from the `payload_default.txt` file
