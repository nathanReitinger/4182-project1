# 4182-project1

## installation

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

4. with the server running (see email with password) execute the program

```
python3 fuzzer.py
```

## User Guide

- that's what this is!
- see also the background.md file for some information on IP layer

## Program Functionality:

-

## Error handling:

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
<> should fail to send and not crash

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
bash-3.2# python3 fuzzer.py
==> the string in hex_pattern is not in hex!
==> try something like '9f' instead
[-] fuzzer will not run until valid hex is entered in payload_default.txt!
```

## Clarity of the Code:

- at a  high level, the code looks like this
```
                                                           -----------
                +---------------------------------------->| server.py |
                |                                          -----------
                |
        TCP_send (main function)
        1. sets up TCP initial connection (SYN and SYNACK)
        2. sends custom ACK packet (if valid packet is given)
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
  post_processing (finishing function, working with log)
  - received_and_match: packet sent, received by server, had server's pattern
  - received_not_matched: packet sent, received by server, no pattern
  - not_matched_not_received: ACK failed, likely bad values
  <> packets are stored in _io.StringIO objects as a string of scapy's pkt.show()
     - this is useful for viewing packets,
```
