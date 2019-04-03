# 4182-project1

- [Installation](#installation)
  * [this repo](#this repo)
  * [server](#server)
- [User Guide](#User Guide (examples and functionality))
  * [Basic Fuzzing](#basic fuzzing)
  * [Videos!](#high-level video)
  * [low-level gui](#lower-level non-GUI with explanations)
- [Error Handling](#Error Handling)
- [Clarity of the Code](#Clarity of the Code)

## installation

### this repo

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

## User Guide (examples and functionality)

- default payload is found in file "payload_default.txt" ==> can change with new hex values if you want
    - make sure this file does not have a trailing "\n" which is read as input and is not hex
- see  the background.md file for some information on IP layer

### basic fuzzing

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

### high-level video

- *packets from files* IP layer and APPLICATION layer using payload from file (application, 'application_from_file.txt' and packet from file (IP, 'ip_from_file.txt'))

![from files](https://github.com/nathanReitinger/4182-project1/blob/master/media/example%20-%20from%20files.gif)

- *parameter setting and error handling* - fuzzer allows the selection non-default IP and ports, but checks for invalid ranges

![from files](https://github.com/nathanReitinger/4182-project1/blob/master/media/example%20-%20parameter%20setting%20and%20error%20handling.gif)

- *IP layer selected field (version) and APPLICATION layer variable length* - fuzzing the "version" field of the IP packet and sending variable length hex values on the application layer

![from files](https://github.com/nathanReitinger/4182-project1/blob/master/media/example%20-%20fuzz%20version%20and%20variable%20length%20application%20layer.gif)

### lower-level non-GUI with explanations

- *IP LAYER* - fuzzing all fields (fuzzes everything---includes options, includes out-of-range values, includes crazy values, runs through the entire number-range of possible values for each field)

```
bash-3.2# python3 fuzzer.py
would you like to check if the server is running (command line IP address for server): [1] yes [2] no ---> 2
would you like to fuzz the IP layer: [1] yes [2] no ---> 1
would you like to run all default tests with set default values: [1] yes [2] no ---> 1
on fields too large to fuzz, would you like a default value to be applied: [1] yes [2] no ---> 1
...
would you like to run default tests and specify the fields: [1] yes [2] no ---> 2
would you like to run IP tests via file: [1] yes [2] no ---> 2
...
<_io.StringIO object at 0x124a5c5e8> False-False
<_io.StringIO object at 0x124a5caf8> False-False
<_io.StringIO object at 0x124a5c438> False-False
<_io.StringIO object at 0x124a5c9d8> False-False
received_and_match: 763
received_not_match: 0
not_matched_not_received 461
total: 1224

<> the io.StringIO printout are the packets in pkt.show() form
<> False-False means packet not send (bad ACK) and not sniffed
<> True-False means packet sent and received, but pattern match failed
<> True-True means packet sent and received and pattern matched

<> this will take a long time (waiting to timeout on failed packet-send sniffs)
<> this could be fixed by only sending valid packets, but that's not a fuzzer!
<> also note that fields that are too large are handled by random selections in the default case
```

- *IP LAYER* - fuzzing specific fields with user input

```
bash-3.2# python3 fuzzer.py      
would you like to check if the server is running (command line IP address for server): [1] yes [2] no ---> 2
would you like to fuzz the IP layer: [1] yes [2] no ---> 1
would you like to run all default tests with set default values: [1] yes [2] no ---> 2
would you like to run default tests and specify the fields: [1] yes [2] no ---> 1
type a field exactly as is: 'version', 'internet_header_length', 'type_of_service', 'length_of_packet', 'id_of_packet', 'flags', 'frag'
, 'time_to_live', 'protocol', 'copy_flag', 'optclass', 'option' ---> version
...
would you like to run IP tests via file: [1] yes [2] no ---> 2
<_io.StringIO object at 0x11b826b88> False-False
<_io.StringIO object at 0x11b826dc8> False-False
<_io.StringIO object at 0x11b829798> False-False
<_io.StringIO object at 0x11b8290d8> False-False
<_io.StringIO object at 0x11b8294c8> True-True
<_io.StringIO object at 0x11b8298b8> False-False
...
<_io.StringIO object at 0x11b830e58> False-False
received_and_match: 1
received_not_match: 0
not_matched_not_received 15
total: 16

<> we can see the printout, version starts at 0 then up to 4 where it is "True-True"
<> the rest fail, which is why we get 1 successful match and the rest not matched and not received
<> see background for more detail ==> version [0,15]
```

- *IP LAYER* - content read from hex from file

```
bash-3.2# python3 fuzzer.py
would you like to check if the server is running (command line IP address for server): [1] yes [2] no ---> 2
would you like to fuzz the IP layer: [1] yes [2] no ---> 1
would you like to run all default tests with set default values: [1] yes [2] no ---> 2
would you like to run default tests and specify the fields: [1] yes [2] no ---> 2
would you like to run IP tests via file: [1] yes [2] no ---> 1
...
<_io.StringIO object at 0x121f51b88> True-True
False False-False
<_io.StringIO object at 0x121f540d8> True-True
received_and_match: 2
received_not_match: 0
not_matched_not_received 1
total: 3

<> this depends on the contents of "ip_from_file.txt"
<> that file expects a syntactically correct dictionary
<> if one of the values is incorrectly formatted, it is skipped (this is the "False False-False above")
<> you can add your own fields this way by either copy-pasting the first one or making a new dictionary
<> this is based around the IP.show() structure. Here it is for clarity

###[ IP ]###
  version   = 13
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     =
  frag      = 0
  ttl       = 64
  proto     = tcp
  chksum    = None
  src       = 192.168.0.191
  dst       = 35.188.14.53
  \options   \
###[ TCP ]###
     sport     = 17654
     dport     = websm
     seq       = 1371070446
     ack       = 3378443242
     dataofs   = None
     reserved  = 0
     flags     = A
     window    = 8192
     chksum    = None
     urgptr    = 0
     options   = []
###[ Raw ]###
        load      = '\xde\xad\xbe\xef\x00\x00'
```

- *APPLICATION LAYER* - default random payloads

```
bash-3.2# python3 fuzzer.py
would you like to check if the server is running (command line IP address for server): [1] yes [2] no ---> 2
would you like to fuzz the IP layer: [1] yes [2] no ---> 2
would you like to fuzz the application layer: [1] yes [2] no ---> 1
would you like to run default fuzzing: [1] yes [2] no ---> 1
would you like to set the number of tests to run (else default): [1] yes [2] no ---> 2
would you like a fixed payload size: [1] yes [2] no ---> 1
would you like to set the payload size (else default): [1] yes [2] no ---> 2
...
<_io.StringIO object at 0x1276b24c8> True-False
received_and_match: 0
received_not_match: 10
not_matched_not_received 0
total: 10

<> we can see that nothing matches because this is randomly filling in the payload
```

- *APPLICATION LAYER* - default variable payloads

```
...
would you like a fixed payload size: [1] yes [2] no ---> 2
would you like to set the range of variable payload size: [1] yes [2] no ---> 1
what is the low end of the range (e.g., 1 byte)? ---> 1
what is the high end of the range (e.g., 10 bytes)? ---> 1000
...
<_io.StringIO object at 0x1276f8c18> True-False
<_io.StringIO object at 0x1276fb828> False-False
<_io.StringIO object at 0x1276f8e58> True-False
<_io.StringIO object at 0x1276fb168> True-False
<_io.StringIO object at 0x1276fb558> False-False
<_io.StringIO object at 0x1276fb798> True-False
<_io.StringIO object at 0x1276fb8b8> False-False
<_io.StringIO object at 0x1276fb948> False-False
<_io.StringIO object at 0x127702d38> True-False
<_io.StringIO object at 0x1277021f8> True-False
received_and_match: 0
received_not_match: 6
not_matched_not_received 4
total: 10

<> none matched again (these are just variable length random payloads)
<> also, some failed to send--this is because the size is set to 1000 and exceeds acceptable bounds
```

- *APPLICATION LAYER* - payload from hex

```
...
would you like to fuzz the application layer: [1] yes [2] no ---> 1
would you like to run default fuzzing: [1] yes [2] no ---> 2
...
total: 4

<> use one packet payload per line
<> this file must be in hex format (without \x or 0x) ==> line is passed if not
```


## Error Handling

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

## Clarity of the Code

- at a  high level, the code looks like this
```
                                                           -----------
                +---------------------------------------->| server.py |
                |                                          -----------
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
