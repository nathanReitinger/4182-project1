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

- all errors should be handled by the code.

 -

For example, the following random values are sent:
`random_values = ['abracadabra', 9, '\x00', '\xff', '0x1', '\xff\xff\xff\xff\xff', float('inf'), float('-inf'), ['one'], {'two':3}]`
- - these values are not only out of range, they are invalid
- - the code notes this as `[-] odd value broke ACK! nothing was sent out. Moving on to next` and moves on

Another example:


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
