# 4182-project1

Here are a few more examples when using the older low-level gui

## lowLevel_gui

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

<> the io.StringIO printout are the packets in pkt.show() form (I left this because it may be good to modify later)
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
