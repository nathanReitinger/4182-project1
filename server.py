


## this is a copy of the server which lives on Google cloud
## to edit the server, use the installation guide and edit it directly
## this file is here for illustrative purposes 




"""
0. set up the log
1. create socket
2. bind socket
3. listen socket
4. accept connections
5. print log
"""
import socket
import sys
import threading
from pathlib import Path
import binascii
import string
import re
from _thread import *

# see [2]
HOST = '0.0.0.0'        # 0.0.0.0 for remote; localhost for local
PORT = 9090             # arbitrarily picked
BACKLOG = 10            # queued connections to server [1]
HEX_PATTERN = Path('hex_pattern.txt').read_text()
if not all(c in string.hexdigits for c in HEX_PATTERN):
    print("==> the string in hex_pattern is not in hex!")
    print("==> try something like '9f' instread")
    # example: foo ==> fail, this is not hex
    # examplee: deadbeef ==> pass, this is hex
    sys.exit("[-] server will not run until valid hex is entered in hex_pattern.txt!")
HEX_PATTERN = binascii.unhexlify(HEX_PATTERN)

# metrics per spec, protected with lock
valid_packets = 0
invalid_packets = 0
threadLock = threading.Lock()

####################
# 0. set up log    #
####################
"""
- counts all packets received, even setup and teardown TCP
- those packets with payload from `hex_pattern.txt` are tallied
- total packets received kept in variable "total packets received"
- when packet is received and has hex_pattern, payload record value incremented

example:
    server receives pattern matched packet "de" 3 times
    server receives b'\xcc' not matching "de" 1 time
    server receives b'\xee' not matching "de" 1 time
    server receives b'' not maching "de" 1 time

    output diciontary looks like this:
        total packets recived: 6
        cc: 1       <== this is server checkup packet
        ee: 1       <== this is an end TCP sequence packet
          : 1       <== this is the ''
        de: 3       <== these are packets received and matching
"""
output = {}
output['total packets recived:'] = 0 # increment value all packets received
output['total valid recived:'] = 0   # increment value match packets received

####################
# 1. create socket #
####################
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       # TCP is SOCK_STREAM
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # reuse the address to remove bind errors [3]
print("[+] TCP socket created")
print("[+] This is server's IP port:", HOST, PORT)

##################
# 2. bind socket #
##################
try:
    s.bind((HOST, PORT))
except socket.error as e:
    print("[-] binding failed: ", e)
    sys.exit("==> exiting on bind failure")
print("[+] socket bound")

####################
# 3. listen socket #
####################
s.listen(BACKLOG)
print("[+] socket listening\n\n")

##################
# 4. connections #
##################
def clients(conn, valid_packets):
    '''
    - sits in loop waiting for client connections
    - checks payload for hex pattern found in `hex_pattern.txt`
    - sends reply based on match
    - logs result ==> printed after server closes <==
    '''
    while True:
        payload = conn.recv(2048)
        # bytes = bytearray(payload)

        print("\t\t", payload)

        start = 0
        stop = len(HEX_PATTERN)
        slice1 = payload[start:stop]
        slice2 = HEX_PATTERN[start:stop]

        reply = b'\xff'

        output['total packets recived:'] += 1

        if slice1 == slice2:
            reply = b'\x00'

            # increment total match received
            output['total valid recived:'] += 1

            # log specific packet payload that matched
            to_log = payload.hex() + ":"
            # print("\t\t to log:", to_log)

            # log the entire paylaod
            if to_log in output:
                output[to_log] += 1
            else:
                output[to_log] = 1
        else:
            to_log = payload.hex() + ":"
            # log the entire paylaod
            if to_log in output:
                output[to_log] += 1
            else:
                output[to_log] = 1

        with threadLock:
            valid_packets += 1
        if not payload:
            break
        conn.sendall(reply)
    conn.close()
try:
    while 1:
        conn, addr = s.accept()  # accept an incoming connection (uses socket library)
        print("connected with " + addr[0] + ":" + str(addr[1]))
        start_new_thread(clients, (conn, valid_packets,))

except KeyboardInterrupt:
    s.close()
    print("\n=====================================")
    ####################
    # 5. print log     #
    ####################
    for key, item in output.items():
        print(key, item)
    sys.exit("-- exiting upon keyboard interrupt --")

# if popped out of while1 and not keyboardInterrupt
s.close()
