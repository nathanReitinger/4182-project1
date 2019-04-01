"""
1. create socket
2. bind socket
3. listen socket
4. accept connections
"""

import socket
import sys
import threading
from _thread import *

# see [2]
HOST = '0.0.0.0'        # 0.0.0.0 for remote; localhost for local
PORT = 9090             # arbitrarily picked
BACKLOG = 10            # queued connections to server [1]

# metrics per spec, protected with lock
valid_packets = 0
invalid_packets = 0
threadLock = threading.Lock()

###########
# helpers #
###########


####################
# 1. create socket #
####################
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       # TCP is SOCK_STREAM
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # reuse the address to remove bind errors [3]
print("TCP socket created")
print("This is server's IP, port:", HOST, PORT)

##################
# 2. bind socket #
##################
try:
    s.bind((HOST, PORT))
except socket.error as e:
    print("binding failed: ", e)
    sys.exit("exiting on bind failure")
print("socket bound")

####################
# 3. listen socket #
####################
s.listen(BACKLOG)
print("socket listening")

##################
# 4. connections #
##################
def clients(conn, valid_packets):
    '''
    - sits in loop waiting for client connections
    - reads

    :param conn: incoming connection
    :return: first index in array of received data
    '''
    while True:
        payload = conn.recv(2048)

        # TODO: the recv needs to be recvall

        # bytes = bytearray(payload)
        print(payload)
        reply = b"pizza"

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
    print("=====================================")
    print("valid packets: " + str(valid_packets))
    print("invalid packets: " + str(invalid_packets))
    sys.exit("-- exiting upon keyboard interrupt --")

# if popped out of while1 and not keyboardInterrupt
s.close()