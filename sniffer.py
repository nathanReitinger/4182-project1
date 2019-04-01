import argparse
from pathlib import Path
from scapy.all import *
import sys
import io

# def pkt_callback(pkt):
#     pkt.show()  # debug statement
#     if Raw in pkt:
#         load = pkt[Raw].load
#         if load == b'\x00' or load == b'\xff':
#             print("PIZZZZZZZA")
#             return True

def hasCode(pkt):
    if Raw in pkt:
        load = pkt[Raw].load
        if load == b'\x00' or load == b'\xff':
            return True

# def hasCode2(ACK):
#     def getPacket(pkt):
#         if Raw in pkt:
#             load = pkt[Raw].load
#             if load == b'\x00' or load == b'\xff':
#                 print("SUCCESS")
#                 return True

def customAction(capture, log2):
    """
    https://gist.github.com/thepacketgeek/6876717
    """
    def logPacket(packet):
        if Raw in packet:

            load = packet[Raw].load

            if load == b'\x00':
                log2[capture] = "True-True"
            if load == b'\xff':
                log2[capture] = "True-False"
    return logPacket
