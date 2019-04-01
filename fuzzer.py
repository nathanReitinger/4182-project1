#! /usr/bin/env python3 root

# ███████╗██╗   ██╗███████╗███████╗███████╗██████╗
# ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔════╝██╔══██╗
# █████╗  ██║   ██║  ███╔╝   ███╔╝ █████╗  ██████╔╝
# ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔══╝  ██╔══██╗
# ██║     ╚██████╔╝███████╗███████╗███████╗██║  ██║
# ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
#           ~use command+z to kill me!~

import argparse
from pathlib import Path
from scapy.all import *
import sys
import io
import copy
import string
import binascii
import ast
import random
import logging
import subprocess
import os
import platform as p

from sniffer import *
from helpers import *

#
# Change log level to suppress annoying IPv6 error
#
def ubuntu():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    name = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
    print("this machine's IP addr:", name)
    print("[+] using ipTables")
    subprocess.check_output(['iptables','-A', 'OUTPUT', '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-s', name, '-j','DROP'])
    # iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.0.148 -j DROP

#
# DEFAULTS
#
IP_DESTINATION = '35.188.14.53'                                 # default server, google cloud hosted
PORT_DESTINATION = 9090                                         # default server port
IP_SOURCE = '127.0.0.2'                                         # this computer, localhost or anything
PORT_SOURCE = 80                                                # randomly picked

#---------------------------------------------------------------# check for default files
try:
    DEFAULT_PAYLOAD = Path('payload_default.txt').read_text()
    IP_FROM_FILE = Path('payload_default.txt').read_text()
    APPLICATION_FROM_FILE = Path('payload_default.txt').read_text()
except:
    sys.exit("[-] please include a file named 'payload_default.txt' and 'ip_from_file.txt' and 'application_from_file.txt")
if not all(c in string.hexdigits for c in DEFAULT_PAYLOAD):
    print("==> the string in hex_pattern is not in hex!")
    print("==> try something like '9f' instread")
    # example: foo ==> fail, this is not hex
    # examplee: deadbeef ==> pass, this is hex
    sys.exit("[-] fuzzer will not run until valid hex is entered in payload_default.txt!")
DEFAULT_PAYLOAD = binascii.unhexlify(DEFAULT_PAYLOAD)
#---------------------------------------------------------------# make sure files are in hex

DEFAULT_FILTER = "ip and host " + IP_DESTINATION                # may be used in sniffing, not currently used
SERVER_CHECK = True                                             # flag for checking if server is on before performing tests
SERVER_IS_ON = False                                            # used to check if a server is ready to receive packets

def IPlayer_from_file(log):
    master_list = []
    is_fast = True

    with open('ip_from_file.txt', 'r') as f:
        for line in f.readlines():
            try:
                temp_dict = ast.literal_eval(line)
                master_list.append(temp_dict)
            except:
                print("this line was not correctly formatted as a dictionary:\n\n", line)
                print("\n\nplease edit the file 'ip_from_file.txt' at this line and try again!")
                pass

    for item in master_list:
        print(item, "\n\n")
        TCP_send(item, log, is_fast)

def IPlayer_default_tests(log, user_specified=False):
    #####################################################
    # TODO check that these are not needing to be hex
    ######################################################
    version = list(range(0, 16))
    internet_header_length = list(range(0, 16))
    type_of_service = list(range(0, 256))
    length_of_packet = list(range(0, 65536))
    id_of_packet = list(range(0, 65536))
    flags = list(range(0, 8))
    frag = list(range(0, 8192))
    time_to_live = list(range(0, 256))
    protocol = list(range(0, 256))
    copy_flag = list(range(0, 2))
    optclass = list(range(0, 4))
    options_list = list(range(0, 32))

    every_field = {'version': version, 'internet_header_length':internet_header_length, 'type_of_service':type_of_service, 'length_of_packet':length_of_packet, 'id_of_packet':id_of_packet, 'flags':flags, 'frag':frag, 'time_to_live':time_to_live, 'protocol':protocol, 'copy_flag':copy_flag, 'optclass':optclass, 'options_list':options_list}

    random_values = ['abracadabra', 9, '\x00', '\xff', '0x1', '\xff\xff\xff\xff\xff', float('inf'), float('-inf'), ['one'], {'two':3}]
    options_default = {'copy_flag':0, 'optclass':0, 'option':0}
    options = options_default.copy()
    all_fields = ['version', 'internet_header_length', 'type_of_service', 'length_of_packet', 'id_of_packet', 'flags', 'frag', 'time_to_live', 'protocol']

    # default values in place
    default = {'version':4, 'internet_header_length':None, 'type_of_service':0x0, 'length_of_packet':None, 'id_of_packet':1, 'flags':'', 'frag':0, 'time_to_live': 64, 'protocol':'tcp', 'copy_flag':0, 'optclass':0, 'option':0}
    fields = default.copy()

    # fast sending without closing TCP connection
    is_fast = True

    #
    # user specified fields to fuzz
    #

    if user_specified:
        if user_specified == copy_flag or user_specified == optclass or user_specified == options_list:
            options = options_default.copy()
            for i in every_field[user_specified]:
                options[user_specified] = i
                TCP_send(fields, log, is_fast, options=options)
            options = options_default.copy()
        else:
            fields = default.copy()
            for i in every_field[user_specified]:
                fields[user_specified] = i
                TCP_send(fields, log, is_fast)
            fields = default.copy()
        return

    #
    # try crazy values (e.g., like dictionary) for all fields
    #

    for i in random_values:
        for j in all_fields:
            print(i, j)
            fields = default.copy()
            fields[j] = i
            TCP_send(fields, log, is_fast)
    fields = default.copy()

    #
    # try all options
    #

    for i in copy_flag:
        options['copy_flag'] = i
        TCP_send(fields, log, is_fast, options=options)
    options = options_default.copy()
    for i in optclass:
        options['optclass'] = i
        TCP_send(fields, log, is_fast, options=options)
    options = options_default.copy()
    for i in options_list:
        options['options'] = i
        TCP_send(fields, log, is_fast, options=options)

    #
    # send to all fields all possible values
    #

    fields = default.copy()
    for i in version:
        fields['version'] = i
        TCP_send(fields, log, is_fast)
    fields = default.copy()
    for i in internet_header_length:
        fields['internet_header_length'] = i
        TCP_send(fields, log, is_fast)
    fields = default.copy()
    for i in type_of_service:
        fields['type_of_service'] = i
        TCP_send(fields, log, is_fast)
    fields = default.copy()
    for i in flags:
        fields['flags'] = i
        TCP_send(fields, log, is_fast)
    fields = default.copy()
    for i in time_to_live:
        fields['time_to_live'] = i
        TCP_send(fields, log, is_fast)
    fields = default.copy()
    for i in protocol:
        fields['protocol'] = i
        TCP_send(fields, log, is_fast)
    fields = default.copy()

    #
    # fields that are too large to send all values
    #

    # send every 250th value
    for i in id_of_packet[::250]:
        fields['id_of_packet'] = i
        TCP_send(fields, log, is_fast)
    fields = default.copy()
    # use beginning, middle, end values
    frag_hits = [0,1,2,3,4,5,4095, 4096, 4097, 8190, 8192]
    for i in frag_hits:
        fields['frag'] = i
        TCP_send(fields, log, is_fast)
    fields = default.copy()
    # use beginning, actual-length based on default packet, end values
    length_hits = [0,1,2,3,4,5,63, 64, 65, 66, 67, 65533, 65534, 65535]
    for i in length_hits:
        fields['length_of_packet'] = i
        TCP_send(fields, log, is_fast)


def TCP_send(fields, log, is_fast, options=False):
    """
    - main send function
    """
    ip = IP(dst=IP_DESTINATION)
    port = RandNum(1024, 65535)
    SYN = ip / TCP(sport=port, dport=PORT_DESTINATION, flags="S", seq=random.randrange(0, (2 ** 32) - 1))

    SYNACK = sr1(SYN, retry=1, timeout=1)
    if (SYNACK == None):
        SYNACK = sr1(SYN, retry=1, timeout=1)
        print("[-] error on SYNACK sr1, simply trying again")
        if (SYNACK == None):
            print("[-] error on SYNACK sr1 again, returning")
            return False
    try:
        if options:
            ACK = IP(dst=IP_DESTINATION, version=fields['version'], ihl=fields['internet_header_length'], tos=fields['type_of_service'], len=fields['length_of_packet'], id=fields['id_of_packet'], flags=fields['flags'], frag=fields['frag'], ttl=fields['time_to_live'], proto=fields['protocol'], options=IPOption(copy_flag=options['copy_flag'], optclass=options['optclass'], option=options['option'])) / TCP(sport=SYNACK.dport, dport=PORT_DESTINATION, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1) / DEFAULT_PAYLOAD
        else:
            ACK = IP(dst=IP_DESTINATION, version=fields['version'], ihl=fields['internet_header_length'], tos=fields['type_of_service'], len=fields['length_of_packet'], id=fields['id_of_packet'], flags=fields['flags'], frag=fields['frag'], ttl=fields['time_to_live'], proto=fields['protocol']) / TCP(sport=SYNACK.dport, dport=PORT_DESTINATION, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1) / DEFAULT_PAYLOAD
        # ACK.show()
    except:
        # what likely happened is that the ACK would not send becuase it contained an invalid value for a field
        # this occurs for too-high numbers or too-low numbers or odd data types
        # ACK.show()
        capture = string2variable(fields)
        log[capture] = "False-False"
        print("[-] odd value broke ACK! nothing was sent out. Moving on to next")
        return
    try:
        send(ACK)
    except:
        # what likely happened is that the ACK would not send becuase it contained an invalid value for a field
        # this occurs for too-high numbers or too-low numbers or odd data types
        # ACK.show()
        capture = packet2variable(ACK)
        if not capture:
            capture = string2variable(fields)
        log[capture] = "False-False"
        print("[-] odd value broke ACK SEND! Moving on to next")
        return

    sequence = ACK[TCP].seq + len(ACK[Raw])
    # tcp[8:4] is for ack <== return ACK needs to be ACK[TCP].seq + len(ACK[Raw]) ==> see [17]
    specific_filter = "tcp[8:4] = " + str(sequence)

    # this way, if timeout triggers then we have false recorded
    # we have a dictionary of pretty print IP packets which either successfully reach the server or not
    capture = packet2variable(ACK)
    log[capture] = "False-False"

    sniff(count=0, prn=customAction(capture, log), filter=specific_filter, store=0, timeout=1, stop_filter=hasCode)

    # do not do FIN close
    if not is_fast:
        FIN = IP(dst=IP_DESTINATION, ttl=100) / TCP(sport=SYNACK.dport, dport=PORT_DESTINATION, flags="FA", seq=sequence, ack=SYNACK.seq+1) / "the end"
        FINACK = sr1(FIN, retry=0, timeout=1)
        if (FINACK != None):
            try:
                sequence = FINACK[TCP].seq + len(FINACK[Raw])
            except:
                pass
            LASTACK = IP(dst=IP_DESTINATION, ttl=100) / TCP(sport=SYNACK.dport, dport=PORT_DESTINATION, flags="A", seq=sequence, ack=SYNACK.seq+1) / "the end"
            send(LASTACK)

def summary(log):
    post_processing(log)

def main():

    #-------------------------------------------------------------------------------------------------------------------------------------#

    #
    # prerequisites
    #

    # get root
    # returncode = subprocess.call(["/usr/bin/sudo", "/usr/bin/id"])    // not used, but works for ad hoc sudo bump
    if not os.geteuid() == 0:
        sys.exit("\nonly root can run this script. use `sudo -s` and run again!\n")
    if (p.system()) == 'Linux':
        # set up iptables and root correctly (this step just skips it on my mac (Darwin))
        ubuntu()

    #-------------------------------------------------------------------------------------------------------------------------------------#

    #
    # setting defaults
    #

    global IP_DESTINATION, PORT_DESTINATION, IP_SOURCE, PORT_SOURCE, DEFAULT_PAYLOAD, DEFAULT_FILTER, SERVER_IS_ON, SERVER_CHECK

    # houses custom scapy packets sent to server
    # <packet, isReceived-didMatch> where result is boolean True/False-True/False
    # True-True means packet was received and matching value identified
    # True-False means packet was received but pattern match failed
    # False-False means packet not received and, obviously, pattern not matched
    log = {}

    arg = argparse.ArgumentParser(description="4182 fuzzer!")
    arg.add_argument("-ip_destination", action="store", dest="ip_destination", help="Destination IP - Default: 127.0.0.1")
    arg.add_argument("-p_destination", action="store", dest="port_destination", help="Destination PORT - Default: 9090")
    arg.add_argument("-ip_source", action="store", dest="ip_source", help="source IP - Default: 127.0.0.1")
    arg.add_argument("-p_source", action="store", dest="port_source", help="source PORT - Default: 80")

    options = arg.parse_args()
    if options.ip_destination:
        IP_DESTINATION = options.ip_destination
    if options.port_destination:
        PORT_DESTINATION = int(options.port_destination)
    if options.ip_source:
        IP_SOURCE = options.ip_source
    if options.port_source:
        PORT_SOURCE = int(options.port_source)

    #-------------------------------------------------------------------------------------------------------------------------------------#

    #
    # check on server
    #

    question = "would you like to check if the server is running (command line IP address for server): [1] yes [2] no"
    ret = get_input(question)
    if ret:
        server_check(IP_DESTINATION, PORT_DESTINATION, IP_SOURCE, PORT_SOURCE)

    #-------------------------------------------------------------------------------------------------------------------------------------#

    #
    # IP LAYER
    #

    question = "would you like to fuzz the IP layer: [1] yes [2] no"
    ret = get_input(question)
    if ret:

        #
        # IP layer by default tests
        #

        question = "would you like to run all default tests with set default values: [1] yes [2] no"
        ret = get_input(question)
        if ret:
            IPlayer_default_tests(log)

        #
        # IP layer user-picks field
        #

        question = "would you like to run default tests and specify the fields: [1] yes [2] no"
        ret = get_input(question)
        if ret:
            question = "type a field exactly as is: 'version', 'internet_header_length', 'type_of_service', 'length_of_packet', 'id_of_packet', 'flags', 'frag', 'time_to_live', 'protocol', 'copy_flag', 'optclass', 'option'"
            ret = get_input_fields(question)
            IPlayer_default_tests(log, user_specified=ret)

        #
        # IP layer by reading fields from file
        #

        question = "would you like to run IP tests via file: [1] yes [2] no"
        ret = get_input(question)
        if ret:
            IPlayer_from_file(log)

        # exit now, done with IP layer
        summary(log)
        sys.exit()

    #-------------------------------------------------------------------------------------------------------------------------------------#

    #
    # APPLICATION LAYER
    #

    question = "would you like to fuzz the application layer: [1] yes [2] no"
    ret = get_input(question)
    if ret:

        #
        # Application layer default tests
        #

        number_of_packets = 100

        question = "would you like to set the number of tests to run (else default): [1] yes [2] no"
        ret = get_input(question)
        if ret:
            question = "how many packets would you like to send?"
            number_of_packets = get_input_number(question)

        question = "would you like a fixed payload size: [1] yes [2] no"
        ret = get_input(question)
        if ret:
            # set the default and change if user wants custom
            payload_size_bytes = 10

            question = "would you like to set the payload size (else default): [1] yes [2] no"
            ret = get_input(question)
            if ret:
                question = "how many bytes would you like the payload to be?"
                payload_size_bytes = get_input_number(question)

            #### send number_of_packets with this payload size as payload_size_bytes ###
            (number_of_packets, payload_size_bytes)

        else:
            #set the defaults, change if user wants custom
            variable_low_end = 1
            variable_high_end = 10
            variable_range = []

            question = "would you like to set the range of variable payload size: [1] yes [2] no"
            ret = get_input(question)
            if ret:
                question = "what is the low end of the range (e.g., 1 byte)?"
                variable_low_end = get_input_number(question)
                question = "what is the high end of the range (e.g., 10 bytes)?"
                variable_high_end = get_input_number(question)

            for i in range(variable_low_end,variable_high_end):
                variable_range.append(i)

            #### send number_of_packets with range of payload size as variable_range ###

        #
        # Application layer by reading payload from file
        #


    #-------------------------------------------------------------------------------------------------------------------------------------#





if __name__ == '__main__':
    main()
