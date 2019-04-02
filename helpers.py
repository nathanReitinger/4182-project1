import argparse
from pathlib import Path
from scapy.all import *
import sys
import io
import binascii

class bcolors:
    WARNING = '\033[95m'
    ENDC = '\033[0m'

def string2variable(string):
    capture = io.StringIO()
    save_stdout = sys.stdout    # turn off stdout
    sys.stdout = capture        # print now goes to capture
    print(string)
    sys.stdout = save_stdout    # turn stdout back on
    return capture

def packet2variable(packet):
    """
    - turns a scapy pretty print packet with show() into a variable
    - the variable may be used to reproduce fuzzing sessions
    <> see [16]
    """
    capture = io.StringIO()
    save_stdout = sys.stdout    # turn off stdout
    sys.stdout = capture        # print now goes to capture
    try:
        packet.show()
    except:
        sys.stdout = save_stdout
        return False
    sys.stdout = save_stdout    # turn stdout back on
    return capture

def server_check(IP_DESTINATION, PORT_DESTINATION, IP_SOURCE, PORT_SOURCE):
    """
    - checks if a message comes back from the server
    - is naive, simple test acts like a ping to see if anything comes back
    """

    print(bcolors.WARNING + "\n[ ] checking on server at:" + bcolors.ENDC, IP_DESTINATION, "\n")

    # helps server know what packets are for setup versus fuzzing
    # cc and ee are for setup: cc is server check and ee is end message from TCP ending sequence
    SERVER_CHECK_PAYLOAD = binascii.unhexlify("cc")
    SERVER_END_PAYLOAD = binascii.unhexlify("ee")

    ip = IP(dst=IP_DESTINATION)
    port = RandNum(1024, 65535)
    SYN = ip / TCP(sport=port, dport=PORT_DESTINATION, flags="S", seq=random.randrange(0, (2 ** 32) - 1))
    SYNACK = sr1(SYN, retry=1, timeout=1)
    if (SYNACK == None):
        print(bcolors.WARNING + "[-] error on SYNACK sr1, simply trying again" + bcolors.ENDC)
        SYNACK = sr1(SYN, retry=1, timeout=1)
        if (SYNACK == None):
            sys.exit(bcolors.WARNING + "[-] error on SYNACK sr1 again, exiting!" + bcolors.ENDC)
    ACK = IP(dst=IP_DESTINATION) / TCP(sport=SYNACK.dport, dport=PORT_DESTINATION, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1) / SERVER_CHECK_PAYLOAD
    recv = sr1(ACK)
    # if the server is not configured properly, our TCP sequence will fail and the ack-back is 0
    if recv.ack == 0:
        SERVER_IS_ON = False
    else:
        SERVER_IS_ON = True

    sequence = ACK[TCP].seq + len(ACK[Raw])

    if SERVER_IS_ON:
        print(bcolors.WARNING + "\n[+] success, server is ready for fuzzing\n" + bcolors.ENDC)
        FIN = IP(dst=IP_DESTINATION, ttl=100) / TCP(sport=SYNACK.dport, dport=PORT_DESTINATION, flags="FA", seq=sequence, ack=SYNACK.seq+1) / SERVER_END_PAYLOAD
        FINACK = sr1(FIN, retry=1, timeout=1)
        if (FINACK != None):
            try:
                sequence = FINACK[TCP].seq + len(FINACK[Raw])
            except:
                pass
            LASTACK = IP(dst=IP_DESTINATION, ttl=100) / TCP(sport=SYNACK.dport, dport=PORT_DESTINATION, flags="A", seq=sequence, ack=SYNACK.seq+1) / SERVER_END_PAYLOAD
            send(LASTACK)
        return True

    if not SERVER_IS_ON:
        FIN = IP(dst=IP_DESTINATION, ttl=100) / TCP(sport=SYNACK.dport, dport=PORT_DESTINATION, flags="FA", seq=sequence, ack=SYNACK.seq+1) / SERVER_END_PAYLOAD
        FINACK = sr1(FIN, retry=1, timeout=1)
        if (FINACK != None):
            try:
                sequence = FINACK[TCP].seq + len(FINACK[Raw])
            except:
                pass
            LASTACK = IP(dst=IP_DESTINATION, ttl=100) / TCP(sport=SYNACK.dport, dport=PORT_DESTINATION, flags="A", seq=sequence, ack=SYNACK.seq+1) / SERVER_END_PAYLOAD
            send(LASTACK)
        sys.exit("\n[-] server error, please check that a server at IP_DESTINATION can receive packets!\n\n")

def get_input_fields(question):
    check = str(input(question + " ---> "))
    try:
        if check == "version":
            return "version"
        if check == "internet_header_length":
            return "internet_header_length"
        if check == "type_of_service":
            return "type_of_service"
        if check == "length":
            return "length"
        if check == "id_of_packet":
            return "id_of_packet"
        if check == "flags":
            return "flags"
        if check == "frag":
            return "frag"
        if check == "time_to_live":
            return "time_to_live"
        if check == "protocol":
            return "protocol"
        if check == "copy_flag":
            return "copy_flag"
        if check == "optclass":
            return "optclass"
        if check == "option":
            return "option"
        else:
            print(bcolors.WARNING + '[-] Invalid Input' + bcolors.ENDC)
            return get_input_fields(question)
    except:
        print(bcolors.WARNING +'[-] Invalid Input' + bcolors.ENDC)
        return get_input_fields(question)


def get_input_number(question):
    check = str(input(question + " ---> "))
    try:
        val = int(check)
        if val > 0:
            return val
        else:
            print("Please enter a number above or equal to 1")
            return get_input_number(question)
    except ValueError:
        print("Please enter a number above or equal to 1")
        return get_input_number(question)

def get_input(question):
    """
    see [15]
    """
    check = str(input(question + " ---> "))
    try:
        if check == '1':
            return True
        elif check == '2':
            return False
        else:
            print(bcolors.WARNING + '[-] Invalid Input' + bcolors.ENDC)
            return get_input(question)
    except Exception as error:
        print(bcolors.WARNING + "[-] Please enter 1 or 2" + bcolors.ENDC)
        print(error)
        return get_input(question)

def post_processing(log, LOG_FILE_PATH=None):
    """
    - printer
    """
    # True-True means packet was received and matching value identified
    # True-False means packet was received but pattern match failed
    # False-False means packet not received and, obviously, pattern not matched

    received_and_match = 0
    received_not_match = 0
    not_matched_not_received = 0

    for key, item in log.items():
        print(key, item)

        if item == "True-True":
            received_and_match += 1
        if item == "True-False":
            received_not_match += 1
        if item == "False-False":
            not_matched_not_received += 1

        if LOG_FILE_PATH and key:
            log_it(key, item, LOG_FILE_PATH)

    print("\n=========================================\n")
    print("received_and_match:", received_and_match)
    print("received_not_match:", received_not_match)
    print("not_matched_not_received", not_matched_not_received)
    print("total:", received_and_match + received_not_match + not_matched_not_received)

def log_it(key, item, LOG_FILE_PATH):

    # print(key.getvalue())

    load = '        load      = '
    index = key.getvalue().find(load)

    if index:
        f = open(LOG_FILE_PATH,"a+")
        payload = key.getvalue()[index+len(load):-2]
        f.write(payload + "\n")
        f.close()

    return
