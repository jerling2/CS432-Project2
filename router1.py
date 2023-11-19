################################################################################
###~- ROUTER 1 -~#~- ROUTER 1 -~#~- ROUTER 1 -~#~- ROUTER 1 -~#~- ROUTER 1 -~###
################################################################################
# ---------------------------------------------------------------------------- #
# ---------------------- Router Network Topology Diagram --------------------- #
#                                 ┌┄┄┄┐              ┌┄┄┄┐                     #
#                          ◁ 8002 | 2 | d ▷┄┄┄◁ 8003 | 3 |                     #
#                        ╱        └┄┄┄┘              └┄┄┄┘                     #
#                       △           c                                          #
#                       a           ▽                                          #
#                     ┌▀▀▀┐         ┊                                          #
#                8001 |*1*|         ┊                                          #
#                     └▄▄▄┘         ┊                                          #
#                       b           △                                          #
#                       ▽  	       8004                                        #
#                        ╲        ┌┄┄┄┐              ┌┄┄┄┐                     #
#                          ◁ 8004 | 4 | e ▷┄┄┄◁ 8005 | 5 |                     #
#                                 └┄┄┄┘              └┄┄┄┘                     #
#                                   f                                          #
#                                   ▽                                          #
#                                    ╲               ┌┄┄┄┐                     #
#                                      ┄┄┄┄┄┄ ◁ 8006 | 6 |                     #
#                                                    └┄┄┄┘                     #
# ---------------------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #
# ----------------- Standard Library Imports + Router Import ----------------- #

import time
import os
import glob
from router import Router

# --------------------------------------------------------------------------- #
# --------------------------------- Settings -------------------------------- #

SECONDS_BETWEEN_PACKETS = 0.1
DELETE_FILES_WHEN_FINISHED = True
SECONDS_BEFORE_FILES_DELETED = 5

# --------------------------------------------------------------------------- #
# ------------------------ Special Router 1 Functions ----------------------- #

def read_packet_file(path):
    packet_file = open(path, 'r')
    packet_list = [p.strip() for p in packet_file.readlines()]
    packet_file.close()
    return packet_list


def proccess_packet(encoded_packet) -> None:
    packet = list(map(lambda x: x.strip(), encoded_packet.split(',')))
    ROUTER.append_packet_to_received_file(packet)
    src_ip, dst_ip, payload, ttl = tuple(packet)
    ttl = int(ttl) - 1
    port = ROUTER.lpm(ROUTER.ip_to_bin(dst_ip))
    new_packet = f'{src_ip},{dst_ip},{payload},{ttl}'
    if port == '127.0.0.1':
        ROUTER.append_payload_to_out_file(payload)
        print(f'packet accepted!')
    elif ttl == 0:
        ROUTER.append_packet_to_discard_file(new_packet)
        print(f'packet from Router {ROUTER.rt_names[port]} discarded')
    else:
        ROUTER.append_packet_to_sent_file(new_packet, ROUTER.rt_names[port])
        print(f'sending packet to Router {ROUTER.rt_names[port]}')
        ROUTER.send_packet(ROUTER.outgoing[port], new_packet)
    return None

# ---------------------------------------------------------------------------- #
# -------------------------------- Main Driver ------------------------------- #

def main():
    global ROUTER 
    ROUTER = Router('127.0.0.1', 8001)
    ROUTER.open()
    ROUTER.load_router_table('./input/router_1_table.csv')
    ROUTER.connect_to('127.0.0.1', '8002', 'a')
    ROUTER.connect_to('127.0.0.1', '8004', 'b')
    packet_list = read_packet_file('./input/packets.csv')
    for packet in packet_list:
        proccess_packet(packet)
        time.sleep(SECONDS_BETWEEN_PACKETS)
    # Wait 5 seconds before deleting files in the output directory.
    if DELETE_FILES_WHEN_FINISHED:
        time.sleep(SECONDS_BEFORE_FILES_DELETED)
        files = glob.glob('./output/*')
        for f in files:
            os.remove(f)
    ROUTER.socket.close()

if __name__ == '__main__':
    main()