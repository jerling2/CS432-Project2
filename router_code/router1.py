import time
import os
import glob
from router import Router


def read_packet_file(path):
    packet_file = open(path, 'r')
    packet_list = [p.strip() for p in packet_file.readlines()]
    packet_file.close()
    return packet_list


def proccess_packet(encoded_packet):
    packet = list(map(lambda x: x.strip(), encoded_packet.split(',')))
    src_ip, dst_ip, payload, ttl = tuple(packet)
    ttl = int(ttl) - 1
    port = ROUTER.lpm(ROUTER.ip_to_bin(dst_ip))
    new_packet = f'{src_ip},{dst_ip},{payload},{ttl}'
    if port == '127.0.0.1':
        print(f'packet accepted!')
    elif ttl == 0:
        print(f'packet from Router {ROUTER.rt_names[port]} discarded')
    else:
        print(f'sending packet to Router {ROUTER.rt_names[port]}')
        ROUTER.send_packet(ROUTER.outgoing[port], new_packet)


def main():
    global ROUTER 
    ROUTER = Router('127.0.0.1', 8001)
    ROUTER.open()
    ROUTER.load_router_table('../input/router_1_table.csv')
    ROUTER.connect_to('127.0.0.1', '8002', 'a')
    ROUTER.connect_to('127.0.0.1', '8004', 'b')
    packet_list = read_packet_file('../input/packets.csv')
    for packet in packet_list:
        proccess_packet(packet)
        time.sleep(0.1)

    files = glob.glob('./output/*')
    for f in files:
        os.remove(f)

if __name__ == '__main__':
    main()