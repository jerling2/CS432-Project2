"""

Header

"""

# ---------------------------------------------------------------------------- #
# ------------------------- Standard Library Imports ------------------------- #

from socket import *
import sys
import time
import os
import glob
import traceback
from threading import Thread

# ---------------------------------------------------------------------------- #
# ------------------------------- Router Class ------------------------------- #

class Router():
    
    def __init__(self) -> None:
        self.socket = None
        self.default_gateway_port = None
        self.table = None
        self.outgoing = {}

    def open(self, host: str, port: int) -> None:
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        try:
            self.socket.bind((host, port))
        except:
            print("Bind failed. Error : " + str(sys.exc_info()))
            sys.exit()
        CONNECTION_QUEUE_SIZE = 2
        self.socket.listen(CONNECTION_QUEUE_SIZE)
        print(f'router {port - 8000} is listening on {host}:{port}')
        return None

    def load_router_table(self, path: str) -> None:
        table = self.read_csv(path)
        self.default_gateway_port = self.find_default_gateway(table)
        self.table = self.generate_forwarding_table_with_range(table)
        return None

    def on_connect(self) -> None:
        connection, (ip, port) = self.socket.accept()
        try:
            client_thread = Thread(target=self.processing_thread, args=(connection, ip, port))
            client_thread.start()
        except:
            print("Thread did not start.")
            traceback.print_exc()
        return None

    def connect_to(self, host: str, port: int) -> None:
        self.outgoing[port] = self.create_socket(host, port)
        return None

    @staticmethod
    def create_socket(host: str, port: int) -> socket:
        soc = socket(AF_INET, SOCK_STREAM)
        try:
            soc.connect((host, port))
        except:
            print("Connection Error to", port)
            sys.exit()
        return soc

    def processing_thread(self, connection, ip, port, max_buffer_size=5120):
        # 2. Continuously process incoming packets
        while True:
            packet = self.receive_packet(connection, max_buffer_size)

            if packet == ['']:
                print(f'Connection closed with port {port}')
                # Empty packet means router 1 has finished sending all packets.
                break

            src_ip, dst_ip, payload, ttl = tuple(packet)
            print(src_ip, dst_ip, payload, ttl)
            # 6. Decrement the TTL by 1 and construct a new packet with the new TTL.
            ## new_ttl = ...
            ## new_packet = ...

            # 7. Convert the destination IP into an integer for comparison purposes.
            ## destinationIP_bin = ...
            ## destinationIP_int = ...

            # 8. Find the appropriate sending port to forward this new packet to.
            ## ...

            # 9. If no port is found, then set the sending port to the default port.
            ## ...

            # 11. Either
            # (a) send the new packet to the appropriate port (and append it to sent_by_router_2.txt),
            # (b) append the payload to out_router_2.txt without forwarding because this router is the last hop, or
            # (c) append the new packet to discarded_by_router_2.txt and do not forward the new packet
            # ## if ...:
            #     print("sending packet", new_packet, "to Router 3")
            #     ## ...
            # ## elif ...:
            #     print("sending packet", new_packet, "to Router 4")
            #     ## ...
            # ## elif ...:
            #     print("OUT:", payload)
            #     ## ...
            # else:
            #     print("DISCARD:", new_packet)
            #     ## ...

    def lpm(self, dest_ip: bin) -> str:
        # Longest Prefix Match Routing Algorithm
        port = '0.0.0.0'
        max_netmax = 0
        for record in self.table:
            netmask = record[1]
            if netmask < max_netmax:
                continue
            ip_range = record[0]
            if dest_ip in range(ip_range[0], ip_range[1]):
                port = record[3]
                max_netmax = netmask
        return port
    
    @staticmethod
    def read_csv(path: str) -> list[list]:
        table_file = open(path, 'r')
        table = table_file.readlines()
        table_list = []
        for record in table:
            record = list(map(lambda x: x.strip(), record.split(',')))
            table_list.append(record)
        table_file.close()
        return table_list
    
    @staticmethod
    def find_default_gateway(table: list[list]) -> str | None:
        for record in table:
            if record[0] == '0.0.0.0':
                return record[3]
        return None
    
    def generate_forwarding_table_with_range(self, table: list[list]) -> list[list]:
        new_table = []
        for old_record in table:
            network_dst_bin = self.ip_to_bin(old_record[0])
            netmask_bin = self.ip_to_bin(old_record[1])
            ip_range = self.find_ip_range(network_dst_bin, netmask_bin)
            new_table.append([ip_range] + [netmask_bin] + old_record[2:])
        return new_table

    @staticmethod
    def ip_to_bin(ip: str) -> bin:
        octlets = list(map(lambda x: bin(int(x))[2:].zfill(8), ip.split('.')))
        return int(''.join(octlets), 2)
    
    @staticmethod
    def bit_not(n: bin, numbits: int = 32) -> bin:
        return (1 << numbits) - 1 - n
    
    def find_ip_range(self, network_dst: bin, netmask: bin) -> list[bin, bin]:
        min_ip = network_dst & netmask
        max_ip = min_ip + self.bit_not(netmask)
        return [min_ip, max_ip]
    
    @staticmethod
    def write_to_file(path: str, packet_to_write: str, send_to_router: str = None) -> None:
        """
        NOTE Valid Paths:
            1. ./output/received_by_router_#.txt
            2. ./output/out_router_#.txt
            3. ./output/discarded_by_router_#.txt
            4. ./output/out_sent_by_router_router_#.txt
        NOTE For most cases:
            * Append the packet to the File
            * Exception: if sending a packet then do the extra step.
        """
        out_file = open(path, "a")
        if not send_to_router:
            out_file.write(packet_to_write + "\n")
        else:
            out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
        out_file.close()
    
    @staticmethod
    def receive_packet(connection: socket, max_buffer_size: int) -> list[list]:
        """
        NOTE:
            packet should look like s"ipsource,ipdestination,payload,TTL"
        """
        req = connection.makefile('rb', 0)
        packet_size = sys.getsizeof(req)
        if packet_size > max_buffer_size:
            print("The packet size is greater than expected", packet_size)
        decoded_packet = req.readline().decode('utf-8')
        # TODO:  Append the packet to received_by_router_2.txt.
        print("received packet", decoded_packet)
        packet = list(map(lambda x: x.strip(), decoded_packet.split(',')))
        return packet
    
