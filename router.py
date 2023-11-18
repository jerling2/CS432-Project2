"""

Header

"""

# ---------------------------------------------------------------------------- #
# ------------------------- Standard Library Imports ------------------------- #

from socket import *
import sys
import traceback
from threading import Thread

# ---------------------------------------------------------------------------- #
# ------------------------------ Global Variable ----------------------------- #

REC_PATH = './output/received_by_router_'
OUT_PATH = './output/out_router_'
DIS_PATH = './output/discarded_by_router_'
SNT_PATH = './output/sent_by_router_'
EXT = '.txt'

# ---------------------------------------------------------------------------- #
# ------------------------------- Router Class ------------------------------- #

class Router():
    
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.name = str(port - 8000)
        self.socket = None
        self.default_gateway_port = None
        self.table = None
        self.outgoing = {}
        self.rt_names = {}

    def open(self) -> None:
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        try:
            self.socket.bind((self.host, self.port))
        except:
            print("Bind failed. Error : " + str(sys.exc_info()))
            sys.exit()
        CONNECTION_QUEUE_SIZE = 2
        self.socket.listen(CONNECTION_QUEUE_SIZE)
        print(f'router {self.name} is listening on {self.host}:{self.port}')
        return None

    def load_router_table(self, path: str) -> None:
        table = self.read_csv(path)
        self.default_gateway_port = self.find_default_gateway(table)
        self.table = self.generate_forwarding_table_with_range(table)
        return None

    def on_connect(self) -> None:
        connection, (ip, port) = self.socket.accept()
        self.handshake(connection)
        try:
            client_thread = Thread(target=self.processing_thread, args=(connection, port))
            client_thread.start()
        except:
            print("Thread did not start.")
            traceback.print_exc()
        return None

    def connect_to(self, host: str, port: str, handshake_message:str) -> None:
        self.outgoing[port] = self.create_socket(host, int(port))
        self.rt_names[port] = str(int(port) - 8000)
        handshake_message = f'{self.host},{self.port},' + handshake_message
        self.outgoing[port].send(handshake_message.encode('utf-8') + b'\n')
        return None

    def handshake(self, connection: socket) -> None:
        handshake_msg = connection.recv(1024).decode('utf-8')
        handshake_list = list(map(lambda x: x.strip(), handshake_msg.split(',')))
        host, port = handshake_list[0], handshake_list[1]
        handshake_msg = handshake_list[2]
        if handshake_msg == 'it is nice to meet you':
            return None
        port_variable = handshake_msg # < Alias
        self.connect_to(host, port, 'it is nice to meet you')
        self.outgoing[port_variable] = self.outgoing.pop(port, None)
        self.rt_names[port_variable] = self.rt_names.pop(port, None)
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

    def processing_thread(self, connection, port, max_buffer_size=5120):
        while True:
            packet = self.receive_packet(connection, max_buffer_size)
            if packet == ['']:
                print(f'Connection with port {port} closed')
                break
            self.write_to_file(REC_PATH + self.name + EXT, ','.join(packet))
            src_ip, dst_ip, payload, ttl = tuple(packet)
            ttl = int(ttl) - 1
            port = self.lpm(self.ip_to_bin(dst_ip))
            new_packet = f'{src_ip},{dst_ip},{payload},{ttl}'
            if port == '127.0.0.1':
                self.write_to_file(OUT_PATH + self.name + EXT, payload)
                print(f'packet accepted!')
            elif ttl == 0:
                self.write_to_file(DIS_PATH + self.name + EXT, new_packet)
                print(f'packet from Router {self.rt_names[port]} discarded')
            else:
                self.write_to_file(SNT_PATH + self.name + EXT, new_packet, self.rt_names[port])
                print(f'sending packet to Router {self.rt_names[port]}')
                self.send_packet(self.outgoing[port], new_packet)
    
    def send_packet(self, connection: socket, packet: str) -> None:
        socket_file = connection.makefile('wb')
        socket_file.write(packet.encode('utf-8'))
        socket_file.write('\n'.encode('utf-8'))

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
        req = connection.makefile('rb', 0)
        packet_size = sys.getsizeof(req)
        if packet_size > max_buffer_size:
            print("The packet size is greater than expected", packet_size)
        decoded_packet = req.readline().decode('utf-8')
        packet = list(map(lambda x: x.strip(), decoded_packet.split(',')))
        return packet
    
