"""

"""

# ----------------------------------------------------------------------------------------------- #
# ----------------------------------- Standard Library Imports ---------------------------------- #

from socket import *
import sys
import traceback
from threading import Thread

# ----------------------------------------------------------------------------------------------- #
# --------------------------------------- Global Variables -------------------------------------- #

REC_PATH = './output/received_by_router_'
OUT_PATH = './output/out_router_'
DIS_PATH = './output/discarded_by_router_'
SNT_PATH = './output/sent_by_router_'
EXT = '.txt'

# ----------------------------------------------------------------------------------------------- #
# ----------------------------------------- Router Class ---------------------------------------- #
class Router():
    """
    Description:
        The Router Class defines how router objects handle:
            1.) other client-router connections
            2.) and the flow of packets.
    Usuage: 
        Run each router object in its own process. Specify the routing table for the router in the
        input directory. Connect client routers to server-routers by evoking connect_to(). Server
        routers automatically connect to client routers due to a handshake protocol. Adding packets
        to the network is the responsibility of the programmer's independent implementation.
    Class Instance Variables:
        self.host (str): the ip of the router's socket in the pattern 'a.b.c.d'.
        self.port (int): the port of the router's socket.
        self.name (str): the name of this router - provides flavor to messages.
        self.socket (socket): the router's socket.
        self.outgoing (dict, key = port <str>): contains the connections of connected routers.
        self.rt_names (dict, key = port <str>): contains the names of connected routers.
    """
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.name = str(port - 8000) # < based on our specific router topology
        self.socket = None
        self.table = None
        self.outgoing = {}
        self.rt_names = {}

    def open(self) -> None:
        """ 
        Description:
            Try to bind the router's socket to a host and port.
        """
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        try:
            self.socket.bind((self.host, self.port))
        except:
            print("Bind failed. Error : " + str(sys.exc_info()))
            sys.exit()
        self.socket.listen(5)
        print(f'router {self.name} is listening on {self.host}:{self.port}')
        return None

    # ------------------------- #
    # Socket Connection Methods #
    # ------------------------- #

    def on_connect(self) -> None:
        """
        Description:
            Wait for a connection, then send a handshake after establishing a
            connection. Handle the client connection in a new thread, which
            will allow the router to accept more connections.
        """
        connection, (ip, port) = self.socket.accept()
        self.handshake(connection)
        try:
            client_thread = Thread(target=self.processing_thread, args=(connection,))
            client_thread.start()
        except:
            print("Thread did not start.")
            traceback.print_exc()
        return None

    def connect_to(self, host: str, port: str, handshake_message:str) -> None:
        """
        Description:
            Establish a connection to a router given a host and port. Store the
            connection in the outgoing dict, and store the name of the router
            in the rt_names dict. Then send a handshake to the connection in
            the form: 'host,port,message'.
        Example Usuage:
            ROUTER.connect_to('127.0.0.1', '8002', 'a')
        Explaination of the Above Example:
            Connect this router to router 2, and tell router 2 to remember this
            connection as port 'a'.
        :param:
            host (str): the ip of the server's socket in the pattern 'a.b.c.d'.
            port (str): the port of the server's socket. Note, this is a string.
            handshake_message (str): the handshake message sent to the server.
        """
        self.outgoing[port] = self.create_socket(host, int(port))
        self.rt_names[port] = str(int(port) - 8000)
        handshake_message = f'{self.host},{self.port},' + handshake_message
        self.outgoing[port].send(handshake_message.encode('utf-8') + b'\n')
        return None

    def handshake(self, connection: socket) -> None:
        """
        Description:
            Receive a handshake and split the string into three fields: host, 
            port, and message. If the message says 'it is nice to meet you',
            then this router is a client that is already connected to the
            server - thus, the handshake can end. Otherwise, the message is a
            variable (i.e. 'a', 'b', 'e', etc.) and this router is a server. As
            such, connect to the client with the host and port given in the
            handshake. Then, store the connection in the outgoing dict where
            the port is equal to a variable (i.e. key = 'a', 'b', 'e', ect.)
            and store the name in the rt_names where again the port is equal to
            a variable.
        :param:
            connection (socket): the socket from either the client or server.
        """
        handshake_data = connection.recv(1024).decode('utf-8')
        handshake_list = list(map(lambda x: x.strip(), handshake_data.split(',')))
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
        """
        Description:
            Try to create a socket connection given a host and port.
        :params:
            host (str): the ip of the server's socket in the pattern 'a.b.c.d'.
            port (int): the port of the server's socket.
        :return:
            soc (socket): the connection with the server's socket.
        """
        soc = socket(AF_INET, SOCK_STREAM)
        try:
            soc.connect((host, port))
        except:
            print("Connection Error to", port)
            sys.exit()
        return soc

    # -------------------------- #
    # The Main Routing Algorithm #
    # -------------------------- #

    def processing_thread(self, connection: socket, max_buffer_size=5120) -> None:
        """
        Description:
            Receive a stream of packets. Each packet is proccessed by receive_packet. Decrement TTL
            by 1 and construct a new packet with the new TTL. Get outgoing port by using lpm
            (longest prefix matching). If the outgoing port is '127.0.0.1', then the packet is
            'accepted' and appended to the out file. Else, if the ttl = 0, then the new packet is
            discarded and appended to the discard file. Otherwise, the new packet is forwarded to
            the next hop router given by the outgoing dict (where key = port given by lpm) and the
            new packet is appended to the sent file. 
        :param:
            connection (socket): connection with the client socket.
        """
        while True:
            packet = self.receive_packet(connection, max_buffer_size)
            if packet == ['']:  # < connection closed
                break
            self.append_packet_to_received_file(packet)
            src_ip, dst_ip, payload, ttl = tuple(packet)
            ttl = int(ttl) - 1
            new_packet = f'{src_ip},{dst_ip},{payload},{ttl}'
            port = self.lpm(self.ip_to_bin(dst_ip))
            if port == '127.0.0.1':
                self.append_payload_to_out_file(payload)
                print(f'packet accepted!')
            elif ttl == 0:
                self.append_packet_to_discard_file(new_packet)
                print(f'packet from Router {self.rt_names[port]} discarded')
            else:
                self.append_packet_to_sent_file(new_packet, self.rt_names[port])
                print(f'sending packet to Router {self.rt_names[port]}')
                self.send_packet(self.outgoing[port], new_packet)
        return None
    
    # ----------------- #
    # Packet IO Methods #
    # ----------------- #

    def send_packet(self, connection: socket, packet: str) -> None:
        socket_file = connection.makefile('wb')
        socket_file.write(packet.encode('utf-8'))
        socket_file.write('\n'.encode('utf-8'))
        return None
    
    @staticmethod
    def receive_packet(connection: socket, max_buffer_size: int) -> list[list]:
        req = connection.makefile('rb', 0)
        packet_size = sys.getsizeof(req)
        if packet_size > max_buffer_size:
            print("The packet size is greater than expected", packet_size)
        decoded_packet = req.readline().decode('utf-8')
        packet = list(map(lambda x: x.strip(), decoded_packet.split(',')))
        return packet
    
    # --------------------------- #
    # Forwarding Table Generation #
    # --------------------------- #

    def load_router_table(self, path: str) -> None:
        table = self.read_csv(path)
        self.table = self.generate_forwarding_table_with_range(table)
        return None

    def generate_forwarding_table_with_range(self, table: list[list]) -> list[list]:
        new_table = []
        for old_record in table:
            network_dst_bin = self.ip_to_bin(old_record[0])
            netmask_bin = self.ip_to_bin(old_record[1])
            ip_range = self.find_ip_range(network_dst_bin, netmask_bin)
            new_table.append([ip_range] + [netmask_bin] + old_record[2:])
        return new_table

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

    # -------------------------------- #
    # IP Conversion and Bit Operations #
    # -------------------------------- #

    def find_ip_range(self, network_dst: bin, netmask: bin) -> list[bin, bin]:
        min_ip = network_dst & netmask
        max_ip = min_ip + self.bit_not(netmask)
        return [min_ip, max_ip]

    @staticmethod
    def ip_to_bin(ip: str) -> bin:
        octlets = list(map(lambda x: bin(int(x))[2:].zfill(8), ip.split('.')))
        return int(''.join(octlets), 2)
    
    @staticmethod
    def bit_not(n: bin, numbits: int = 32) -> bin:
        return (1 << numbits) - 1 - n
    
    # --------------- #
    # File IO Methods #
    # --------------- #

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
    def write_to_file(path: str, packet_to_write: str, send_to_router: str = None) -> None:
        out_file = open(path, "a")
        if not send_to_router:
            out_file.write(packet_to_write + "\n")
        else:
            out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
        out_file.close()
        return None

    def append_packet_to_received_file(self, packet_to_write: list) -> None:
        self.write_to_file(REC_PATH + self.name + EXT, ','.join(packet_to_write))
        return None
    
    def append_payload_to_out_file(self, payload_to_write: str) -> None:
        self.write_to_file(OUT_PATH + self.name + EXT, payload_to_write)
        return None
    
    def append_packet_to_discard_file(self, packet_to_write: str) -> None:
        self.write_to_file(DIS_PATH + self.name + EXT, packet_to_write)
        return None
    
    def append_packet_to_sent_file(self, packet_to_write, send_to_router) -> None:
        self.write_to_file(SNT_PATH + self.name + EXT, packet_to_write, send_to_router)
        return None
    