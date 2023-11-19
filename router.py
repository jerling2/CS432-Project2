"""
    Title: Router
    Brief: A Python file that contains the Router class.
    Author: Joseph Erlinger.
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
        """
        Description:
            Send a packet to the server's connection, and send a newline
            character to indicate the end of the message.
        :param:
            connection (socket): connection with the server's socket.
            packet (str): packet in form of 'ip_src,ip_dst,payload,ttl'.
        """
        socket_file = connection.makefile('wb')
        socket_file.write(packet.encode('utf-8'))
        socket_file.write('\n'.encode('utf-8'))
        return None
    
    @staticmethod
    def receive_packet(connection: socket, max_buffer_size: int) -> list[str]:
        """
        Description:
            receive a packet from the client's connection. Process the packet
            into a list.
        :param:
            connection (socket): connection with the client's socket.
            max_buffer_size (int): (used mainly for debug).
        :return:
            packet (list[str]): [ip_src, ip_dst, payload, ttl].
        """
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
        """ Load forwarding table (with range) into self.table """
        table = self.read_csv(path)
        self.table = self.generate_forwarding_table_with_range(table)
        return None

    def generate_forwarding_table_with_range(self, table: list[list]) -> list[list]:
        """
        Description:
            For each record in the forwarding table, find the ip range given
            the binary representation of the network destination address and
            netmask. Then, construct a new record in the form of:
            '[ip_range (bin), netmask_bin (bin), host_ip (str), outgoing port (str)]'
        :param:
            table (list[list]): forwarding table given by router_#_table.csv.
        :return:
            new_table (list[list]): New forwarding table with an ip range and
            a binary representation of netmask.
        """
        new_table = []
        for record in table:
            network_dst_bin = self.ip_to_bin(record[0])
            netmask_bin = self.ip_to_bin(record[1])
            ip_range = self.find_ip_range(network_dst_bin, netmask_bin)
            new_table.append([ip_range] + [netmask_bin] + record[2:])
        return new_table

    def lpm(self, dest_ip: bin) -> str:
        """
        Description:
            Longest Prefix Matching routing algorithm. Start with port = undefined, and the
            longest_netmask_length = 0. Iterate through this router's forwarding table. If the
            current netmask is shorter than the longest_netmask_length, then simply skip the 
            record. Otherwise, if the destination ip is within the ip range of the record, then 
            the port is equal to the record's interface/port and the new longest_netmask_length 
            = current netmask. At the end of the algorithm, return the 'longest prefix matched'
            port/interface.
        Note:
            It is gaurenteed that lpm returns a port if a default interface is defined in the
            router's forwarding table 
        :param:
            dest_ip (bin): the destination ip of a packet.
        :return:
            port (str): the outgoing port/interface of which to send that packet through.
        """
        port = None
        longest_netmask_length = 0
        for record in self.table:
            netmask = record[1]
            if netmask < longest_netmask_length:
                continue
            ip_range = record[0]
            if dest_ip in range(ip_range[0], ip_range[1]):
                port = record[3]
                longest_netmask_length = netmask
        return port

    # -------------------------------- #
    # IP Conversion and Bit Operations #
    # -------------------------------- #

    def find_ip_range(self, network_dst: bin, netmask: bin) -> list[bin, bin]:
        """ Straightforward process of getting the ip range """
        min_ip = network_dst & netmask 
        possible_number_of_hosts_in_range = self.bit_not(netmask)
        max_ip = min_ip + possible_number_of_hosts_in_range
        return [min_ip, max_ip]

    @staticmethod
    def ip_to_bin(ip: str) -> bin:
        """
        Convert an ip into a binary number with the following steps:
            1. split the string on '.'s
            2. convert each element of list into an integer then into binary.
            3. remove the 0b that python places infront of a binary number string.
            4. fill in zeros to the left so that each octlets length is 8.
            5. join the list of octlets into a string.
            6. tell python to intepret the string as an binary integer.
        :param:
            ip (str): an ip address in the form of 'a.b.c.d'
        :return:
            ip_bin (bin): binary reprsentation of 'a.b.c.d'
        """
        octlets = list(map(lambda x: bin(int(x))[2:].zfill(8), ip.split('.')))
        return int(''.join(octlets), 2)
    
    @staticmethod
    def bit_not(n: bin, numbits: int = 32) -> bin:
        """ Flip 1's to 0's and 0's to 1's """
        return (1 << numbits) - 1 - n
    
    # --------------- #
    # File IO Methods #
    # --------------- #

    @staticmethod
    def read_csv(path: str) -> list[list]:
        """
        Description:
            Read a csv file line by line. For each line, split on the ','s.
            Strip any leading or trailing newline or whitespace from each
            element in the record. Append the record to the table.
        :param:
            path (str): path to csv file.
        :return:
            table (list[list]): a table of records (lists) made by the csv.
        """
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
        """
        Description:
            When a router receives, discards, accepts, or sends a packet, then append
            some data to a specified file path.
        :params:
            path (str): REC/OUT/DIS/SNT_PATH + router's # + 'txt'.
            packet_to_write (str): packet in form of 'ip_src,ip_dst,payload,ttl' or just 'payload'.
            send_to_router (str): the name of the router that is being sent a packet.
        """
        out_file = open(path, "a")
        if not send_to_router:
            out_file.write(packet_to_write + "\n")
        else:
            out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
        out_file.close()
        return None

    def append_packet_to_received_file(self, packet_to_write: list) -> None:
        """ wrapper function to improve readability in processing_thread """
        self.write_to_file(REC_PATH + self.name + EXT, ','.join(packet_to_write))
        return None
    
    def append_payload_to_out_file(self, payload_to_write: str) -> None:
        """ wrapper function to improve readability in processing_thread """
        self.write_to_file(OUT_PATH + self.name + EXT, payload_to_write)
        return None
    
    def append_packet_to_discard_file(self, packet_to_write: str) -> None:
        """ wrapper function to improve readability in processing_thread """
        self.write_to_file(DIS_PATH + self.name + EXT, packet_to_write)
        return None
    
    def append_packet_to_sent_file(self, packet_to_write, send_to_router) -> None:
        """ wrapper function to improve readability in processing_thread """
        self.write_to_file(SNT_PATH + self.name + EXT, packet_to_write, send_to_router)
        return None
    