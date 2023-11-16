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

# ---------------------------------------------------------------------------- #
# ------------------------------- Router Class ------------------------------- #

class Router():
    """ The router should be able to 
        1. Open a socket
        2. Connect to a socket
        3. read from a csv file 
        4. write output to a file
    """
    def listen(self, port) -> None:
        """ Open the proxy server so it can be ready to serve."""
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.bind(('localhost', port))
        print(f'router {port - 8000} is listening on {port}')
        return None
    
    @staticmethod
    def read_csv(path) -> list:
        table_file = open(path, 'r')
        table = table_file.readlines()
        table_list = []
        for record in table:
            record = list(map(lambda x: x.strip(), record.split(',')))
            table_list.append(record)
        table_file.close()
        return table_list
    
    @staticmethod
    def find_default_gateway(table):
        for record in table:
            if record[0] == '0.0.0.0':
                return record[3]
        return None
    
    def generate_forwarding_table_with_range(self, table):
        # 1. Create an empty list to store the new forwarding table.
        new_table = []
        for old_record in table:
            network_dst_bin = self.ip_to_bin(old_record[0])
            netmask_bin = self.ip_to_bin(old_record[1])
            ip_range = self.find_ip_range(network_dst_bin, netmask_bin)
            new_table.append([ip_range] + old_record[2:])
        return new_table

    @staticmethod
    def ip_to_bin(ip):
        octlets = list(map(lambda x: bin(int(x))[2:].zfill(8), ip.split('.')))
        return int(''.join(octlets), 2)
    
    @staticmethod
    def bit_not(n, numbits=32):
        return (1 << numbits) - 1 - n
    
    def find_ip_range(self, network_dst: bin, netmask: bin):
        min_ip = network_dst & netmask
        max_ip = min_ip + self.bit_not(netmask)
        return [min_ip, max_ip]
    
    @staticmethod
    def write_to_file(path, packet_to_write, send_to_router=None):
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


# Temporary
def main():
    # NOTE: might remove port and path from initilization step
    router = Router()
    router.listen(8001)
    table = router.read_csv("../input/router_1_table.csv")
    router.find_default_gateway(table)
    router.generate_forwarding_table_with_range(table)
    
if __name__ == '__main__':
    main()